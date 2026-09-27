// Package web serves azk's local web interface: server-rendered pages with
// a little htmx on top, plus a small JSON API under /api/v1. It is meant
// for one person on one machine; it binds to loopback unless told
// otherwise and holds the vault unlocked only while a session is active.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
	"github.com/danto7/azk/internal/vault"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Options configure the server.
type Options struct {
	// IdleTimeout locks the vault and ends the session after this much
	// inactivity. Zero disables it.
	IdleTimeout time.Duration
	// Secure marks cookies Secure; set when serving TLS.
	Secure bool
	// Logger receives request and lifecycle logs; nil uses log.Default.
	Logger *log.Logger
	// Unwrapper unlocks keyvault slots for the "Unlock with Key Vault"
	// button; nil uses the default credential.
	Unwrapper vault.Unwrapper
}

// maxBody caps request bodies; imports and secrets are small.
const maxBody = 2 << 20

// Server is the web UI.
type Server struct {
	svc  *service.Service
	opts Options
	log  *log.Logger
	tmpl map[string]*template.Template
	mux  *http.ServeMux

	mu       sync.Mutex
	session  *session // single user, single session
	lastSeen time.Time
}

type session struct {
	token string
	csrf  string
}

// New builds a server.
func New(svc *service.Service, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	s := &Server{svc: svc, opts: opts, log: opts.Logger}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"time": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"opttime": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"json": func(v any) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err.Error()
			}
			return string(b)
		},
		"short": func(s string) string {
			if len(s) > 8 {
				return s[:8]
			}
			return s
		},
	}
	pages, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.tmpl = map[string]*template.Template{}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", p)
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		s.tmpl[name] = t
	}
	return nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	s.mux.ServeHTTP(w, r)
}

// Serve listens and serves until ctx is done. It refuses non-loopback
// addresses unless allowRemote is set and logs a warning in that case.
func (s *Server) Serve(ctx context.Context, listen string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", listen, err)
	}
	if !isLoopback(host) {
		if !allowRemote {
			return fmt.Errorf("refusing to listen on %s: pass --allow-remote to expose the UI beyond this machine", listen)
		}
		s.log.Printf("WARNING: listening on %s without TLS; anyone who can reach this port and knows the passphrase can use the vault", listen)
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { //nolint:gosec // shutdown must outlive the cancelled context
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		s.lock()
	}()
	if s.opts.IdleTimeout > 0 {
		go s.idleWatch(ctx)
	}
	s.log.Printf("azk web UI on http://%s (vault %s)", ln.Addr(), s.svc.Vault().Path())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" || host == "" {
		return host == "localhost"
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) idleWatch(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			idle := s.session != nil && time.Since(s.lastSeen) > s.opts.IdleTimeout
			s.mu.Unlock()
			if idle {
				s.log.Printf("idle for %s, locking vault", s.opts.IdleTimeout)
				s.lock()
			}
		}
	}
}

// --- sessions ---

const cookieName = "azk_session"

func randomToken() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) login(w http.ResponseWriter) error {
	tok, err := randomToken()
	if err != nil {
		return err
	}
	csrf, err := randomToken()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.session = &session{token: tok, csrf: csrf}
	s.lastSeen = time.Now()
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.opts.Secure}) //nolint:gosec // Secure follows TLS; loopback http cannot set it
	return nil
}

// lock forgets the session and locks the vault.
func (s *Server) lock() {
	s.mu.Lock()
	s.session = nil
	s.mu.Unlock()
	s.svc.Vault().Lock()
}

// current returns the session for the request, touching lastSeen.
func (s *Server) current(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session.token)) != 1 {
		return nil
	}
	if s.svc.Vault().IsLocked() {
		s.session = nil
		return nil
	}
	s.lastSeen = time.Now()
	return s.session
}

// requireAuth wraps handlers that need an unlocked vault and a session.
func (s *Server) requireAuth(next func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.current(r)
		if sess == nil {
			if wantsJSON(r) {
				jsonError(w, http.StatusUnauthorized, "not logged in")
				return
			}
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.csrf)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r, sess)
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// --- rendering ---

type page struct {
	Title   string
	CSRF    string
	Flash   string
	Error   string
	Path    string
	Locked  bool
	Vault   string
	Version string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess *session, name string, data any) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "missing template "+name, http.StatusInternalServerError)
		return
	}
	p := page{Title: name, Path: r.URL.Path, Locked: s.svc.Vault().IsLocked(), Vault: s.svc.Vault().Path(), Data: data}
	if sess != nil {
		p.CSRF = sess.csrf
	}
	p.Flash = r.URL.Query().Get("flash")
	p.Error = r.URL.Query().Get("error")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", p); err != nil {
		s.log.Printf("render %s: %v", name, err)
	}
}

// fragment renders a named block from a page template (for htmx swaps).
func (s *Server) fragment(w http.ResponseWriter, name, block string, data any) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "missing template "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, block, data); err != nil {
		s.log.Printf("render %s/%s: %v", name, block, err)
	}
}

func redirectMsg(w http.ResponseWriter, r *http.Request, to, flash, errMsg string) {
	q := ""
	switch {
	case errMsg != "":
		q = "?error=" + urlEscape(errMsg)
	case flash != "":
		q = "?flash=" + urlEscape(flash)
	}
	http.Redirect(w, r, to+q, http.StatusSeeOther) //nolint:gosec // "to" is always a literal internal path
}

func urlEscape(s string) string { return url.QueryEscape(s) }

func userError(err error) string {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "not found"
	case errors.Is(err, store.ErrExists):
		return "an item with that name already exists"
	case errors.Is(err, vault.ErrLocked):
		return "the vault is locked"
	}
	return err.Error()
}

// keyvaultUnwrapper returns the configured unwrapper or the default.
func (s *Server) keyvaultUnwrapper() vault.Unwrapper {
	if s.opts.Unwrapper != nil {
		return s.opts.Unwrapper
	}
	return keyvault.Unwrapper{}
}
