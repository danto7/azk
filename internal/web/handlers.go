package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
	"github.com/danto7/azk/internal/vault"
)

func (s *Server) routes() {
	m := http.NewServeMux()
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(mustSub(staticFS, "static"))))

	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.loginPost)
	m.HandleFunc("POST /login/keyvault", s.loginKeyVault)
	m.HandleFunc("POST /lock", s.lockPost)

	m.HandleFunc("GET /{$}", s.requireAuth(s.dashboard))
	m.HandleFunc("GET /items", s.requireAuth(s.items))
	m.HandleFunc("GET /items/new", s.requireAuth(s.newItem))
	m.HandleFunc("POST /items/generate", s.requireAuth(s.generate))
	m.HandleFunc("POST /items/import", s.requireAuth(s.importKey))
	m.HandleFunc("POST /items/secret", s.requireAuth(s.setSecret))
	m.HandleFunc("GET /items/{name}", s.requireAuth(s.item))
	m.HandleFunc("POST /items/{name}/rotate", s.requireAuth(s.itemAction("rotate")))
	m.HandleFunc("POST /items/{name}/delete", s.requireAuth(s.itemAction("delete")))
	m.HandleFunc("POST /items/{name}/recover", s.requireAuth(s.itemAction("recover")))
	m.HandleFunc("POST /items/{name}/purge", s.requireAuth(s.itemAction("purge")))
	m.HandleFunc("POST /items/{name}/tags", s.requireAuth(s.itemAction("tags")))
	m.HandleFunc("POST /items/{name}/secret", s.requireAuth(s.itemAction("secret")))
	m.HandleFunc("POST /items/{name}/versions/{seq}/enable", s.requireAuth(s.versionEnable(true)))
	m.HandleFunc("POST /items/{name}/versions/{seq}/disable", s.requireAuth(s.versionEnable(false)))
	m.HandleFunc("POST /items/{name}/reveal", s.requireAuth(s.reveal))
	m.HandleFunc("GET /items/{name}/versions/{seq}/public.pem", s.requireAuth(s.publicKey("pem")))
	m.HandleFunc("GET /items/{name}/versions/{seq}/public.jwk", s.requireAuth(s.publicKey("jwk")))
	m.HandleFunc("GET /audit", s.requireAuth(s.audit))
	m.HandleFunc("GET /remotes", s.requireAuth(s.remotes))
	m.HandleFunc("POST /remotes", s.requireAuth(s.addRemote))
	m.HandleFunc("POST /remotes/{name}/remove", s.requireAuth(s.removeRemote))
	m.HandleFunc("POST /remotes/{name}/run", s.requireAuth(s.runRemote))

	m.HandleFunc("GET /api/v1/status", s.apiStatus)
	m.HandleFunc("GET /api/v1/items", s.requireAuth(s.apiItems))
	m.HandleFunc("GET /api/v1/items/{name}", s.requireAuth(s.apiItem))
	m.HandleFunc("GET /api/v1/audit", s.requireAuth(s.apiAudit))
	m.HandleFunc("POST /api/v1/lock", s.requireAuth(func(w http.ResponseWriter, r *http.Request, _ *session) {
		s.lock()
		writeJSON(w, map[string]bool{"locked": true})
	}))
	s.mux = m
}

// --- auth pages ---

type loginData struct {
	HasKeyVault bool
}

func (s *Server) loginData(ctx context.Context) loginData {
	d := loginData{}
	if slots, err := s.svc.Vault().Slots(ctx); err == nil {
		for _, sl := range slots {
			if sl.Kind == vault.SlotKeyVault {
				d.HasKeyVault = true
			}
		}
	}
	return d
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.current(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "login", s.loginData(r.Context()))
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pass := []byte(r.PostFormValue("passphrase"))
	defer crypto.Zero(pass)
	if err := s.svc.Vault().Unlock(r.Context(), pass); err != nil {
		s.log.Printf("login failed: %v", err)
		time.Sleep(500 * time.Millisecond) // slow down guessing
		redirectMsg(w, r, "/login", "", "wrong passphrase")
		return
	}
	s.finishLogin(w, r, "passphrase")
}

func (s *Server) loginKeyVault(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Vault().UnlockWith(r.Context(), s.keyvaultUnwrapper()); err != nil {
		s.log.Printf("keyvault unlock failed: %v", err)
		redirectMsg(w, r, "/login", "", "Key Vault unlock failed: "+err.Error())
		return
	}
	s.finishLogin(w, r, "keyvault")
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, how string) {
	if err := s.login(w); err != nil {
		s.svc.Vault().Lock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.svc.Record(r.Context(), "web.login", how, nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) lockPost(w http.ResponseWriter, r *http.Request) {
	if s.current(r) != nil {
		s.svc.Record(r.Context(), "web.lock", "", nil)
	}
	s.lock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.opts.Secure}) //nolint:gosec // Secure follows TLS; loopback http cannot set it
	redirectMsg(w, r, "/login", "vault locked", "")
}

// --- dashboard ---

type dashboardData struct {
	Info    *vault.Info
	Keys    int
	Secrets int
	Deleted int
	Remotes []store.Remote
	Audit   []store.AuditEntry
	Slots   []store.Slot
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	d := dashboardData{}
	var err error
	if d.Info, err = s.svc.Vault().Info(ctx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items, _ := s.svc.ListItems(ctx, store.ItemFilter{IncludeDeleted: true})
	for _, it := range items {
		switch {
		case it.DeletedAt != nil:
			d.Deleted++
		case it.Kind == string(crypto.KindSecret):
			d.Secrets++
		default:
			d.Keys++
		}
	}
	d.Remotes, _ = s.svc.Vault().Store().ListRemotes(ctx)
	d.Audit, _ = s.svc.Audit(ctx, 10)
	d.Slots, _ = s.svc.Vault().Slots(ctx)
	s.render(w, r, sess, "dashboard", d)
}

// --- items ---

type itemsData struct {
	Items   []*store.Item
	Kind    string
	Tag     string
	Query   string
	Deleted bool
	Kinds   []string
}

func (s *Server) items(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	d := itemsData{Kind: q.Get("kind"), Tag: q.Get("tag"), Query: q.Get("q"), Deleted: q.Get("deleted") == "1",
		Kinds: []string{"rsa", "ec", "oct", "ed25519", "secret"}}
	f := store.ItemFilter{Kind: d.Kind, Tag: d.Tag, NamePrefix: d.Query, OnlyDeleted: d.Deleted}
	items, err := s.svc.ListItems(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.Items = items
	s.render(w, r, sess, "items", d)
}

func (s *Server) newItem(w http.ResponseWriter, r *http.Request, sess *session) {
	s.render(w, r, sess, "new", map[string]string{"Tab": r.URL.Query().Get("tab")})
}

func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == ',' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid tag %q (want key=value)", line)
		}
		tags[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return tags, nil
}

func parseOptTime(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("invalid time %q", s)
}

func createOptions(r *http.Request) (service.CreateOptions, error) {
	tags, err := parseTags(r.PostFormValue("tags"))
	if err != nil {
		return service.CreateOptions{}, err
	}
	nbf, err := parseOptTime(r.PostFormValue("not_before"))
	if err != nil {
		return service.CreateOptions{}, err
	}
	exp, err := parseOptTime(r.PostFormValue("expires"))
	if err != nil {
		return service.CreateOptions{}, err
	}
	return service.CreateOptions{Tags: tags, NotBefore: nbf, Expires: exp}, nil
}

func (s *Server) generate(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	kind, err := crypto.ParseKind(r.PostFormValue("kind"))
	if err != nil {
		redirectMsg(w, r, "/items/new?tab=generate", "", err.Error())
		return
	}
	opts, err := createOptions(r)
	if err != nil {
		redirectMsg(w, r, "/items/new?tab=generate", "", err.Error())
		return
	}
	bits, _ := strconv.Atoi(r.PostFormValue("bits"))
	gen := crypto.GenerateOptions{Bits: bits, Curve: r.PostFormValue("curve")}
	if _, err := s.svc.CreateKey(r.Context(), name, kind, gen, opts); err != nil {
		redirectMsg(w, r, "/items/new?tab=generate", "", userError(err))
		return
	}
	redirectMsg(w, r, "/items/"+name, "key generated", "")
}

func (s *Server) importKey(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := r.ParseMultipartForm(maxBody); err != nil && !errors.Is(err, http.ErrNotMultipart) { //nolint:gosec // bounded by MaxBytesReader in ServeHTTP
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	data := []byte(r.PostFormValue("material"))
	if f, _, err := r.FormFile("file"); err == nil {
		defer func() { _ = f.Close() }()
		data, err = io.ReadAll(io.LimitReader(f, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	defer crypto.Zero(data)
	opts, err := createOptions(r)
	if err != nil {
		redirectMsg(w, r, "/items/new?tab=import", "", err.Error())
		return
	}
	trimmed := strings.TrimSpace(string(data))
	var jwk *crypto.JWK
	switch {
	case strings.HasPrefix(trimmed, "-----BEGIN"):
		jwk, err = crypto.ParsePEM(data)
	case strings.HasPrefix(trimmed, "{"):
		jwk, err = crypto.ParseJWK([]byte(trimmed))
	default:
		err = errors.New("paste a PEM or JWK key")
	}
	if err != nil {
		redirectMsg(w, r, "/items/new?tab=import", "", err.Error())
		return
	}
	defer jwk.Zero()
	if _, err := s.svc.ImportKey(r.Context(), name, jwk, opts); err != nil {
		redirectMsg(w, r, "/items/new?tab=import", "", userError(err))
		return
	}
	redirectMsg(w, r, "/items/"+name, "key imported", "")
}

func (s *Server) setSecret(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	value := []byte(r.PostFormValue("value"))
	defer crypto.Zero(value)
	opts, err := createOptions(r)
	if err != nil {
		redirectMsg(w, r, "/items/new?tab=secret", "", err.Error())
		return
	}
	if _, err := s.svc.SetSecret(r.Context(), name, value, r.PostFormValue("content_type"), opts); err != nil {
		redirectMsg(w, r, "/items/new?tab=secret", "", userError(err))
		return
	}
	redirectMsg(w, r, "/items/"+name, "secret stored", "")
}

type itemData struct {
	*service.ItemDetail
	IsSecret bool
	SigAlgs  []string
	EncAlgs  []string
	Tags     string
}

func (s *Server) itemData(ctx context.Context, name string) (*itemData, error) {
	d, err := s.svc.GetItem(ctx, name)
	if err != nil {
		return nil, err
	}
	out := &itemData{ItemDetail: d, IsSecret: d.Kind == string(crypto.KindSecret)}
	if v := d.Latest(); v != nil && v.PublicJWK != nil {
		out.SigAlgs = crypto.SignatureAlgorithms(v.PublicJWK)
		out.EncAlgs = crypto.EncryptionAlgorithms(v.PublicJWK)
	}
	var lines []string
	for k, v := range d.Tags {
		lines = append(lines, k+"="+v)
	}
	sortStrings(lines)
	out.Tags = strings.Join(lines, "\n")
	return out, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (s *Server) item(w http.ResponseWriter, r *http.Request, sess *session) {
	d, err := s.itemData(r.Context(), r.PathValue("name"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, sess, "item", d)
}

func (s *Server) itemAction(action string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		name := r.PathValue("name")
		ctx := r.Context()
		var err error
		var flash string
		back := "/items/" + name
		switch action {
		case "rotate":
			_, err = s.svc.Rotate(ctx, name, r.PostFormValue("disable_old") == "1")
			flash = "new version created"
		case "delete":
			err = s.svc.Delete(ctx, name)
			flash = "deleted; it can be recovered until purged"
		case "recover":
			err = s.svc.Recover(ctx, name)
			flash = "recovered"
		case "purge":
			err = s.svc.Purge(ctx, name, false)
			flash = "purged"
			back = "/items"
		case "tags":
			var tags map[string]string
			tags, err = parseTags(r.PostFormValue("tags"))
			if err == nil {
				err = s.svc.SetTags(ctx, name, tags)
			}
			flash = "tags saved"
		case "secret":
			value := []byte(r.PostFormValue("value"))
			defer crypto.Zero(value)
			_, err = s.svc.SetSecret(ctx, name, value, r.PostFormValue("content_type"), service.CreateOptions{})
			flash = "new secret version stored"
		}
		if err != nil {
			redirectMsg(w, r, back, "", userError(err))
			return
		}
		redirectMsg(w, r, back, flash, "")
	}
}

func (s *Server) versionEnable(enable bool) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		name := r.PathValue("name")
		seq, err := strconv.Atoi(r.PathValue("seq"))
		if err != nil {
			http.Error(w, "bad version", http.StatusBadRequest)
			return
		}
		if err := s.svc.SetVersionEnabled(r.Context(), name, seq, enable); err != nil {
			redirectMsg(w, r, "/items/"+name, "", userError(err))
			return
		}
		redirectMsg(w, r, "/items/"+name, fmt.Sprintf("version %d %s", seq, map[bool]string{true: "enabled", false: "disabled"}[enable]), "")
	}
}

type revealData struct {
	Name        string
	Seq         int
	Value       string
	ContentType string
	Error       string
}

// reveal returns a secret's value as an htmx fragment (or a full page
// when JavaScript is off). Every reveal is audited by the service.
func (s *Server) reveal(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	seq, _ := strconv.Atoi(r.PostFormValue("seq"))
	d := revealData{Name: name, Seq: seq}
	m, v, err := s.svc.Export(r.Context(), name, seq, false)
	if err != nil {
		d.Error = userError(err)
	} else {
		defer m.Zero()
		if m.JWK != nil {
			d.Error = "keys are exported with the CLI (azk key export --reveal-private)"
		} else {
			d.Value, d.ContentType, d.Seq = string(m.Value), m.ContentType, v.Seq
		}
	}
	if r.Header.Get("HX-Request") == "true" {
		s.fragment(w, "item", "reveal", d)
		return
	}
	s.render(w, r, sess, "reveal", d)
}

func (s *Server) publicKey(format string) func(http.ResponseWriter, *http.Request, *session) {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		name := r.PathValue("name")
		seq, _ := strconv.Atoi(r.PathValue("seq"))
		m, _, err := s.svc.Export(r.Context(), name, seq, true)
		if err != nil {
			http.Error(w, userError(err), http.StatusBadRequest)
			return
		}
		var out []byte
		if format == "pem" {
			out, err = m.JWK.ToPEM(true)
			w.Header().Set("Content-Type", "application/x-pem-file")
		} else {
			out, err = json.MarshalIndent(m.JWK, "", "  ")
			w.Header().Set("Content-Type", "application/json")
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-v%d.pub.%s", name, seq, format))
		_, _ = w.Write(out) //nolint:gosec // generated PEM/JSON served as an attachment, not HTML
	}
}

// --- audit ---

func (s *Server) audit(w http.ResponseWriter, r *http.Request, sess *session) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 100
	}
	entries, err := s.svc.Audit(r.Context(), n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, sess, "audit", entries)
}

// --- remotes ---

type remotesData struct {
	Remotes []store.Remote
	Plan    *keyvault.Plan
	Result  *keyvault.Result
	Remote  string
	Mode    string
	DryRun  bool
	Error   string
}

func (s *Server) remotes(w http.ResponseWriter, r *http.Request, sess *session) {
	remotes, err := s.svc.Vault().Store().ListRemotes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, sess, "remotes", remotesData{Remotes: remotes})
}

func (s *Server) addRemote(w http.ResponseWriter, r *http.Request, sess *session) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := service.ValidateName(name); err != nil {
		redirectMsg(w, r, "/remotes", "", err.Error())
		return
	}
	cfg := keyvault.Config{VaultURL: strings.TrimRight(strings.TrimSpace(r.PostFormValue("vault_url")), "/"), InsecureHTTP: r.PostFormValue("insecure_http") == "1"}
	if err := cfg.Validate(); err != nil {
		redirectMsg(w, r, "/remotes", "", err.Error())
		return
	}
	rem := store.Remote{Name: name, VaultURL: cfg.VaultURL, InsecureHTTP: cfg.InsecureHTTP, CreatedAt: time.Now()}
	if err := s.svc.Vault().Store().AddRemote(r.Context(), rem); err != nil {
		redirectMsg(w, r, "/remotes", "", userError(err))
		return
	}
	s.svc.Record(r.Context(), "remote.add", name, map[string]any{"vault_url": cfg.VaultURL})
	redirectMsg(w, r, "/remotes", "remote added", "")
}

func (s *Server) removeRemote(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if err := s.svc.Vault().Store().DeleteRemote(r.Context(), name); err != nil {
		redirectMsg(w, r, "/remotes", "", userError(err))
		return
	}
	s.svc.Record(r.Context(), "remote.remove", name, nil)
	redirectMsg(w, r, "/remotes", "remote removed", "")
}

func (s *Server) runRemote(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	d := remotesData{Remote: r.PathValue("name"), Mode: r.PostFormValue("mode"), DryRun: r.PostFormValue("dry_run") == "1"}
	d.Remotes, _ = s.svc.Vault().Store().ListRemotes(ctx)
	if d.Mode != "push" && d.Mode != "pull" {
		d.Mode = "sync"
	}
	rem, err := s.svc.Vault().Store().GetRemote(ctx, d.Remote)
	if err == nil {
		var c *keyvault.Client
		c, err = keyvault.Open(keyvault.Config{VaultURL: rem.VaultURL, InsecureHTTP: rem.InsecureHTTP})
		if err == nil {
			sy := keyvault.NewSyncer(s.svc, c, *rem)
			d.Plan, err = sy.Plan(ctx, d.Mode != "pull", d.Mode != "push", nil)
			if err == nil && !d.DryRun {
				d.Result, err = sy.Apply(ctx, d.Plan)
			}
		}
	}
	if err != nil {
		d.Error = userError(err)
	}
	if r.Header.Get("HX-Request") == "true" {
		s.fragment(w, "remotes", "plan", d)
		return
	}
	s.render(w, r, sess, "remotes", d)
}

// --- JSON API ---

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	info, err := s.svc.Vault().Info(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"locked": info.Locked, "format_version": info.FormatVersion, "slots": info.Slots, "logged_in": s.current(r) != nil})
}

func (s *Server) apiItems(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	items, err := s.svc.ListItems(r.Context(), store.ItemFilter{Kind: q.Get("kind"), Tag: q.Get("tag"), NamePrefix: q.Get("q"), OnlyDeleted: q.Get("deleted") == "1", IncludeDeleted: q.Get("all") == "1"})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []*store.Item{}
	}
	writeJSON(w, items)
}

func (s *Server) apiItem(w http.ResponseWriter, r *http.Request, sess *session) {
	d, err := s.svc.GetItem(r.Context(), r.PathValue("name"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, d)
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request, sess *session) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	entries, err := s.svc.Audit(r.Context(), n)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, entries)
}

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
