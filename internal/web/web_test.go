package web

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/vault"
)

type env struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	c   *http.Client
	csr string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	v, err := vault.Create(context.Background(), filepath.Join(t.TempDir(), "v.db"), []byte("pw"),
		vault.CreateOptions{Argon2: crypto.Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	svc := service.New(v, "web")
	srv, err := New(svc, Options{Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { ts.Close(); v.Close() })
	return &env{t: t, srv: srv, ts: ts, c: c}
}

func (e *env) get(path string) (*http.Response, string) {
	e.t.Helper()
	res, err := e.c.Get(e.ts.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func (e *env) post(path string, form url.Values, hx bool) (*http.Response, string) {
	e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if e.csr != "" && form.Get("csrf") == "" {
		form.Set("csrf", e.csr)
	}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	res, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (e *env) login(pass string) *http.Response {
	e.t.Helper()
	res, _ := e.post("/login", url.Values{"passphrase": {pass}}, false)
	if res.StatusCode == http.StatusSeeOther && res.Header.Get("Location") == "/" {
		_, body := e.get("/")
		m := csrfRe.FindStringSubmatch(body)
		if m == nil {
			e.t.Fatal("no csrf token on dashboard")
		}
		e.csr = m[1]
	}
	return res
}

func TestLoginAndLock(t *testing.T) {
	e := newEnv(t)
	res, _ := e.get("/")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated dashboard: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = e.get("/api/v1/items")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("api without login: %d", res.StatusCode)
	}
	if res := e.login("nope"); !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatalf("wrong passphrase accepted: %s", res.Header.Get("Location"))
	}
	if !e.srv.svc.Vault().IsLocked() {
		t.Fatal("vault unlocked after failed login")
	}
	if res := e.login("pw"); res.Header.Get("Location") != "/" {
		t.Fatalf("login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := e.get("/")
	if res.StatusCode != 200 || !strings.Contains(body, "Dashboard") {
		t.Fatalf("dashboard: %d", res.StatusCode)
	}
	res, body = e.get("/api/v1/status")
	if res.StatusCode != 200 || !strings.Contains(body, `"logged_in": true`) {
		t.Fatalf("status: %d %s", res.StatusCode, body)
	}
	e.post("/lock", nil, false)
	if !e.srv.svc.Vault().IsLocked() {
		t.Fatal("vault not locked")
	}
	if res, _ := e.get("/items"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("after lock: %d", res.StatusCode)
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	e.login("pw")
	res, _ := e.post("/items/generate", url.Values{"csrf": {"bogus"}, "name": {"x"}, "kind": {"ec"}}, false)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("bad csrf accepted: %d", res.StatusCode)
	}
	res, _ = e.post("/items/generate", url.Values{"name": {"x"}, "kind": {"ec"}}, false)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/items/x?flash=key+generated" {
		t.Fatalf("generate: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// htmx requests carry the token in a header instead.
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/items/x/rotate", nil)
	req.Header.Set("X-CSRF-Token", e.csr)
	res2, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusSeeOther {
		t.Fatalf("header csrf: %d", res2.StatusCode)
	}
}

func TestItemLifecycle(t *testing.T) {
	e := newEnv(t)
	e.login("pw")
	e.post("/items/generate", url.Values{"name": {"signer"}, "kind": {"rsa"}, "bits": {"2048"}, "tags": {"env=dev"}}, false)
	res, body := e.get("/items/signer")
	if res.StatusCode != 200 || !strings.Contains(body, "env=dev") || !strings.Contains(body, "RS256") {
		t.Fatalf("detail: %d", res.StatusCode)
	}
	res, body = e.get("/items/signer/versions/1/public.pem")
	if res.StatusCode != 200 || !strings.Contains(body, "BEGIN PUBLIC KEY") {
		t.Fatalf("pem: %d %s", res.StatusCode, body)
	}
	e.post("/items/signer/rotate", url.Values{"disable_old": {"1"}}, false)
	_, body = e.get("/api/v1/items/signer")
	var d service.ItemDetail
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 2 || d.Versions[1].Enabled || d.Versions[0].PublicJWK == nil || d.Versions[0].PublicJWK.IsPrivate() {
		t.Fatalf("api detail: %+v", d.Versions)
	}
	e.post("/items/signer/versions/1/enable", nil, false)
	_, body = e.get("/api/v1/items/signer")
	if !strings.Contains(body, `"seq": 1,\n      "enabled": true`) && !strings.Contains(strings.ReplaceAll(body, " ", ""), `"seq":1,\n"enabled":true`) {
		// fall back to a structural check
		_ = json.Unmarshal([]byte(body), &d)
		if !d.Versions[1].Enabled {
			t.Fatal("version 1 not re-enabled")
		}
	}
	e.post("/items/signer/delete", nil, false)
	_, body = e.get("/api/v1/items?deleted=1")
	if !strings.Contains(body, "signer") {
		t.Fatal("deleted item not listed")
	}
	_, body = e.get("/api/v1/items")
	if strings.Contains(body, "signer") {
		t.Fatal("deleted item still listed as active")
	}
	e.post("/items/signer/recover", nil, false)
	e.post("/items/signer/delete", nil, false)
	res, _ = e.post("/items/signer/purge", nil, false)
	if res.Header.Get("Location") != "/items?flash=purged" {
		t.Fatalf("purge: %s", res.Header.Get("Location"))
	}
	if res, _ := e.get("/items/signer"); res.StatusCode != 404 {
		t.Fatalf("purged item: %d", res.StatusCode)
	}
	_, body = e.get("/api/v1/audit")
	for _, want := range []string{"key.generate", "key.rotate", "item.purge", "web.login"} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit missing %s: %s", want, body)
		}
	}
}

func TestSecretReveal(t *testing.T) {
	e := newEnv(t)
	e.login("pw")
	e.post("/items/secret", url.Values{"name": {"db"}, "value": {"hunter2"}, "content_type": {"text/plain"}}, false)
	res, body := e.get("/items/db")
	if res.StatusCode != 200 || strings.Contains(body, "hunter2") {
		t.Fatalf("detail leaks value: %d", res.StatusCode)
	}
	res, body = e.post("/items/db/reveal", url.Values{"seq": {"1"}}, true)
	if res.StatusCode != 200 || !strings.Contains(body, "hunter2") || strings.Contains(body, "<html") {
		t.Fatalf("reveal fragment: %d %s", res.StatusCode, body)
	}
	res, body = e.post("/items/db/reveal", url.Values{"seq": {"1"}}, false)
	if res.StatusCode != 200 || !strings.Contains(body, "hunter2") || !strings.Contains(body, "<html") {
		t.Fatalf("reveal page: %d", res.StatusCode)
	}
	e.post("/items/db/secret", url.Values{"value": {"hunter3"}}, false)
	_, body = e.post("/items/db/reveal", nil, true)
	if !strings.Contains(body, "hunter3") || !strings.Contains(body, "version 2") {
		t.Fatalf("latest reveal: %s", body)
	}
	_, body = e.get("/api/v1/audit")
	if strings.Count(body, "secret.get") != 3 {
		t.Fatalf("reveals not audited: %s", body)
	}
	_, body = e.get("/items/db")
	if strings.Contains(body, "hunter") {
		t.Fatal("value leaked into detail page")
	}
}

func TestImportAndValidation(t *testing.T) {
	e := newEnv(t)
	e.login("pw")
	k, _ := crypto.Generate(crypto.KindEC, crypto.GenerateOptions{Curve: "P-384"})
	pem, _ := k.ToPEM(true)
	res, _ := e.post("/items/import", url.Values{"name": {"pub"}, "material": {string(pem)}}, false)
	if res.Header.Get("Location") != "/items/pub?flash=key+imported" {
		t.Fatalf("import: %s", res.Header.Get("Location"))
	}
	_, body := e.get("/items/pub")
	if !strings.Contains(body, "public-only") || !strings.Contains(body, "P-384") {
		t.Fatal("imported key detail")
	}
	res, _ = e.post("/items/import", url.Values{"name": {"bad"}, "material": {"garbage"}}, false)
	if !strings.Contains(res.Header.Get("Location"), "error=") {
		t.Fatal("garbage import accepted")
	}
	res, _ = e.post("/items/generate", url.Values{"name": {"bad name"}, "kind": {"ec"}}, false)
	if !strings.Contains(res.Header.Get("Location"), "error=invalid+name") {
		t.Fatalf("bad name accepted: %s", res.Header.Get("Location"))
	}
	res, _ = e.post("/items/generate", url.Values{"name": {"pub"}, "kind": {"ec"}}, false)
	if !strings.Contains(res.Header.Get("Location"), "already+exists") {
		t.Fatalf("duplicate accepted: %s", res.Header.Get("Location"))
	}
}

func TestIdleLock(t *testing.T) {
	e := newEnv(t)
	e.srv.opts.IdleTimeout = 50 * time.Millisecond
	e.login("pw")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// idleWatch ticks every 10s; drive the check directly instead.
		for ctx.Err() == nil {
			e.srv.mu.Lock()
			idle := e.srv.session != nil && time.Since(e.srv.lastSeen) > e.srv.opts.IdleTimeout
			e.srv.mu.Unlock()
			if idle {
				e.srv.lock()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	if !e.srv.svc.Vault().IsLocked() {
		t.Fatal("vault not locked after idle timeout")
	}
	if res, _ := e.get("/"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("session survived idle lock: %d", res.StatusCode)
	}
}

func TestServeRefusesRemote(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.srv.Serve(ctx, "0.0.0.0:0", false); err == nil || !strings.Contains(err.Error(), "allow-remote") {
		t.Fatalf("remote listen allowed: %v", err)
	}
	if err := e.srv.Serve(ctx, "127.0.0.1:0", false); err != nil {
		t.Fatalf("loopback listen: %v", err)
	}
}
