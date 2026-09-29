// Package kvtest holds test support for the Key Vault remote: an in-memory
// fake of the Key Vault REST API used where Docker is unavailable, and
// scenarios that run identically against the fake and against floci-az.
package kvtest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/danto7/azk/internal/crypto"
)

// Fake is a minimal Key Vault: keys (import, create, get, list, versions,
// sign/verify/encrypt/decrypt/wrap/unwrap) and secrets (set, get, list,
// versions). It performs the bearer challenge dance the SDK expects and
// accepts any token.
type Fake struct {
	Server *httptest.Server

	mu      sync.Mutex
	keys    map[string]*fakeObject
	secrets map[string]*fakeObject
}

type fakeObject struct {
	versions []*fakeVersion // oldest first
}

type fakeVersion struct {
	id      string
	created time.Time
	enabled bool
	nbf     *time.Time
	exp     *time.Time
	tags    map[string]string
	jwk     *crypto.JWK // keys
	value   string      // secrets
	ctype   string
}

// NewFake starts a fake vault. Close it with Server.Close.
func NewFake() *Fake {
	f := &Fake{keys: map[string]*fakeObject{}, secrets: map[string]*fakeObject{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

// URL is the vault URL.
func (f *Fake) URL() string { return f.Server.URL }

// KeyCount returns how many keys exist.
func (f *Fake) KeyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

// SecretVersions returns the values of a secret, oldest first.
func (f *Fake) SecretVersions(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	if o := f.secrets[name]; o != nil {
		for _, v := range o.versions {
			out = append(out, v.value)
		}
	}
	return out
}

// KeyVersions returns the number of versions of a key.
func (f *Fake) KeyVersions(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if o := f.keys[name]; o != nil {
		return len(o.versions)
	}
	return 0
}

func (f *Fake) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/fake", resource="`+f.Server.URL+`"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case len(parts) >= 1 && parts[0] == "keys":
		f.handleKeys(w, r, parts[1:])
	case len(parts) >= 1 && parts[0] == "secrets":
		f.handleSecrets(w, r, parts[1:])
	default:
		fail(w, 404, "NotFound", "unknown route "+r.URL.Path)
	}
}

func fail(w http.ResponseWriter, code int, ec, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": ec, "message": msg}})
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	return b
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func unixPtr(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	u := t.Unix()
	return &u
}

func fromUnix(v *int64) *time.Time {
	if v == nil {
		return nil
	}
	t := time.Unix(*v, 0).UTC()
	return &t
}

type attrs struct {
	Enabled *bool  `json:"enabled,omitempty"`
	NBF     *int64 `json:"nbf,omitempty"`
	Exp     *int64 `json:"exp,omitempty"`
	Created *int64 `json:"created,omitempty"`
	Updated *int64 `json:"updated,omitempty"`
}

func (v *fakeVersion) attrs() attrs {
	c := v.created.Unix()
	return attrs{Enabled: &v.enabled, NBF: unixPtr(v.nbf), Exp: unixPtr(v.exp), Created: &c, Updated: &c}
}

func (v *fakeVersion) apply(a *attrs) {
	v.enabled = true
	if a == nil {
		return
	}
	if a.Enabled != nil {
		v.enabled = *a.Enabled
	}
	v.nbf, v.exp = fromUnix(a.NBF), fromUnix(a.Exp)
}

// IDHost is the host the fake puts into object ids. Like floci-az, it is a
// real-looking Azure host rather than the address the server listens on,
// so callers cannot assume ids share the vault URL's host.
const IDHost = "https://fakeaccount.vault.azure.net"

func (f *Fake) kid(name, version string) string {
	return IDHost + "/keys/" + name + "/" + version
}
func (f *Fake) sid(name, version string) string {
	return IDHost + "/secrets/" + name + "/" + version
}

func (f *Fake) keyBundle(name string, v *fakeVersion) map[string]any {
	pub := v.jwk.Public()
	if pub == nil { // oct: Key Vault returns no material
		pub = &crypto.JWK{Kty: "oct"}
	}
	pub.Kid = f.kid(name, v.id)
	return map[string]any{"key": pub, "attributes": v.attrs(), "tags": v.tags}
}

func (f *Fake) handleKeys(w http.ResponseWriter, r *http.Request, p []string) {
	// GET /keys
	if len(p) == 0 {
		var items []map[string]any
		for name, o := range f.keys {
			last := o.versions[len(o.versions)-1]
			items = append(items, map[string]any{"kid": IDHost + "/keys/" + name, "attributes": last.attrs(), "tags": last.tags})
		}
		reply(w, map[string]any{"value": items, "nextLink": nil})
		return
	}
	name := p[0]
	obj := f.keys[name]
	switch {
	case r.Method == http.MethodPut && len(p) == 1: // import
		var body struct {
			Key   crypto.JWK        `json:"key"`
			Attrs *attrs            `json:"attributes"`
			Tags  map[string]string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key.Kind() == "" {
			fail(w, 400, "BadParameter", "invalid key")
			return
		}
		if !body.Key.IsPrivate() {
			fail(w, 400, "BadParameter", "import needs private material")
			return
		}
		v := &fakeVersion{id: newID(), created: time.Now(), tags: body.Tags, jwk: &body.Key}
		v.apply(body.Attrs)
		f.addKey(name, v)
		reply(w, f.keyBundle(name, v))
	case r.Method == http.MethodPost && len(p) == 2 && p[1] == "create":
		var body struct {
			Kty     string            `json:"kty"`
			KeySize int               `json:"key_size"`
			Crv     string            `json:"crv"`
			Attrs   *attrs            `json:"attributes"`
			Tags    map[string]string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, 400, "BadParameter", "invalid body")
			return
		}
		var kind crypto.Kind
		switch strings.TrimSuffix(body.Kty, "-HSM") {
		case "RSA":
			kind = crypto.KindRSA
		case "EC":
			kind = crypto.KindEC
		case "oct":
			kind = crypto.KindOct
		default:
			fail(w, 400, "BadParameter", "unsupported kty")
			return
		}
		jwk, err := crypto.Generate(kind, crypto.GenerateOptions{Bits: body.KeySize, Curve: body.Crv})
		if err != nil {
			fail(w, 400, "BadParameter", err.Error())
			return
		}
		v := &fakeVersion{id: newID(), created: time.Now(), tags: body.Tags, jwk: jwk}
		v.apply(body.Attrs)
		f.addKey(name, v)
		reply(w, f.keyBundle(name, v))
	case obj == nil:
		fail(w, 404, "KeyNotFound", "key not found: "+name)
	case r.Method == http.MethodGet && len(p) == 2 && p[1] == "versions":
		var items []map[string]any
		for _, v := range obj.versions {
			items = append(items, map[string]any{"kid": f.kid(name, v.id), "attributes": v.attrs(), "tags": v.tags})
		}
		reply(w, map[string]any{"value": items, "nextLink": nil})
	case r.Method == http.MethodGet && len(p) <= 2:
		v := obj.find(p[1:])
		if v == nil {
			fail(w, 404, "KeyNotFound", "version not found")
			return
		}
		reply(w, f.keyBundle(name, v))
	case r.Method == http.MethodPost && len(p) == 2 && isKeyOp(p[1]):
		f.keyOp(w, r, name, obj.find(nil), p[1])
	case r.Method == http.MethodPost && len(p) == 3:
		v := obj.find(p[1:2])
		if v == nil {
			fail(w, 404, "KeyNotFound", "version not found")
			return
		}
		f.keyOp(w, r, name, v, p[2])
	default:
		fail(w, 404, "NotFound", "unsupported key route")
	}
}

func (f *Fake) addKey(name string, v *fakeVersion) {
	if f.keys[name] == nil {
		f.keys[name] = &fakeObject{}
	}
	f.keys[name].versions = append(f.keys[name].versions, v)
}

func (o *fakeObject) find(p []string) *fakeVersion {
	if len(p) == 0 || p[0] == "" {
		return o.versions[len(o.versions)-1]
	}
	for _, v := range o.versions {
		if v.id == p[0] {
			return v
		}
	}
	return nil
}

func isKeyOp(s string) bool {
	switch s {
	case "sign", "verify", "encrypt", "decrypt", "wrapkey", "unwrapkey":
		return true
	}
	return false
}

func (f *Fake) keyOp(w http.ResponseWriter, r *http.Request, name string, v *fakeVersion, op string) {
	var body struct {
		Alg    string `json:"alg"`
		Value  string `json:"value"`
		Digest string `json:"digest"`
		IV     string `json:"iv"`
		Tag    string `json:"tag"`
		AAD    string `json:"aad"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, "BadParameter", "invalid body")
		return
	}
	kid := f.kid(name, v.id)
	var out []byte
	var err error
	switch op {
	case "sign":
		out, err = crypto.Sign(v.jwk, body.Alg, unb64(body.Value))
	case "verify":
		ok, verr := crypto.Verify(v.jwk, body.Alg, unb64(body.Digest), unb64(body.Value))
		if verr != nil {
			fail(w, 400, "BadParameter", verr.Error())
			return
		}
		reply(w, map[string]any{"value": ok})
		return
	case "encrypt":
		ct, eerr := crypto.Encrypt(v.jwk, body.Alg, unb64(body.Value), unb64(body.AAD))
		if eerr != nil {
			fail(w, 400, "BadParameter", eerr.Error())
			return
		}
		res := map[string]any{"kid": kid, "value": b64(ct.Ciphertext)}
		if ct.IV != nil {
			res["iv"], res["tag"] = b64(ct.IV), b64(ct.Tag)
		}
		reply(w, res)
		return
	case "decrypt":
		out, err = crypto.Decrypt(v.jwk, body.Alg, &crypto.Ciphertext{Ciphertext: unb64(body.Value), IV: unb64(body.IV), Tag: unb64(body.Tag)}, unb64(body.AAD))
	case "wrapkey":
		out, err = crypto.WrapKey(v.jwk, body.Alg, unb64(body.Value))
	case "unwrapkey":
		out, err = crypto.UnwrapKey(v.jwk, body.Alg, unb64(body.Value))
	default:
		fail(w, 404, "NotFound", "unknown operation "+op)
		return
	}
	if err != nil {
		fail(w, 400, "BadParameter", err.Error())
		return
	}
	reply(w, map[string]any{"kid": kid, "value": b64(out)})
}

func (f *Fake) secretBundle(name string, v *fakeVersion, withValue bool) map[string]any {
	m := map[string]any{"id": f.sid(name, v.id), "attributes": v.attrs(), "tags": v.tags}
	if v.ctype != "" {
		m["contentType"] = v.ctype
	}
	if withValue {
		m["value"] = v.value
	}
	return m
}

func (f *Fake) handleSecrets(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 0 {
		var items []map[string]any
		for name, o := range f.secrets {
			last := o.versions[len(o.versions)-1]
			b := f.secretBundle(name, last, false)
			b["id"] = IDHost + "/secrets/" + name
			items = append(items, b)
		}
		reply(w, map[string]any{"value": items, "nextLink": nil})
		return
	}
	name := p[0]
	obj := f.secrets[name]
	switch {
	case r.Method == http.MethodPut && len(p) == 1:
		var body struct {
			Value string            `json:"value"`
			CT    string            `json:"contentType"`
			Attrs *attrs            `json:"attributes"`
			Tags  map[string]string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, 400, "BadParameter", "invalid body")
			return
		}
		v := &fakeVersion{id: newID(), created: time.Now(), tags: body.Tags, value: body.Value, ctype: body.CT}
		v.apply(body.Attrs)
		if obj == nil {
			obj = &fakeObject{}
			f.secrets[name] = obj
		}
		obj.versions = append(obj.versions, v)
		reply(w, f.secretBundle(name, v, true))
	case obj == nil:
		fail(w, 404, "SecretNotFound", "secret not found: "+name)
	case r.Method == http.MethodGet && len(p) == 2 && p[1] == "versions":
		var items []map[string]any
		for _, v := range obj.versions {
			items = append(items, f.secretBundle(name, v, false))
		}
		reply(w, map[string]any{"value": items, "nextLink": nil})
	case r.Method == http.MethodGet && len(p) <= 2:
		v := obj.find(p[1:])
		if v == nil {
			fail(w, 404, "SecretNotFound", "version not found")
			return
		}
		reply(w, f.secretBundle(name, v, true))
	default:
		fail(w, 404, "NotFound", "unsupported secret route")
	}
}
