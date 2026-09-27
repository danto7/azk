package kvtest

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
	"github.com/danto7/azk/internal/vault"
)

var fastKDF = crypto.Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}

// Target is a Key Vault the scenarios run against.
type Target struct {
	Config keyvault.Config
	// Prefix keeps item names unique when several scenarios share one vault.
	Prefix string
}

func (t Target) name(s string) string { return t.Prefix + s }

func (t Target) client(tb testing.TB) *keyvault.Client {
	tb.Helper()
	c, err := keyvault.New(t.Config, keyvault.StaticCredential("test-token"))
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// NewVault creates a throwaway unlocked vault with a service.
func NewVault(tb testing.TB) *service.Service {
	tb.Helper()
	v, err := vault.Create(context.Background(), filepath.Join(tb.TempDir(), "vault.db"), []byte("pw"), vault.CreateOptions{Argon2: fastKDF})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { v.Close() })
	return service.New(v, "test")
}

func (t Target) syncer(tb testing.TB, svc *service.Service) *keyvault.Syncer {
	tb.Helper()
	r := store.Remote{Name: "t", VaultURL: t.Config.VaultURL, InsecureHTTP: t.Config.InsecureHTTP}
	if err := svc.Vault().Store().AddRemote(context.Background(), r); err != nil && !errors.Is(err, store.ErrExists) {
		tb.Fatal(err)
	}
	return keyvault.NewSyncer(svc, t.client(tb), r)
}

// PushPull creates keys and secrets locally, pushes them, pulls them into
// a second vault and checks that material matches.
func PushPull(t *testing.T, target Target) {
	ctx := context.Background()
	src := NewVault(t)
	mk := func(name string, kind crypto.Kind, gen crypto.GenerateOptions) {
		t.Helper()
		if _, err := src.CreateKey(ctx, target.name(name), kind, gen, service.CreateOptions{Tags: map[string]string{"origin": "azk"}}); err != nil {
			t.Fatal(err)
		}
	}
	mk("rsa", crypto.KindRSA, crypto.GenerateOptions{Bits: 2048})
	mk("ec", crypto.KindEC, crypto.GenerateOptions{Curve: "P-256"})
	mk("aes", crypto.KindOct, crypto.GenerateOptions{Bits: 256})
	mk("ed", crypto.KindEd25519, crypto.GenerateOptions{})
	if _, err := src.SetSecret(ctx, target.name("sec"), []byte("one"), "text/plain", service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.SetSecret(ctx, target.name("sec"), []byte("two"), "", service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	sy := target.syncer(t, src)
	plan, err := sy.Plan(ctx, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	counts := plan.Counts()
	if counts[keyvault.OpPush] != 5 || counts[keyvault.OpSkip] != 1 {
		t.Fatalf("push plan: %+v", plan.Actions)
	}
	res, err := sy.Apply(ctx, plan)
	if err != nil {
		t.Fatalf("apply: %v (done %d)", err, len(res.Done))
	}
	if res.Pushed != 5 {
		t.Fatalf("pushed %d", res.Pushed)
	}
	// Idempotent.
	plan, err = sy.Plan(ctx, true, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range plan.Actions {
		if a.Op == keyvault.OpPush || a.Op == keyvault.OpPull {
			t.Fatalf("second plan not empty: %+v", plan.Actions)
		}
	}
	d, err := src.GetItem(ctx, target.name("rsa"))
	if err != nil || d.RemoteID == "" || d.Versions[0].RemoteVersion == "" {
		t.Fatalf("remote ids not recorded: %v %+v", err, d)
	}
	if !keyvault.SameObject(d.RemoteID, target.Config.VaultURL+"/keys/"+target.name("rsa")) {
		t.Fatalf("remote id %q does not point at the vault", d.RemoteID)
	}

	// Remote agrees on the public key.
	c := target.client(t)
	got, err := c.Keys().GetKey(ctx, target.name("rsa"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := src.Export(ctx, target.name("rsa"), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Key.N) != string(local.JWK.N) {
		t.Fatal("remote modulus differs from local")
	}

	// Pull everything into a fresh vault.
	dst := NewVault(t)
	sy2 := target.syncer(t, dst)
	plan, err = sy2.Plan(ctx, false, true, []string{target.name("rsa"), target.name("ec"), target.name("aes"), target.name("sec")})
	if err != nil {
		t.Fatal(err)
	}
	counts = plan.Counts()
	if counts[keyvault.OpPull] != 4 || counts[keyvault.OpSkip] != 1 {
		t.Fatalf("pull plan: %+v", plan.Actions)
	}
	res, err = sy2.Apply(ctx, plan)
	if err != nil {
		t.Fatalf("apply pull: %v", err)
	}
	if res.Pulled != 4 {
		t.Fatalf("pulled %d", res.Pulled)
	}
	m, v, err := dst.Export(ctx, target.name("sec"), 0, false)
	if err != nil || string(m.Value) != "two" || v.Seq != 2 || v.RemoteVersion == "" {
		t.Fatalf("pulled secret: %v %q seq %d", err, m.Value, v.Seq)
	}
	m, _, _ = dst.Export(ctx, target.name("sec"), 1, false)
	if string(m.Value) != "one" || m.ContentType != "text/plain" {
		t.Fatalf("pulled secret v1: %q %q", m.Value, m.ContentType)
	}
	pd, err := dst.GetItem(ctx, target.name("ec"))
	if err != nil {
		t.Fatal(err)
	}
	if !pd.Versions[0].PublicOnly || pd.Tags["origin"] != "azk" {
		t.Fatalf("pulled key: %+v", pd)
	}
	sd, _ := src.GetItem(ctx, target.name("ec"))
	if sd.Versions[0].Thumbprint != pd.Versions[0].Thumbprint {
		t.Fatal("pulled public key thumbprint differs")
	}
	if _, err := dst.GetItem(ctx, target.name("aes")); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("symmetric key should not be pulled: %v", err)
	}

	// Pull again: nothing new.
	plan, _ = sy2.Plan(ctx, false, true, nil)
	if plan.Counts()[keyvault.OpPull] != 0 {
		t.Fatalf("third plan: %+v", plan.Actions)
	}

	// A new remote version of the secret is pulled as v3 on the source side.
	sy3 := target.syncer(t, dst)
	if _, err := dst.SetSecret(ctx, target.name("sec"), []byte("three"), "", service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	plan, _ = sy3.Plan(ctx, true, false, nil)
	if plan.Counts()[keyvault.OpPush] != 1 {
		t.Fatalf("push from dst: %+v", plan.Actions)
	}
	if _, err := sy3.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	plan, _ = sy.Plan(ctx, false, true, nil)
	if plan.Counts()[keyvault.OpPull] != 1 {
		t.Fatalf("pull into src: %+v", plan.Actions)
	}
	if _, err := sy.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	m, v, _ = src.Export(ctx, target.name("sec"), 0, false)
	if string(m.Value) != "three" || v.Seq != 3 {
		t.Fatalf("round-tripped secret %q seq %d", m.Value, v.Seq)
	}
}

// Conflict checks that a local key and a remote secret of the same name are
// reported, not merged.
func Conflict(t *testing.T, target Target) {
	ctx := context.Background()
	a := NewVault(t)
	if _, err := a.SetSecret(ctx, target.name("clash"), []byte("x"), "", service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	sa := target.syncer(t, a)
	plan, err := sa.Plan(ctx, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sa.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	b := NewVault(t)
	if _, err := b.CreateKey(ctx, target.name("clash"), crypto.KindEC, crypto.GenerateOptions{}, service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	sb := target.syncer(t, b)
	plan, err = sb.Plan(ctx, true, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, act := range plan.Actions {
		if act.Name == target.name("clash") {
			if act.Op != keyvault.OpConflict {
				t.Fatalf("expected conflict, got %+v", act)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no conflict reported: %+v", plan.Actions)
	}
}

// Slot adds a keyvault unlock slot, locks, and unlocks through the remote.
func Slot(t *testing.T, target Target) {
	ctx := context.Background()
	svc := NewVault(t)
	v := svc.Vault()
	c := target.client(t)
	if _, err := keyvault.AddSlot(ctx, v, c, "t", "", target.name("kek"), false); err == nil {
		t.Fatal("slot added with a missing key and no --create")
	}
	id, err := keyvault.AddSlot(ctx, v, c, "t", "", target.name("kek"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateKey(ctx, target.name("k"), crypto.KindEd25519, crypto.GenerateOptions{}, service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	dial := func(cfg keyvault.Config) (*keyvault.Client, error) {
		return keyvault.New(cfg, keyvault.StaticCredential("test-token"))
	}
	if err := v.UnlockWith(ctx, keyvault.Unwrapper{Dial: dial}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sign(ctx, target.name("k"), 0, "", []byte("m")); err != nil {
		t.Fatalf("sign after keyvault unlock: %v", err)
	}
	slots, _ := v.Slots(ctx)
	var p keyvault.SlotParams
	for _, s := range slots {
		if s.ID == id {
			_ = json.Unmarshal(s.Params, &p)
		}
	}
	if p.Key != target.name("kek") || p.Version == "" || p.VaultURL != target.Config.VaultURL {
		t.Fatalf("slot params %+v", p)
	}
	if err := v.RemoveSlot(ctx, id); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.UnlockWith(ctx, keyvault.Unwrapper{Dial: dial}); err == nil {
		t.Fatal("unlock succeeded without the slot")
	}
	if err := v.Unlock(ctx, []byte("pw")); err != nil {
		t.Fatal(err)
	}
}

// Interop checks that signatures and wrapped keys are interchangeable
// between azk and the remote: what one side produces, the other verifies.
func Interop(t *testing.T, target Target) {
	ctx := context.Background()
	svc := NewVault(t)
	c := target.client(t)
	for _, tc := range []struct {
		name string
		kind crypto.Kind
		gen  crypto.GenerateOptions
		alg  string
	}{
		{"irsa", crypto.KindRSA, crypto.GenerateOptions{Bits: 2048}, "PS256"},
		{"iec", crypto.KindEC, crypto.GenerateOptions{Curve: "P-384"}, "ES384"},
	} {
		if _, err := svc.CreateKey(ctx, target.name(tc.name), tc.kind, tc.gen, service.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	sy := target.syncer(t, svc)
	plan, _ := sy.Plan(ctx, true, false, nil)
	if _, err := sy.Apply(ctx, plan); err != nil {
		t.Fatal(err)
	}
	msg := []byte("interop message")
	for _, tc := range []struct{ name, alg string }{{"irsa", "PS256"}, {"iec", "ES384"}} {
		name := target.name(tc.name)
		// Local signature verified remotely.
		sig, err := svc.Sign(ctx, name, 0, tc.alg, msg)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := crypto.Digest(tc.alg, msg)
		alg := azkeys.SignatureAlgorithm(tc.alg)
		vr, err := c.Keys().Verify(ctx, name, "", azkeys.VerifyParameters{Algorithm: &alg, Digest: digest, Signature: sig.Result}, nil)
		if err != nil || vr.Value == nil || !*vr.Value {
			t.Fatalf("%s: remote verify of local signature failed: %v", tc.alg, err)
		}
		// Remote signature verified locally.
		sr, err := c.Keys().Sign(ctx, name, "", azkeys.SignParameters{Algorithm: &alg, Value: digest}, nil)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := svc.Verify(ctx, name, 0, tc.alg, msg, sr.Result)
		if err != nil || !ok {
			t.Fatalf("%s: local verify of remote signature failed: %v", tc.alg, err)
		}
	}
	// Wrap remotely, unwrap locally, and the reverse.
	name := target.name("irsa")
	secret := []byte("0123456789abcdef0123456789abcdef")
	wrapped, _, err := c.WrapDEK(ctx, name, "", secret)
	if err != nil {
		t.Fatal(err)
	}
	un, err := svc.Unwrap(ctx, name, 0, "RSA-OAEP-256", wrapped)
	if err != nil || string(un) != string(secret) {
		t.Fatalf("local unwrap of remote wrap: %v", err)
	}
	w, err := svc.Wrap(ctx, name, 0, "RSA-OAEP-256", secret)
	if err != nil {
		t.Fatal(err)
	}
	un, err = c.UnwrapDEK(ctx, name, "", w.Result)
	if err != nil || string(un) != string(secret) {
		t.Fatalf("remote unwrap of local wrap: %v", err)
	}
}

// Unreachable checks that a dead remote leaves the local vault untouched.
func Unreachable(t *testing.T) {
	ctx := context.Background()
	svc := NewVault(t)
	if _, err := svc.CreateKey(ctx, "k", crypto.KindEC, crypto.GenerateOptions{}, service.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	c, err := keyvault.New(keyvault.Config{VaultURL: "http://127.0.0.1:1/dead-keyvault", InsecureHTTP: true}, keyvault.StaticCredential("x"))
	if err != nil {
		t.Fatal(err)
	}
	sy := keyvault.NewSyncer(svc, c, store.Remote{Name: "dead"})
	if _, err := sy.Plan(ctx, true, true, nil); err == nil {
		t.Fatal("plan against dead remote succeeded")
	}
	d, _ := svc.GetItem(ctx, "k")
	if d.RemoteID != "" || d.Versions[0].RemoteVersion != "" {
		t.Fatal("local item was modified")
	}
}
