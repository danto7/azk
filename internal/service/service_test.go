package service

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/store"
	"github.com/danto7/azk/internal/vault"
)

func newService(t *testing.T) *Service {
	t.Helper()
	v, err := vault.Create(context.Background(), filepath.Join(t.TempDir(), "v.db"), []byte("pw"),
		vault.CreateOptions{Argon2: crypto.Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return New(v, "test")
}

func TestKeyLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	d, err := s.CreateKey(ctx, "signer", crypto.KindEC, crypto.GenerateOptions{Curve: "P-256"}, CreateOptions{Tags: map[string]string{"env": "dev"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 1 || d.Versions[0].PublicJWK == nil || d.Versions[0].Size != "P-256" {
		t.Fatalf("unexpected detail %+v", d)
	}
	if _, err := s.CreateKey(ctx, "signer", crypto.KindEC, crypto.GenerateOptions{}, CreateOptions{}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	if _, err := s.CreateKey(ctx, "bad name!", crypto.KindEC, crypto.GenerateOptions{}, CreateOptions{}); err == nil {
		t.Fatal("bad name accepted")
	}

	msg := []byte("payload")
	sig, err := s.Sign(ctx, "signer", 0, "", msg)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Algorithm != "ES256" || sig.Seq != 1 {
		t.Fatalf("sig %+v", sig)
	}
	ok, err := s.Verify(ctx, "signer", 1, "ES256", msg, sig.Result)
	if err != nil || !ok {
		t.Fatalf("verify %v %v", ok, err)
	}

	d, err = s.Rotate(ctx, "signer", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 2 || d.Versions[0].Seq != 2 || d.Versions[1].Enabled {
		t.Fatalf("rotate %+v", d.Versions)
	}
	if _, err := s.Sign(ctx, "signer", 1, "", msg); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled version signed: %v", err)
	}
	// Old signature still verifies with the old version.
	if ok, _ := s.Verify(ctx, "signer", 1, "ES256", msg, sig.Result); !ok {
		t.Fatal("old sig should verify against v1")
	}
	if ok, _ := s.Verify(ctx, "signer", 2, "ES256", msg, sig.Result); ok {
		t.Fatal("old sig verified against v2")
	}

	pub, _, err := s.Export(ctx, "signer", 0, true)
	if err != nil || pub.JWK.IsPrivate() {
		t.Fatalf("public export %v", err)
	}
	priv, _, err := s.Export(ctx, "signer", 0, false)
	if err != nil || !priv.JWK.IsPrivate() {
		t.Fatalf("private export %v", err)
	}

	items, _ := s.ListItems(ctx, store.ItemFilter{Tag: "env=dev"})
	if len(items) != 1 {
		t.Fatalf("tag filter: %d", len(items))
	}
	if err := s.Delete(ctx, "signer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(ctx, "signer", 0, "", msg); !errors.Is(err, ErrDeleted) {
		t.Fatalf("deleted item usable: %v", err)
	}
	items, _ = s.ListItems(ctx, store.ItemFilter{})
	if len(items) != 0 {
		t.Fatal("deleted item listed")
	}
	items, _ = s.ListItems(ctx, store.ItemFilter{OnlyDeleted: true})
	if len(items) != 1 {
		t.Fatal("deleted item not listed with OnlyDeleted")
	}
	if err := s.Recover(ctx, "signer"); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx, "signer", false); err == nil {
		t.Fatal("purge of live item succeeded")
	}
	if err := s.Purge(ctx, "signer", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetItem(ctx, "signer"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged item still present: %v", err)
	}
	entries, _ := s.Audit(ctx, 50)
	if len(entries) < 6 {
		t.Fatalf("audit entries: %d", len(entries))
	}
}

func TestSecretsAndCryptoOps(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	if _, err := s.SetSecret(ctx, "db-pass", []byte("hunter2"), "text/plain", CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	d, err := s.SetSecret(ctx, "db-pass", []byte("hunter3"), "", CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Versions) != 2 {
		t.Fatalf("versions %d", len(d.Versions))
	}
	m, v, err := s.Export(ctx, "db-pass", 0, false)
	if err != nil || string(m.Value) != "hunter3" || v.Seq != 2 {
		t.Fatalf("latest secret %q %v", m.Value, err)
	}
	m, _, _ = s.Export(ctx, "db-pass", 1, false)
	if string(m.Value) != "hunter2" || m.ContentType != "text/plain" {
		t.Fatalf("v1 secret %q %q", m.Value, m.ContentType)
	}
	if _, err := s.Sign(ctx, "db-pass", 0, "", []byte("x")); !errors.Is(err, ErrNotKey) {
		t.Fatalf("sign with secret: %v", err)
	}

	if _, err := s.CreateKey(ctx, "aes", crypto.KindOct, crypto.GenerateOptions{Bits: 256}, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ct, err := s.Encrypt(ctx, "aes", 0, "", []byte("plain"), nil)
	if err != nil || ct.Algorithm != "A256GCM" || len(ct.IV) == 0 {
		t.Fatalf("encrypt %+v %v", ct, err)
	}
	pt, err := s.Decrypt(ctx, "aes", 0, ct.Algorithm, ct.Result, ct.IV, ct.Tag, nil)
	if err != nil || string(pt) != "plain" {
		t.Fatalf("decrypt %q %v", pt, err)
	}
	w, err := s.Wrap(ctx, "aes", 0, "", bytes.Repeat([]byte{1}, 32))
	if err != nil || w.Algorithm != "A256KW" {
		t.Fatalf("wrap %v", err)
	}
	u, err := s.Unwrap(ctx, "aes", 0, "", w.Result)
	if err != nil || !bytes.Equal(u, bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("unwrap %v", err)
	}

	if _, err := s.CreateKey(ctx, "rsa", crypto.KindRSA, crypto.GenerateOptions{Bits: 2048}, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	ct, err = s.Encrypt(ctx, "rsa", 0, "RSA-OAEP-256", []byte("plain"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err = s.Decrypt(ctx, "rsa", 0, "RSA-OAEP-256", ct.Result, nil, nil, nil)
	if err != nil || string(pt) != "plain" {
		t.Fatalf("rsa decrypt %q %v", pt, err)
	}
}

func TestImportPublicOnly(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	k, _ := crypto.Generate(crypto.KindRSA, crypto.GenerateOptions{Bits: 2048})
	d, err := s.ImportKey(ctx, "pub", k.Public(), CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Versions[0].PublicOnly {
		t.Fatal("not flagged public only")
	}
	if _, err := s.Sign(ctx, "pub", 0, "", []byte("m")); !errors.Is(err, ErrPublicOnly) {
		t.Fatalf("sign with public key: %v", err)
	}
	// Verify works with a public-only key.
	digest, _ := crypto.Digest("RS256", []byte("m"))
	sig, _ := crypto.Sign(k, "RS256", digest)
	ok, err := s.Verify(ctx, "pub", 0, "RS256", []byte("m"), sig)
	if err != nil || !ok {
		t.Fatalf("verify %v %v", ok, err)
	}
}

func TestLockedVault(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	if _, err := s.CreateKey(ctx, "k", crypto.KindEd25519, crypto.GenerateOptions{}, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	s.Vault().Lock()
	if _, err := s.CreateKey(ctx, "k2", crypto.KindEd25519, crypto.GenerateOptions{}, CreateOptions{}); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("create while locked: %v", err)
	}
	// Metadata is still readable.
	d, err := s.GetItem(ctx, "k")
	if err != nil || d.Versions[0].PublicJWK != nil {
		t.Fatalf("locked get: %v %+v", err, d)
	}
	if _, err := s.Sign(ctx, "k", 0, "", []byte("m")); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("sign while locked: %v", err)
	}
}
