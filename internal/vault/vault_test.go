package vault

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/danto7/azk/internal/crypto"
)

var fast = crypto.Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}

func TestCreateUnlockLock(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v.db")
	v, err := Create(ctx, path, []byte("pw"), CreateOptions{Argon2: fast})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := v.Seal([]byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()

	if _, err := Create(ctx, path, []byte("pw"), CreateOptions{Argon2: fast}); err == nil {
		t.Fatal("create over existing vault succeeded")
	}

	v, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if !v.IsLocked() {
		t.Fatal("opened vault should be locked")
	}
	if _, err := v.Open(ct, []byte("aad")); err != ErrLocked {
		t.Fatalf("want ErrLocked got %v", err)
	}
	if err := v.Unlock(ctx, []byte("wrong")); err != ErrBadPassphrase {
		t.Fatalf("want ErrBadPassphrase got %v", err)
	}
	if err := v.Unlock(ctx, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	pt, err := v.Open(ct, []byte("aad"))
	if err != nil || string(pt) != "hello" {
		t.Fatalf("open: %q %v", pt, err)
	}
	v.Lock()
	if !v.IsLocked() {
		t.Fatal("still unlocked")
	}
}

func TestSlots(t *testing.T) {
	ctx := context.Background()
	v, err := Create(ctx, filepath.Join(t.TempDir(), "v.db"), []byte("one"), CreateOptions{Argon2: fast})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	id2, err := v.AddPassphraseSlot(ctx, "second", []byte("two"), fast)
	if err != nil {
		t.Fatal(err)
	}
	// A fake external wrapper: XOR with a constant, good enough to exercise the flow.
	wrapKey := []byte("0123456789abcdef0123456789abcdef")
	xor := func(b []byte) []byte {
		out := make([]byte, len(b))
		for i := range b {
			out[i] = b[i] ^ wrapKey[i%len(wrapKey)]
		}
		return out
	}
	id3, err := v.AddWrappedSlot(ctx, "fake", "ext", map[string]string{"k": "v"}, func(dek []byte) ([]byte, error) { return xor(dek), nil })
	if err != nil {
		t.Fatal(err)
	}
	slots, _ := v.Slots(ctx)
	if len(slots) != 3 {
		t.Fatalf("want 3 slots got %d", len(slots))
	}

	v.Lock()
	if err := v.Unlock(ctx, []byte("two")); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	err = v.UnlockWith(ctx, unwrapFunc(func(ctx context.Context, kind string, params json.RawMessage, wrapped []byte) ([]byte, error) {
		if kind != "fake" {
			return nil, ErrSkip
		}
		return xor(wrapped), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	err = v.UnlockWith(ctx, unwrapFunc(func(ctx context.Context, kind string, params json.RawMessage, wrapped []byte) ([]byte, error) {
		return make([]byte, 32), nil
	}))
	if err == nil {
		t.Fatal("wrong dek accepted")
	}
	if err := v.Unlock(ctx, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveSlot(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveSlot(ctx, id3); err != nil {
		t.Fatal(err)
	}
	slots, _ = v.Slots(ctx)
	if err := v.RemoveSlot(ctx, slots[0].ID); err != ErrLastSlot {
		t.Fatalf("want ErrLastSlot got %v", err)
	}
}

type unwrapFunc func(ctx context.Context, kind string, params json.RawMessage, wrapped []byte) ([]byte, error)

func (f unwrapFunc) Unwrap(ctx context.Context, kind string, params json.RawMessage, wrapped []byte) ([]byte, error) {
	return f(ctx, kind, params, wrapped)
}
