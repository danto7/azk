// Package vault owns the encrypted vault file: the data encryption key
// (DEK), the key slots that wrap it, and the seal/open primitives every
// stored record goes through.
//
// Layout: one DEK encrypts all material with XChaCha20-Poly1305. The DEK is
// never stored in the clear; each slot holds a copy wrapped either by a KEK
// derived from a passphrase (Argon2id) or by an external key such as an
// Azure Key Vault RSA key. Any single slot unlocks the vault, in the style
// of LUKS.
package vault

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/store"
)

// FormatVersion is bumped when the on-disk layout changes incompatibly.
const FormatVersion = 1

const (
	metaFormatVersion = "format_version"
	metaDEKID         = "dek_id"
	metaCreatedAt     = "created_at"

	// SlotPassphrase unlocks with an Argon2id-derived KEK.
	SlotPassphrase = "passphrase"
	// SlotKeyVault unlocks by asking an Azure Key Vault key to unwrap the DEK.
	SlotKeyVault = "keyvault"
)

// ErrLocked is returned when an operation needs the DEK and the vault is locked.
var ErrLocked = errors.New("vault is locked")

// ErrBadPassphrase is returned when no passphrase slot accepts the passphrase.
var ErrBadPassphrase = errors.New("passphrase does not unlock any slot")

// ErrLastSlot is returned when removing a slot would leave the vault unopenable.
var ErrLastSlot = errors.New("cannot remove the last slot")

// PassphraseParams are the stored parameters of a passphrase slot.
type PassphraseParams struct {
	Salt   []byte              `json:"salt"`
	Argon2 crypto.Argon2Params `json:"argon2"`
}

// Vault is an open vault file, locked or unlocked.
type Vault struct {
	path  string
	store *store.Store

	mu  sync.RWMutex
	dek []byte
}

// CreateOptions tune vault creation.
type CreateOptions struct {
	Argon2 crypto.Argon2Params
	Label  string
}

// Create initialises a new vault at path with one passphrase slot and
// returns it unlocked. It fails if the file already holds a vault.
func Create(ctx context.Context, path string, passphrase []byte, opts CreateOptions) (*Vault, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := st.GetMeta(ctx, metaFormatVersion); err == nil {
		st.Close()
		return nil, fmt.Errorf("%s already contains a vault", path)
	}
	dek, err := crypto.RandomBytes(crypto.KeySize)
	if err != nil {
		st.Close()
		return nil, err
	}
	dekID, err := randomID()
	if err != nil {
		st.Close()
		return nil, err
	}
	v := &Vault{path: path, store: st, dek: dek}
	err = st.Tx(ctx, func(q *store.Queries) error {
		if err := q.SetMeta(ctx, metaFormatVersion, []byte(strconv.Itoa(FormatVersion))); err != nil {
			return err
		}
		if err := q.SetMeta(ctx, metaDEKID, []byte(dekID)); err != nil {
			return err
		}
		if err := q.SetMeta(ctx, metaCreatedAt, []byte(time.Now().UTC().Format(time.RFC3339))); err != nil {
			return err
		}
		_, err := v.addPassphraseSlot(ctx, q, opts.Label, passphrase, opts.Argon2)
		return err
	})
	if err != nil {
		v.Lock()
		st.Close()
		return nil, err
	}
	return v, nil
}

// Open opens an existing vault in the locked state.
func Open(ctx context.Context, path string) (*Vault, error) {
	st, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	raw, err := st.GetMeta(ctx, metaFormatVersion)
	if err != nil {
		st.Close()
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%s is not an azk vault (run `azk init`)", path)
		}
		return nil, err
	}
	ver, err := strconv.Atoi(string(raw))
	if err != nil || ver != FormatVersion {
		st.Close()
		return nil, fmt.Errorf("vault format version %s is not supported by this build (want %d)", raw, FormatVersion)
	}
	return &Vault{path: path, store: st}, nil
}

// Path returns the vault file location.
func (v *Vault) Path() string { return v.path }

// Store exposes the underlying database.
func (v *Vault) Store() *store.Store { return v.store }

// Close locks and closes the vault.
func (v *Vault) Close() error {
	v.Lock()
	return v.store.Close()
}

// IsLocked reports whether the DEK is held in memory.
func (v *Vault) IsLocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek == nil
}

// Lock forgets the DEK.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	crypto.Zero(v.dek)
	v.dek = nil
}

// Unlock tries the passphrase against every passphrase slot.
func (v *Vault) Unlock(ctx context.Context, passphrase []byte) error {
	slots, err := v.store.ListSlots(ctx)
	if err != nil {
		return err
	}
	for _, s := range slots {
		if s.Kind != SlotPassphrase {
			continue
		}
		var p PassphraseParams
		if err := json.Unmarshal(s.Params, &p); err != nil {
			return fmt.Errorf("slot %s: corrupt parameters: %w", s.ID, err)
		}
		kek, err := crypto.DeriveKey(passphrase, p.Salt, p.Argon2)
		if err != nil {
			return err
		}
		dek, err := crypto.Open(kek, s.WrappedDEK, slotAAD(s.ID))
		crypto.Zero(kek)
		if err == nil {
			v.setDEK(dek)
			return nil
		}
	}
	return ErrBadPassphrase
}

// Unwrapper unwraps a slot's DEK using an external key. It is implemented
// by the Key Vault remote so this package stays free of Azure dependencies.
type Unwrapper interface {
	// Unwrap returns the DEK for a slot of the given kind and params, or an
	// error. ErrSkip means the unwrapper does not handle this slot.
	Unwrap(ctx context.Context, kind string, params json.RawMessage, wrapped []byte) ([]byte, error)
}

// ErrSkip lets an Unwrapper decline a slot.
var ErrSkip = errors.New("slot not handled")

// UnlockWith tries every non-passphrase slot against the unwrapper.
func (v *Vault) UnlockWith(ctx context.Context, u Unwrapper) error {
	slots, err := v.store.ListSlots(ctx)
	if err != nil {
		return err
	}
	var lastErr error
	for _, s := range slots {
		if s.Kind == SlotPassphrase {
			continue
		}
		dek, err := u.Unwrap(ctx, s.Kind, s.Params, s.WrappedDEK)
		if errors.Is(err, ErrSkip) {
			continue
		}
		if err != nil {
			lastErr = fmt.Errorf("slot %s (%s): %w", s.Label, s.ID, err)
			continue
		}
		if len(dek) != crypto.KeySize {
			lastErr = fmt.Errorf("slot %s returned a %d byte key", s.ID, len(dek))
			continue
		}
		if err := v.verifyDEK(ctx, dek); err != nil {
			lastErr = fmt.Errorf("slot %s: %w", s.ID, err)
			continue
		}
		v.setDEK(dek)
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("no slot could be unlocked")
}

// verifyDEK checks an externally unwrapped DEK against the DEK check value
// so a wrong key is detected before it is used.
func (v *Vault) verifyDEK(ctx context.Context, dek []byte) error {
	raw, err := v.store.GetMeta(ctx, "dek_check")
	if err != nil {
		return err
	}
	if _, err := crypto.Open(dek, raw, []byte("dek_check")); err != nil {
		return errors.New("unwrapped key does not match this vault")
	}
	return nil
}

func (v *Vault) setDEK(dek []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	crypto.Zero(v.dek)
	v.dek = dek
}

func (v *Vault) getDEK() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return nil, ErrLocked
	}
	return v.dek, nil
}

func slotAAD(id string) []byte { return []byte("slot:" + id) }

func randomID() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (v *Vault) addPassphraseSlot(ctx context.Context, q *store.Queries, label string, passphrase []byte, params crypto.Argon2Params) (string, error) {
	dek, err := v.getDEK()
	if err != nil {
		return "", err
	}
	if params == (crypto.Argon2Params{}) {
		params = crypto.DefaultArgon2Params
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	kek, err := crypto.DeriveKey(passphrase, salt, params)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(kek)
	id, err := randomID()
	if err != nil {
		return "", err
	}
	wrapped, err := crypto.Seal(kek, dek, slotAAD(id))
	if err != nil {
		return "", err
	}
	p, _ := json.Marshal(PassphraseParams{Salt: salt, Argon2: params})
	if label == "" {
		label = "passphrase"
	}
	if err := q.AddSlot(ctx, store.Slot{ID: id, Kind: SlotPassphrase, Label: label, Params: p, WrappedDEK: wrapped, CreatedAt: time.Now()}); err != nil {
		return "", err
	}
	// Keep a check value so external slots can verify an unwrapped DEK.
	check, err := crypto.Seal(dek, []byte("azk"), []byte("dek_check"))
	if err != nil {
		return "", err
	}
	return id, q.SetMeta(ctx, "dek_check", check)
}

// AddPassphraseSlot adds another passphrase that unlocks the vault.
func (v *Vault) AddPassphraseSlot(ctx context.Context, label string, passphrase []byte, params crypto.Argon2Params) (string, error) {
	if len(passphrase) == 0 {
		return "", errors.New("passphrase must not be empty")
	}
	var id string
	err := v.store.Tx(ctx, func(q *store.Queries) error {
		var err error
		id, err = v.addPassphraseSlot(ctx, q, label, passphrase, params)
		return err
	})
	return id, err
}

// AddWrappedSlot adds a slot whose DEK copy is wrapped by an external key.
// wrap receives the DEK and returns the wrapped bytes.
func (v *Vault) AddWrappedSlot(ctx context.Context, kind, label string, params any, wrap func(dek []byte) ([]byte, error)) (string, error) {
	dek, err := v.getDEK()
	if err != nil {
		return "", err
	}
	wrapped, err := wrap(dek)
	if err != nil {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(params)
	if err != nil {
		return "", err
	}
	return id, v.store.AddSlot(ctx, store.Slot{ID: id, Kind: kind, Label: label, Params: p, WrappedDEK: wrapped, CreatedAt: time.Now()})
}

// RemoveSlot deletes a slot by id or unique label, refusing to delete the
// last one.
func (v *Vault) RemoveSlot(ctx context.Context, idOrLabel string) error {
	return v.store.Tx(ctx, func(q *store.Queries) error {
		slots, err := q.ListSlots(ctx)
		if err != nil {
			return err
		}
		if len(slots) <= 1 {
			return ErrLastSlot
		}
		id := ""
		for _, s := range slots {
			if s.ID == idOrLabel {
				id = s.ID
				break
			}
		}
		if id == "" {
			for _, s := range slots {
				if s.Label == idOrLabel {
					if id != "" {
						return fmt.Errorf("label %q matches several slots; use the id", idOrLabel)
					}
					id = s.ID
				}
			}
		}
		if id == "" {
			return fmt.Errorf("slot %q: %w", idOrLabel, store.ErrNotFound)
		}
		return q.DeleteSlot(ctx, id)
	})
}

// Slots lists the slots without their wrapped material.
func (v *Vault) Slots(ctx context.Context) ([]store.Slot, error) {
	slots, err := v.store.ListSlots(ctx)
	if err != nil {
		return nil, err
	}
	for i := range slots {
		slots[i].WrappedDEK = nil
	}
	return slots, nil
}

// Seal encrypts a record with the DEK. aad binds the ciphertext to its
// location so it cannot be moved between rows.
func (v *Vault) Seal(plaintext, aad []byte) ([]byte, error) {
	dek, err := v.getDEK()
	if err != nil {
		return nil, err
	}
	return crypto.Seal(dek, plaintext, aad)
}

// Open decrypts a record sealed with Seal.
func (v *Vault) Open(ciphertext, aad []byte) ([]byte, error) {
	dek, err := v.getDEK()
	if err != nil {
		return nil, err
	}
	return crypto.Open(dek, ciphertext, aad)
}

// Info is the non-sensitive summary shown by `azk status`.
type Info struct {
	Path          string    `json:"path"`
	FormatVersion int       `json:"format_version"`
	Locked        bool      `json:"locked"`
	CreatedAt     time.Time `json:"created_at"`
	Slots         int       `json:"slots"`
}

// Info summarises the vault.
func (v *Vault) Info(ctx context.Context) (*Info, error) {
	slots, err := v.store.ListSlots(ctx)
	if err != nil {
		return nil, err
	}
	info := &Info{Path: v.path, FormatVersion: FormatVersion, Locked: v.IsLocked(), Slots: len(slots)}
	if raw, err := v.store.GetMeta(ctx, metaCreatedAt); err == nil {
		info.CreatedAt, _ = time.Parse(time.RFC3339, string(raw))
	}
	return info, nil
}
