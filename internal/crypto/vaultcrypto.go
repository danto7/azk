package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size of every symmetric key the vault itself uses (DEK and
// derived KEKs).
const KeySize = chacha20poly1305.KeySize

// Argon2Params are the Argon2id cost parameters stored next to a passphrase
// slot so they can be raised over time without breaking existing vaults.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// DefaultArgon2Params are the parameters for new passphrase slots: 64 MiB,
// three passes, four lanes. Roughly 150 ms on a laptop.
var DefaultArgon2Params = Argon2Params{Time: 3, Memory: 64 * 1024, Threads: 4}

// Validate rejects parameters that would be trivially cheap to brute force
// or would exhaust memory.
func (p Argon2Params) Validate() error {
	if p.Time < 1 || p.Memory < 8*1024 || p.Threads < 1 {
		return errors.New("argon2 parameters too weak")
	}
	if p.Memory > 4*1024*1024 {
		return errors.New("argon2 memory parameter too large")
	}
	return nil
}

// DeriveKey stretches a passphrase into a KEK with Argon2id.
func DeriveKey(passphrase, salt []byte, p Argon2Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) < 16 {
		return nil, errors.New("salt too short")
	}
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, KeySize), nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Seal encrypts plaintext with XChaCha20-Poly1305 and returns nonce||ciphertext.
// aad is authenticated but not encrypted; the vault uses it to bind records
// to their identity so ciphertexts cannot be swapped between rows.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Open reverses Seal.
func Open(key, sealed, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return pt, nil
}

// Zero overwrites a byte slice.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
