package keyvault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/danto7/azk/internal/vault"
)

// SlotParams are stored with a keyvault unlock slot.
type SlotParams struct {
	Remote       string `json:"remote"`
	VaultURL     string `json:"vault_url"`
	InsecureHTTP bool   `json:"insecure_http,omitempty"`
	Key          string `json:"key"`
	Version      string `json:"version"`
	Algorithm    string `json:"algorithm"`
}

// AddSlot wraps the vault's DEK with the named RSA key and stores a slot.
func AddSlot(ctx context.Context, v *vault.Vault, c *Client, remote, label, key string, create bool) (string, error) {
	version, err := c.EnsureRSAKey(ctx, key, create)
	if err != nil {
		return "", err
	}
	params := SlotParams{Remote: remote, VaultURL: c.VaultURL(), InsecureHTTP: c.cfg.InsecureHTTP, Key: key, Version: version, Algorithm: "RSA-OAEP-256"}
	if label == "" {
		label = remote + "/" + key
	}
	return v.AddWrappedSlot(ctx, vault.SlotKeyVault, label, params, func(dek []byte) ([]byte, error) {
		wrapped, _, err := c.WrapDEK(ctx, key, version, dek)
		return wrapped, err
	})
}

// Unwrapper implements vault.Unwrapper for keyvault slots. A nil Dial uses
// Open with the default credential.
type Unwrapper struct {
	Dial func(cfg Config) (*Client, error)
}

// Unwrap implements vault.Unwrapper.
func (u Unwrapper) Unwrap(ctx context.Context, kind string, raw json.RawMessage, wrapped []byte) ([]byte, error) {
	if kind != vault.SlotKeyVault {
		return nil, vault.ErrSkip
	}
	var p SlotParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("corrupt keyvault slot: %w", err)
	}
	dial := u.Dial
	if dial == nil {
		dial = Open
	}
	c, err := dial(Config{VaultURL: p.VaultURL, InsecureHTTP: p.InsecureHTTP})
	if err != nil {
		return nil, err
	}
	return c.UnwrapDEK(ctx, p.Key, p.Version, wrapped)
}
