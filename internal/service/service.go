// Package service implements azk's use cases on top of the vault. The CLI
// and the web UI are thin layers over it; nothing here knows about
// terminals or HTTP.
package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/store"
	"github.com/danto7/azk/internal/vault"
)

// Errors surfaced to callers.
var (
	ErrNotFound   = store.ErrNotFound
	ErrExists     = store.ErrExists
	ErrDeleted    = errors.New("item is deleted (recover it first)")
	ErrNotDeleted = errors.New("item is not deleted")
	ErrDisabled   = errors.New("version is disabled")
	ErrPublicOnly = errors.New("version holds only public material")
	ErrNotKey     = errors.New("item is not a key")
	ErrNotSecret  = errors.New("item is not a secret")
)

// nameRe matches Azure Key Vault object names so every local item can be
// pushed without renaming.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9-]{1,127}$`)

// ValidateName checks an item name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid name %q: use 1-127 letters, digits or dashes", name)
	}
	return nil
}

// Material is the decrypted payload of a version.
type Material struct {
	JWK         *crypto.JWK `json:"jwk,omitempty"`
	Value       []byte      `json:"value,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
}

// Zero wipes the material.
func (m *Material) Zero() {
	if m.JWK != nil {
		m.JWK.Zero()
	}
	crypto.Zero(m.Value)
}

// VersionInfo is a version without ciphertext, plus the public key when
// the item is an asymmetric key and the vault is unlocked.
type VersionInfo struct {
	store.Version
	PublicJWK  *crypto.JWK `json:"public_jwk,omitempty"`
	Thumbprint string      `json:"thumbprint,omitempty"`
	Size       string      `json:"size,omitempty"`
}

// ItemDetail is an item with its versions.
type ItemDetail struct {
	*store.Item
	Versions []VersionInfo `json:"versions"`
}

// Latest returns the newest enabled version, or nil.
func (d *ItemDetail) Latest() *VersionInfo {
	for i := range d.Versions {
		if d.Versions[i].Enabled {
			return &d.Versions[i]
		}
	}
	return nil
}

// Service exposes vault operations.
type Service struct {
	v     *vault.Vault
	actor string
}

// New wraps a vault. actor is recorded in the audit log ("cli", "web").
func New(v *vault.Vault, actor string) *Service {
	return &Service{v: v, actor: actor}
}

// Vault exposes the underlying vault for lock/unlock/slot management.
func (s *Service) Vault() *vault.Vault { return s.v }

func (s *Service) audit(ctx context.Context, action, target string, details any) {
	var d string
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			d = string(b)
		}
	}
	_ = s.v.Store().AppendAudit(ctx, store.AuditEntry{At: time.Now(), Actor: s.actor, Action: action, Target: target, Details: d})
}

// Audit returns recent audit entries.
func (s *Service) Audit(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	return s.v.Store().ListAudit(ctx, limit)
}

func randomID() (string, error) {
	b, err := crypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func versionAAD(itemID string, seq int) []byte {
	return []byte("v1:" + itemID + ":" + strconv.Itoa(seq))
}

func (s *Service) sealMaterial(itemID string, seq int, m *Material) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(raw)
	return s.v.Seal(raw, versionAAD(itemID, seq))
}

func (s *Service) openMaterial(v *store.Version) (*Material, error) {
	raw, err := s.v.Open(v.Ciphertext, versionAAD(v.ItemID, v.Seq))
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(raw)
	var m Material
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("corrupt material for version %s: %w", v.ID, err)
	}
	return &m, nil
}

// CreateOptions configure new items.
type CreateOptions struct {
	Tags      map[string]string
	NotBefore *time.Time
	Expires   *time.Time
}

// CreateKey generates a new key item.
func (s *Service) CreateKey(ctx context.Context, name string, kind crypto.Kind, gen crypto.GenerateOptions, opts CreateOptions) (*ItemDetail, error) {
	if !kind.IsKey() {
		return nil, ErrNotKey
	}
	jwk, err := crypto.Generate(kind, gen)
	if err != nil {
		return nil, err
	}
	defer jwk.Zero()
	d, err := s.createItem(ctx, name, kind, &Material{JWK: jwk}, false, opts)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.generate", name, map[string]any{"kind": kind, "size": jwk.Size()})
	return d, nil
}

// ImportKey stores existing key material. Public-only JWKs are accepted and
// flagged so they cannot be used for private operations.
func (s *Service) ImportKey(ctx context.Context, name string, jwk *crypto.JWK, opts CreateOptions) (*ItemDetail, error) {
	kind := jwk.Kind()
	if kind == "" {
		return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
	}
	d, err := s.createItem(ctx, name, kind, &Material{JWK: jwk}, !jwk.IsPrivate(), opts)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.import", name, map[string]any{"kind": kind, "size": jwk.Size(), "public_only": !jwk.IsPrivate()})
	return d, nil
}

// SetSecret creates a secret or adds a version to an existing one.
func (s *Service) SetSecret(ctx context.Context, name string, value []byte, contentType string, opts CreateOptions) (*ItemDetail, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	it, err := s.v.Store().GetItem(ctx, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		d, err := s.createItem(ctx, name, crypto.KindSecret, &Material{Value: value, ContentType: contentType}, false, opts)
		if err != nil {
			return nil, err
		}
		s.audit(ctx, "secret.set", name, map[string]any{"seq": 1})
		return d, nil
	case err != nil:
		return nil, err
	}
	if it.Kind != string(crypto.KindSecret) {
		return nil, ErrNotSecret
	}
	if it.DeletedAt != nil {
		return nil, ErrDeleted
	}
	v, err := s.addVersion(ctx, it, &Material{Value: value, ContentType: contentType}, false, opts)
	if err != nil {
		return nil, err
	}
	if len(opts.Tags) > 0 {
		it.Tags = opts.Tags
		it.UpdatedAt = time.Now()
		if err := s.v.Store().UpdateItem(ctx, it); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, "secret.set", name, map[string]any{"seq": v.Seq})
	return s.GetItem(ctx, name)
}

func (s *Service) createItem(ctx context.Context, name string, kind crypto.Kind, m *Material, publicOnly bool, opts CreateOptions) (*ItemDetail, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if s.v.IsLocked() {
		return nil, vault.ErrLocked
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	vid, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tags := opts.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	it := &store.Item{ID: id, Name: name, Kind: string(kind), Tags: tags, CreatedAt: now, UpdatedAt: now}
	ct, err := s.sealMaterial(id, 1, m)
	if err != nil {
		return nil, err
	}
	ver := &store.Version{ID: vid, ItemID: id, Seq: 1, Enabled: true, NotBefore: opts.NotBefore, Expires: opts.Expires, CreatedAt: now, UpdatedAt: now, Ciphertext: ct, PublicOnly: publicOnly}
	err = s.v.Store().Tx(ctx, func(q *store.Queries) error {
		if err := q.CreateItem(ctx, it); err != nil {
			return err
		}
		return q.AddVersion(ctx, ver)
	})
	if err != nil {
		return nil, err
	}
	return s.GetItem(ctx, name)
}

func (s *Service) addVersion(ctx context.Context, it *store.Item, m *Material, publicOnly bool, opts CreateOptions) (*store.Version, error) {
	if s.v.IsLocked() {
		return nil, vault.ErrLocked
	}
	vid, err := randomID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var ver *store.Version
	err = s.v.Store().Tx(ctx, func(q *store.Queries) error {
		seq, err := q.NextSeq(ctx, it.ID)
		if err != nil {
			return err
		}
		ct, err := s.sealMaterial(it.ID, seq, m)
		if err != nil {
			return err
		}
		ver = &store.Version{ID: vid, ItemID: it.ID, Seq: seq, Enabled: true, NotBefore: opts.NotBefore, Expires: opts.Expires, CreatedAt: now, UpdatedAt: now, Ciphertext: ct, PublicOnly: publicOnly}
		if err := q.AddVersion(ctx, ver); err != nil {
			return err
		}
		it.UpdatedAt = now
		return q.UpdateItem(ctx, it)
	})
	return ver, err
}

// GetItem returns an item with its versions. Public keys are included when
// the vault is unlocked.
func (s *Service) GetItem(ctx context.Context, name string) (*ItemDetail, error) {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return nil, err
	}
	return s.detail(ctx, it)
}

func (s *Service) detail(ctx context.Context, it *store.Item) (*ItemDetail, error) {
	vs, err := s.v.Store().ListVersions(ctx, it.ID)
	if err != nil {
		return nil, err
	}
	d := &ItemDetail{Item: it}
	for _, v := range vs {
		info := VersionInfo{Version: *v}
		info.Ciphertext = nil
		if !s.v.IsLocked() && it.Kind != string(crypto.KindSecret) {
			m, err := s.openMaterial(v)
			if err != nil {
				return nil, err
			}
			if m.JWK != nil {
				info.PublicJWK = m.JWK.Public()
				info.Thumbprint, _ = m.JWK.Thumbprint()
				info.Size = m.JWK.Size()
			}
			m.Zero()
		}
		d.Versions = append(d.Versions, info)
	}
	return d, nil
}

// ListItems returns items matching the filter.
func (s *Service) ListItems(ctx context.Context, f store.ItemFilter) ([]*store.Item, error) {
	return s.v.Store().ListItems(ctx, f)
}

// resolve finds an item and the requested version (seq 0 = latest enabled).
func (s *Service) resolve(ctx context.Context, name string, seq int) (*store.Item, *store.Version, error) {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return nil, nil, err
	}
	if it.DeletedAt != nil {
		return nil, nil, ErrDeleted
	}
	var v *store.Version
	if seq == 0 {
		v, err = s.v.Store().LatestVersion(ctx, it.ID)
	} else {
		v, err = s.v.Store().GetVersion(ctx, it.ID, seq)
	}
	if err != nil {
		return nil, nil, err
	}
	return it, v, nil
}

func usable(v *store.Version) error {
	if !v.Enabled {
		return ErrDisabled
	}
	now := time.Now()
	if v.NotBefore != nil && now.Before(*v.NotBefore) {
		return fmt.Errorf("version %d is not valid before %s", v.Seq, v.NotBefore.Format(time.RFC3339))
	}
	if v.Expires != nil && now.After(*v.Expires) {
		return fmt.Errorf("version %d expired at %s", v.Seq, v.Expires.Format(time.RFC3339))
	}
	return nil
}

// Rotate creates a new version with freshly generated material of the same
// kind and size. Secrets are rotated with SetSecret instead.
func (s *Service) Rotate(ctx context.Context, name string, disableOld bool) (*ItemDetail, error) {
	it, v, err := s.resolve(ctx, name, 0)
	if err != nil {
		return nil, err
	}
	if it.Kind == string(crypto.KindSecret) {
		return nil, errors.New("secrets are rotated with `azk secret set`")
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if m.JWK == nil {
		return nil, ErrNotKey
	}
	gen := crypto.GenerateOptions{}
	switch m.JWK.Kty {
	case "RSA", "oct":
		gen.Bits, _ = strconv.Atoi(m.JWK.Size())
	case "EC":
		gen.Curve = m.JWK.Crv
	}
	fresh, err := crypto.Generate(crypto.Kind(it.Kind), gen)
	if err != nil {
		return nil, err
	}
	defer fresh.Zero()
	nv, err := s.addVersion(ctx, it, &Material{JWK: fresh}, false, CreateOptions{})
	if err != nil {
		return nil, err
	}
	if disableOld {
		v.Enabled = false
		v.UpdatedAt = time.Now()
		if err := s.v.Store().UpdateVersion(ctx, v); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, "key.rotate", name, map[string]any{"seq": nv.Seq, "disabled_old": disableOld})
	return s.GetItem(ctx, name)
}

// SetVersionEnabled toggles a version.
func (s *Service) SetVersionEnabled(ctx context.Context, name string, seq int, enabled bool) error {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return err
	}
	v, err := s.v.Store().GetVersion(ctx, it.ID, seq)
	if err != nil {
		return err
	}
	v.Enabled = enabled
	v.UpdatedAt = time.Now()
	if err := s.v.Store().UpdateVersion(ctx, v); err != nil {
		return err
	}
	s.audit(ctx, "version.enable", name, map[string]any{"seq": seq, "enabled": enabled})
	return nil
}

// SetTags replaces an item's tags.
func (s *Service) SetTags(ctx context.Context, name string, tags map[string]string) error {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return err
	}
	if tags == nil {
		tags = map[string]string{}
	}
	it.Tags = tags
	it.UpdatedAt = time.Now()
	if err := s.v.Store().UpdateItem(ctx, it); err != nil {
		return err
	}
	s.audit(ctx, "item.tags", name, tags)
	return nil
}

// Delete soft-deletes an item.
func (s *Service) Delete(ctx context.Context, name string) error {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return err
	}
	if it.DeletedAt != nil {
		return ErrDeleted
	}
	now := time.Now()
	it.DeletedAt = &now
	it.UpdatedAt = now
	if err := s.v.Store().UpdateItem(ctx, it); err != nil {
		return err
	}
	s.audit(ctx, "item.delete", name, nil)
	return nil
}

// Recover undoes a soft delete.
func (s *Service) Recover(ctx context.Context, name string) error {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return err
	}
	if it.DeletedAt == nil {
		return ErrNotDeleted
	}
	it.DeletedAt = nil
	it.UpdatedAt = time.Now()
	if err := s.v.Store().UpdateItem(ctx, it); err != nil {
		return err
	}
	s.audit(ctx, "item.recover", name, nil)
	return nil
}

// Purge permanently removes a soft-deleted item. With force it removes a
// live item too.
func (s *Service) Purge(ctx context.Context, name string, force bool) error {
	it, err := s.v.Store().GetItem(ctx, name)
	if err != nil {
		return err
	}
	if it.DeletedAt == nil && !force {
		return errors.New("item is not deleted; delete it first or use --force")
	}
	if err := s.v.Store().PurgeItem(ctx, it.ID); err != nil {
		return err
	}
	s.audit(ctx, "item.purge", name, nil)
	return nil
}

// Export returns decrypted material. Private key export is audited; callers
// must gate it behind an explicit flag.
func (s *Service) Export(ctx context.Context, name string, seq int, publicOnly bool) (*Material, *store.Version, error) {
	it, v, err := s.resolve(ctx, name, seq)
	if err != nil {
		return nil, nil, err
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return nil, nil, err
	}
	if it.Kind == string(crypto.KindSecret) {
		if publicOnly {
			return nil, nil, errors.New("secrets have no public part")
		}
		s.audit(ctx, "secret.get", name, map[string]any{"seq": v.Seq})
		return m, v, nil
	}
	if publicOnly {
		pub := m.JWK.Public()
		m.Zero()
		if pub == nil {
			return nil, nil, errors.New("symmetric keys have no public part")
		}
		return &Material{JWK: pub}, v, nil
	}
	if v.PublicOnly {
		s.audit(ctx, "key.export", name, map[string]any{"seq": v.Seq, "public_only": true})
		return m, v, nil
	}
	s.audit(ctx, "key.export", name, map[string]any{"seq": v.Seq, "private": true})
	return m, v, nil
}

// privateJWK loads a usable private key for an operation.
func (s *Service) privateJWK(ctx context.Context, name string, seq int) (*Material, *store.Version, error) {
	it, v, err := s.resolve(ctx, name, seq)
	if err != nil {
		return nil, nil, err
	}
	if it.Kind == string(crypto.KindSecret) {
		return nil, nil, ErrNotKey
	}
	if err := usable(v); err != nil {
		return nil, nil, err
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return nil, nil, err
	}
	return m, v, nil
}

// OpResult carries the output of a key operation together with the
// version and algorithm that produced it.
type OpResult struct {
	Name      string `json:"name"`
	Seq       int    `json:"seq"`
	VersionID string `json:"version_id"`
	Algorithm string `json:"algorithm"`
	Result    []byte `json:"result"`
	IV        []byte `json:"iv,omitempty"`
	Tag       []byte `json:"tag,omitempty"`
}

// Sign signs a message. alg may be empty to use the key's default. The
// message is hashed here; use SignDigest when the caller already has one.
func (s *Service) Sign(ctx context.Context, name string, seq int, alg string, message []byte) (*OpResult, error) {
	m, v, err := s.privateJWK(ctx, name, seq)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if v.PublicOnly {
		return nil, ErrPublicOnly
	}
	if alg == "" {
		if alg, err = crypto.DefaultSignatureAlgorithm(m.JWK); err != nil {
			return nil, err
		}
	}
	digest, err := crypto.Digest(alg, message)
	if err != nil {
		return nil, err
	}
	sig, err := crypto.Sign(m.JWK, alg, digest)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.sign", name, map[string]any{"seq": v.Seq, "alg": alg})
	return &OpResult{Name: name, Seq: v.Seq, VersionID: v.ID, Algorithm: alg, Result: sig}, nil
}

// Verify checks a signature over a message.
func (s *Service) Verify(ctx context.Context, name string, seq int, alg string, message, sig []byte) (bool, error) {
	it, v, err := s.resolve(ctx, name, seq)
	if err != nil {
		return false, err
	}
	if it.Kind == string(crypto.KindSecret) {
		return false, ErrNotKey
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return false, err
	}
	defer m.Zero()
	if alg == "" {
		if alg, err = crypto.DefaultSignatureAlgorithm(m.JWK); err != nil {
			return false, err
		}
	}
	digest, err := crypto.Digest(alg, message)
	if err != nil {
		return false, err
	}
	return crypto.Verify(m.JWK, alg, digest, sig)
}

// Encrypt encrypts plaintext with a key.
func (s *Service) Encrypt(ctx context.Context, name string, seq int, alg string, plaintext, aad []byte) (*OpResult, error) {
	it, v, err := s.resolve(ctx, name, seq)
	if err != nil {
		return nil, err
	}
	if it.Kind == string(crypto.KindSecret) {
		return nil, ErrNotKey
	}
	if err := usable(v); err != nil {
		return nil, err
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if alg == "" {
		if alg, err = crypto.DefaultEncryptionAlgorithm(m.JWK); err != nil {
			return nil, err
		}
	}
	ct, err := crypto.Encrypt(m.JWK, alg, plaintext, aad)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.encrypt", name, map[string]any{"seq": v.Seq, "alg": alg})
	return &OpResult{Name: name, Seq: v.Seq, VersionID: v.ID, Algorithm: alg, Result: ct.Ciphertext, IV: ct.IV, Tag: ct.Tag}, nil
}

// Decrypt reverses Encrypt.
func (s *Service) Decrypt(ctx context.Context, name string, seq int, alg string, ciphertext, iv, tag, aad []byte) ([]byte, error) {
	m, v, err := s.privateJWK(ctx, name, seq)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if v.PublicOnly {
		return nil, ErrPublicOnly
	}
	if alg == "" {
		if alg, err = crypto.DefaultEncryptionAlgorithm(m.JWK); err != nil {
			return nil, err
		}
	}
	pt, err := crypto.Decrypt(m.JWK, alg, &crypto.Ciphertext{Ciphertext: ciphertext, IV: iv, Tag: tag}, aad)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.decrypt", name, map[string]any{"seq": v.Seq, "alg": alg})
	return pt, nil
}

// Wrap wraps key material with a key.
func (s *Service) Wrap(ctx context.Context, name string, seq int, alg string, key []byte) (*OpResult, error) {
	it, v, err := s.resolve(ctx, name, seq)
	if err != nil {
		return nil, err
	}
	if it.Kind == string(crypto.KindSecret) {
		return nil, ErrNotKey
	}
	if err := usable(v); err != nil {
		return nil, err
	}
	m, err := s.openMaterial(v)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if alg == "" {
		if alg, err = crypto.DefaultWrapAlgorithm(m.JWK); err != nil {
			return nil, err
		}
	}
	out, err := crypto.WrapKey(m.JWK, alg, key)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.wrap", name, map[string]any{"seq": v.Seq, "alg": alg})
	return &OpResult{Name: name, Seq: v.Seq, VersionID: v.ID, Algorithm: alg, Result: out}, nil
}

// Unwrap reverses Wrap.
func (s *Service) Unwrap(ctx context.Context, name string, seq int, alg string, wrapped []byte) ([]byte, error) {
	m, v, err := s.privateJWK(ctx, name, seq)
	if err != nil {
		return nil, err
	}
	defer m.Zero()
	if v.PublicOnly {
		return nil, ErrPublicOnly
	}
	if alg == "" {
		if alg, err = crypto.DefaultWrapAlgorithm(m.JWK); err != nil {
			return nil, err
		}
	}
	out, err := crypto.UnwrapKey(m.JWK, alg, wrapped)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, "key.unwrap", name, map[string]any{"seq": v.Seq, "alg": alg})
	return out, nil
}

// Material returns the decrypted material of a version without auditing;
// for internal use by sync. Callers must zero it.
func (s *Service) Material(ctx context.Context, v *store.Version) (*Material, error) {
	return s.openMaterial(v)
}

// AddVersion stores material as a new version of an existing item. Used by
// pull to record remote versions.
func (s *Service) AddVersion(ctx context.Context, it *store.Item, m *Material, publicOnly bool, opts CreateOptions) (*store.Version, error) {
	return s.addVersion(ctx, it, m, publicOnly, opts)
}

// CreateWithMaterial creates an item from ready material. Used by pull.
func (s *Service) CreateWithMaterial(ctx context.Context, name string, kind crypto.Kind, m *Material, publicOnly bool, opts CreateOptions) (*ItemDetail, error) {
	return s.createItem(ctx, name, kind, m, publicOnly, opts)
}

// Record writes an audit entry on behalf of a caller (e.g. sync).
func (s *Service) Record(ctx context.Context, action, target string, details any) {
	s.audit(ctx, action, target, details)
}
