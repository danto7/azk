// Package store persists vault contents in a single SQLite file. It knows
// nothing about encryption: item material arrives and leaves as opaque
// ciphertext, and the vault package is responsible for sealing it.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is returned when a unique constraint would be violated.
var ErrExists = errors.New("already exists")

// Store is an open vault database.
type Store struct {
	*Queries
	db *sql.DB
}

// Open opens (or creates) the database at path with restrictive
// permissions and applies migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Create the file ourselves so the mode is right from the start.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(FULL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{Queries: &Queries{db: db}, db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Tx runs fn inside a transaction.
func (s *Store) Tx(ctx context.Context, fn func(q *Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Queries{db: tx}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS slots (
	id          TEXT PRIMARY KEY,
	kind        TEXT NOT NULL,
	label       TEXT NOT NULL,
	params      BLOB NOT NULL,
	wrapped_dek BLOB NOT NULL,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE,
	kind       TEXT NOT NULL,
	tags       TEXT NOT NULL DEFAULT '{}',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	deleted_at INTEGER,
	remote_id  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS versions (
	id             TEXT PRIMARY KEY,
	item_id        TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
	seq            INTEGER NOT NULL,
	enabled        INTEGER NOT NULL DEFAULT 1,
	not_before     INTEGER,
	expires        INTEGER,
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	ciphertext     BLOB NOT NULL,
	public_only    INTEGER NOT NULL DEFAULT 0,
	remote_version TEXT NOT NULL DEFAULT '',
	UNIQUE(item_id, seq)
);
CREATE TABLE IF NOT EXISTS audit (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	at      INTEGER NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL,
	details TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS remotes (
	name          TEXT PRIMARY KEY,
	vault_url     TEXT NOT NULL,
	insecure_http INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	last_sync_at  INTEGER
);
`

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// Queries is the set of operations available both directly and inside Tx.
type Queries struct {
	db interface {
		ExecContext(context.Context, string, ...any) (sql.Result, error)
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func ts(t time.Time) int64 { return t.UTC().UnixMilli() }

func fromTS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func optTS(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func fromOptTS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromTS(v.Int64)
	return &t
}

// --- meta ---

// GetMeta reads a metadata value.
func (q *Queries) GetMeta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := q.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetMeta writes a metadata value.
func (q *Queries) SetMeta(ctx context.Context, key string, value []byte) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- slots ---

// Slot is one way of unwrapping the data encryption key.
type Slot struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Label      string          `json:"label"`
	Params     json.RawMessage `json:"params"`
	WrappedDEK []byte          `json:"-"`
	CreatedAt  time.Time       `json:"created_at"`
}

// AddSlot inserts a slot.
func (q *Queries) AddSlot(ctx context.Context, s Slot) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO slots(id, kind, label, params, wrapped_dek, created_at) VALUES(?,?,?,?,?,?)`,
		s.ID, s.Kind, s.Label, []byte(s.Params), s.WrappedDEK, ts(s.CreatedAt))
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// ListSlots returns all slots in creation order.
func (q *Queries) ListSlots(ctx context.Context) ([]Slot, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT id, kind, label, params, wrapped_dek, created_at FROM slots ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Slot
	for rows.Next() {
		var s Slot
		var created int64
		var params []byte
		if err := rows.Scan(&s.ID, &s.Kind, &s.Label, &params, &s.WrappedDEK, &created); err != nil {
			return nil, err
		}
		s.Params = params
		s.CreatedAt = fromTS(created)
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSlot removes a slot.
func (q *Queries) DeleteSlot(ctx context.Context, id string) error {
	res, err := q.db.ExecContext(ctx, `DELETE FROM slots WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- items ---

// Item is a named key or secret. Material lives in Versions.
type Item struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Tags      map[string]string `json:"tags"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	DeletedAt *time.Time        `json:"deleted_at,omitempty"`
	RemoteID  string            `json:"remote_id,omitempty"`
}

// Version is one generation of an item's material.
type Version struct {
	ID            string     `json:"id"`
	ItemID        string     `json:"item_id"`
	Seq           int        `json:"seq"`
	Enabled       bool       `json:"enabled"`
	NotBefore     *time.Time `json:"not_before,omitempty"`
	Expires       *time.Time `json:"expires,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Ciphertext    []byte     `json:"-"`
	PublicOnly    bool       `json:"public_only"`
	RemoteVersion string     `json:"remote_version,omitempty"`
}

// ItemFilter narrows ListItems.
type ItemFilter struct {
	Kind           string
	Tag            string // "key" or "key=value"
	IncludeDeleted bool
	OnlyDeleted    bool
	NamePrefix     string
}

const itemCols = `id, name, kind, tags, created_at, updated_at, deleted_at, remote_id`

func scanItem(sc interface{ Scan(...any) error }) (*Item, error) {
	var it Item
	var tags string
	var created, updated int64
	var deleted sql.NullInt64
	if err := sc.Scan(&it.ID, &it.Name, &it.Kind, &tags, &created, &updated, &deleted, &it.RemoteID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	it.Tags = map[string]string{}
	if tags != "" {
		if err := json.Unmarshal([]byte(tags), &it.Tags); err != nil {
			return nil, fmt.Errorf("corrupt tags for item %s: %w", it.Name, err)
		}
	}
	it.CreatedAt, it.UpdatedAt, it.DeletedAt = fromTS(created), fromTS(updated), fromOptTS(deleted)
	return &it, nil
}

// CreateItem inserts an item.
func (q *Queries) CreateItem(ctx context.Context, it *Item) error {
	tags, err := json.Marshal(it.Tags)
	if err != nil {
		return err
	}
	_, err = q.db.ExecContext(ctx, `INSERT INTO items(id, name, kind, tags, created_at, updated_at, deleted_at, remote_id) VALUES(?,?,?,?,?,?,?,?)`,
		it.ID, it.Name, it.Kind, string(tags), ts(it.CreatedAt), ts(it.UpdatedAt), optTS(it.DeletedAt), it.RemoteID)
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// GetItem fetches an item by name, including soft-deleted ones.
func (q *Queries) GetItem(ctx context.Context, name string) (*Item, error) {
	return scanItem(q.db.QueryRowContext(ctx, `SELECT `+itemCols+` FROM items WHERE name = ?`, name))
}

// GetItemByID fetches an item by id.
func (q *Queries) GetItemByID(ctx context.Context, id string) (*Item, error) {
	return scanItem(q.db.QueryRowContext(ctx, `SELECT `+itemCols+` FROM items WHERE id = ?`, id))
}

// ListItems returns items matching the filter ordered by name.
func (q *Queries) ListItems(ctx context.Context, f ItemFilter) ([]*Item, error) {
	where := []string{"1=1"}
	var args []any
	switch {
	case f.OnlyDeleted:
		where = append(where, "deleted_at IS NOT NULL")
	case !f.IncludeDeleted:
		where = append(where, "deleted_at IS NULL")
	}
	if f.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.NamePrefix != "" {
		where = append(where, "name LIKE ? ESCAPE '\\'")
		args = append(args, escapeLike(f.NamePrefix)+"%")
	}
	rows, err := q.db.QueryContext(ctx, `SELECT `+itemCols+` FROM items WHERE `+strings.Join(where, " AND ")+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Item
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		if f.Tag != "" && !matchTag(it.Tags, f.Tag) {
			continue
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func matchTag(tags map[string]string, want string) bool {
	k, v, hasV := strings.Cut(want, "=")
	got, ok := tags[k]
	if !ok {
		return false
	}
	return !hasV || got == v
}

// UpdateItem writes mutable item columns.
func (q *Queries) UpdateItem(ctx context.Context, it *Item) error {
	tags, err := json.Marshal(it.Tags)
	if err != nil {
		return err
	}
	res, err := q.db.ExecContext(ctx, `UPDATE items SET tags = ?, updated_at = ?, deleted_at = ?, remote_id = ? WHERE id = ?`,
		string(tags), ts(it.UpdatedAt), optTS(it.DeletedAt), it.RemoteID, it.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeItem permanently deletes an item and its versions.
func (q *Queries) PurgeItem(ctx context.Context, id string) error {
	res, err := q.db.ExecContext(ctx, `DELETE FROM items WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- versions ---

const versionCols = `id, item_id, seq, enabled, not_before, expires, created_at, updated_at, ciphertext, public_only, remote_version`

func scanVersion(sc interface{ Scan(...any) error }) (*Version, error) {
	var v Version
	var created, updated int64
	var nbf, exp sql.NullInt64
	if err := sc.Scan(&v.ID, &v.ItemID, &v.Seq, &v.Enabled, &nbf, &exp, &created, &updated, &v.Ciphertext, &v.PublicOnly, &v.RemoteVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.NotBefore, v.Expires = fromOptTS(nbf), fromOptTS(exp)
	v.CreatedAt, v.UpdatedAt = fromTS(created), fromTS(updated)
	return &v, nil
}

// AddVersion inserts a version. Seq must be set by the caller (see NextSeq).
func (q *Queries) AddVersion(ctx context.Context, v *Version) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO versions(`+versionCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		v.ID, v.ItemID, v.Seq, v.Enabled, optTS(v.NotBefore), optTS(v.Expires), ts(v.CreatedAt), ts(v.UpdatedAt), v.Ciphertext, v.PublicOnly, v.RemoteVersion)
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// NextSeq returns the sequence number for a new version of the item.
func (q *Queries) NextSeq(ctx context.Context, itemID string) (int, error) {
	var n sql.NullInt64
	if err := q.db.QueryRowContext(ctx, `SELECT MAX(seq) FROM versions WHERE item_id = ?`, itemID).Scan(&n); err != nil {
		return 0, err
	}
	return int(n.Int64) + 1, nil
}

// ListVersions returns an item's versions, newest first.
func (q *Queries) ListVersions(ctx context.Context, itemID string) ([]*Version, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT `+versionCols+` FROM versions WHERE item_id = ? ORDER BY seq DESC`, itemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVersion returns one version by sequence number.
func (q *Queries) GetVersion(ctx context.Context, itemID string, seq int) (*Version, error) {
	return scanVersion(q.db.QueryRowContext(ctx, `SELECT `+versionCols+` FROM versions WHERE item_id = ? AND seq = ?`, itemID, seq))
}

// GetVersionByID returns one version by its id.
func (q *Queries) GetVersionByID(ctx context.Context, id string) (*Version, error) {
	return scanVersion(q.db.QueryRowContext(ctx, `SELECT `+versionCols+` FROM versions WHERE id = ?`, id))
}

// LatestVersion returns the newest enabled version, or the newest version at
// all when none is enabled (the caller decides whether that is usable).
func (q *Queries) LatestVersion(ctx context.Context, itemID string) (*Version, error) {
	v, err := scanVersion(q.db.QueryRowContext(ctx, `SELECT `+versionCols+` FROM versions WHERE item_id = ? AND enabled = 1 ORDER BY seq DESC LIMIT 1`, itemID))
	if errors.Is(err, ErrNotFound) {
		return scanVersion(q.db.QueryRowContext(ctx, `SELECT `+versionCols+` FROM versions WHERE item_id = ? ORDER BY seq DESC LIMIT 1`, itemID))
	}
	return v, err
}

// UpdateVersion writes mutable version columns.
func (q *Queries) UpdateVersion(ctx context.Context, v *Version) error {
	res, err := q.db.ExecContext(ctx, `UPDATE versions SET enabled = ?, not_before = ?, expires = ?, updated_at = ?, ciphertext = ?, public_only = ?, remote_version = ? WHERE id = ?`,
		v.Enabled, optTS(v.NotBefore), optTS(v.Expires), ts(v.UpdatedAt), v.Ciphertext, v.PublicOnly, v.RemoteVersion, v.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- audit ---

// AuditEntry records one operation.
type AuditEntry struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Details string    `json:"details,omitempty"`
}

// AppendAudit adds an entry.
func (q *Queries) AppendAudit(ctx context.Context, e AuditEntry) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO audit(at, actor, action, target, details) VALUES(?,?,?,?,?)`, ts(e.At), e.Actor, e.Action, e.Target, e.Details)
	return err
}

// ListAudit returns the newest entries first.
func (q *Queries) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.db.QueryContext(ctx, `SELECT id, at, actor, action, target, details FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, err
		}
		e.At = fromTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- remotes ---

// Remote is a configured Azure Key Vault.
type Remote struct {
	Name         string     `json:"name"`
	VaultURL     string     `json:"vault_url"`
	InsecureHTTP bool       `json:"insecure_http,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastSyncAt   *time.Time `json:"last_sync_at,omitempty"`
}

// AddRemote inserts a remote.
func (q *Queries) AddRemote(ctx context.Context, r Remote) error {
	_, err := q.db.ExecContext(ctx, `INSERT INTO remotes(name, vault_url, insecure_http, created_at, last_sync_at) VALUES(?,?,?,?,?)`,
		r.Name, r.VaultURL, r.InsecureHTTP, ts(r.CreatedAt), optTS(r.LastSyncAt))
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// GetRemote fetches a remote by name.
func (q *Queries) GetRemote(ctx context.Context, name string) (*Remote, error) {
	var r Remote
	var created int64
	var last sql.NullInt64
	err := q.db.QueryRowContext(ctx, `SELECT name, vault_url, insecure_http, created_at, last_sync_at FROM remotes WHERE name = ?`, name).
		Scan(&r.Name, &r.VaultURL, &r.InsecureHTTP, &created, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt, r.LastSyncAt = fromTS(created), fromOptTS(last)
	return &r, nil
}

// ListRemotes returns all remotes by name.
func (q *Queries) ListRemotes(ctx context.Context) ([]Remote, error) {
	rows, err := q.db.QueryContext(ctx, `SELECT name, vault_url, insecure_http, created_at, last_sync_at FROM remotes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Remote
	for rows.Next() {
		var r Remote
		var created int64
		var last sql.NullInt64
		if err := rows.Scan(&r.Name, &r.VaultURL, &r.InsecureHTTP, &created, &last); err != nil {
			return nil, err
		}
		r.CreatedAt, r.LastSyncAt = fromTS(created), fromOptTS(last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRemote removes a remote.
func (q *Queries) DeleteRemote(ctx context.Context, name string) error {
	res, err := q.db.ExecContext(ctx, `DELETE FROM remotes WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchRemote records a sync time.
func (q *Queries) TouchRemote(ctx context.Context, name string, at time.Time) error {
	_, err := q.db.ExecContext(ctx, `UPDATE remotes SET last_sync_at = ? WHERE name = ?`, ts(at), name)
	return err
}
