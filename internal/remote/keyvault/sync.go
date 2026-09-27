package keyvault

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
)

// Op is the kind of a planned action.
type Op string

const (
	OpPush     Op = "push"
	OpPull     Op = "pull"
	OpSkip     Op = "skip"
	OpConflict Op = "conflict"
)

// Action is one step of a sync plan.
type Action struct {
	Op            Op     `json:"op"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Seq           int    `json:"seq,omitempty"`
	RemoteVersion string `json:"remote_version,omitempty"`
	Reason        string `json:"reason,omitempty"`

	created time.Time
}

// Plan is an ordered list of actions.
type Plan struct {
	Remote  string   `json:"remote"`
	Actions []Action `json:"actions"`
}

// Counts summarises the plan by op.
func (p *Plan) Counts() map[Op]int {
	m := map[Op]int{}
	for _, a := range p.Actions {
		m[a.Op]++
	}
	return m
}

// Result reports what Apply did.
type Result struct {
	Pushed int      `json:"pushed"`
	Pulled int      `json:"pulled"`
	Done   []Action `json:"done"`
}

// Syncer reconciles the local vault with one remote.
type Syncer struct {
	svc    *service.Service
	client *Client
	remote store.Remote
}

// NewSyncer builds a syncer.
func NewSyncer(svc *service.Service, client *Client, remote store.Remote) *Syncer {
	return &Syncer{svc: svc, client: client, remote: remote}
}

type remoteObject struct {
	kind     string // "key" or "secret"
	versions []remoteVersion
}

type remoteVersion struct {
	id      string
	created time.Time
}

// inventory lists remote keys and secrets with their versions.
func (s *Syncer) inventory(ctx context.Context) (map[string]*remoteObject, error) {
	inv := map[string]*remoteObject{}
	kp := s.client.keys.NewListKeyPropertiesPager(nil)
	for kp.More() {
		page, err := kp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		for _, k := range page.Value {
			name := k.KID.Name()
			obj := &remoteObject{kind: "key"}
			vp := s.client.keys.NewListKeyPropertiesVersionsPager(name, nil)
			for vp.More() {
				vpage, err := vp.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list versions of key %s: %w", name, err)
				}
				for _, v := range vpage.Value {
					rv := remoteVersion{id: v.KID.Version()}
					if v.Attributes != nil && v.Attributes.Created != nil {
						rv.created = *v.Attributes.Created
					}
					obj.versions = append(obj.versions, rv)
				}
			}
			inv[name] = obj
		}
	}
	sp := s.client.secrets.NewListSecretPropertiesPager(nil)
	for sp.More() {
		page, err := sp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		for _, sec := range page.Value {
			name := sec.ID.Name()
			if _, dup := inv[name]; dup {
				return nil, fmt.Errorf("remote has both a key and a secret named %s", name)
			}
			obj := &remoteObject{kind: "secret"}
			vp := s.client.secrets.NewListSecretPropertiesVersionsPager(name, nil)
			for vp.More() {
				vpage, err := vp.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("list versions of secret %s: %w", name, err)
				}
				for _, v := range vpage.Value {
					rv := remoteVersion{id: v.ID.Version()}
					if v.Attributes != nil && v.Attributes.Created != nil {
						rv.created = *v.Attributes.Created
					}
					obj.versions = append(obj.versions, rv)
				}
			}
			inv[name] = obj
		}
	}
	for _, obj := range inv {
		sort.SliceStable(obj.versions, func(i, j int) bool { return obj.versions[i].created.Before(obj.versions[j].created) })
	}
	return inv, nil
}

func localKind(it *store.Item) string {
	if it.Kind == string(crypto.KindSecret) {
		return "secret"
	}
	return "key"
}

// Plan computes push and/or pull actions. names limits the plan to those
// items; empty means everything.
func (s *Syncer) Plan(ctx context.Context, push, pull bool, names []string) (*Plan, error) {
	inv, err := s.inventory(ctx)
	if err != nil {
		return nil, err
	}
	locals, err := s.svc.ListItems(ctx, store.ItemFilter{})
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	selected := func(n string) bool { return len(want) == 0 || want[n] }
	plan := &Plan{Remote: s.remote.Name}
	localByName := map[string]*store.Item{}

	for _, it := range locals {
		localByName[it.Name] = it
		if !selected(it.Name) {
			continue
		}
		if it.RemoteID != "" && !SameObject(it.RemoteID, s.objectID(localKind(it), it.Name)) {
			plan.Actions = append(plan.Actions, Action{Op: OpSkip, Kind: it.Kind, Name: it.Name, Reason: "linked to a different remote"})
			continue
		}
		robj := inv[it.Name]
		if robj != nil && robj.kind != localKind(it) {
			plan.Actions = append(plan.Actions, Action{Op: OpConflict, Kind: it.Kind, Name: it.Name, Reason: fmt.Sprintf("local %s but remote %s", localKind(it), robj.kind)})
			continue
		}
		if push {
			acts, err := s.planPush(ctx, it)
			if err != nil {
				return nil, err
			}
			plan.Actions = append(plan.Actions, acts...)
		}
	}
	if pull {
		for name, robj := range inv {
			if !selected(name) {
				continue
			}
			it := localByName[name]
			if it != nil && robj.kind != localKind(it) {
				continue // conflict already recorded
			}
			if it != nil && it.RemoteID != "" && !SameObject(it.RemoteID, s.objectID(robj.kind, name)) {
				continue // linked elsewhere, already recorded
			}
			known := map[string]bool{}
			if it != nil {
				vs, err := s.svc.Vault().Store().ListVersions(ctx, it.ID)
				if err != nil {
					return nil, err
				}
				for _, v := range vs {
					if v.RemoteVersion != "" {
						known[v.RemoteVersion] = true
					}
				}
			}
			kind, err := s.remoteKind(ctx, name, robj, it)
			if err != nil {
				return nil, err
			}
			if kind == string(crypto.KindOct) {
				if len(known) < len(robj.versions) {
					plan.Actions = append(plan.Actions, Action{Op: OpSkip, Kind: kind, Name: name, Reason: "Key Vault does not export symmetric keys"})
				}
				continue
			}
			for _, rv := range robj.versions {
				if !known[rv.id] {
					plan.Actions = append(plan.Actions, Action{Op: OpPull, Kind: kind, Name: name, RemoteVersion: rv.id, created: rv.created})
				}
			}
		}
	}
	// Deleted local items are neither pushed nor pulled; they are simply absent above.
	sort.SliceStable(plan.Actions, func(i, j int) bool {
		a, b := plan.Actions[i], plan.Actions[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		if a.Seq != b.Seq {
			return a.Seq < b.Seq
		}
		return a.created.Before(b.created)
	})
	return plan, nil
}

// remoteKind determines the azk kind of a remote object, fetching the key
// once when it is not known locally.
func (s *Syncer) remoteKind(ctx context.Context, name string, robj *remoteObject, it *store.Item) (string, error) {
	if it != nil {
		return it.Kind, nil
	}
	if robj.kind == "secret" {
		return string(crypto.KindSecret), nil
	}
	r, err := s.client.keys.GetKey(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("get key %s: %w", name, err)
	}
	jwk, err := fromKV(r.Key)
	if err != nil {
		return "", err
	}
	return string(jwk.Kind()), nil
}

func (s *Syncer) objectID(kind, name string) string {
	if kind == "secret" {
		return s.client.VaultURL() + "/secrets/" + name
	}
	return s.client.VaultURL() + "/keys/" + name
}

func (s *Syncer) planPush(ctx context.Context, it *store.Item) ([]Action, error) {
	if it.Kind == string(crypto.KindEd25519) {
		return []Action{{Op: OpSkip, Kind: it.Kind, Name: it.Name, Reason: "Key Vault does not support Ed25519"}}, nil
	}
	vs, err := s.svc.Vault().Store().ListVersions(ctx, it.ID)
	if err != nil {
		return nil, err
	}
	var acts []Action
	for i := len(vs) - 1; i >= 0; i-- { // ascending seq
		v := vs[i]
		if v.RemoteVersion != "" {
			continue
		}
		if v.PublicOnly {
			acts = append(acts, Action{Op: OpSkip, Kind: it.Kind, Name: it.Name, Seq: v.Seq, Reason: "public-only material cannot be imported"})
			continue
		}
		acts = append(acts, Action{Op: OpPush, Kind: it.Kind, Name: it.Name, Seq: v.Seq})
	}
	return acts, nil
}

// Apply executes a plan, stopping at the first error. Local rows are only
// updated after the remote call succeeded, so a re-run resumes cleanly.
func (s *Syncer) Apply(ctx context.Context, plan *Plan) (*Result, error) {
	res := &Result{}
	for _, a := range plan.Actions {
		var err error
		switch a.Op {
		case OpPush:
			err = s.push(ctx, a)
			if err == nil {
				res.Pushed++
			}
		case OpPull:
			err = s.pull(ctx, a)
			if err == nil {
				res.Pulled++
			}
		default:
			continue
		}
		if err != nil {
			return res, fmt.Errorf("%s %s (%s): %w", a.Op, a.Name, versionLabel(a), err)
		}
		res.Done = append(res.Done, a)
	}
	if res.Pushed+res.Pulled > 0 {
		_ = s.svc.Vault().Store().TouchRemote(ctx, s.remote.Name, time.Now())
	}
	return res, nil
}

func versionLabel(a Action) string {
	if a.Seq > 0 {
		return fmt.Sprintf("v%d", a.Seq)
	}
	return a.RemoteVersion
}

func (s *Syncer) push(ctx context.Context, a Action) error {
	st := s.svc.Vault().Store()
	it, err := st.GetItem(ctx, a.Name)
	if err != nil {
		return err
	}
	v, err := st.GetVersion(ctx, it.ID, a.Seq)
	if err != nil {
		return err
	}
	m, err := s.svc.Material(ctx, v)
	if err != nil {
		return err
	}
	defer m.Zero()
	var remoteVersion, remoteID string
	if it.Kind == string(crypto.KindSecret) {
		if !utf8.Valid(m.Value) {
			return errors.New("secret is not valid UTF-8; Key Vault secrets are strings")
		}
		params := azsecrets.SetSecretParameters{
			Value:            ptr(string(m.Value)),
			SecretAttributes: &azsecrets.SecretAttributes{Enabled: ptr(v.Enabled), NotBefore: v.NotBefore, Expires: v.Expires},
			Tags:             strTags(it.Tags),
		}
		if m.ContentType != "" {
			params.ContentType = ptr(m.ContentType)
		}
		r, err := s.client.secrets.SetSecret(ctx, a.Name, params, nil)
		if err != nil {
			return err
		}
		remoteVersion, remoteID = r.ID.Version(), baseID(string(*r.ID))
	} else {
		if m.JWK == nil {
			return service.ErrNotKey
		}
		r, err := s.client.keys.ImportKey(ctx, a.Name, azkeys.ImportKeyParameters{
			Key:           toKV(m.JWK),
			KeyAttributes: &azkeys.KeyAttributes{Enabled: ptr(v.Enabled), NotBefore: v.NotBefore, Expires: v.Expires},
			Tags:          strTags(it.Tags),
		}, nil)
		if err != nil {
			return err
		}
		remoteVersion, remoteID = r.Key.KID.Version(), baseID(string(*r.Key.KID))
	}
	err = st.Tx(ctx, func(q *store.Queries) error {
		v.RemoteVersion = remoteVersion
		v.UpdatedAt = time.Now()
		if err := q.UpdateVersion(ctx, v); err != nil {
			return err
		}
		it.RemoteID = remoteID
		it.UpdatedAt = time.Now()
		return q.UpdateItem(ctx, it)
	})
	if err != nil {
		return err
	}
	s.svc.Record(ctx, "remote.push", a.Name, map[string]any{"remote": s.remote.Name, "seq": a.Seq, "remote_version": remoteVersion})
	return nil
}

func (s *Syncer) pull(ctx context.Context, a Action) error {
	st := s.svc.Vault().Store()
	it, err := st.GetItem(ctx, a.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	var (
		m          service.Material
		kind       crypto.Kind
		publicOnly bool
		enabled    = true
		opts       service.CreateOptions
		remoteID   string
	)
	if a.Kind == string(crypto.KindSecret) || (it == nil && a.Kind == "secret") {
		r, err := s.client.secrets.GetSecret(ctx, a.Name, a.RemoteVersion, nil)
		if err != nil {
			return err
		}
		kind = crypto.KindSecret
		if r.Value != nil {
			m.Value = []byte(*r.Value)
		}
		if r.ContentType != nil {
			m.ContentType = *r.ContentType
		}
		if r.Attributes != nil {
			if r.Attributes.Enabled != nil {
				enabled = *r.Attributes.Enabled
			}
			opts.NotBefore, opts.Expires = r.Attributes.NotBefore, r.Attributes.Expires
		}
		opts.Tags = fromStrTags(r.Tags)
		remoteID = baseID(string(*r.ID))
	} else {
		r, err := s.client.keys.GetKey(ctx, a.Name, a.RemoteVersion, nil)
		if err != nil {
			return err
		}
		jwk, err := fromKV(r.Key)
		if err != nil {
			return err
		}
		kind = jwk.Kind()
		if kind == crypto.KindOct {
			// Key Vault never returns symmetric material; nothing usable to store.
			return errors.New("symmetric keys cannot be pulled (Key Vault does not export them)")
		}
		pub := jwk.Public()
		pub.Kid = ""
		m.JWK = pub
		publicOnly = true
		if r.Attributes != nil {
			if r.Attributes.Enabled != nil {
				enabled = *r.Attributes.Enabled
			}
			opts.NotBefore, opts.Expires = r.Attributes.NotBefore, r.Attributes.Expires
		}
		opts.Tags = fromStrTags(r.Tags)
		remoteID = baseID(string(*r.Key.KID))
	}
	defer m.Zero()
	if it != nil && it.Kind != string(kind) {
		return fmt.Errorf("local item is %s but remote is %s", it.Kind, kind)
	}
	var v *store.Version
	if it == nil {
		d, err := s.svc.CreateWithMaterial(ctx, a.Name, kind, &m, publicOnly, opts)
		if err != nil {
			return err
		}
		it = d.Item
		v, err = st.GetVersion(ctx, it.ID, 1)
		if err != nil {
			return err
		}
	} else {
		v, err = s.svc.AddVersion(ctx, it, &m, publicOnly, opts)
		if err != nil {
			return err
		}
	}
	err = st.Tx(ctx, func(q *store.Queries) error {
		v.RemoteVersion = a.RemoteVersion
		v.Enabled = enabled
		v.UpdatedAt = time.Now()
		if err := q.UpdateVersion(ctx, v); err != nil {
			return err
		}
		it.RemoteID = remoteID
		if len(opts.Tags) > 0 {
			it.Tags = opts.Tags
		}
		it.UpdatedAt = time.Now()
		return q.UpdateItem(ctx, it)
	})
	if err != nil {
		return err
	}
	s.svc.Record(ctx, "remote.pull", a.Name, map[string]any{"remote": s.remote.Name, "seq": v.Seq, "remote_version": a.RemoteVersion})
	return nil
}
