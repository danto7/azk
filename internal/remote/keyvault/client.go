// Package keyvault talks to Azure Key Vault (or the floci-az emulator): it
// pushes and pulls keys and secrets, and implements the vault unlock slot
// that wraps the local data encryption key with a Key Vault RSA key.
package keyvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/danto7/azk/internal/crypto"
)

// Config identifies a Key Vault.
type Config struct {
	// VaultURL is https://<name>.vault.azure.net or the emulator's
	// http://host:4577/<account>-keyvault.
	VaultURL string
	// InsecureHTTP allows bearer tokens over plain HTTP and disables the
	// challenge resource check; only for emulators.
	InsecureHTTP bool
}

// Validate checks the URL and the HTTP/insecure combination.
func (c Config) Validate() error {
	u, err := url.Parse(c.VaultURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid vault url %q", c.VaultURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !c.InsecureHTTP {
			return errors.New("plain http vault url requires --insecure-http (emulators only)")
		}
	default:
		return fmt.Errorf("vault url must use https (or http with --insecure-http), got %q", u.Scheme)
	}
	return nil
}

// TokenEnv names the environment variable that overrides Azure credentials
// with a static bearer token. Emulators accept any token.
const TokenEnv = "AZK_AZURE_TOKEN" //nolint:gosec // an environment variable name, not a credential

// Credential returns the credential azk uses for Azure: a static token from
// AZK_AZURE_TOKEN when set, otherwise DefaultAzureCredential (environment,
// workload identity, managed identity, Azure CLI, ...).
func Credential() (azcore.TokenCredential, error) {
	if tok := os.Getenv(TokenEnv); tok != "" {
		return StaticCredential(tok), nil
	}
	return azidentity.NewDefaultAzureCredential(nil)
}

// StaticCredential presents a fixed bearer token.
type StaticCredential string

// GetToken implements azcore.TokenCredential.
func (s StaticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(s), ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// Client wraps the keys and secrets clients for one vault.
type Client struct {
	cfg     Config
	keys    *azkeys.Client
	secrets *azsecrets.Client
}

// New builds a client.
//
// The SDK refuses to send bearer tokens over plain HTTP, and the Key Vault
// challenge policy ignores azcore's InsecureAllowCredentialWithHTTP. For an
// emulator the client is therefore configured with an https URL and a
// transport that downgrades the scheme to http on the wire.
func New(cfg Config, cred azcore.TokenCredential) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clientURL := cfg.VaultURL
	core := azcore.ClientOptions{}
	if strings.HasPrefix(clientURL, "http://") {
		clientURL = "https://" + strings.TrimPrefix(clientURL, "http://")
		core.InsecureAllowCredentialWithHTTP = true
		core.Transport = downgradeTransport{}
	}
	keys, err := azkeys.NewClient(clientURL, cred, &azkeys.ClientOptions{ClientOptions: core, DisableChallengeResourceVerification: cfg.InsecureHTTP})
	if err != nil {
		return nil, err
	}
	secrets, err := azsecrets.NewClient(clientURL, cred, &azsecrets.ClientOptions{ClientOptions: core, DisableChallengeResourceVerification: cfg.InsecureHTTP})
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, keys: keys, secrets: secrets}, nil
}

// downgradeTransport sends https requests as http. Only used for emulators.
type downgradeTransport struct{}

func (downgradeTransport) Do(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if r.URL.Scheme == "https" {
		r.URL.Scheme = "http"
	}
	return http.DefaultClient.Do(r) //nolint:gosec // the emulator URL is user configuration by design
}

// Open builds a client with the default credential.
func Open(cfg Config) (*Client, error) {
	cred, err := Credential()
	if err != nil {
		return nil, err
	}
	return New(cfg, cred)
}

// VaultURL returns the configured vault URL.
func (c *Client) VaultURL() string { return c.cfg.VaultURL }

// Keys exposes the raw keys client.
func (c *Client) Keys() *azkeys.Client { return c.keys }

// Secrets exposes the raw secrets client.
func (c *Client) Secrets() *azsecrets.Client { return c.secrets }

// IsNotFound reports whether err is a Key Vault 404.
func IsNotFound(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == 404
}

// Ping lists one page of keys to prove connectivity and credentials.
func (c *Client) Ping(ctx context.Context) error {
	pager := c.keys.NewListKeyPropertiesPager(nil)
	if pager.More() {
		if _, err := pager.NextPage(ctx); err != nil {
			return fmt.Errorf("key vault %s: %w", c.cfg.VaultURL, err)
		}
	}
	return nil
}

// --- JWK conversion ---

func toKV(j *crypto.JWK) *azkeys.JSONWebKey {
	k := &azkeys.JSONWebKey{
		Kty: ptr(azkeys.KeyType(j.Kty)),
		N:   j.N, E: j.E, D: j.D, P: j.P, Q: j.Q, DP: j.DP, DQ: j.DQ, QI: j.QI,
		X: j.X, Y: j.Y, K: j.K,
	}
	if j.Crv != "" {
		k.Crv = ptr(azkeys.CurveName(j.Crv))
	}
	return k
}

func fromKV(k *azkeys.JSONWebKey) (*crypto.JWK, error) {
	if k == nil || k.Kty == nil {
		return nil, errors.New("key vault returned no key material")
	}
	j := &crypto.JWK{
		Kty: strings.TrimSuffix(string(*k.Kty), "-HSM"),
		N:   k.N, E: k.E, D: k.D, P: k.P, Q: k.Q, DP: k.DP, DQ: k.DQ, QI: k.QI,
		X: k.X, Y: k.Y, K: k.K,
	}
	if k.Crv != nil {
		j.Crv = string(*k.Crv)
	}
	if k.KID != nil {
		j.Kid = string(*k.KID)
	}
	if j.Kind() == "" {
		return nil, fmt.Errorf("unsupported key vault key type %q", j.Kty)
	}
	return j, nil
}

// WrapDEK wraps key material with an RSA key in the vault. version may be
// empty for the latest.
func (c *Client) WrapDEK(ctx context.Context, name, version string, dek []byte) ([]byte, string, error) {
	res, err := c.keys.WrapKey(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: ptr(azkeys.EncryptionAlgorithmRSAOAEP256), Value: dek,
	}, nil)
	if err != nil {
		return nil, "", err
	}
	ver := ""
	if res.KID != nil {
		ver = res.KID.Version()
	}
	return res.Result, ver, nil
}

// UnwrapDEK reverses WrapDEK.
func (c *Client) UnwrapDEK(ctx context.Context, name, version string, wrapped []byte) ([]byte, error) {
	res, err := c.keys.UnwrapKey(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: ptr(azkeys.EncryptionAlgorithmRSAOAEP256), Value: wrapped,
	}, nil)
	if err != nil {
		return nil, err
	}
	return res.Result, nil
}

// EnsureRSAKey returns the version of an existing RSA key, creating a 3072
// bit one when create is set and the key is missing.
func (c *Client) EnsureRSAKey(ctx context.Context, name string, create bool) (string, error) {
	res, err := c.keys.GetKey(ctx, name, "", nil)
	if err == nil {
		if res.Key == nil || res.Key.Kty == nil || !strings.HasPrefix(string(*res.Key.Kty), "RSA") {
			return "", fmt.Errorf("key %s is not an RSA key", name)
		}
		return res.Key.KID.Version(), nil
	}
	if !IsNotFound(err) {
		return "", err
	}
	if !create {
		return "", fmt.Errorf("key %s does not exist in %s (use --create)", name, c.cfg.VaultURL)
	}
	cr, err := c.keys.CreateKey(ctx, name, azkeys.CreateKeyParameters{
		Kty: ptr(azkeys.KeyTypeRSA), KeySize: ptr(int32(3072)),
		KeyOps: []*azkeys.KeyOperation{ptr(azkeys.KeyOperationWrapKey), ptr(azkeys.KeyOperationUnwrapKey)},
	}, nil)
	if err != nil {
		return "", err
	}
	return cr.Key.KID.Version(), nil
}

func ptr[T any](v T) *T { return &v }

func strTags(tags map[string]string) map[string]*string {
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string]*string, len(tags))
	for k, v := range tags {
		out[k] = ptr(v)
	}
	return out
}

func fromStrTags(tags map[string]*string) map[string]string {
	out := map[string]string{}
	for k, v := range tags {
		if v != nil {
			out[k] = *v
		}
	}
	return out
}

// SameObject reports whether two object ids name the same vault object,
// ignoring version and scheme (emulators report http while the client is
// configured with https).
func SameObject(a, b string) bool {
	ua, err1 := url.Parse(baseID(a))
	ub, err2 := url.Parse(baseID(b))
	if err1 != nil || err2 != nil {
		return a == b
	}
	return strings.EqualFold(ua.Host, ub.Host) && strings.EqualFold(strings.Trim(ua.Path, "/"), strings.Trim(ub.Path, "/"))
}

// baseID strips the version from a Key Vault object id.
func baseID(id string) string {
	u, err := url.Parse(id)
	if err != nil {
		return id
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	// .../keys/<name>/<version> or .../<account>-keyvault/keys/<name>/<version>
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "keys" || parts[i] == "secrets" {
			u.Path = "/" + strings.Join(parts[:i+2], "/")
			return u.String()
		}
	}
	return id
}
