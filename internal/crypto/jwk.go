// Package crypto implements the primitives azk relies on: key generation and
// JWK/PEM conversion, the vault KDF and AEAD, and the JOSE-style key
// operations (sign, verify, encrypt, decrypt, wrap, unwrap) that mirror the
// Azure Key Vault surface so that material round-trips between both.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Kind is the item type azk stores. It maps to a JWK key type where one
// exists; KindSecret holds opaque bytes without a JWK.
type Kind string

const (
	KindOct     Kind = "oct"
	KindRSA     Kind = "rsa"
	KindEC      Kind = "ec"
	KindEd25519 Kind = "ed25519"
	KindSecret  Kind = "secret"
)

// ParseKind validates a user supplied kind string.
func ParseKind(s string) (Kind, error) {
	switch Kind(s) {
	case KindOct, KindRSA, KindEC, KindEd25519, KindSecret:
		return Kind(s), nil
	}
	return "", fmt.Errorf("unknown kind %q (want oct, rsa, ec, ed25519 or secret)", s)
}

// IsKey reports whether the kind carries cryptographic key material rather
// than an opaque secret.
func (k Kind) IsKey() bool { return k != KindSecret }

// Bytes is a byte slice encoded as base64url without padding in JSON, as
// RFC 7517 requires.
type Bytes []byte

// MarshalJSON implements json.Marshaler.
func (b Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Be lenient with padded input from other tools.
		out, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("invalid base64url: %w", err)
		}
	}
	*b = out
	return nil
}

// JWK is a JSON Web Key (RFC 7517/7518). It is the canonical in-memory and
// export representation of key material in azk; the same document shape is
// what Azure Key Vault accepts on import and returns on read.
type JWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`

	// RSA
	N  Bytes `json:"n,omitempty"`
	E  Bytes `json:"e,omitempty"`
	D  Bytes `json:"d,omitempty"`
	P  Bytes `json:"p,omitempty"`
	Q  Bytes `json:"q,omitempty"`
	DP Bytes `json:"dp,omitempty"`
	DQ Bytes `json:"dq,omitempty"`
	QI Bytes `json:"qi,omitempty"`

	// EC / OKP
	X Bytes `json:"x,omitempty"`
	Y Bytes `json:"y,omitempty"`

	// oct
	K Bytes `json:"k,omitempty"`
}

// Kind returns the azk kind for this JWK.
func (j *JWK) Kind() Kind {
	switch j.Kty {
	case "RSA":
		return KindRSA
	case "EC":
		return KindEC
	case "OKP":
		return KindEd25519
	case "oct":
		return KindOct
	}
	return ""
}

// IsPrivate reports whether the JWK carries private material.
func (j *JWK) IsPrivate() bool {
	switch j.Kty {
	case "RSA", "EC", "OKP":
		return len(j.D) > 0
	case "oct":
		return len(j.K) > 0
	}
	return false
}

// Public returns a copy with only the public parameters. For symmetric keys
// there is no public part and nil is returned.
func (j *JWK) Public() *JWK {
	switch j.Kty {
	case "RSA":
		return &JWK{Kty: j.Kty, Kid: j.Kid, N: clone(j.N), E: clone(j.E)}
	case "EC":
		return &JWK{Kty: j.Kty, Kid: j.Kid, Crv: j.Crv, X: clone(j.X), Y: clone(j.Y)}
	case "OKP":
		return &JWK{Kty: j.Kty, Kid: j.Kid, Crv: j.Crv, X: clone(j.X)}
	}
	return nil
}

// Size describes the key: bit length for RSA and oct, curve name for EC/OKP.
func (j *JWK) Size() string {
	switch j.Kty {
	case "RSA":
		return fmt.Sprintf("%d", len(j.N)*8)
	case "oct":
		return fmt.Sprintf("%d", len(j.K)*8)
	case "EC", "OKP":
		return j.Crv
	}
	return ""
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of the public key (or of the
// raw key for oct), base64url encoded.
func (j *JWK) Thumbprint() (string, error) {
	var canon any
	switch j.Kty {
	case "RSA":
		canon = struct {
			E   Bytes  `json:"e"`
			Kty string `json:"kty"`
			N   Bytes  `json:"n"`
		}{j.E, j.Kty, j.N}
	case "EC":
		canon = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   Bytes  `json:"x"`
			Y   Bytes  `json:"y"`
		}{j.Crv, j.Kty, j.X, j.Y}
	case "OKP":
		canon = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   Bytes  `json:"x"`
		}{j.Crv, j.Kty, j.X}
	case "oct":
		canon = struct {
			K   Bytes  `json:"k"`
			Kty string `json:"kty"`
		}{j.K, j.Kty}
	default:
		return "", fmt.Errorf("unsupported kty %q", j.Kty)
	}
	b, err := json.Marshal(canon)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Zero overwrites private material in place. Go cannot guarantee no copies
// remain, so this is best effort.
func (j *JWK) Zero() {
	for _, b := range []Bytes{j.D, j.P, j.Q, j.DP, j.DQ, j.QI, j.K} {
		for i := range b {
			b[i] = 0
		}
	}
}

func clone(b []byte) Bytes {
	if b == nil {
		return nil
	}
	return append(Bytes(nil), b...)
}

// GenerateOptions tunes key generation. Bits applies to RSA and oct, Curve to
// EC. Zero values pick sensible defaults (RSA 3072, oct 256, EC P-256).
type GenerateOptions struct {
	Bits  int
	Curve string
}

// Generate creates fresh key material of the given kind.
func Generate(kind Kind, opts GenerateOptions) (*JWK, error) {
	switch kind {
	case KindRSA:
		bits := opts.Bits
		if bits == 0 {
			bits = 3072
		}
		if bits != 2048 && bits != 3072 && bits != 4096 {
			return nil, fmt.Errorf("unsupported RSA size %d (want 2048, 3072 or 4096)", bits)
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case KindEC:
		curve, err := curveByName(opts.Curve)
		if err != nil {
			return nil, err
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case KindEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case KindOct:
		bits := opts.Bits
		if bits == 0 {
			bits = 256
		}
		if bits != 128 && bits != 192 && bits != 256 {
			return nil, fmt.Errorf("unsupported oct size %d (want 128, 192 or 256)", bits)
		}
		k := make([]byte, bits/8)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		return &JWK{Kty: "oct", K: k}, nil
	}
	return nil, fmt.Errorf("cannot generate kind %q", kind)
}

func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "", "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("unsupported curve %q (want P-256, P-384 or P-521)", name)
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	return ""
}

// FromPrivateKey converts a Go private key into a JWK.
func FromPrivateKey(k crypto.PrivateKey) (*JWK, error) {
	switch k := k.(type) {
	case *rsa.PrivateKey:
		k.Precompute()
		return &JWK{
			Kty: "RSA",
			N:   k.N.Bytes(),
			E:   big.NewInt(int64(k.E)).Bytes(),
			D:   k.D.Bytes(),
			P:   k.Primes[0].Bytes(),
			Q:   k.Primes[1].Bytes(),
			DP:  k.Precomputed.Dp.Bytes(),
			DQ:  k.Precomputed.Dq.Bytes(),
			QI:  k.Precomputed.Qinv.Bytes(),
		}, nil
	case *ecdsa.PrivateKey:
		pub, err := FromPublicKey(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		d, err := k.Bytes()
		if err != nil {
			return nil, err
		}
		pub.D = d
		return pub, nil
	case ed25519.PrivateKey:
		return &JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   clone(k.Public().(ed25519.PublicKey)),
			D:   clone(k.Seed()),
		}, nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", k)
}

// FromPublicKey converts a Go public key into a JWK.
func FromPublicKey(k crypto.PublicKey) (*JWK, error) {
	switch k := k.(type) {
	case *rsa.PublicKey:
		return &JWK{Kty: "RSA", N: k.N.Bytes(), E: big.NewInt(int64(k.E)).Bytes()}, nil
	case *ecdsa.PublicKey:
		name := curveName(k.Curve)
		if name == "" {
			return nil, errors.New("unsupported EC curve")
		}
		raw, err := k.Bytes() // 0x04 || X || Y
		if err != nil {
			return nil, err
		}
		size := (len(raw) - 1) / 2
		return &JWK{Kty: "EC", Crv: name, X: clone(raw[1 : 1+size]), Y: clone(raw[1+size:])}, nil
	case ed25519.PublicKey:
		return &JWK{Kty: "OKP", Crv: "Ed25519", X: clone(k)}, nil
	}
	return nil, fmt.Errorf("unsupported public key type %T", k)
}

// PrivateKey converts the JWK into a Go private key.
func (j *JWK) PrivateKey() (crypto.PrivateKey, error) {
	if !j.IsPrivate() {
		return nil, errors.New("jwk has no private material")
	}
	switch j.Kty {
	case "RSA":
		e := new(big.Int).SetBytes(j.E)
		if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
			return nil, errors.New("rsa exponent too large")
		}
		k := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: new(big.Int).SetBytes(j.N), E: int(e.Int64())},
			D:         new(big.Int).SetBytes(j.D),
		}
		if len(j.P) > 0 && len(j.Q) > 0 {
			k.Primes = []*big.Int{new(big.Int).SetBytes(j.P), new(big.Int).SetBytes(j.Q)}
		} else {
			return nil, errors.New("rsa jwk is missing primes p and q")
		}
		k.Precompute()
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("invalid rsa key: %w", err)
		}
		return k, nil
	case "EC":
		curve, err := curveByName(j.Crv)
		if err != nil {
			return nil, err
		}
		k, err := ecdsa.ParseRawPrivateKey(curve, j.D)
		if err != nil {
			return nil, fmt.Errorf("invalid ec private key: %w", err)
		}
		pub, err := j.PublicKey()
		if err != nil {
			return nil, err
		}
		if !k.PublicKey.Equal(pub) {
			return nil, errors.New("ec public point does not match the private key")
		}
		return k, nil
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", j.Crv)
		}
		if len(j.D) != ed25519.SeedSize {
			return nil, errors.New("invalid ed25519 seed length")
		}
		return ed25519.NewKeyFromSeed(j.D), nil
	}
	return nil, fmt.Errorf("kty %q has no private key form", j.Kty)
}

// PublicKey converts the JWK into a Go public key.
func (j *JWK) PublicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		e := new(big.Int).SetBytes(j.E)
		if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
			return nil, errors.New("rsa exponent too large")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(j.N), E: int(e.Int64())}, nil
	case "EC":
		curve, err := curveByName(j.Crv)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(j.X) != size || len(j.Y) != size {
			return nil, errors.New("ec coordinate length does not match the curve")
		}
		raw := append(append([]byte{4}, j.X...), j.Y...)
		k, err := ecdsa.ParseUncompressedPublicKey(curve, raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ec public key: %w", err)
		}
		return k, nil
	case "OKP":
		if j.Crv != "Ed25519" || len(j.X) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key")
		}
		return ed25519.PublicKey(j.X), nil
	}
	return nil, fmt.Errorf("kty %q has no public key form", j.Kty)
}

// ParsePEM reads a private or public key from PEM. PKCS#8, PKCS#1, SEC 1 and
// SubjectPublicKeyInfo blocks are accepted.
func ParsePEM(data []byte) (*JWK, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return FromPrivateKey(k)
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return FromPublicKey(k)
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return FromPublicKey(k)
	}
	return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
}

// ParseJWK reads a JWK JSON document.
func ParseJWK(data []byte) (*JWK, error) {
	var j JWK
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("invalid jwk: %w", err)
	}
	if j.Kind() == "" {
		return nil, fmt.Errorf("unsupported kty %q", j.Kty)
	}
	// Round-trip through Go types to validate the parameters.
	if j.IsPrivate() {
		if j.Kty != "oct" {
			if _, err := j.PrivateKey(); err != nil {
				return nil, err
			}
		}
	} else if j.Kty != "oct" {
		if _, err := j.PublicKey(); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("oct jwk has no k parameter")
	}
	return &j, nil
}

// ToPEM encodes the key as PEM. Private keys use PKCS#8, public keys use
// SubjectPublicKeyInfo. Symmetric keys have no PEM form.
func (j *JWK) ToPEM(public bool) ([]byte, error) {
	if j.Kty == "oct" {
		return nil, errors.New("symmetric keys have no PEM representation")
	}
	if public || !j.IsPrivate() {
		pk, err := j.PublicKey()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
	}
	sk, err := j.PrivateKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
