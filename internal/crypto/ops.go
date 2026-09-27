package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm names follow JOSE / Azure Key Vault so that an operation done
// locally is interchangeable with one done in Key Vault. RSA1_5 is left out
// on purpose: PKCS#1 v1.5 encryption is padding-oracle prone.
const (
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
	AlgPS256 = "PS256"
	AlgPS384 = "PS384"
	AlgPS512 = "PS512"
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
	AlgEdDSA = "EdDSA"

	AlgRSAOAEP    = "RSA-OAEP"
	AlgRSAOAEP256 = "RSA-OAEP-256"
	AlgA128GCM    = "A128GCM"
	AlgA192GCM    = "A192GCM"
	AlgA256GCM    = "A256GCM"
	AlgA128KW     = "A128KW"
	AlgA192KW     = "A192KW"
	AlgA256KW     = "A256KW"
)

// SignatureAlgorithms lists the signing algorithms supported for a key.
func SignatureAlgorithms(j *JWK) []string {
	switch j.Kty {
	case "RSA":
		return []string{AlgRS256, AlgRS384, AlgRS512, AlgPS256, AlgPS384, AlgPS512}
	case "EC":
		switch j.Crv {
		case "P-256":
			return []string{AlgES256}
		case "P-384":
			return []string{AlgES384}
		case "P-521":
			return []string{AlgES512}
		}
	case "OKP":
		return []string{AlgEdDSA}
	}
	return nil
}

// EncryptionAlgorithms lists the encryption algorithms supported for a key.
func EncryptionAlgorithms(j *JWK) []string {
	switch j.Kty {
	case "RSA":
		return []string{AlgRSAOAEP256, AlgRSAOAEP}
	case "oct":
		switch len(j.K) {
		case 16:
			return []string{AlgA128GCM}
		case 24:
			return []string{AlgA192GCM}
		case 32:
			return []string{AlgA256GCM}
		}
	}
	return nil
}

// WrapAlgorithms lists the key wrapping algorithms supported for a key.
func WrapAlgorithms(j *JWK) []string {
	switch j.Kty {
	case "RSA":
		return []string{AlgRSAOAEP256, AlgRSAOAEP}
	case "oct":
		switch len(j.K) {
		case 16:
			return []string{AlgA128KW}
		case 24:
			return []string{AlgA192KW}
		case 32:
			return []string{AlgA256KW}
		}
	}
	return nil
}

// DefaultSignatureAlgorithm picks the algorithm used when the caller does
// not name one.
func DefaultSignatureAlgorithm(j *JWK) (string, error) {
	algs := SignatureAlgorithms(j)
	if len(algs) == 0 {
		return "", fmt.Errorf("key type %s cannot sign", j.Kty)
	}
	return algs[0], nil
}

// DefaultEncryptionAlgorithm picks the algorithm used when the caller does
// not name one.
func DefaultEncryptionAlgorithm(j *JWK) (string, error) {
	algs := EncryptionAlgorithms(j)
	if len(algs) == 0 {
		return "", fmt.Errorf("key type %s cannot encrypt", j.Kty)
	}
	return algs[0], nil
}

// DefaultWrapAlgorithm picks the algorithm used when the caller does not name one.
func DefaultWrapAlgorithm(j *JWK) (string, error) {
	algs := WrapAlgorithms(j)
	if len(algs) == 0 {
		return "", fmt.Errorf("key type %s cannot wrap", j.Kty)
	}
	return algs[0], nil
}

// HashForSignature returns the digest algorithm a signing algorithm expects.
// EdDSA signs the message directly and returns crypto.Hash(0).
func HashForSignature(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRS256, AlgPS256, AlgES256:
		return crypto.SHA256, nil
	case AlgRS384, AlgPS384, AlgES384:
		return crypto.SHA384, nil
	case AlgRS512, AlgPS512, AlgES512:
		return crypto.SHA512, nil
	case AlgEdDSA:
		return crypto.Hash(0), nil
	}
	return 0, fmt.Errorf("unsupported signature algorithm %q", alg)
}

// Digest hashes a message for the given signature algorithm. For EdDSA the
// message is returned unchanged.
func Digest(alg string, message []byte) ([]byte, error) {
	h, err := HashForSignature(alg)
	if err != nil {
		return nil, err
	}
	if h == 0 {
		return message, nil
	}
	hh := h.New()
	hh.Write(message)
	return hh.Sum(nil), nil
}

func supports(list []string, alg string) bool {
	for _, a := range list {
		if a == alg {
			return true
		}
	}
	return false
}

// Sign produces a signature over a digest (or the message itself for
// EdDSA). ECDSA signatures are the raw r||s concatenation used by JWS and
// Key Vault, not ASN.1.
func Sign(j *JWK, alg string, digest []byte) ([]byte, error) {
	if !supports(SignatureAlgorithms(j), alg) {
		return nil, fmt.Errorf("algorithm %s is not supported by this %s key", alg, j.Size())
	}
	sk, err := j.PrivateKey()
	if err != nil {
		return nil, err
	}
	h, _ := HashForSignature(alg)
	switch k := sk.(type) {
	case *rsa.PrivateKey:
		if h.Size() != len(digest) {
			return nil, fmt.Errorf("digest length %d does not match %s", len(digest), alg)
		}
		if alg[0] == 'P' {
			return rsa.SignPSS(rand.Reader, k, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.SignPKCS1v15(rand.Reader, k, h, digest)
	case *ecdsa.PrivateKey:
		if h.Size() != len(digest) {
			return nil, fmt.Errorf("digest length %d does not match %s", len(digest), alg)
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	case ed25519.PrivateKey:
		return ed25519.Sign(k, digest), nil
	}
	return nil, errors.New("unsupported key")
}

// Verify checks a signature produced by Sign.
func Verify(j *JWK, alg string, digest, sig []byte) (bool, error) {
	if !supports(SignatureAlgorithms(j), alg) {
		return false, fmt.Errorf("algorithm %s is not supported by this %s key", alg, j.Size())
	}
	pk, err := j.PublicKey()
	if err != nil {
		return false, err
	}
	h, _ := HashForSignature(alg)
	switch k := pk.(type) {
	case *rsa.PublicKey:
		if alg[0] == 'P' {
			return rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil, nil
		}
		return rsa.VerifyPKCS1v15(k, h, digest, sig) == nil, nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return false, nil
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s), nil
	case ed25519.PublicKey:
		return ed25519.Verify(k, digest, sig), nil
	}
	return false, errors.New("unsupported key")
}

// Ciphertext is the result of Encrypt. IV and Tag are only set for AES-GCM,
// matching the Key Vault response shape.
type Ciphertext struct {
	Ciphertext []byte
	IV         []byte
	Tag        []byte
}

func oaepHash(alg string) crypto.Hash {
	if alg == AlgRSAOAEP256 {
		return crypto.SHA256
	}
	return crypto.SHA1
}

// Encrypt encrypts plaintext with the key. RSA algorithms ignore aad.
func Encrypt(j *JWK, alg string, plaintext, aad []byte) (*Ciphertext, error) {
	if !supports(EncryptionAlgorithms(j), alg) {
		return nil, fmt.Errorf("algorithm %s is not supported by this key", alg)
	}
	switch j.Kty {
	case "RSA":
		pk, err := j.PublicKey()
		if err != nil {
			return nil, err
		}
		rk := pk.(*rsa.PublicKey)
		ct, err := rsa.EncryptOAEP(oaepHash(alg).New(), rand.Reader, rk, plaintext, nil)
		if err != nil {
			return nil, err
		}
		return &Ciphertext{Ciphertext: ct}, nil
	case "oct":
		block, err := aes.NewCipher(j.K)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		iv, err := RandomBytes(gcm.NonceSize())
		if err != nil {
			return nil, err
		}
		sealed := gcm.Seal(nil, iv, plaintext, aad)
		n := len(sealed) - gcm.Overhead()
		return &Ciphertext{Ciphertext: sealed[:n], IV: iv, Tag: sealed[n:]}, nil
	}
	return nil, errors.New("unsupported key")
}

// Decrypt reverses Encrypt.
func Decrypt(j *JWK, alg string, ct *Ciphertext, aad []byte) ([]byte, error) {
	if !supports(EncryptionAlgorithms(j), alg) {
		return nil, fmt.Errorf("algorithm %s is not supported by this key", alg)
	}
	switch j.Kty {
	case "RSA":
		sk, err := j.PrivateKey()
		if err != nil {
			return nil, err
		}
		rk := sk.(*rsa.PrivateKey)
		return rsa.DecryptOAEP(oaepHash(alg).New(), rand.Reader, rk, ct.Ciphertext, nil)
	case "oct":
		block, err := aes.NewCipher(j.K)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sealed := append(append([]byte{}, ct.Ciphertext...), ct.Tag...)
		pt, err := gcm.Open(nil, ct.IV, sealed, aad)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
		return pt, nil
	}
	return nil, errors.New("unsupported key")
}

// WrapKey wraps key material with the key. RSA uses the same padding as
// Encrypt; oct keys use AES Key Wrap (RFC 3394).
func WrapKey(j *JWK, alg string, key []byte) ([]byte, error) {
	if !supports(WrapAlgorithms(j), alg) {
		return nil, fmt.Errorf("algorithm %s is not supported by this key", alg)
	}
	if j.Kty == "RSA" {
		ct, err := Encrypt(j, alg, key, nil)
		if err != nil {
			return nil, err
		}
		return ct.Ciphertext, nil
	}
	return aesKeyWrap(j.K, key)
}

// UnwrapKey reverses WrapKey.
func UnwrapKey(j *JWK, alg string, wrapped []byte) ([]byte, error) {
	if !supports(WrapAlgorithms(j), alg) {
		return nil, fmt.Errorf("algorithm %s is not supported by this key", alg)
	}
	if j.Kty == "RSA" {
		return Decrypt(j, alg, &Ciphertext{Ciphertext: wrapped}, nil)
	}
	return aesKeyUnwrap(j.K, wrapped)
}

var kwIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap implements RFC 3394 without padding; the plaintext must be a
// multiple of 8 bytes and at least 16 bytes.
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("key wrap input must be a multiple of 8 bytes and at least 16 bytes")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	a := append([]byte{}, kwIV...)
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte{}, plaintext[i*8:(i+1)*8]...)
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			copy(a, buf[:8])
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t >> (8 * k))
			}
			copy(r[i], buf[8:])
		}
	}
	out := append([]byte{}, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errors.New("invalid wrapped key length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := append([]byte{}, wrapped[:8]...)
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte{}, wrapped[(i+1)*8:(i+2)*8]...)
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t >> (8 * k))
			}
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}
	if string(a) != string(kwIV) {
		return nil, errors.New("key unwrap integrity check failed")
	}
	out := make([]byte, 0, n*8)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

// Ensure hash packages are linked for crypto.Hash.New.
var _ = sha256.New
var _ = sha512.New
