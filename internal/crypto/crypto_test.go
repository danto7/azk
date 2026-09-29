package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	cases := []struct {
		kind Kind
		opts GenerateOptions
	}{
		{KindRSA, GenerateOptions{Bits: 2048}},
		{KindEC, GenerateOptions{Curve: "P-256"}},
		{KindEC, GenerateOptions{Curve: "P-384"}},
		{KindEC, GenerateOptions{Curve: "P-521"}},
		{KindEd25519, GenerateOptions{}},
		{KindOct, GenerateOptions{Bits: 256}},
	}
	for _, c := range cases {
		t.Run(string(c.kind)+c.opts.Curve, func(t *testing.T) {
			k, err := Generate(c.kind, c.opts)
			if err != nil {
				t.Fatal(err)
			}
			if k.Kind() != c.kind || !k.IsPrivate() {
				t.Fatalf("kind %s private %v", k.Kind(), k.IsPrivate())
			}
			raw, err := json.Marshal(k)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParseJWK(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back.D, k.D) || !bytes.Equal(back.K, k.K) {
				t.Fatal("jwk round trip changed private material")
			}
			if c.kind != KindOct {
				pemPriv, err := k.ToPEM(false)
				if err != nil {
					t.Fatal(err)
				}
				fromPEM, err := ParsePEM(pemPriv)
				if err != nil {
					t.Fatal(err)
				}
				tp1, _ := k.Thumbprint()
				tp2, _ := fromPEM.Thumbprint()
				if tp1 != tp2 {
					t.Fatal("pem round trip changed key")
				}
				pemPub, err := k.ToPEM(true)
				if err != nil {
					t.Fatal(err)
				}
				pub, err := ParsePEM(pemPub)
				if err != nil {
					t.Fatal(err)
				}
				if pub.IsPrivate() {
					t.Fatal("public pem yielded private key")
				}
				if tp3, _ := pub.Thumbprint(); tp3 != tp1 {
					t.Fatal("public thumbprint mismatch")
				}
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	msg := []byte("hello azk")
	for _, kind := range []struct {
		kind Kind
		opts GenerateOptions
	}{{KindRSA, GenerateOptions{Bits: 2048}}, {KindEC, GenerateOptions{Curve: "P-384"}}, {KindEd25519, GenerateOptions{}}} {
		k, err := Generate(kind.kind, kind.opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, alg := range SignatureAlgorithms(k) {
			d, err := Digest(alg, msg)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Sign(k, alg, d)
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			ok, err := Verify(k.Public(), alg, d, sig)
			if err != nil || !ok {
				t.Fatalf("%s: verify failed ok=%v err=%v", alg, ok, err)
			}
			sig[0] ^= 1
			ok, _ = Verify(k.Public(), alg, d, sig)
			if ok {
				t.Fatalf("%s: tampered signature verified", alg)
			}
		}
	}
}

func TestEncryptDecryptWrap(t *testing.T) {
	rsaKey, _ := Generate(KindRSA, GenerateOptions{Bits: 2048})
	octKey, _ := Generate(KindOct, GenerateOptions{Bits: 256})
	for _, k := range []*JWK{rsaKey, octKey} {
		for _, alg := range EncryptionAlgorithms(k) {
			ct, err := Encrypt(k, alg, []byte("secret"), []byte("aad"))
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			pt, err := Decrypt(k, alg, ct, []byte("aad"))
			if err != nil || string(pt) != "secret" {
				t.Fatalf("%s: decrypt %q %v", alg, pt, err)
			}
		}
		for _, alg := range WrapAlgorithms(k) {
			key := bytes.Repeat([]byte{7}, 32)
			w, err := WrapKey(k, alg, key)
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			u, err := UnwrapKey(k, alg, w)
			if err != nil || !bytes.Equal(u, key) {
				t.Fatalf("%s: unwrap %v", alg, err)
			}
		}
	}
}

// RFC 3394 section 4.1 test vector.
func TestAESKeyWrapVector(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	want, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	got, err := aesKeyWrap(kek, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wrap = %X want %X", got, want)
	}
	back, err := aesKeyUnwrap(kek, got)
	if err != nil || !bytes.Equal(back, key) {
		t.Fatalf("unwrap = %X err %v", back, err)
	}
	got[9] ^= 1
	if _, err := aesKeyUnwrap(kek, got); err == nil {
		t.Fatal("tampered unwrap succeeded")
	}
}

func TestSealOpen(t *testing.T) {
	key, _ := RandomBytes(KeySize)
	sealed, err := Seal(key, []byte("data"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, sealed, []byte("aad"))
	if err != nil || string(pt) != "data" {
		t.Fatal(err)
	}
	if _, err := Open(key, sealed, []byte("other")); err == nil {
		t.Fatal("wrong aad accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(key, sealed, []byte("aad")); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	p := Argon2Params{Time: 1, Memory: 8 * 1024, Threads: 1}
	salt := bytes.Repeat([]byte{1}, 16)
	a, err := DeriveKey([]byte("pw"), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKey([]byte("pw"), salt, p)
	c, _ := DeriveKey([]byte("pw2"), salt, p)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || len(a) != KeySize {
		t.Fatal("kdf misbehaves")
	}
	if _, err := DeriveKey([]byte("pw"), salt, Argon2Params{}); err == nil {
		t.Fatal("weak params accepted")
	}
}

func FuzzParseJWK(f *testing.F) {
	k, _ := Generate(KindEC, GenerateOptions{})
	raw, _ := json.Marshal(k)
	f.Add(raw)
	f.Add([]byte(`{"kty":"oct","k":"AAAA"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		j, err := ParseJWK(data)
		if err != nil {
			return
		}
		if j.Kty != "oct" {
			if _, err := j.PublicKey(); err != nil {
				t.Fatalf("parsed jwk has invalid public key: %v", err)
			}
		}
	})
}

func FuzzOpen(f *testing.F) {
	key := bytes.Repeat([]byte{3}, KeySize)
	sealed, _ := Seal(key, []byte("x"), nil)
	f.Add(sealed)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Open(key, data, nil)
	})
}
