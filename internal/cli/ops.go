package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

type opFlags struct {
	key  string
	seq  int
	alg  string
	in   string
	out  string
	raw  bool
	rawI bool
}

func (f *opFlags) bind(cmd *cobra.Command, algHelp string) {
	cmd.Flags().StringVarP(&f.key, "key", "k", "", "key name")
	_ = cmd.MarkFlagRequired("key")
	cmd.Flags().IntVar(&f.seq, "version", 0, "key version (default latest enabled)")
	cmd.Flags().StringVar(&f.alg, "alg", "", algHelp)
	cmd.Flags().StringVar(&f.in, "in", "-", "input file, - for stdin")
	cmd.Flags().StringVarP(&f.out, "out", "o", "-", "output file, - for stdout")
}

func newSignCmd(g *globals) *cobra.Command {
	var f opFlags
	cmd := &cobra.Command{
		Use:   "sign --key NAME [--in FILE]",
		Short: "Sign a message (hashed with the algorithm's digest)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			res, err := s.Sign(cmd.Context(), f.key, f.seq, f.alg, msg)
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(map[string]any{"name": res.Name, "seq": res.Seq, "version_id": res.VersionID, "algorithm": res.Algorithm, "signature": base64.StdEncoding.EncodeToString(res.Result)})
			}
			return g.writeEncoded(f.out, res.Result, f.raw)
		},
	}
	f.bind(cmd, "signature algorithm: RS256/384/512, PS256/384/512, ES256/384/512, EdDSA (default by key)")
	cmd.Flags().BoolVar(&f.raw, "raw", false, "write the raw signature instead of base64")
	return cmd
}

func newVerifyCmd(g *globals) *cobra.Command {
	var f opFlags
	var sigArg string
	cmd := &cobra.Command{
		Use:   "verify --key NAME --signature SIG|FILE [--in FILE]",
		Short: "Verify a signature; exits 0 when valid, 1 when not",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			msg, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			sig, err := readSigArg(g, sigArg, f.rawI)
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			ok, err := s.Verify(cmd.Context(), f.key, f.seq, f.alg, msg, sig)
			if err != nil {
				return err
			}
			if g.json {
				_ = g.printJSON(map[string]any{"valid": ok})
			} else if ok {
				fmt.Fprintln(g.stdout, "valid")
			} else {
				fmt.Fprintln(g.stdout, "invalid")
			}
			if !ok {
				return &exitError{code: 1}
			}
			return nil
		},
	}
	f.bind(cmd, "signature algorithm (default by key)")
	cmd.Flags().StringVar(&sigArg, "signature", "", "base64 signature, or @FILE to read it from a file")
	cmd.Flags().BoolVar(&f.rawI, "raw-signature", false, "the signature file holds raw bytes, not base64")
	_ = cmd.MarkFlagRequired("signature")
	return cmd
}

func readSigArg(g *globals, arg string, raw bool) ([]byte, error) {
	if strings.HasPrefix(arg, "@") {
		data, err := g.readInput(arg[1:])
		if err != nil {
			return nil, err
		}
		return decodeInput(data, raw)
	}
	return decodeInput([]byte(arg), false)
}

// envelope is the JSON form of an encryption result so decrypt can consume
// what encrypt produced.
type envelope struct {
	Key        string `json:"key"`
	Seq        int    `json:"seq"`
	VersionID  string `json:"version_id"`
	Algorithm  string `json:"algorithm"`
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv,omitempty"`
	Tag        string `json:"tag,omitempty"`
	AAD        string `json:"aad,omitempty"`
}

func newEncryptCmd(g *globals) *cobra.Command {
	var f opFlags
	var aad string
	cmd := &cobra.Command{
		Use:   "encrypt --key NAME [--in FILE]",
		Short: "Encrypt data; prints a JSON envelope that decrypt accepts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			pt, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			res, err := s.Encrypt(cmd.Context(), f.key, f.seq, f.alg, pt, []byte(aad))
			if err != nil {
				return err
			}
			if f.raw {
				if len(res.IV) > 0 {
					return errors.New("--raw is only available for RSA algorithms; AES-GCM needs iv and tag")
				}
				return g.writeOutput(f.out, res.Result, 0o600)
			}
			env := envelope{Key: res.Name, Seq: res.Seq, VersionID: res.VersionID, Algorithm: res.Algorithm,
				Ciphertext: base64.StdEncoding.EncodeToString(res.Result)}
			if len(res.IV) > 0 {
				env.IV = base64.StdEncoding.EncodeToString(res.IV)
				env.Tag = base64.StdEncoding.EncodeToString(res.Tag)
			}
			if aad != "" {
				env.AAD = aad
			}
			data, _ := json.MarshalIndent(env, "", "  ")
			return g.writeOutput(f.out, append(data, '\n'), 0o600)
		},
	}
	f.bind(cmd, "algorithm: RSA-OAEP-256, RSA-OAEP, RSA1_5, A128GCM, A192GCM, A256GCM (default by key)")
	cmd.Flags().StringVar(&aad, "aad", "", "additional authenticated data (AES-GCM only)")
	cmd.Flags().BoolVar(&f.raw, "raw", false, "write raw ciphertext (RSA only)")
	return cmd
}

func newDecryptCmd(g *globals) *cobra.Command {
	var f opFlags
	cmd := &cobra.Command{
		Use:   "decrypt [--key NAME] [--in FILE]",
		Short: "Decrypt a JSON envelope (or raw RSA ciphertext with --raw)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			var ct, iv, tag, aad []byte
			key, seq, alg := f.key, f.seq, f.alg
			if f.raw {
				if key == "" {
					return errors.New("--key is required with --raw")
				}
				ct = data
			} else {
				var env envelope
				if err := json.Unmarshal(data, &env); err != nil {
					return fmt.Errorf("input is not an encrypt envelope: %w", err)
				}
				if key == "" {
					key = env.Key
				}
				if seq == 0 {
					seq = env.Seq
				}
				if alg == "" {
					alg = env.Algorithm
				}
				if ct, err = base64.StdEncoding.DecodeString(env.Ciphertext); err != nil {
					return err
				}
				if env.IV != "" {
					if iv, err = base64.StdEncoding.DecodeString(env.IV); err != nil {
						return err
					}
					if tag, err = base64.StdEncoding.DecodeString(env.Tag); err != nil {
						return err
					}
				}
				aad = []byte(env.AAD)
			}
			if key == "" {
				return errors.New("envelope has no key name; pass --key")
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			pt, err := s.Decrypt(cmd.Context(), key, seq, alg, ct, iv, tag, aad)
			if err != nil {
				return err
			}
			return g.writeOutput(f.out, pt, 0o600)
		},
	}
	cmd.Flags().StringVarP(&f.key, "key", "k", "", "key name (default from envelope)")
	cmd.Flags().IntVar(&f.seq, "version", 0, "key version (default from envelope)")
	cmd.Flags().StringVar(&f.alg, "alg", "", "algorithm (default from envelope)")
	cmd.Flags().StringVar(&f.in, "in", "-", "input file, - for stdin")
	cmd.Flags().StringVarP(&f.out, "out", "o", "-", "output file, - for stdout")
	cmd.Flags().BoolVar(&f.raw, "raw", false, "input is raw RSA ciphertext")
	return cmd
}

func newWrapCmd(g *globals) *cobra.Command {
	var f opFlags
	cmd := &cobra.Command{
		Use:   "wrap --key NAME [--in FILE]",
		Short: "Wrap key material with a key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			material, err := decodeInput(data, f.rawI)
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			res, err := s.Wrap(cmd.Context(), f.key, f.seq, f.alg, material)
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(map[string]any{"name": res.Name, "seq": res.Seq, "version_id": res.VersionID, "algorithm": res.Algorithm, "wrapped": base64.StdEncoding.EncodeToString(res.Result)})
			}
			return g.writeEncoded(f.out, res.Result, f.raw)
		},
	}
	f.bind(cmd, "algorithm: RSA-OAEP-256, RSA-OAEP, RSA1_5, A128KW, A192KW, A256KW (default by key)")
	cmd.Flags().BoolVar(&f.rawI, "raw-in", false, "input is raw bytes rather than base64")
	cmd.Flags().BoolVar(&f.raw, "raw", false, "write raw output instead of base64")
	return cmd
}

func newUnwrapCmd(g *globals) *cobra.Command {
	var f opFlags
	cmd := &cobra.Command{
		Use:   "unwrap --key NAME [--in FILE]",
		Short: "Unwrap key material",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := g.readInput(f.in)
			if err != nil {
				return err
			}
			wrapped, err := decodeInput(data, f.rawI)
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			out, err := s.Unwrap(cmd.Context(), f.key, f.seq, f.alg, wrapped)
			if err != nil {
				return err
			}
			return g.writeEncoded(f.out, out, f.raw)
		},
	}
	f.bind(cmd, "algorithm (default by key)")
	cmd.Flags().BoolVar(&f.rawI, "raw-in", false, "input is raw bytes rather than base64")
	cmd.Flags().BoolVar(&f.raw, "raw", false, "write raw output instead of base64")
	return cmd
}
