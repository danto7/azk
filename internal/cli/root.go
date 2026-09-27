// Package cli implements the azk command line interface on top of the
// service layer. Main is the entry point used by cmd/azk and by the
// testscript suite.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/vault"
)

// Version is set by the release build.
var Version = "dev"

// globals holds root flags.
type globals struct {
	vaultPath      string
	json           bool
	passphraseFile string
	unlockMode     string
	stdin          io.Reader
	stdout, stderr io.Writer
}

// Main runs the CLI and returns the process exit code.
func Main() int {
	return Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}

// Run executes args with the given streams; used by tests.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	g := &globals{stdin: stdin, stdout: stdout, stderr: stderr}
	root := newRoot(g)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(stderr, "azk:", ee.msg)
			}
			return ee.code
		}
		fmt.Fprintln(stderr, "azk:", err)
		return 1
	}
	return 0
}

type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func newRoot(g *globals) *cobra.Command {
	root := &cobra.Command{
		Use:   "azk",
		Short: "azk keeps keys and secrets in a locally encrypted vault",
		Long: `azk stores cryptographic keys and secrets in an encrypted vault file,
performs sign/verify, encrypt/decrypt and wrap/unwrap with them, and can
push and pull to Azure Key Vault.

The passphrase is read from AZK_PASSPHRASE_FILE (or --passphrase-file), from
AZK_PASSPHRASE, or prompted on the terminal.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}
	root.PersistentFlags().StringVar(&g.vaultPath, "vault", "", "vault file (default $AZK_VAULT or "+defaultVaultPath()+")")
	root.PersistentFlags().BoolVar(&g.json, "json", false, "print machine readable JSON")
	root.PersistentFlags().StringVar(&g.passphraseFile, "passphrase-file", "", "read the passphrase from this file (default $AZK_PASSPHRASE_FILE)")
	root.PersistentFlags().StringVar(&g.unlockMode, "unlock", "", "how to unlock: passphrase, keyvault or auto (default $AZK_UNLOCK or auto)")

	root.AddCommand(
		newInitCmd(g), newStatusCmd(g), newKeyCmd(g), newSecretCmd(g),
		newSignCmd(g), newVerifyCmd(g), newEncryptCmd(g), newDecryptCmd(g), newWrapCmd(g), newUnwrapCmd(g),
		newSlotCmd(g), newAuditCmd(g), newRemoteCmd(g), newServeCmd(g),
	)
	return root
}

func defaultVaultPath() string {
	if p := os.Getenv("AZK_VAULT"); p != "" {
		return p
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "azk", "vault.db")
}

func (g *globals) path() string {
	if g.vaultPath != "" {
		return g.vaultPath
	}
	return defaultVaultPath()
}

// passphrase resolves the passphrase from env, file or terminal. confirm
// asks twice, for init and slot creation.
func (g *globals) passphrase(confirm bool) ([]byte, error) {
	if p := os.Getenv("AZK_PASSPHRASE"); p != "" {
		return []byte(p), nil
	}
	file := g.passphraseFile
	if file == "" {
		file = os.Getenv("AZK_PASSPHRASE_FILE")
	}
	if file != "" {
		return readPassphraseFile(file)
	}
	f, ok := g.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil, errors.New("no passphrase: set AZK_PASSPHRASE_FILE or run on a terminal")
	}
	fmt.Fprint(g.stderr, "Passphrase: ")
	p, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(g.stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(g.stderr, "Confirm passphrase: ")
		p2, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(g.stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(p, p2) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return p, nil
}

// hasPassphraseSource reports whether a passphrase can be obtained without
// prompting.
func (g *globals) hasPassphraseSource() bool {
	return os.Getenv("AZK_PASSPHRASE") != "" || g.passphraseFile != "" || os.Getenv("AZK_PASSPHRASE_FILE") != ""
}

func (g *globals) isTerminal() bool {
	f, ok := g.stdin.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// unlock opens the DEK using the passphrase or a keyvault slot. In auto
// mode a keyvault slot is used when no passphrase source is configured
// and no terminal is available to prompt on.
func (g *globals) unlock(ctx context.Context, v *vault.Vault) error {
	mode := g.unlockMode
	if mode == "" {
		mode = os.Getenv("AZK_UNLOCK")
	}
	if mode == "" {
		mode = "auto"
	}
	useKeyVault := false
	switch mode {
	case "passphrase":
	case "keyvault":
		useKeyVault = true
	case "auto":
		if !g.hasPassphraseSource() && !g.isTerminal() {
			slots, err := v.Slots(ctx)
			if err != nil {
				return err
			}
			for _, s := range slots {
				if s.Kind == vault.SlotKeyVault {
					useKeyVault = true
				}
			}
		}
	default:
		return fmt.Errorf("unknown unlock mode %q (want passphrase, keyvault or auto)", mode)
	}
	if useKeyVault {
		return v.UnlockWith(ctx, keyvault.Unwrapper{})
	}
	p, err := g.passphrase(false)
	if err != nil {
		return err
	}
	defer crypto.Zero(p)
	return v.Unlock(ctx, p)
}

// open opens the vault; unlock decides whether the DEK is needed.
func (g *globals) open(ctx context.Context, unlock bool) (*service.Service, error) {
	v, err := vault.Open(ctx, g.path())
	if err != nil {
		return nil, err
	}
	if unlock {
		if err := g.unlock(ctx, v); err != nil {
			v.Close()
			return nil, err
		}
	}
	return service.New(v, "cli"), nil
}

// --- output helpers ---

func (g *globals) printJSON(v any) error {
	enc := json.NewEncoder(g.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (g *globals) table(header []string, rows [][]string) {
	w := tabwriter.NewWriter(g.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func fmtOptTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return fmtTime(*t)
}

func fmtTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(tags))
	for k, v := range tags {
		parts = append(parts, k+"="+v)
	}
	sortStrings(parts)
	return strings.Join(parts, ",")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func parseTags(kv []string) (map[string]string, error) {
	if len(kv) == 0 {
		return nil, nil
	}
	tags := map[string]string{}
	for _, s := range kv {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("invalid tag %q (want key=value)", s)
		}
		tags[k] = v
	}
	return tags, nil
}

func parseTimeFlag(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	return nil, fmt.Errorf("invalid time %q (want RFC3339, YYYY-MM-DD or a duration like 720h)", s)
}

// readInput reads a file, or stdin when path is "" or "-".
func (g *globals) readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(bufio.NewReader(g.stdin))
	}
	return os.ReadFile(path)
}

// writeOutput writes to a file, or stdout when path is "" or "-".
func (g *globals) writeOutput(path string, data []byte) error {
	if path == "" || path == "-" {
		_, err := g.stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// writeEncoded writes bytes as base64 (plus newline) unless raw.
func (g *globals) writeEncoded(path string, data []byte, raw bool) error {
	if raw {
		return g.writeOutput(path, data)
	}
	return g.writeOutput(path, []byte(base64.StdEncoding.EncodeToString(data)+"\n"))
}

// decodeMaybeBase64 accepts raw bytes or base64 text, deciding by flag.
func decodeInput(data []byte, raw bool) ([]byte, error) {
	if raw {
		return data, nil
	}
	s := strings.TrimSpace(string(data))
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		out, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("input is not base64 (use --raw for binary input): %w", err)
		}
	}
	return out, nil
}

// kdfFlags exposes the Argon2id parameters. Defaults come from
// AZK_KDF_TIME, AZK_KDF_MEMORY (KiB) and AZK_KDF_THREADS when set.
func kdfFlags(cmd *cobra.Command, p *crypto.Argon2Params) {
	def := crypto.DefaultArgon2Params
	if v, err := strconv.ParseUint(os.Getenv("AZK_KDF_TIME"), 10, 32); err == nil {
		def.Time = uint32(v)
	}
	if v, err := strconv.ParseUint(os.Getenv("AZK_KDF_MEMORY"), 10, 32); err == nil {
		def.Memory = uint32(v)
	}
	if v, err := strconv.ParseUint(os.Getenv("AZK_KDF_THREADS"), 10, 8); err == nil {
		def.Threads = uint8(v)
	}
	cmd.Flags().Uint32Var(&p.Time, "kdf-time", def.Time, "Argon2id passes ($AZK_KDF_TIME)")
	cmd.Flags().Uint32Var(&p.Memory, "kdf-memory", def.Memory, "Argon2id memory in KiB ($AZK_KDF_MEMORY)")
	cmd.Flags().Uint8Var(&p.Threads, "kdf-threads", def.Threads, "Argon2id lanes ($AZK_KDF_THREADS)")
}

// --- init / status ---

func newInitCmd(g *globals) *cobra.Command {
	var params crypto.Argon2Params
	var label string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new vault protected by a passphrase",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := g.passphrase(true)
			if err != nil {
				return err
			}
			defer crypto.Zero(p)
			v, err := vault.Create(cmd.Context(), g.path(), p, vault.CreateOptions{Argon2: params, Label: label})
			if err != nil {
				return err
			}
			defer v.Close()
			info, err := v.Info(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(info)
			}
			fmt.Fprintf(g.stdout, "Created vault %s\n", info.Path)
			return nil
		},
	}
	kdfFlags(cmd, &params)
	cmd.Flags().StringVar(&label, "label", "passphrase", "label for the initial passphrase slot")
	return cmd
}

func newStatusCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault location, format and slot count",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			info, err := s.Vault().Info(cmd.Context())
			if err != nil {
				return err
			}
			items, err := s.ListItems(cmd.Context(), storeFilter{}.all())
			if err != nil {
				return err
			}
			out := struct {
				*vault.Info
				Items int `json:"items"`
			}{info, len(items)}
			if g.json {
				return g.printJSON(out)
			}
			fmt.Fprintf(g.stdout, "Vault:    %s\nFormat:   v%d\nCreated:  %s\nSlots:    %d\nItems:    %d\n",
				info.Path, info.FormatVersion, fmtTime(info.CreatedAt), info.Slots, len(items))
			return nil
		},
	}
}
