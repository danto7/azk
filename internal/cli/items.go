package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danto7/azk/internal/crypto"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
)

type storeFilter struct{}

func (storeFilter) all() store.ItemFilter { return store.ItemFilter{} }

// --- key ---

func newKeyCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Manage cryptographic keys"}
	cmd.AddCommand(
		newKeyGenerateCmd(g), newKeyImportCmd(g), newKeyExportCmd(g), newListCmd(g, "key"), newKeyShowCmd(g),
		newKeyRotateCmd(g), newDeleteCmd(g, "key"), newRecoverCmd(g, "key"), newPurgeCmd(g, "key"),
		newEnableCmd(g, true), newEnableCmd(g, false), newTagCmd(g),
	)
	return cmd
}

type createFlags struct {
	tags      []string
	notBefore string
	expires   string
}

func (f *createFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&f.tags, "tag", nil, "tag as key=value (repeatable)")
	cmd.Flags().StringVar(&f.notBefore, "not-before", "", "activation time (RFC3339, date, or duration)")
	cmd.Flags().StringVar(&f.expires, "expires", "", "expiry time (RFC3339, date, or duration)")
}

func (f *createFlags) options() (service.CreateOptions, error) {
	tags, err := parseTags(f.tags)
	if err != nil {
		return service.CreateOptions{}, err
	}
	nbf, err := parseTimeFlag(f.notBefore)
	if err != nil {
		return service.CreateOptions{}, err
	}
	exp, err := parseTimeFlag(f.expires)
	if err != nil {
		return service.CreateOptions{}, err
	}
	return service.CreateOptions{Tags: tags, NotBefore: nbf, Expires: exp}, nil
}

func newKeyGenerateCmd(g *globals) *cobra.Command {
	var kind, curve string
	var bits int
	var cf createFlags
	cmd := &cobra.Command{
		Use:   "generate NAME",
		Short: "Generate a new key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := crypto.ParseKind(kind)
			if err != nil {
				return err
			}
			opts, err := cf.options()
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.CreateKey(cmd.Context(), args[0], k, crypto.GenerateOptions{Bits: bits, Curve: curve}, opts)
			if err != nil {
				return err
			}
			return g.printItem(d)
		},
	}
	cmd.Flags().StringVarP(&kind, "type", "t", "rsa", "key type: rsa, ec, oct, ed25519")
	cmd.Flags().IntVar(&bits, "bits", 0, "key size for rsa (2048/3072/4096) and oct (128/192/256)")
	cmd.Flags().StringVar(&curve, "curve", "", "curve for ec: P-256, P-384, P-521")
	cf.bind(cmd)
	return cmd
}

func newKeyImportCmd(g *globals) *cobra.Command {
	var from, format string
	var cf createFlags
	cmd := &cobra.Command{
		Use:   "import NAME",
		Short: "Import a key from PEM, JWK or raw bytes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := g.readInput(from)
			if err != nil {
				return err
			}
			defer crypto.Zero(data)
			jwk, err := parseKeyInput(data, format)
			if err != nil {
				return err
			}
			defer jwk.Zero()
			opts, err := cf.options()
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.ImportKey(cmd.Context(), args[0], jwk, opts)
			if err != nil {
				return err
			}
			return g.printItem(d)
		},
	}
	cmd.Flags().StringVar(&from, "from", "-", "input file, - for stdin")
	cmd.Flags().StringVar(&format, "format", "auto", "input format: auto, pem, jwk, raw (raw = symmetric key bytes)")
	cf.bind(cmd)
	return cmd
}

func parseKeyInput(data []byte, format string) (*crypto.JWK, error) {
	trimmed := strings.TrimSpace(string(data))
	if format == "auto" {
		switch {
		case strings.HasPrefix(trimmed, "-----BEGIN"):
			format = "pem"
		case strings.HasPrefix(trimmed, "{"):
			format = "jwk"
		default:
			return nil, errors.New("cannot detect key format; pass --format pem, jwk or raw")
		}
	}
	switch format {
	case "pem":
		return crypto.ParsePEM(data)
	case "jwk":
		return crypto.ParseJWK([]byte(trimmed))
	case "raw":
		switch len(data) {
		case 16, 24, 32:
			return &crypto.JWK{Kty: "oct", K: append([]byte(nil), data...)}, nil
		}
		return nil, fmt.Errorf("raw key must be 16, 24 or 32 bytes, got %d", len(data))
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

func newKeyExportCmd(g *globals) *cobra.Command {
	var format, out string
	var seq int
	var public, revealPrivate bool
	cmd := &cobra.Command{
		Use:   "export NAME",
		Short: "Export a key (public part by default)",
		Long: `Export a key. Without --reveal-private only the public part is written.
Private material leaves the vault unencrypted; --reveal-private acknowledges that
and the export is recorded in the audit log.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !public && !revealPrivate {
				public = true
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			m, _, err := s.Export(cmd.Context(), args[0], seq, public)
			if err != nil {
				return err
			}
			defer m.Zero()
			if m.JWK == nil {
				return service.ErrNotKey
			}
			var data []byte
			switch format {
			case "jwk":
				data, err = json.MarshalIndent(m.JWK, "", "  ")
				data = append(data, '\n')
			case "pem":
				data, err = m.JWK.ToPEM(public)
			case "raw":
				if m.JWK.Kty != "oct" {
					return errors.New("--format raw only applies to symmetric keys")
				}
				data = m.JWK.K
			default:
				return fmt.Errorf("unknown format %q", format)
			}
			if err != nil {
				return err
			}
			return g.writeOutput(out, data)
		},
	}
	cmd.Flags().StringVar(&format, "format", "pem", "output format: pem, jwk, raw")
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output file, - for stdout")
	cmd.Flags().IntVar(&seq, "version", 0, "version number (default latest enabled)")
	cmd.Flags().BoolVar(&public, "public", false, "export only the public part (default)")
	cmd.Flags().BoolVar(&revealPrivate, "reveal-private", false, "export private material")
	return cmd
}

func newListCmd(g *globals, what string) *cobra.Command {
	var kind, tag, prefix string
	var deleted, all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List " + what + "s",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			f := store.ItemFilter{Tag: tag, NamePrefix: prefix, OnlyDeleted: deleted, IncludeDeleted: all}
			if what == "secret" {
				f.Kind = string(crypto.KindSecret)
			} else if kind != "" {
				if _, err := crypto.ParseKind(kind); err != nil {
					return err
				}
				f.Kind = kind
			}
			items, err := s.ListItems(cmd.Context(), f)
			if err != nil {
				return err
			}
			if what == "key" {
				keep := items[:0]
				for _, it := range items {
					if it.Kind != string(crypto.KindSecret) {
						keep = append(keep, it)
					}
				}
				items = keep
			}
			if g.json {
				if items == nil {
					items = []*store.Item{}
				}
				return g.printJSON(items)
			}
			rows := make([][]string, 0, len(items))
			for _, it := range items {
				state := "active"
				if it.DeletedAt != nil {
					state = "deleted"
				}
				rows = append(rows, []string{it.Name, it.Kind, state, fmtTime(it.UpdatedAt), fmtTags(it.Tags)})
			}
			g.table([]string{"NAME", "KIND", "STATE", "UPDATED", "TAGS"}, rows)
			return nil
		},
	}
	if what == "key" {
		cmd.Flags().StringVarP(&kind, "type", "t", "", "filter by type")
	}
	cmd.Flags().StringVar(&tag, "tag", "", "filter by tag (key or key=value)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "filter by name prefix")
	cmd.Flags().BoolVar(&deleted, "deleted", false, "show only deleted items")
	cmd.Flags().BoolVar(&all, "all", false, "include deleted items")
	return cmd
}

func newKeyShowCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show key metadata, versions and public parts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.GetItem(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return g.printItem(d)
		},
	}
	return cmd
}

func (g *globals) printItem(d *service.ItemDetail) error {
	if g.json {
		return g.printJSON(d)
	}
	fmt.Fprintf(g.stdout, "Name:     %s\nKind:     %s\nTags:     %s\nCreated:  %s\nUpdated:  %s\n",
		d.Name, d.Kind, fmtTags(d.Tags), fmtTime(d.CreatedAt), fmtTime(d.UpdatedAt))
	if d.DeletedAt != nil {
		fmt.Fprintf(g.stdout, "Deleted:  %s\n", fmtTime(*d.DeletedAt))
	}
	if d.RemoteID != "" {
		fmt.Fprintf(g.stdout, "Remote:   %s\n", d.RemoteID)
	}
	fmt.Fprintln(g.stdout, "Versions:")
	rows := make([][]string, 0, len(d.Versions))
	for _, v := range d.Versions {
		state := "enabled"
		if !v.Enabled {
			state = "disabled"
		}
		if v.PublicOnly {
			state += ",public-only"
		}
		tp := v.Thumbprint
		if tp == "" {
			tp = "-"
		}
		rows = append(rows, []string{"  " + strconv.Itoa(v.Seq), v.ID[:8], state, fmtTime(v.CreatedAt), fmtOptTime(v.NotBefore), fmtOptTime(v.Expires), v.Size, tp})
	}
	g.table([]string{"  SEQ", "ID", "STATE", "CREATED", "NOT-BEFORE", "EXPIRES", "SIZE", "THUMBPRINT"}, rows)
	return nil
}

func newKeyRotateCmd(g *globals) *cobra.Command {
	var disableOld bool
	cmd := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Create a new version with fresh material",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.Rotate(cmd.Context(), args[0], disableOld)
			if err != nil {
				return err
			}
			return g.printItem(d)
		},
	}
	cmd.Flags().BoolVar(&disableOld, "disable-old", false, "disable the previous version")
	return cmd
}

func newDeleteCmd(g *globals, what string) *cobra.Command {
	return &cobra.Command{
		Use:   "delete NAME",
		Short: "Soft-delete a " + what + " (recoverable until purged)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			if err := s.Delete(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(g.stderr, "Deleted %s (recover with `azk %s recover %s`)\n", args[0], what, args[0])
			return nil
		},
	}
}

func newRecoverCmd(g *globals, what string) *cobra.Command {
	return &cobra.Command{
		Use:   "recover NAME",
		Short: "Undo a soft delete of a " + what,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			return s.Recover(cmd.Context(), args[0])
		},
	}
}

func newPurgeCmd(g *globals, what string) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "purge NAME",
		Short: "Permanently remove a deleted " + what,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			return s.Purge(cmd.Context(), args[0], force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "purge even if not deleted")
	return cmd
}

func newEnableCmd(g *globals, enable bool) *cobra.Command {
	use, short := "enable", "Enable a version"
	if !enable {
		use, short = "disable", "Disable a version"
	}
	var seq int
	cmd := &cobra.Command{
		Use:   use + " NAME --version N",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			return s.SetVersionEnabled(cmd.Context(), args[0], seq, enable)
		},
	}
	cmd.Flags().IntVar(&seq, "version", 0, "version number")
	_ = cmd.MarkFlagRequired("version")
	return cmd
}

func newTagCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "tag NAME [key=value ...]",
		Short: "Replace an item's tags",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tags, err := parseTags(args[1:])
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			return s.SetTags(cmd.Context(), args[0], tags)
		},
	}
}

// --- secret ---

func newSecretCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "secret", Short: "Manage opaque secrets"}
	cmd.AddCommand(newSecretSetCmd(g), newSecretGetCmd(g), newListCmd(g, "secret"), newSecretShowCmd(g),
		newDeleteCmd(g, "secret"), newRecoverCmd(g, "secret"), newPurgeCmd(g, "secret"))
	return cmd
}

func newSecretSetCmd(g *globals) *cobra.Command {
	var value, from, contentType string
	var cf createFlags
	cmd := &cobra.Command{
		Use:   "set NAME",
		Short: "Create a secret or add a new version",
		Long:  "The value comes from --value, --from FILE, or stdin. A trailing newline from stdin is kept.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			if cmd.Flags().Changed("value") {
				data = []byte(value)
			} else {
				data, err = g.readInput(from)
				if err != nil {
					return err
				}
			}
			defer crypto.Zero(data)
			opts, err := cf.options()
			if err != nil {
				return err
			}
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.SetSecret(cmd.Context(), args[0], data, contentType, opts)
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(d)
			}
			fmt.Fprintf(g.stderr, "Stored %s version %d\n", d.Name, d.Versions[0].Seq)
			return nil
		},
	}
	cmd.Flags().StringVar(&value, "value", "", "secret value (prefer --from or stdin; arguments are visible in process lists)")
	cmd.Flags().StringVar(&from, "from", "-", "read the value from this file, - for stdin")
	cmd.Flags().StringVar(&contentType, "content-type", "", "content type hint")
	cf.bind(cmd)
	return cmd
}

func newSecretGetCmd(g *globals) *cobra.Command {
	var seq int
	var out string
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Print a secret value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			m, v, err := s.Export(cmd.Context(), args[0], seq, false)
			if err != nil {
				return err
			}
			defer m.Zero()
			if m.JWK != nil {
				return service.ErrNotSecret
			}
			if g.json {
				return g.printJSON(map[string]any{"name": args[0], "seq": v.Seq, "version_id": v.ID, "value": string(m.Value), "content_type": m.ContentType})
			}
			return g.writeOutput(out, m.Value)
		},
	}
	cmd.Flags().IntVar(&seq, "version", 0, "version number (default latest enabled)")
	cmd.Flags().StringVarP(&out, "out", "o", "-", "output file, - for stdout")
	return cmd
}

func newSecretShowCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show secret metadata and versions (not the value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			d, err := s.GetItem(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return g.printItem(d)
		},
	}
}
