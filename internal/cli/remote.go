package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/service"
	"github.com/danto7/azk/internal/store"
)

func newRemoteCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Sync with Azure Key Vault",
		Long: `Remotes are Azure Key Vaults (or a floci-az emulator). Keys and secrets are
pushed version by version; pulls bring back secrets and the public parts of keys.

Credentials come from DefaultAzureCredential (environment, managed identity,
Azure CLI login). Set ` + keyvault.TokenEnv + ` to use a static bearer token, which
is what emulators expect.`,
	}
	cmd.AddCommand(newRemoteAddCmd(g), newRemoteListCmd(g), newRemoteRemoveCmd(g),
		newRemoteSyncCmd(g, "push"), newRemoteSyncCmd(g, "pull"), newRemoteSyncCmd(g, "sync"))
	return cmd
}

func newRemoteAddCmd(g *globals) *cobra.Command {
	var vaultURL string
	var insecure, noCheck bool
	cmd := &cobra.Command{
		Use:   "add NAME --vault-url URL",
		Short: "Register a Key Vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.ValidateName(args[0]); err != nil {
				return err
			}
			cfg := keyvault.Config{VaultURL: strings.TrimRight(vaultURL, "/"), InsecureHTTP: insecure}
			if err := cfg.Validate(); err != nil {
				return err
			}
			if !noCheck {
				c, err := keyvault.Open(cfg)
				if err != nil {
					return err
				}
				if err := c.Ping(cmd.Context()); err != nil {
					return fmt.Errorf("%w (use --no-check to add anyway)", err)
				}
			}
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			r := store.Remote{Name: args[0], VaultURL: cfg.VaultURL, InsecureHTTP: insecure, CreatedAt: time.Now()}
			if err := s.Vault().Store().AddRemote(cmd.Context(), r); err != nil {
				return err
			}
			s.Record(cmd.Context(), "remote.add", args[0], map[string]any{"vault_url": cfg.VaultURL})
			if g.json {
				return g.printJSON(r)
			}
			fmt.Fprintf(g.stdout, "Added remote %s (%s)\n", r.Name, r.VaultURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&vaultURL, "vault-url", "", "vault URL, e.g. https://myvault.vault.azure.net")
	_ = cmd.MarkFlagRequired("vault-url")
	cmd.Flags().BoolVar(&insecure, "insecure-http", false, "allow a plain http URL (emulators only)")
	cmd.Flags().BoolVar(&noCheck, "no-check", false, "skip the connectivity check")
	return cmd
}

func newRemoteListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List remotes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			remotes, err := s.Vault().Store().ListRemotes(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				if remotes == nil {
					remotes = []store.Remote{}
				}
				return g.printJSON(remotes)
			}
			rows := make([][]string, 0, len(remotes))
			for _, r := range remotes {
				mode := "https"
				if r.InsecureHTTP {
					mode = "insecure-http"
				}
				rows = append(rows, []string{r.Name, r.VaultURL, mode, fmtOptTime(r.LastSyncAt)})
			}
			g.table([]string{"NAME", "VAULT URL", "MODE", "LAST SYNC"}, rows)
			return nil
		},
	}
}

func newRemoteRemoveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "remove NAME",
		Short: "Forget a remote (local items stay)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			if err := s.Vault().Store().DeleteRemote(cmd.Context(), args[0]); err != nil {
				return err
			}
			s.Record(cmd.Context(), "remote.remove", args[0], nil)
			return nil
		},
	}
}

func (g *globals) syncer(cmd *cobra.Command, s *service.Service, name string) (*keyvault.Syncer, error) {
	r, err := s.Vault().Store().GetRemote(cmd.Context(), name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("remote %q not found (see `azk remote list`)", name)
		}
		return nil, err
	}
	c, err := keyvault.Open(keyvault.Config{VaultURL: r.VaultURL, InsecureHTTP: r.InsecureHTTP})
	if err != nil {
		return nil, err
	}
	return keyvault.NewSyncer(s, c, *r), nil
}

func newRemoteSyncCmd(g *globals, mode string) *cobra.Command {
	var dryRun bool
	short := map[string]string{
		"push": "Upload local versions that the remote does not have",
		"pull": "Download remote versions that the vault does not have",
		"sync": "Push then pull",
	}[mode]
	cmd := &cobra.Command{
		Use:   mode + " REMOTE [ITEM...]",
		Short: short,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			sy, err := g.syncer(cmd, s, args[0])
			if err != nil {
				return err
			}
			plan, err := sy.Plan(cmd.Context(), mode != "pull", mode != "push", args[1:])
			if err != nil {
				return err
			}
			if dryRun {
				return g.printPlan(plan, nil)
			}
			res, applyErr := sy.Apply(cmd.Context(), plan)
			if err := g.printPlan(plan, res); err != nil {
				return err
			}
			if applyErr != nil {
				return applyErr
			}
			if plan.Counts()[keyvault.OpConflict] > 0 {
				return &exitError{code: 1, msg: "conflicts need manual resolution"}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan without changing anything")
	return cmd
}

func (g *globals) printPlan(plan *keyvault.Plan, res *keyvault.Result) error {
	if g.json {
		return g.printJSON(map[string]any{"plan": plan, "result": res})
	}
	done := map[string]bool{}
	if res != nil {
		for _, a := range res.Done {
			done[fmt.Sprintf("%s/%s/%d/%s", a.Op, a.Name, a.Seq, a.RemoteVersion)] = true
		}
	}
	rows := make([][]string, 0, len(plan.Actions))
	for _, a := range plan.Actions {
		ver := "-"
		if a.Seq > 0 {
			ver = fmt.Sprintf("v%d", a.Seq)
		} else if a.RemoteVersion != "" {
			ver = a.RemoteVersion
		}
		state := "planned"
		switch {
		case res == nil:
		case a.Op == keyvault.OpSkip || a.Op == keyvault.OpConflict:
			state = "-"
		case done[fmt.Sprintf("%s/%s/%d/%s", a.Op, a.Name, a.Seq, a.RemoteVersion)]:
			state = "done"
		default:
			state = "failed"
		}
		reason := a.Reason
		if reason == "" {
			reason = "-"
		}
		rows = append(rows, []string{string(a.Op), a.Kind, a.Name, ver, state, reason})
	}
	if len(rows) == 0 {
		fmt.Fprintln(g.stdout, "Nothing to do; local vault and remote are in sync.")
		return nil
	}
	g.table([]string{"OP", "KIND", "NAME", "VERSION", "STATE", "REASON"}, rows)
	if res != nil {
		fmt.Fprintf(g.stdout, "Pushed %d, pulled %d\n", res.Pushed, res.Pulled)
	}
	return nil
}

func newSlotAddKeyVaultCmd(g *globals) *cobra.Command {
	var remote, key, label string
	var create bool
	cmd := &cobra.Command{
		Use:   "keyvault --remote NAME --key KEY",
		Short: "Add a slot unlocked by an Azure Key Vault RSA key",
		Long: `Wraps the vault's data encryption key with an RSA key held in Key Vault.
Afterwards ` + "`azk --unlock keyvault ...`" + ` (or AZK_UNLOCK=keyvault) unlocks without a
passphrase by asking Key Vault to unwrap it, so whoever can use that Key Vault
key can open the vault.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			r, err := s.Vault().Store().GetRemote(cmd.Context(), remote)
			if err != nil {
				return fmt.Errorf("remote %q: %w", remote, err)
			}
			c, err := keyvault.Open(keyvault.Config{VaultURL: r.VaultURL, InsecureHTTP: r.InsecureHTTP})
			if err != nil {
				return err
			}
			id, err := keyvault.AddSlot(cmd.Context(), s.Vault(), c, remote, label, key, create)
			if err != nil {
				return err
			}
			s.Record(cmd.Context(), "slot.add", id, map[string]string{"kind": "keyvault", "remote": remote, "key": key})
			if g.json {
				return g.printJSON(map[string]string{"id": id, "kind": "keyvault", "remote": remote, "key": key})
			}
			fmt.Fprintf(g.stdout, "Added keyvault slot %s (%s/%s)\n", id, remote, key)
			return nil
		},
	}
	cmd.Flags().StringVar(&remote, "remote", "", "remote name")
	cmd.Flags().StringVar(&key, "key", "", "RSA key name in the vault")
	cmd.Flags().StringVar(&label, "label", "", "slot label (default REMOTE/KEY)")
	cmd.Flags().BoolVar(&create, "create", false, "create the RSA key if it does not exist")
	_ = cmd.MarkFlagRequired("remote")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}
