package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danto7/azk/internal/crypto"
)

func newSlotCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "slot", Short: "Manage the ways the vault can be unlocked"}
	add := &cobra.Command{Use: "add", Short: "Add an unlock slot"}
	add.AddCommand(newSlotAddPassphraseCmd(g), newSlotAddKeyVaultCmd(g))
	cmd.AddCommand(add, newSlotListCmd(g), newSlotRemoveCmd(g))
	return cmd
}

func newSlotAddPassphraseCmd(g *globals) *cobra.Command {
	var params crypto.Argon2Params
	var label, newFile string
	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Add another passphrase that unlocks the vault",
		Long: `Unlocks with the current passphrase, then adds a slot for a new one.
The new passphrase is read from --new-passphrase-file or prompted.
To change a passphrase: add the new one, then remove the old slot.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			var np []byte
			if newFile != "" {
				np, err = readPassphraseFile(newFile)
			} else {
				np, err = g.passphrase(true)
			}
			if err != nil {
				return err
			}
			defer crypto.Zero(np)
			id, err := s.Vault().AddPassphraseSlot(cmd.Context(), label, np, params)
			if err != nil {
				return err
			}
			s.Record(cmd.Context(), "slot.add", id, map[string]string{"kind": "passphrase", "label": label})
			if g.json {
				return g.printJSON(map[string]string{"id": id, "kind": "passphrase", "label": label})
			}
			fmt.Fprintf(g.stdout, "Added passphrase slot %s\n", id)
			return nil
		},
	}
	kdfFlags(cmd, &params)
	cmd.Flags().StringVar(&label, "label", "passphrase", "slot label")
	cmd.Flags().StringVar(&newFile, "new-passphrase-file", "", "read the new passphrase from this file")
	return cmd
}

func newSlotListCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List unlock slots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			slots, err := s.Vault().Slots(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(slots)
			}
			rows := make([][]string, 0, len(slots))
			for _, sl := range slots {
				rows = append(rows, []string{sl.ID, sl.Kind, sl.Label, fmtTime(sl.CreatedAt)})
			}
			g.table([]string{"ID", "KIND", "LABEL", "CREATED"}, rows)
			return nil
		},
	}
}

func newSlotRemoveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "remove ID|LABEL",
		Short: "Remove an unlock slot (the last slot cannot be removed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), true)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			if err := s.Vault().RemoveSlot(cmd.Context(), args[0]); err != nil {
				return err
			}
			s.Record(cmd.Context(), "slot.remove", args[0], nil)
			return nil
		},
	}
}

func newAuditCmd(g *globals) *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect the audit log"}
	var n int
	tail := &cobra.Command{
		Use:   "tail",
		Short: "Show the most recent audit entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			entries, err := s.Audit(cmd.Context(), n)
			if err != nil {
				return err
			}
			if g.json {
				return g.printJSON(entries)
			}
			rows := make([][]string, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, []string{e.At.Local().Format("2006-01-02 15:04:05"), e.Actor, e.Action, e.Target, e.Details})
			}
			g.table([]string{"TIME", "ACTOR", "ACTION", "TARGET", "DETAILS"}, rows)
			return nil
		},
	}
	tail.Flags().IntVarP(&n, "lines", "n", 20, "number of entries")
	cmd.AddCommand(tail)
	return cmd
}
