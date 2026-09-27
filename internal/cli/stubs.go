package cli

import (
	"github.com/spf13/cobra"
)

// Placeholders replaced by the remote (M3) and web (M4) milestones.

func newRemoteCmd(g *globals) *cobra.Command {
	return &cobra.Command{Use: "remote", Short: "Manage Azure Key Vault remotes", Hidden: true}
}

func newServeCmd(g *globals) *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "Run the local web interface", Hidden: true}
}

func newSlotAddKeyVaultCmd(g *globals) *cobra.Command {
	return &cobra.Command{Use: "keyvault", Short: "Add a slot unlocked by an Azure Key Vault key", Hidden: true}
}
