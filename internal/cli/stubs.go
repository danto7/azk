package cli

import (
	"github.com/spf13/cobra"
)

// Placeholder replaced by the web milestone.

func newServeCmd(g *globals) *cobra.Command {
	return &cobra.Command{Use: "serve", Short: "Run the local web interface", Hidden: true}
}
