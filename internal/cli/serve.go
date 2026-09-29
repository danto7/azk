package cli

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/danto7/azk/internal/web"
)

func newServeCmd(g *globals) *cobra.Command {
	var listen string
	var idle time.Duration
	var allowRemote bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the local web interface",
		Long: `Serves the web UI. The vault starts locked; the login page unlocks it with the
passphrase (or a Key Vault slot). It locks again after --idle-timeout of
inactivity, on the Lock button, and on shutdown.

By default the UI listens on loopback only. --listen with another address
requires --allow-remote and is served without TLS, so put a reverse proxy with
TLS and authentication in front of it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := g.open(cmd.Context(), false)
			if err != nil {
				return err
			}
			defer s.Vault().Close()
			s = serviceWithActor(s, "web")
			srv, err := web.New(s, web.Options{IdleTimeout: idle, Logger: log.New(g.stderr, "", log.LstdFlags)})
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return srv.Serve(ctx, listen, allowRemote)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", envOr("AZK_LISTEN", "127.0.0.1:7788"), "address to listen on ($AZK_LISTEN)")
	cmd.Flags().DurationVar(&idle, "idle-timeout", 15*time.Minute, "lock the vault after this much inactivity (0 disables)")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow a non-loopback --listen address")
	return cmd
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
