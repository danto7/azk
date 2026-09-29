// Command azk is the key manager CLI.
package main

import (
	"os"

	"github.com/danto7/azk/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
