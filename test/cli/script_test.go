package cli_test

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/danto7/azk/internal/cli"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"azk": func() { os.Exit(cli.Main()) },
	})
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			env.Setenv("AZK_VAULT", env.WorkDir+"/vault.db")
			env.Setenv("AZK_PASSPHRASE", "correct horse")
			env.Setenv("AZK_KDF_TIME", "1")
			env.Setenv("AZK_KDF_MEMORY", "8192")
			env.Setenv("AZK_KDF_THREADS", "1")
			return nil
		},
	})
}
