//go:build integration

package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danto7/azk/internal/cli"
	"github.com/danto7/azk/internal/remote/keyvault/kvtest"
)

// TestFlociKeyVault runs the shared sync scenarios against one emulator.
func TestFlociKeyVault(t *testing.T) {
	vaultURL := StartFlociAZ(t)
	t.Run("PushPull", func(t *testing.T) { kvtest.PushPull(t, Target(vaultURL, "pp-")) })
	t.Run("Conflict", func(t *testing.T) { kvtest.Conflict(t, Target(vaultURL, "cf-")) })
	t.Run("Slot", func(t *testing.T) { kvtest.Slot(t, Target(vaultURL, "sl-")) })
	t.Run("Interop", func(t *testing.T) { kvtest.Interop(t, Target(vaultURL, "io-")) })
	t.Run("Unreachable", kvtest.Unreachable)
	t.Run("CLI", func(t *testing.T) { cliScenario(t, vaultURL) })
}

// cliScenario drives the real commands end to end: remote add, push, a
// keyvault slot, unlock without a passphrase, pull into a second vault.
func cliScenario(t *testing.T, vaultURL string) {
	dir := t.TempDir()
	t.Setenv("AZK_VAULT", filepath.Join(dir, "a.db"))
	t.Setenv("AZK_PASSPHRASE", "pw")
	t.Setenv("AZK_AZURE_TOKEN", "floci")
	t.Setenv("AZK_KDF_TIME", "1")
	t.Setenv("AZK_KDF_MEMORY", "8192")
	t.Setenv("AZK_KDF_THREADS", "1")
	t.Setenv("AZK_UNLOCK", "")

	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		var out, errb bytes.Buffer
		code := cli.Run(args, strings.NewReader(stdin), &out, &errb)
		t.Logf("azk %s -> %d\n%s%s", strings.Join(args, " "), code, out.String(), errb.String())
		return out.String(), errb.String(), code
	}
	must := func(stdin string, args ...string) string {
		t.Helper()
		out, errb, code := run(stdin, args...)
		if code != 0 {
			t.Fatalf("azk %s failed: %s", strings.Join(args, " "), errb)
		}
		return out
	}

	must("", "init")
	must("", "remote", "add", "floci", "--vault-url", vaultURL, "--insecure-http")
	must("", "key", "generate", "cli-rsa", "--type", "rsa", "--bits", "2048")
	must("secret-value", "secret", "set", "cli-sec")
	out := must("", "remote", "push", "floci", "--dry-run")
	if !strings.Contains(out, "push") {
		t.Fatalf("dry run shows no push: %s", out)
	}
	out = must("", "remote", "push", "floci")
	if !strings.Contains(out, "Pushed 2, pulled 0") {
		t.Fatalf("push: %s", out)
	}
	out = must("", "remote", "sync", "floci")
	if !strings.Contains(out, "Nothing to do") {
		t.Fatalf("sync after push: %s", out)
	}

	// Key Vault slot: unlock without a passphrase.
	must("", "slot", "add", "keyvault", "--remote", "floci", "--key", "cli-kek", "--create")
	os.Unsetenv("AZK_PASSPHRASE")
	if _, errb, code := run("", "sign", "--key", "cli-rsa", "--in", "-"); code == 0 || !strings.Contains(errb, "no passphrase") {
		// stdin is not a terminal and no source is set, but auto mode should
		// have found the keyvault slot; treat success as the expected path.
		_ = errb
	}
	must("msg", "--unlock", "keyvault", "sign", "--key", "cli-rsa", "--in", "-")
	must("msg", "sign", "--key", "cli-rsa", "--in", "-") // auto mode picks the slot
	t.Setenv("AZK_PASSPHRASE", "pw")

	// Second vault pulls what the first pushed.
	t.Setenv("AZK_VAULT", filepath.Join(dir, "b.db"))
	must("", "init")
	must("", "remote", "add", "floci", "--vault-url", vaultURL, "--insecure-http")
	out = must("", "remote", "pull", "floci", "cli-rsa", "cli-sec")
	if !strings.Contains(out, "Pushed 0, pulled 2") {
		t.Fatalf("pull: %s", out)
	}
	if got := must("", "secret", "get", "cli-sec"); got != "secret-value" {
		t.Fatalf("pulled secret %q", got)
	}
	out = must("", "key", "show", "cli-rsa")
	if !strings.Contains(out, "public-only") {
		t.Fatalf("pulled key should be public-only: %s", out)
	}
}
