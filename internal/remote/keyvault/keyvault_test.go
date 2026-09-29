package keyvault_test

import (
	"testing"

	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/remote/keyvault/kvtest"
)

func fakeTarget(t *testing.T) kvtest.Target {
	t.Helper()
	f := kvtest.NewFake()
	t.Cleanup(f.Server.Close)
	return kvtest.Target{Config: keyvault.Config{VaultURL: f.URL(), InsecureHTTP: true}}
}

func TestPushPull(t *testing.T)    { kvtest.PushPull(t, fakeTarget(t)) }
func TestConflict(t *testing.T)    { kvtest.Conflict(t, fakeTarget(t)) }
func TestSlot(t *testing.T)        { kvtest.Slot(t, fakeTarget(t)) }
func TestInterop(t *testing.T)     { kvtest.Interop(t, fakeTarget(t)) }
func TestUnreachable(t *testing.T) { kvtest.Unreachable(t) }

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		cfg keyvault.Config
		ok  bool
	}{
		{keyvault.Config{VaultURL: "https://v.vault.azure.net"}, true},
		{keyvault.Config{VaultURL: "http://localhost:4577/devstoreaccount1-keyvault"}, false},
		{keyvault.Config{VaultURL: "http://localhost:4577/devstoreaccount1-keyvault", InsecureHTTP: true}, true},
		{keyvault.Config{VaultURL: "ftp://x"}, false},
		{keyvault.Config{VaultURL: "nonsense"}, false},
	}
	for _, c := range cases {
		if err := c.cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v", c.cfg, err)
		}
	}
}
