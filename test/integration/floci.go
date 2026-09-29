//go:build integration

// Package integration runs azk against floci-az, the local Azure emulator,
// using testcontainers. Build tag: integration. Needs Docker.
package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/danto7/azk/internal/remote/keyvault"
	"github.com/danto7/azk/internal/remote/keyvault/kvtest"
)

// Image is the pinned floci-az release. Bump deliberately; floci ships
// stable releases twice a month.
const Image = "floci/floci-az:0.13.0"

// Account is floci's default storage account, which names the emulated vault.
const Account = "devstoreaccount1"

// StartFlociAZ starts the emulator and returns the Key Vault URL. When
// AZK_TEST_VAULT_URL is set, that URL is used instead and no container is
// started, which allows running against `docker compose up` locally.
func StartFlociAZ(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("AZK_TEST_VAULT_URL"); u != "" {
		return u
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := testcontainers.Run(ctx, Image,
		testcontainers.WithExposedPorts("4577/tcp"),
		testcontainers.WithEnv(map[string]string{"FLOCI_AZ_STORAGE_MODE": "memory"}),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("4577/tcp").WithStartupTimeout(90*time.Second)),
	)
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("start %s: %v", Image, err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := ctr.MappedPort(ctx, "4577/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("http://%s:%s/%s-keyvault", host, port.Port(), Account)
}

// Target builds the scenario target for a floci vault. prefix isolates
// scenarios that share one container.
func Target(vaultURL, prefix string) kvtest.Target {
	return kvtest.Target{Config: keyvault.Config{VaultURL: vaultURL, InsecureHTTP: true}, Prefix: prefix}
}
