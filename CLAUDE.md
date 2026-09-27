# azk

Local key manager: keys and secrets in an encrypted SQLite vault, CLI and web
UI, optional Azure Key Vault sync. See PLAN.md for the design.

## Layout

- `cmd/azk` — main; all logic lives in `internal/cli`.
- `internal/crypto` — JWK model, key generation, Argon2id/XChaCha20 vault crypto, JOSE-style sign/encrypt/wrap ops.
- `internal/store` — SQLite persistence (modernc.org/sqlite, pure Go). Only ciphertext for material.
- `internal/vault` — DEK, key slots (passphrase / keyvault), Seal/Open.
- `internal/service` — use cases shared by CLI and web; audit log.
- `internal/remote/keyvault` — Azure Key Vault push/pull/sync and the keyvault unlock slot.
- `internal/web` — `azk serve`: Go templates + htmx, embedded.
- `test/cli` — testscript suites (`testdata/*.txt`), run as part of `go test ./...`.
- `test/integration` — floci-az backed tests, build tag `integration`, need Docker.
- `test/e2e` — Playwright against `azk serve`.

## Commands

```
make build            # bin/azk
make test             # go test -race ./...
make lint             # golangci-lint
make vet              # includes -tags integration so the floci tests compile
make test-integration # needs Docker (starts floci/floci-az)
make e2e              # Playwright
```

## Conventions

- Item names follow Key Vault rules (`[a-zA-Z0-9-]{1,127}`) so everything can sync.
- Algorithm names are JOSE / Key Vault names (RS256, ES256, RSA-OAEP-256, A256GCM, A256KW).
- Every stored record is sealed with AAD tying it to its row; never store material outside `vault.Seal`.
- Private material never goes to logs, error strings or audit details.
- Tests use fast Argon2 parameters via `AZK_KDF_TIME=1 AZK_KDF_MEMORY=8192 AZK_KDF_THREADS=1`, set by the testscript harness.
- Passphrase for tests: `AZK_PASSPHRASE` env. It is documented as insecure for real use.
