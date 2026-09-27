# azk — implementation plan

`azk` is a key manager that keeps key material on the local machine in encrypted
form, exposes it through a CLI and a local web interface, and can talk to Azure
Key Vault. Integration tests run against [floci-az](https://github.com/floci-io/floci-az),
the local Azure emulator, so no real Azure subscription is needed for development or CI.

## 1. Assumptions (please confirm or correct)

| # | Assumption | Why |
|---|------------|-----|
| A1 | **Azure Key Vault is the remote counterpart.** azk can push/pull keys and secrets to a Key Vault and can use a Key Vault key to wrap the local master key. | The repo is called `azk`, and floci only makes sense as a test tool if azk talks to a cloud API. Floci-az emulates Key Vault (keys, secrets, certificates, crypto ops). The local vault, CLI and web UI do **not** depend on this; it is milestone M3 and can be dropped or re-scoped. |
| A2 | **Go** is the implementation language. | Single static binary for CLI + embedded web UI, strong stdlib crypto, official Azure SDK (`azkeys`, `azsecrets`, `azidentity`), and `testcontainers-go` for floci. Your recent repos (gosume, sshp, go-imap) suggest Go is the comfortable choice. |
| A3 | **Single user, single machine.** The vault is a file owned by one OS user; there is no multi-tenant access control. | "Stores key material locally." The web UI is a local convenience, bound to loopback, not a hosted service. |
| A4 | **Item types:** symmetric keys (AES/`oct`), RSA, EC (P‑256/384/521), Ed25519, and opaque secrets (passwords, tokens, arbitrary bytes). | Mirrors what Key Vault models (keys + secrets), which keeps sync a 1:1 mapping. Certificates are out of scope for v1. |
| A5 | **Web UI is server-rendered** (Go `html/template` + htmx), embedded in the binary. | One toolchain, no Node build in the release path, trivially testable with Playwright. A SPA can replace it later behind the same JSON API. |

## 2. Threat model (what the encryption is for)

Protects against:
- Theft or backup leakage of the vault file (disk at rest). Everything sensitive is encrypted with an authenticated cipher; metadata that is needed for listing is plaintext but contains no material.
- Tampering with the vault file: every record is AEAD‑authenticated with the record id and version as associated data, so records cannot be swapped or rolled back undetected.
- Accidental exposure: exports require an explicit flag, key material never appears in logs, error messages, shell history (passphrase is prompted, never a positional arg).

Does not protect against:
- A compromised machine while the vault is unlocked (memory is best‑effort zeroed, nothing more).
- Weak passphrases beyond what Argon2id can compensate for.

## 3. Architecture

```
cmd/azk/                  CLI entry point (cobra)
internal/
  vault/                  file format, header, key slots, lock/unlock
  crypto/                 KDF (argon2id), AEAD (XChaCha20‑Poly1305), key generation, sign/encrypt/wrap
  store/                  SQLite persistence (modernc.org/sqlite, pure Go), migrations
  service/                application layer: use cases shared by CLI and HTTP
  remote/keyvault/        Azure Key Vault client: push, pull, sync, KEK wrap slot
  web/                    HTTP server, templates, static assets (embed.FS), session handling
  audit/                  append‑only audit log of operations
test/
  integration/            floci‑backed tests (build tag `integration`)
  e2e/                    Playwright tests against `azk serve`
```

### 3.1 Vault format

- One SQLite file, default `$XDG_DATA_HOME/azk/vault.db` (override with `--vault` / `AZK_VAULT`), mode 0600.
- **Envelope encryption.** A random 256‑bit Data Encryption Key (DEK) encrypts all material. The DEK is wrapped by one or more **key slots** (LUKS style):
  - `passphrase` slot: KEK = Argon2id(passphrase, salt; t=3, m=64 MiB, p=4, tunable and stored in the header).
  - `keyvault` slot (M3): DEK wrapped by an RSA key living in Azure Key Vault via `wrapKey`/`unwrapKey`. Unlocking then needs Azure credentials instead of a passphrase. This is the natural place to exercise floci's crypto operations.
- `header` table: format version, DEK id, KDF parameters, slots (each: type, salt, wrapped DEK, AEAD nonce).
- `items` table: `id`, `name` (unique), `kind` (oct/rsa/ec/ed25519/secret), `created_at`, `updated_at`, `deleted_at` (soft delete), `tags` (JSON), `remote_id` (Key Vault URL if synced).
- `versions` table: `item_id`, `version`, `created_at`, `enabled`, `not_before`, `expires`, `ciphertext`, `nonce`. AAD = `item_id || version`. Plaintext is a small CBOR/JSON document holding the material (JWK) plus attributes that must be tamper‑proof.
- Cipher: XChaCha20‑Poly1305 (24‑byte random nonces, no counter management). AES‑256‑GCM stays available for interop exports.
- Format version in the header, migrations in `store/`, and an `azk vault export --format=json` / `import` pair for forward migration and backups.

### 3.2 Unlock model

- CLI: prompts for the passphrase per invocation (also `AZK_PASSPHRASE_FILE` for scripts, never a CLI arg). Later (M5): an optional agent daemon on a Unix socket, `azk agent`, that holds the DEK for a configurable TTL, like `ssh-agent`.
- `azk serve`: unlocks once through the web login screen, holds the DEK in memory, auto‑locks after an idle timeout (default 15 min) and on SIGTERM.

### 3.3 CLI surface (v1)

```
azk init [--vault PATH]                       create vault, set passphrase
azk lock | azk status
azk key generate NAME --type rsa|ec|oct|ed25519 [--size|--curve] [--tag k=v]
azk key import  NAME --from FILE|- [--format pem|jwk|raw]
azk key export  NAME [--version N] [--format pem|jwk|raw] [--public] --i-know-this-exposes-the-private-key
azk key list [--kind] [--tag] [--deleted]
azk key show NAME [--version N]               metadata + public part only
azk key rotate NAME                           new version, old stays enabled unless --disable-old
azk key delete NAME | azk key recover NAME | azk key purge NAME
azk secret set|get|list|delete NAME           opaque secrets, same version/soft‑delete model
azk sign   --key NAME [--alg] < data          / azk verify
azk encrypt --key NAME < data                 / azk decrypt
azk wrap   --key NAME < key                   / azk unwrap
azk slot add passphrase | slot add keyvault --vault-url URL --key NAME | slot list | slot remove
azk remote add NAME --vault-url URL           (M3) configure a Key Vault
azk remote push|pull|sync [NAME] [--dry-run]  (M3)
azk audit tail
azk serve [--listen 127.0.0.1:7788] [--idle-timeout 15m]
```

Output: human tables by default, `--json` everywhere, exit codes documented.

### 3.4 Web interface

- Served by `azk serve`, loopback only by default; refuses to bind non‑loopback without `--insecure-listen`.
- Login screen (passphrase) → session cookie (HttpOnly, SameSite=Strict) + CSRF token; idle timeout; explicit lock button.
- Pages: dashboard (counts, lock state, last sync), items list with filters, item detail (metadata, versions, public key, tags), create/import/rotate/delete forms, secrets reveal‑on‑click with auto‑hide, audit log, remotes (M3) with push/pull/diff.
- htmx for partial updates, Pico CSS or Tailwind (pre‑built, committed) for styling; all assets embedded with `embed.FS`, no CDN.
- JSON API under `/api/v1/...` used by the pages and available to scripts; the CLI does **not** go through HTTP, both sit on `internal/service`.

### 3.5 Azure Key Vault remote (M3)

- Client via `azkeys`/`azsecrets` with `azidentity.DefaultAzureCredential` in production.
- **Push:** local key → Key Vault import (`PUT /keys/{name}`) for RSA/EC/oct, secret → Key Vault secret; stores the returned key id in `remote_id`. Ed25519 is not a Key Vault type, push is refused with a clear message.
- **Pull:** Key Vault secrets and *public* parts of keys → local (Key Vault never exports private material; the local copy is marked `public-only`).
- **Sync:** diff by name/version/updated timestamp, `--dry-run` prints the plan, conflicts are reported not auto‑resolved.
- **KEK slot:** `azk slot add keyvault` wraps the DEK with a Key Vault RSA key (RSA‑OAEP‑256); unlock calls `unwrapKey`.

## 4. Testing strategy (floci)

### 4.1 Layers

| Layer | Tooling | Needs Docker | Runs on |
|-------|---------|--------------|---------|
| Unit | `go test ./...` | no | every push |
| Property/fuzz | `testing/quick`, `go test -fuzz` for the vault format and PEM/JWK parsers | no | every push (short), nightly (long) |
| Integration (Key Vault) | `testcontainers-go` starting `floci/floci-az:<pinned>`; build tag `integration` | yes | every push on ubuntu runners |
| CLI end‑to‑end | `testscript` (rogpeppe/go-internal) scripts exercising the built binary against a temp vault | no | every push |
| Web e2e | Playwright (already pre‑installed here) against `azk serve` on a random port | no (Chromium) | every push |
| Interop | floci Key Vault as **reference implementation**: sign locally → verify in Key Vault, wrap in Key Vault → unwrap locally, and the reverse | yes | every push |

### 4.2 floci harness

`test/integration/floci.go` provides:

```go
func StartFlociAZ(t *testing.T) (vaultURL string)   // testcontainers GenericContainer,
                                                     // image floci/floci-az:X.Y.Z, port 4577,
                                                     // wait.ForListeningPort, FLOCI_AZ_STORAGE_MODE=memory
func NewTestCredential() azcore.TokenCredential      // returns a static fake bearer token
```

Details that matter with the Go SDK:
- floci‑az serves plain HTTP; the Go SDK refuses bearer auth over HTTP unless `azcore.ClientOptions{InsecureAllowCredentialWithHTTP: true}` is set, and challenge resource verification must be disabled with `azkeys.ClientOptions{DisableChallengeResourceVerification: true}`. Both are only enabled in the test harness / when the remote is flagged `--insecure-http`. Alternative: run floci with `FLOCI_AZ_TLS_ENABLED=true` and trust its cert from `GET /_floci/tls-cert`; decide in M0 based on which is less special‑casing.
- Vault URL pattern: `http://<host>:<port>/devstoreaccount1-keyvault`.
- Any bearer token is accepted in dev mode, so the fake credential just returns `"floci"`.
- Docker socket is **not** needed for Key Vault, so the container runs unprivileged in CI.
- Image tag is pinned and bumped by Dependabot/Renovate; floci ships stable releases twice a month.

`docker-compose.yml` at the repo root starts the same floci‑az for manual development (`azk remote add dev --vault-url http://localhost:4577/devstoreaccount1-keyvault --insecure-http`).

### 4.3 What the integration suite covers

1. Push every supported key type, read it back through the Key Vault API, compare public JWK.
2. Push a secret, rotate locally, push again → two versions in Key Vault.
3. Pull: secrets round‑trip byte‑for‑byte; keys arrive public‑only.
4. Sync dry‑run output is stable (golden file) and a real sync reconciles.
5. KEK slot: add, lock, unlock through floci `unwrapKey`; remove slot; vault still opens with passphrase.
6. Interop: RS256/ES256 signatures and RSA‑OAEP‑256 wrapping cross‑verify between azk and Key Vault.
7. Failure modes: Key Vault unreachable mid‑sync leaves the local vault unchanged (transactional).

### 4.4 CI

GitHub Actions `ci.yml`: `go vet`, `golangci-lint`, `go test -race ./...`, `go test -tags integration ./test/integration/...` (Docker is available on `ubuntu-latest`), Playwright e2e, `govulncheck`. A `release.yml` with goreleaser builds linux/darwin/windows binaries on tags.

## 5. Milestones

| M | Deliverable | Definition of done |
|---|-------------|--------------------|
| M0 Scaffold | Go module, `cmd/azk` hello, Makefile/justfile, golangci config, CI, docker‑compose with floci‑az, testcontainers harness proven by one smoke test that lists secrets on floci, `CLAUDE.md` with build/test commands | CI green with the floci smoke test |
| M1 Vault core | `internal/crypto`, `internal/vault`, `internal/store`; `azk init/status/lock`; item + version CRUD via `internal/service`; fuzz tests for the format | Unit + fuzz tests, a vault created on one OS opens on another |
| M2 CLI | All `key`, `secret`, `sign/verify/encrypt/decrypt/wrap/unwrap`, `slot add passphrase`, `audit` commands; import/export PEM/JWK; `--json`; testscript suite | testscript coverage for every command, docs in `README.md` |
| M3 Key Vault remote | `internal/remote/keyvault`, `remote add/push/pull/sync`, `slot add keyvault`; full floci integration suite from §4.3 | Integration suite green in CI against pinned floci‑az |
| M4 Web UI | `azk serve`, login/lock, list/detail/create/import/rotate/delete, secrets reveal, audit, remotes page; Playwright e2e | e2e green, UI works with JS disabled for read paths |
| M5 Hardening & release | agent daemon, idle auto‑lock everywhere, memory zeroing, backup/restore, goreleaser, threat‑model doc, `SECURITY.md` | Tagged v0.1.0 with binaries |

Rough sizing: M0 1 day, M1 3–4 days, M2 2–3 days, M3 3–4 days, M4 4–5 days, M5 2–3 days.

## 6. Open questions

1. Confirm A1: should Key Vault be a full remote (push/pull/sync + KEK slot), or only one direction (e.g. backup‑to‑Key‑Vault only)?
2. Confirm A2 (Go) and A5 (server‑rendered UI). If you prefer a SPA (Svelte/React + TS), M4 grows by ~2 days and adds a Node build step.
3. Are certificates (Key Vault `certificates/`) needed in v1? Floci supports self‑signed issuance, so tests are cheap, but the local model gets larger.
4. Should the web UI ever be reachable from another machine (needs TLS + real auth), or is loopback‑only a hard rule?
5. Passphrase‑less unlock on trusted machines (OS keychain / TPM) — v1 or later?

## 7. Status and deviations (updated as milestones land)

All milestones M0 to M4 are implemented. Deviations from the plan above:

- `RSA1_5` is not supported; Go 1.26 deprecates PKCS#1 v1.5 encryption for
  good reason.
- Private export uses `--reveal-private` rather than the longer flag proposed.
- `azk serve --listen` on a non-loopback address additionally requires
  `--allow-remote`; the server is served without TLS and says so.
- Unlock mode is a global `--unlock auto|passphrase|keyvault` (`AZK_UNLOCK`).
- The Go SDK cannot send credentials over plain HTTP, so the emulator is
  reached through an https client URL and a transport that downgrades the
  scheme on the wire (the same trick floci documents for other SDKs).
- Sync logic is unit tested against an in-memory fake Key Vault
  (`internal/remote/keyvault/kvtest`) in addition to floci, so it runs
  without Docker. The floci suite runs the same scenarios.
- The agent daemon and OS keychain unlock from M5 are not started.
