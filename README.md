# azk

`azk` keeps cryptographic keys and secrets in an encrypted vault file on your
machine, works with them from the command line or a local web interface, and
can push and pull them to Azure Key Vault. Tests run against
[floci-az](https://github.com/floci-io/floci-az), a local Azure emulator, so
no Azure subscription is needed for development.

- Keys: RSA, EC (P-256/384/521), Ed25519, AES. Secrets: opaque values.
- Operations: sign/verify, encrypt/decrypt, wrap/unwrap with JOSE algorithm
  names (RS256, ES256, RSA-OAEP-256, A256GCM, A256KW, …), so results are
  interchangeable with Key Vault.
- Versions, soft delete, tags, activation and expiry, audit log.
- Vault encryption: XChaCha20-Poly1305 with a data key wrapped by one or more
  unlock slots (Argon2id passphrase, or an RSA key in Azure Key Vault).

## Install

```
go install github.com/danto7/azk/cmd/azk@latest
```

or `make build` for `bin/azk`.

## Quick start

```sh
azk init                                  # creates ~/.local/share/azk/vault.db
azk key generate signing --type ec --curve P-256 --tag env=dev
azk key list
echo -n "release 1.2.3" | azk sign --key signing > sig.b64
echo -n "release 1.2.3" | azk verify --key signing --signature @sig.b64
azk key export signing                    # public PEM; --reveal-private for the private key
azk secret set db-pass --from -           # reads the value from stdin
azk secret get db-pass
azk key rotate signing --disable-old
azk audit tail
```

Every command takes `--json`. The vault path comes from `--vault`, `AZK_VAULT`,
or the XDG data directory. The passphrase is prompted, read from
`AZK_PASSPHRASE_FILE` (`--passphrase-file`), or taken from `AZK_PASSPHRASE`
(convenient for scripts, but visible in the environment).

### Encrypt and decrypt

```sh
azk key generate data --type oct --bits 256
azk encrypt --key data --in report.pdf --out report.enc   # JSON envelope with iv/tag
azk decrypt --in report.enc --out report.pdf              # key and algorithm come from the envelope
```

## Web interface

```sh
azk serve                     # http://127.0.0.1:7788
azk serve --listen 0.0.0.0:7788 --allow-remote   # no TLS; put a proxy in front
```

The server starts locked. The login page unlocks the vault with the passphrase
(or through a Key Vault slot). It locks again after `--idle-timeout`
(15 minutes by default), on the Lock button, and on shutdown. Secrets are
revealed on demand, hidden again after 30 seconds, and every reveal is audited.
Private key material is deliberately not shown in the browser; use
`azk key export --reveal-private`.

A small JSON API is available to a logged-in session under `/api/v1`
(`status`, `items`, `items/{name}`, `audit`, `lock`).

## Azure Key Vault

```sh
azk remote add prod --vault-url https://myvault.vault.azure.net
azk remote push prod --dry-run     # show what would be uploaded
azk remote sync prod               # push local versions, pull remote ones
```

- Push imports each local key version into Key Vault as a new version and
  stores each secret version. Ed25519 keys are skipped (Key Vault has no
  such type), as are public-only keys.
- Pull downloads secrets and the public part of keys (Key Vault never releases
  private material); pulled keys are marked `public-only`. Symmetric keys are
  skipped because Key Vault does not export them.
- A name that is a key locally and a secret remotely (or vice versa) is
  reported as a conflict and left alone.

Credentials come from `DefaultAzureCredential` (environment variables, managed
identity, Azure CLI login). `AZK_AZURE_TOKEN=<token>` uses a static bearer
token instead, which is what the emulator expects.

### Unlocking with Key Vault

```sh
azk slot add keyvault --remote prod --key azk-kek --create
azk --unlock keyvault key list       # or AZK_UNLOCK=keyvault
```

This wraps the vault's data key with an RSA key in Key Vault. Anyone who can
call `unwrapKey` on that key can open the vault without the passphrase, which
is useful for CI and servers. Remove the slot with `azk slot remove`. In `auto`
mode a Key Vault slot is used whenever no passphrase source is configured and
there is no terminal to prompt on.

### Local emulator

```sh
docker compose up -d
export AZK_AZURE_TOKEN=floci
azk remote add dev --vault-url http://localhost:4577/devstoreaccount1-keyvault --insecure-http
azk remote sync dev
```

## Security notes

- The vault is a SQLite file with mode 0600. Names, kinds, tags and timestamps
  are stored in the clear so listing works without unlocking; all key and
  secret material is encrypted with a random 256-bit data key.
- Each record is authenticated together with its row identity, so ciphertexts
  cannot be swapped between items or versions without detection.
- Passphrase slots use Argon2id (64 MiB, 3 passes by default; tunable with
  `--kdf-*` flags or `AZK_KDF_*` variables and stored per slot).
- Unlocked material lives only in process memory and is zeroed on a best-effort
  basis. A compromised machine with an unlocked vault is out of scope.
- RSA1_5 is not offered: PKCS#1 v1.5 encryption is padding-oracle prone.

## Development

```
make test              # unit tests, fake-Key-Vault sync tests, CLI testscripts
make lint              # golangci-lint
make test-integration  # floci-az via testcontainers (needs Docker)
make e2e               # Playwright against azk serve
```

See `PLAN.md` for the design and `CLAUDE.md` for the layout.

## License

MIT
