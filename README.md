# Crypto Pigeon

Crypto Pigeon is an independent, single-device end-to-end encrypted messaging MVP. Each user runs a local daemon that owns the vault and Signal private material; a PostgreSQL-backed relay stores public prekeys and opaque, temporary ciphertext envelopes.

> **Security status:** this is an independent implementation using `@signalapp/libsignal-client` 0.96.4. It is not audited, endorsed by, or equivalent to Signal. Do not rely on it for safety-critical communications without an independent security review and a production deployment review.

## Contents

- [What runs where](#what-runs-where)
- [Architecture and data flow](#architecture-and-data-flow)
- [Security model](#security-model)
- [Requirements](#requirements)
- [Environment configuration](#environment-configuration)
- [Install, build, and run](#install-build-and-run)
- [User and administrator workflow](#user-and-administrator-workflow)
- [API and storage map](#api-and-storage-map)
- [Development commands](#development-commands)
- [Testing and verification](#testing-and-verification)
- [Operations and deployment](#operations-and-deployment)
- [Limitations](#limitations)

## What runs where

| Component | Location | Responsibility | May handle plaintext/private keys? |
|---|---|---|---|
| `apps/local-ui` | User's browser, served by the daemon | Displays UI and submits local API requests | Displays plaintext after daemon decrypts it; no private keys are sent to it |
| `apps/local-daemon` | User's computer, `127.0.0.1` only | Vault, Signal operations, attachment crypto, relay client | Yes |
| `apps/relay-server` | Relay host | Access approval state, public prekeys, queue, attachment ciphertext blobs | No plaintext or private keys |
| PostgreSQL | Relay host | Durable relay metadata/ciphertext storage | Ciphertexts, routing and account metadata only |
| `apps/admin-cli` | Trusted administrator workstation | Approves/rejects access and issues activation codes | No message content |
| `packages/protocol` | Shared code | Wire schemas and device-auth signing helpers | No persistent state |
| `packages/shared-types` | Shared code | Type definitions for payloads/manifests | No persistent state |

## Architecture and data flow

```mermaid
flowchart LR
  UI["React local UI"] -->|"HTTP: cookie + CSRF"| D["Local daemon\n127.0.0.1:random port"]
  D -->|"encrypted vault / SQLCipher"| V["Local vault"]
  D -->|"TLS in production\nchallenge-authenticated HTTP / WebSocket"| R["Relay server"]
  R --> P["PostgreSQL"]
  A["Admin CLI"] -->|"trusted DB connection"| P
  D2["Recipient local daemon"] <-->|"opaque ciphertext envelopes"| R
```

### Repository map

```text
apps/
  admin-cli/       Database-backed access administration
  local-daemon/    Vault, Signal adapter/store, relay client, local API
  local-ui/        React/Vite UI built and served by the daemon
  relay-server/    Fastify relay, PostgreSQL schema, queue, prekeys, blobs
packages/
  protocol/        Zod request schemas and Ed25519 helpers
  shared-types/    Shared TypeScript interfaces
  tests/           Core cryptographic/validation checks
docs/              Architecture, protocol flow, threat model, deployment notes
```

### End-to-end message path

1. The sender unlocks their vault locally; the daemon creates/loads Signal identity keys, signed prekeys, one-time prekeys, PQ prekeys, and the separate device-auth Ed25519 key.
2. The sender requests the recipient's prekey bundle from the relay. The relay atomically consumes eligible one-time prekeys.
3. The daemon pins the recipient identity key on first contact (TOFU), establishes the Signal session, and creates an E2EE payload.
4. The Signal ciphertext is placed in a `RelayEnvelopeV1`: a random 128-bit envelope ID, recipient mailbox/device ID, and opaque ciphertext.
5. The authenticated relay checks that the two accounts have an approved conversation permission, stores the envelope with a server-side 30-day TTL, and optionally pushes a notification over WebSocket.
6. The recipient daemon fetches pending envelopes, decrypts locally, writes the message and deduplication record in a durable vault transaction, then acknowledges the envelope. The relay deletes it only after that acknowledgement.

### Key-domain mapping

| Domain | Generated/derived from | Used for | Never used for |
|---|---|---|---|
| Vault master key (VMK) | Random 256-bit value | Root local secret | Relay authentication, message transport |
| Vault subkeys | HKDF-SHA256(VMK, separate salt, context) | SQLCipher, local field/attachment/token domains | Signal or relay signing |
| Signal identity/prekeys | libsignal APIs | Signal session establishment and ratchet state | Generic signing or relay authentication |
| Device-auth Ed25519 key | Node crypto / protocol helper | Relay challenge-response only | Signal encryption/identity |
| Attachment AES key | Random per attachment | AES-256-GCM chunk encryption | Vault or message/session key reuse |

## Security model

### Local vault

- A vault password must be at least 12 characters, include upper/lowercase letters and a digit, and not match the bundled common-password list.
- Argon2id derives a KEK with a baseline of 64 MiB memory, 3 iterations, and parallelism 1.
- The KEK unwraps a random VMK using AES-256-GCM with AAD `vmk-wrap-v1`.
- Distinct HKDF-SHA256 contexts derive the SQLCipher, field, attachment-metadata, and local-token keys.
- Changing the vault password re-wraps the VMK; it does not bulk re-encrypt the database.
- Vault files are stored in `CRYPTO_PIGEON_HOME` (default `%USERPROFILE%\.crypto_pigeon` on Windows) and permissions are tightened best-effort on startup.
- Locking zeroes in-memory derived buffers, closes the database, and invalidates the local browser session.

### Local browser API

- The daemon binds only to `127.0.0.1` on a random available port.
- Startup prints `http://127.0.0.1:PORT/bootstrap#SECRET`; the 256-bit fragment secret is consumed once by `POST /api/bootstrap`.
- A successful bootstrap receives an HttpOnly, `SameSite=Strict` cookie and an in-memory CSRF token.
- Requests are bound to `Host: 127.0.0.1:PORT`; non-local host headers and non-local Origins are rejected.
- Security headers include CSP, no-sniff, no-frame, no-referrer, no-cache, COOP/CORP, and restrictive permissions policy.

### Relay authentication and prekeys

- Devices authenticate to the relay with a 60-second, single-use random challenge signed by the separate Ed25519 device-auth key.
- The signed challenge includes the configured relay hostname. Set `RELAY_HOSTNAME` to the exact hostname and port clients use.
- Signal identity keys remain opaque serialized libsignal values. They are not converted into relay-auth keys.
- The relay uses transactional `FOR UPDATE SKIP LOCKED` consumption for classical/PQ one-time prekeys. If PQ inventory is exhausted, the signed last-resort PQ prekey is returned without being consumed.
- Local identity pinning is authoritative for identity-change detection. A changed key blocks automatic session replacement until explicit user action.

### Attachments

- Files are limited by the daemon/relay body limit to 25 MiB.
- A fresh AES-256-GCM key encrypts each attachment in 64 KiB chunks.
- Every chunk has a random 12-byte nonce and authenticated data containing attachment ID, chunk index, chunk count, and protocol version.
- The E2EE attachment manifest carries the key, nonces, filename, MIME claim, size, and SHA-256 digest. The relay receives only encrypted chunks and blob metadata.
- Download verifies GCM authentication, chunk ordering/count, and the complete plaintext digest.

## Requirements

- Node.js **22+** (`node --version`)
- npm (bundled with Node.js)
- Docker Desktop/Engine with Docker Compose, for PostgreSQL and optionally the relay
- A modern browser for the local UI
- On Windows PowerShell, use `npm.cmd` if execution policy blocks `npm.ps1`.

## Environment configuration

Copy [.env.example](.env.example) to `.env`; never commit `.env`.

```powershell
Copy-Item .env.example .env
```

Generate secret values with Node:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

### Root `.env` values

| Variable | Required | Used by | Meaning |
|---|---:|---|---|
| `POSTGRES_PASSWORD` | Yes | Docker Compose | Password for the `crypto_pigeon` PostgreSQL role |
| `ADMIN_USERNAME` | Yes | Relay | Admin dashboard username |
| `ADMIN_TOKEN` | Yes, 32+ chars | Relay | Admin dashboard/API credential; use a high-entropy secret |
| `ACTIVATION_PEPPER` | Yes, 32+ chars | Relay and admin CLI | Secret HMAC key for activation-code verification; must be identical in both environments |
| `RELAY_URL` | Client only | Local daemon | Client-visible relay base URL; default `http://127.0.0.1:8443` |
| `CRYPTO_PIGEON_HOME` | No | Local daemon | Absolute vault directory; defaults to the user's `.crypto_pigeon` directory |
| `DATABASE_URL` | Admin CLI/manual relay only | Admin CLI / relay | PostgreSQL URL. Docker Compose supplies it to the relay automatically. |
| `RELAY_HOSTNAME` | Production recommended | Relay | Exact `host:port` included in device challenge signatures. Default is `HOST:PORT`. |
| `HOST` | No | Relay | Bind address; default `127.0.0.1` |
| `PORT` | No | Relay/local daemon | Relay port (default `8443`) or daemon port (`0` means random) |
| `LOG_LEVEL` | No | Relay | `debug`, `info`, `warn`, or `error`; production should normally use `warn` |

### Example development `.env`

```dotenv
POSTGRES_PASSWORD=replace-with-a-long-random-password
ADMIN_USERNAME=admin
ADMIN_TOKEN=replace-with-a-random-32-byte-or-longer-admin-token
ACTIVATION_PEPPER=replace-with-a-separate-random-32-byte-or-longer-secret
RELAY_URL=http://127.0.0.1:8443
# CRYPTO_PIGEON_HOME=C:\Users\you\.crypto_pigeon
```

`docker-compose.yml` passes `RELAY_HOSTNAME=127.0.0.1:8443` to the container. For a public relay, use the externally visible hostname and terminate TLS before exposing it.

## Install, build, and run

All commands below are run from the repository root.

### 1. Install dependencies and build

```powershell
npm.cmd install
npm.cmd run build
```

### 2. Start PostgreSQL and the relay

The simplest local path starts both services in Docker:

```powershell
docker compose up --build -d
docker compose ps
```

The relay is available at `http://127.0.0.1:8443`; its health check is `GET /healthz`.

To use a locally running relay instead, start only PostgreSQL, then export the relay variables and run it:

```powershell
docker compose up -d postgres
$env:DATABASE_URL = 'postgresql://crypto_pigeon:YOUR_POSTGRES_PASSWORD@127.0.0.1:5432/crypto_pigeon'
$env:ADMIN_USERNAME = 'admin'
$env:ADMIN_TOKEN = 'YOUR_32_PLUS_CHARACTER_ADMIN_TOKEN'
$env:ACTIVATION_PEPPER = 'YOUR_32_PLUS_CHARACTER_ACTIVATION_PEPPER'
$env:RELAY_HOSTNAME = '127.0.0.1:8443'
npm.cmd run dev:relay
```

### 3. Start a local daemon and open the UI

In another terminal:

```powershell
$env:RELAY_URL = 'http://127.0.0.1:8443'
npm.cmd run dev:daemon
```

The daemon prints a single-use bootstrap URL. Open the exact URL it prints in the same computer's browser. Create a vault on first use or unlock the existing vault.

For a second test user, use a separate vault directory and terminal:

```powershell
$env:CRYPTO_PIGEON_HOME = "$env:TEMP\crypto-pigeon-user-b"
$env:RELAY_URL = 'http://127.0.0.1:8443'
npm.cmd run dev:daemon
```

### 4. Stop services

```powershell
docker compose down
```

`docker compose down -v` also deletes the PostgreSQL volume and all relay state. Use it only when intentionally resetting local development data.

## User and administrator workflow

### Account activation

1. In the local UI, create/unlock a vault and submit a username access request.
2. On the trusted administrator workstation, export both `DATABASE_URL` and the **same** `ACTIVATION_PEPPER` used by the relay.
3. List requests and approve the target request. The CLI prints the one-time code once; give it to the user through an appropriate secure channel.
4. The user enters the request ID and activation code in the local UI. The daemon generates local keys, uploads only public identity/prekey/device-auth material, and stores the relay account ID in its vault.

```powershell
$env:DATABASE_URL = 'postgresql://crypto_pigeon:YOUR_POSTGRES_PASSWORD@127.0.0.1:5432/crypto_pigeon'
$env:ACTIVATION_PEPPER = 'THE_SAME_RELAY_ACTIVATION_PEPPER'

npm.cmd run admin -- requests
npm.cmd run admin -- inspect <request-id>
npm.cmd run admin -- approve <request-id>
npm.cmd run admin -- reject <request-id>
npm.cmd run admin -- revoke <user-id>
```

Activation codes are random 128-bit values, expire after 10 minutes, become invalid after use, and are stored as HMAC-SHA256 values keyed by `ACTIVATION_PEPPER`. The relay limits failed attempts per request.

### Conversation and message workflow

1. Add a contact by exact username in the local UI.
2. The relay must authorize the conversation pair before a prekey bundle can be used.
3. Check and compare the displayed safety number out-of-band before treating a contact as verified.
4. Send text, attachments, or voice-note data. The daemon encrypts before any relay request.
5. Use **Fetch messages** / normal UI synchronization on the recipient. The recipient vault commits before relay acknowledgement.

## API and storage map

The local API is intentionally local-only and is not a public integration API. It uses the bootstrap cookie and CSRF header for authenticated operations.

### Local daemon API (selected routes)

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/bootstrap` | Consume fragment secret; establish local browser session |
| `GET` | `/api/session` | Refresh in-memory CSRF token for a valid session |
| `GET` | `/api/vault/status` | Return unconfigured/locked/unlocked state |
| `POST` | `/api/vault/create`, `/api/vault/open`, `/api/vault/lock` | Vault lifecycle |
| `POST` | `/api/vault/change-password` | Re-wrap VMK with a new password |
| `POST` | `/api/access/apply`, `/api/access/activate` | Account request and activation |
| `GET`/`POST` | `/api/contacts`, `/api/contacts/add` | Local contact/session management |
| `POST`/`GET` | `/api/send`, `/api/messages/:conversationId`, `/api/fetch-messages` | Send, read, and synchronize messages |
| `POST`/`GET` | `/api/attachments/encrypt`, `/api/attachments/:attachmentId/decrypt` | Local attachment operations |

### Relay API (selected routes)

| Route group | Purpose |
|---|---|
| `/api/access/*` | Access-request submission and activation |
| `/api/auth/challenge`, `/api/auth/respond` | Device-auth challenge response |
| `/api/prekeys/*` | Signed/one-time/PQ prekey upload, inventory, and atomic bundle retrieval |
| `/api/messages/*` | Queue send, pending fetch, durable acknowledgement |
| `/api/attachments/*` | Encrypted blob metadata/chunk upload, fetch, and deletion |
| `/api/admin/*`, `/admin` | Admin dashboard routes |
| `/healthz` | Relay liveness response |

### Data placement

| Data | Local vault | Relay database |
|---|---:|---:|
| Vault password / VMK | Yes | Never |
| Signal private identity, prekeys, session state | Yes | Never |
| Device-auth private key | Yes | Never |
| Public identity and prekeys | Local copy | Yes |
| Message plaintext | Yes | Never |
| Relay envelope ciphertext | Temporary local processing | Yes, until acknowledgement/TTL |
| Attachment plaintext | Local encrypted-at-rest file | Never |
| Attachment encrypted chunks | Optional local cache | Yes |
| Usernames, account/device IDs, queue timing | Local contact metadata | Yes |

## Development commands

```powershell
npm.cmd run build       # Compile all workspaces; build the Vite UI
npm.cmd run typecheck   # Alias for the workspace TypeScript build
npm.cmd run test        # Run available workspace tests
npm.cmd run dev:relay   # Run relay with tsx watch
npm.cmd run dev:daemon  # Run local daemon with tsx watch
npm.cmd run dev:ui      # Run Vite UI separately (development only)
npm.cmd run admin -- requests
```

The daemon serves the production UI from `apps/local-ui/dist`, so run `npm.cmd run build` before using `dev:daemon` if the UI has changed.

## Testing and verification

Run the automated build and core test suite:

```powershell
npm.cmd run build
npm.cmd run test
git diff --check
```

The current automated suite covers password policy, Argon2id/VMK wrapping, HKDF key separation, device-auth signing, attachment filename sanitization, and chunk AAD layout. It is **not** a substitute for an end-to-end security audit or full integration test environment.

For a manual canary check, send a unique plaintext string through an activated conversation, then inspect the relay database/logs for it. The relay `messages.encrypted_payload` and attachment chunk columns should contain ciphertext, not the canary. This is evidence-based verification, not proof that plaintext can never leak through infrastructure or future code changes.

## Operations and deployment

- Use HTTPS/WSS and set `RELAY_URL` to the public HTTPS origin in any networked deployment.
- Set `RELAY_HOSTNAME` to the exact public `host:port` clients use; otherwise device challenge authentication will fail.
- Keep `ACTIVATION_PEPPER` in a secrets manager and make it available to both the relay and the trusted admin CLI. Rotating it requires a planned compatibility process for outstanding activation codes.
- Do not use development defaults, expose PostgreSQL publicly, or put the admin dashboard behind an untrusted network boundary without further hardening.
- Configure reverse proxies, containers, and hosts not to retain request/access logs if metadata minimization is required. The application itself aims not to log IP addresses, but surrounding infrastructure can.
- Back up the relay database according to your operational needs. A local vault backup without its passphrase is not recoverable; a passphrase compromise defeats its confidentiality.
- Monitor prekey inventory and relay health. Queue expiry is determined by relay receipt time, not a client-provided expiry.

## Limitations

- This is unaudited and not Signal-equivalent.
- The MVP is one active device per user; it is not a linked-device or multi-device implementation.
- TOFU cannot detect a malicious relay substitution on first contact without out-of-band safety-number verification.
- The relay and network infrastructure can observe IP addresses, connection times, recipient routing IDs, encrypted sizes, online presence, queue activity, usernames used for lookup, and attachment timing/size.
- No sealed-sender scheme or traffic-analysis resistance is provided.
- Disappearing messages are best-effort local deletion, not protection against screenshots, compromised endpoints, backups, or modified clients.
- Endpoint malware, browser extensions, screen capture, weak passwords, denial of service, and malicious infrastructure remain outside the E2EE guarantee.
- The precise continuous post-quantum-ratchet behavior of the pinned libsignal version has not been independently verified here; do not claim continuous PQ forward secrecy.

## License

Crypto Pigeon is intended to be distributed under **AGPL-3.0**. Network users must be offered the corresponding source for modified AGPL-covered components. Add and maintain a repository `LICENSE` file before distributing the project.

## Further documentation

- [Architecture](docs/architecture.md)
- [Protocol flow](docs/protocol-flow.md)
- [Threat model](docs/threat-model.md)
- [Deployment notes](docs/deployment.md)
