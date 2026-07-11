# Crypto Pigeon (Final v3 Specifications)

An independent, privacy-first end-to-end encrypted (E2EE) messaging application utilizing `libsignal-client`-based sessions, SQLCipher database storage, a randomized master key vault hierarchy, and a modular monorepo structure.

---

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [Security Architecture & Algorithms](#2-security-architecture--algorithms)
3. [Setup & Running Locally](#3-setup--running-locally)
4. [Administrative Commands](#4-administrative-commands)
5. [Canary-Based Verification](#5-canary-based-verification)
6. [AGPL-3.0 Compliance](#6-agpl-30-compliance)

---

## 1. Architecture Overview

Crypto Pigeon is organized as a modular TypeScript monorepo with the following workspace configuration:

```
├── apps
│   ├── admin-cli       # Administrative command-line tool for access requests
│   ├── local-daemon    # Local Node.js background process (SQLCipher, libsignal, Local API)
│   ├── local-ui        # React + Vite browser UI served locally by the daemon
│   └── relay-server    # Fastify + PostgreSQL + WS centralized routing server
└── packages
    ├── protocol        # Common Zod validation schemas and cryptographic signature helpers
    ├── shared-types    # Global TypeScript interfaces (manifests, payloads, vault states)
    └── tests           # Core automated test suite executing E2EE validations
```

### Protocol Flow
1. **Bootstrap**: Client connects to local daemon via port randomized on start, authenticating using a single-use 256-bit bootstrap secret fragment `#secret`.
2. **Access & Activation**: User requests username approval -> approved via `admin-cli` -> activated via single-use activation code.
3. **Session Establishment**: Prekey bundles (including Kyber post-quantum prekeys) are fetched from the relay and classical/PQ Signal sessions are negotiated.
4. **Messaging**: Payload envelopes are encrypted, routed through the relay, committed durably to the client's SQLCipher database, and acknowledged.

---

## 2. Security Architecture & Algorithms

### Domain 1: Local Vault & Key Hierarchy
* **KEK Derivation**: Derived from a passphrase (checked against weak/common lists) using **Argon2id** (memory cost: 64MB, time cost: 3, parallelism: 1).
* **Vault Master Key (VMK)**: A cryptographically random 256-bit key. Changing the vault password only re-encrypts the VMK using the KEK via **AES-256-GCM** (with AAD `"vmk-wrap-v1"`), meaning database re-encryption is never needed on password changes.
* **Subkey Derivation**: Key derivation from the VMK is done using **HKDF-SHA256** with distinct context strings:
  - `"sqlcipher-key-v1"` -> SQLCipher database key
  - `"field-aead-v1"` -> Field-level encryption key
  - `"attachment-meta-v1"` -> Attachment metadata encryption
  - `"local-token-v1"` -> Local session validation
* **File Protections**: Restricts directory access dynamically on start (Windows `icacls`, Unix `chmod 700`).

### Domain 2: Signal Protocol Integration
* **Library**: Bound to `@signalapp/libsignal-client` version `0.96.4`.
* **Trust On First Use (TOFU)**: The recipient client pins contact identity keys. If an identity key changes, the local daemon flags the contact as `identity_changed` and blocks E2EE session replacing until verified out-of-band.
* **Safety Numbers**: Numeric Fingerprints are calculated out-of-band via libsignal's `Fingerprint.new` using local/remote keys and identity addresses.

### Domain 3: Relay Authentication
* **Device Authentication Key**: Relay challenge-responses are signed using a dedicated **Ed25519 device auth keypair**, completely separate from the Signal identity key.
* **Challenge Expiry**: Cryptographically random challenges expire after 60 seconds and are single-use.
* **Atomic Prekey Consumption**: Fetches client prekey bundles atomically using transactional locks (`FOR UPDATE SKIP LOCKED`) to prevent double-allocation during concurrent message attempts.

### Domain 4: Messaging & Queue Logic
* **Ciphertext Packaging**: Standard message payload is packed into an indivisible combined byte format: `1-byte ciphertext type || libsignal ciphertext bytes`.
* **Durable Sync Commit-Ack**: Incoming envelopes are decrypted, committed within a SQLCipher transaction (with `PRAGMA synchronous = FULL`), added to `seen_envelope_ids` to suppress duplicate deliveries, and only then acknowledged (ACK) back to the relay server.

### Domain 5: Attachment Security
* **Format**: Attachments are chunked into **64KB blocks** and encrypted with a random **AES-256-GCM** key.
* **AAD Format**: `attachmentId (16 bytes) || chunkIndex (4 bytesBE) || totalChunkCount (4 bytesBE) || protocolVersion (4 bytesBE)`.
* **Digest Check**: Verification of timing-safe SHA-256 hash computed over the fully assembled plaintext file data.
* **Filename Sanitization**: Sanitization prevents path traversals (`/`, `\`, null bytes `\0`).

### Domain 6: Localhost API Protection
* **Port Randomization**: The daemon binds to `127.0.0.1` on a random port at startup.
* **DNS Rebinding**: Strict Host and Origin header validation checks.
* **Cross-Site Request Forgery (CSRF)**: Random 256-bit CSRF tokens refresh on GET `/api/session` and are verified on all write operations.

---

## 3. Setup & Running Locally

### Prerequisites
* **Node.js**: v22 or higher
* **Docker**: Desktop / Engine
* **PostgreSQL**: Handled by Docker Compose

### 1. Launch Services (Docker Database)
Create a `.env` file at the root using `.env.example`:
```bash
docker compose up -d postgres
```

### 2. Build the Monorepo
Install and compile all packages:
```bash
npm install
npm run build
```

### 3. Run the Relay Server
Starts the centralized relay:
```bash
npm run dev:relay
```

### 4. Run the Local Daemon
Starts the local background client daemon:
```bash
npm run dev:daemon
```
The terminal will output the bootstrap link to open in your browser:
`Open: http://127.0.0.1:PORT/bootstrap#SECRET`

---

## 4. Administrative Commands

The admin CLI allows managing connection access requests.

```bash
# Set environment
$env:DATABASE_URL="postgresql://crypto_pigeon:PASSWORD@127.0.0.1:5432/crypto_pigeon"

# List access requests
npm run admin -- requests

# Approve request (prints single-use activation code)
npm run admin -- approve <request-id>

# Reject request
npm run admin -- reject <request-id>

# Revoke user device
npm run admin -- revoke <user-id>
```

---

## 5. Canary-Based Verification

To verify that plaintext information is never leaked to the central relay server or local logs:

1. Send a unique canary string (e.g., `"canary_secret_998877"`) in an E2EE chat message.
2. Execute a search across all database tables and columns:
   ```sql
   -- Verify no matching text is stored in postgres envelope rows
   SELECT * FROM messages WHERE encrypted_payload::text LIKE '%canary_secret_998877%';
   ```
3. Scan relay application and container logs for the canary string.

This confirms that the relay operates strictly on opaque sealed envelopes and cannot decrypt transit payload data.

---

## 6. AGPL-3.0 Compliance

Crypto Pigeon is licensed under the **GNU Affero General Public License (AGPL-3.0)**. 
* **obligation**: Any modifications to the relay server or daemon must be made available to users interacting with it over the network.
* See the [LICENSE](LICENSE) file for complete terms.
