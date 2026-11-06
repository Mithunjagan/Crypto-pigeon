# Desktop private beta

Current serverless packaging and Android signing instructions are in
[release-packaging.md](release-packaging.md). Fresh desktop profiles can now choose
**Start with Tor** without configuring a relay. The legacy relay workflow below
still applies to existing relay accounts; its relay requirements do not apply to
direct Tor pairing. Windows installers remain unsigned by Authenticode.

This release adds a desktop shell, a bundled Node daemon, a Windows installer
build, HTTPS relay deployment, and a durable encrypted outgoing queue. It is a
private-beta foundation; code signing, automatic updates and an independent
security review are release gates before broad distribution.

## What users install

Install `Crypto-Pigeon-Setup-0.1.0-x64.exe` from `artifacts/desktop`.
Launch Crypto Pigeon and enter the operator's HTTPS relay origin. The app checks
`/readyz`, saves the address, starts its bundled daemon and opens its local UI.
Users do not install Node, PostgreSQL or Docker. Both contacts must use the same
relay. Account activation and recipient approval remain required.

Vault keys and Signal operations remain in the local daemon. The Electron
renderer has no Node access, uses a sandbox, and cannot navigate or connect to
external sites. The daemon listens on `127.0.0.1:17421`; do not expose that port.
One desktop instance runs per user. A conflict on this port produces a startup
error instead of connecting to another process.

Desktop state is in Electron's userData directory (`%APPDATA%/Crypto Pigeon` on
Windows); the vault is in its `vault` subdirectory. Chromium storage contains
one required vault fragment. Preserve the complete profile when backing up.
Uninstall does not intentionally remove the profile. The installer is unsigned
until an operator configures a signing certificate. Do not bypass OS warnings
for builds from an untrusted source.

The desktop profile is separate from existing command-line/browser vaults.
To move an existing secure vault, use the existing explicit Restore flow with
the original relay, Vault ID and password; this transfers the active instance.
There is no automatic migration of password-only legacy vaults. Save those
files and credentials before experimenting.

The relay address is set once for a profile. Changing relay operators is not a
supported migration: backups, activation and contacts belong to the old relay.
Do not edit desktop.json to migrate an existing account.

## Build on Windows x64

Use Node 22+ and npm. Build native dependencies on the target OS and architecture.

```powershell
npm ci
npm run setup:dev
npm run build
npm test
npm run desktop:dev
```

`setup:dev` creates local development secrets without overwriting an existing
`.env`; the desktop still requires an HTTPS relay. Production operator secrets
are never passed into the desktop's daemon environment.

```powershell
npm run desktop:installer
```

The staging step copies only the daemon's production dependencies and compiled
UI, bundles the exact Node executable used for the build, and loads Signal,
SQLCipher and Argon2 in that runtime before packaging. Electron never rebuilds
these libraries against its own ABI. No `.env` files or vaults are bundled.
Build output is in `artifacts/desktop`. Staging refuses to overwrite a nonempty
`artifacts/desktop-runtime`; move that generated directory aside before another
installer build. `desktop:pack` produces an unpacked app for inspection.

After packaging, run `npm run desktop:smoke` on Windows. It rejects workspace
links that point outside the app, copies packaged resources outside the source
checkout, and checks onboarding, private daemon login, renderer isolation,
storage persistence across restart and daemon shutdown in hidden windows.
Native prebuilds are restricted to the build host's OS and architecture.

The included configuration also declares macOS/Linux targets; those builds,
native dependencies and signing must be verified on their respective platforms.

## Delivery behavior

Outgoing text and attachment-message envelopes are saved to SQLCipher before
contacting the relay. The Signal session advance, message record and encrypted
outbox bytes commit together. A failed request keeps the original envelope ID
and ciphertext for retry, including after restart. Polling retries while the
window is running and the vault is unlocked; identity-change blocks apply to
queued messages. `Queued` means stored locally; the check mark means accepted
by the relay, not read by the recipient. Locked or closed apps do not send.
Initial attachment upload still needs a connection; uploading files offline
is not supported.

The relay retains pending messages for up to 30 days and removes them after the
recipient acknowledges. Existing recipient deduplication remains in use.
This is not a guarantee of lossless delivery under every failure mode. Durable attachment download retry and receive-side ratchet rollback now have regression checks. Relay backup restore and real network transitions still need broader beta testing. Secure vaults
also need the relay fragment to unlock; cold-start offline unlock is not added.

## Public relay

Use a Linux server with Docker Compose, a DNS hostname pointing at the server,
and inbound TCP ports 80/443 (UDP 443 is optional). Do not expose PostgreSQL or
desktop-daemon ports. Run from the repository root:

```sh
node scripts/setup-production.mjs relay.your-domain.com operator@your-domain.com
docker compose --env-file .env.production -f compose.production.yml config --quiet
docker compose --env-file .env.production -f compose.production.yml up --build -d
curl --fail https://relay.your-domain.com/readyz
```

Keep `.env.production` private and retain it in secure operator backup storage.
Caddy obtains and renews TLS certificates. The public URL is also the relay's
authentication hostname. Clients reject remote HTTP and redirects. Caddy
does not enable access logs and blocks public administration paths. Database
traffic remains internal; the relay's host binding is localhost only.
The relay trusts one proxy hop for rate limits; public clients must reach it
through Caddy. Do not publish the relay container port to a public interface.

To administer access, use SSH forwarding on the operator's computer:

```sh
ssh -N -L 8443:127.0.0.1:8443 operator@your-server
```

Open `http://127.0.0.1:8443/admin` locally. Use ADMIN_USERNAME and ADMIN_TOKEN
from the protected server configuration. This loopback HTTP traffic travels
inside SSH to the server. Never send administrator credentials over public HTTP.

Back up PostgreSQL, relay attachment storage if configured, configuration and
secrets using your infrastructure's encrypted off-host backups. Perform a restore
test before onboarding beta users. This change does not provision a server,
DNS, scheduled backups, monitoring, signing identities or an update service.

## Cross-network acceptance gate

Use two Windows computers with separate desktop profiles and a real hosted
relay. Put one on home Wi-Fi and the other on a phone hotspot. Neither client
requires inbound router ports.

1. Install both clients, configure the same HTTPS relay, activate accounts and
   accept a contact request. Compare safety numbers over a trusted channel.
2. Exchange text and a file in each direction. Compare downloaded file hashes.
3. Disconnect the sender after sending; reconnect and confirm one copy appears.
4. Disconnect a sender before sending text; verify Queued, restart the app,
   reconnect, unlock and confirm one copy reaches the recipient.
5. Close the recipient, send messages, restart and unlock it, then verify history.
6. Restart the relay and test recovery. Check that failed TLS certificates are
   rejected and public `/admin` and `/api/admin/*` return 404.
7. Restore a vault on a replacement computer and verify old-instance rejection.

Record results for every gate. Repository tests and a local desktop smoke test
do not substitute for this two-network validation.
