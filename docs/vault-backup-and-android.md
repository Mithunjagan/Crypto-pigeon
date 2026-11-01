# Vault backup, public UIDs, and Android USB development

This extends the existing desktop daemon, relay and UI. It does **not** make the
Node/native Signal daemon run on Android. The debug APK is a WebView paired to a
separate daemon on the USB host. The host and cable must remain connected. Native
on-phone key storage, background delivery, push notifications, release signing,
and a security review remain necessary for a standalone mobile product.

## Build and verification

From the repository root, with Node 22+:

```sh
npm ci
npm run build
npm test
npm run test:integration
git diff --check
```

The root build now builds shared-types/protocol before applications, including on
a clean checkout. `npm test` retains all 11 original checks and adds six checks
for derivation, fragments, authenticated backup, UIDs, and an actual libsignal
0.96.4 session/encryption/decryption roundtrip. Build before running tests because
the additional tests exercise the daemon's compiled production modules.

Integration checks require PostgreSQL and the root `.env` configuration from the
README, including `DATABASE_URL`, `ADMIN_USERNAME`, `ADMIN_TOKEN`, and
`ACTIVATION_PEPPER`. The database role needs CREATE DATABASE privileges: the
runner creates a random isolated database, tests migrations, restore, backup
ownership, instance transfer, password rotation, and UID approval gates, then
removes the database. Do not point the runner at an untrusted database server.

## New vaults and legacy vaults

New vault creation and unlock require a secret Vault ID (8–256 characters) and
the existing password policy. The Vault ID is case-sensitive and exact UTF-8;
it is neither trimmed nor stored in the vault, relay, status or contact payloads.
It is **not** the public UID. Save both credentials securely: neither can be
recovered for the user. A long randomly generated Vault ID is recommended.

Existing version-2 password-only vaults remain readable with their current
password. They are explicitly labelled legacy in the UI. They do not silently
gain cloud backup or seven-fragment protection. Automatic conversion of legacy
vaults is not implemented; preserve their files and credentials.

Argon2id uses 64 MiB, three iterations and parallelism one. Its salt is SHA-256
of the versioned domain and Vault ID. A deterministic salt is required to restore
without any old-device files or public identifier lookup. HKDF separates the KEK,
lookup token, backup key, session mask and backup signing key. The VMK remains
random; its existing SQLCipher, field, attachment metadata and local-token HKDF
domains are unchanged. VMK wrapping still uses AES-256-GCM with `vmk-wrap-v1`.

## Fragment storage

The **48-byte authenticated wrapped VMK**, not a plaintext VMK, is split using a
seven-way cryptographic XOR split. Six random shares plus their XOR complement
require all seven shares. Per-share hashes and the VMK's GCM tag detect damage.
The config contains no complete wrapped VMK for a new secure vault.

| Fragment | Storage |
|---|---|
| 1 | `shards/f1.bin`, in the protected vault directory |
| 2 | `vault_horcrux_shard` in `shards/metadata.db` |
| 3 | GCM-encrypted `config/f3.json` |
| 4 | `assets/f4.dat` |
| 5 | Origin-scoped browser/WebView localStorage (`cp-browser-shard-v1`) |
| 6 | Raw share only in RAM while unlocked; authenticated masked form in `shards/f6.masked` |
| 7 | GCM-encrypted share retrieved from the relay during unlock |

Fragment 2 uses a separate metadata SQLite file: putting an unlock prerequisite
inside the VMK-encrypted chat database would create a circular dependency.
Fragment 1 currently uses protected files rather than a hardware keystore.
Locations on the same filesystem are not independent hardware security boundaries.
The shield reports observed storage/session presence, not a hardware attestation;
the unlock path validates the hashes and GCM authentication for all seven shares.
Clearing browser storage or losing any fragment requires cloud restore.

Sync & Logout first prepares and encrypts a snapshot, then clears the VMK,
derived keys and raw session share **before waiting for the network**. It locks
even if upload fails and tells the UI the cloud copy may be stale. JavaScript
buffers are explicitly zeroed; managed strings and native library allocations
cannot be guaranteed to be immediately erased by the runtime.

## Backup and transfer

The backup contains the SQLCipher database (messages, account, Signal keys and
sessions, pins and approval state), VMK and HKDF salt, plus cached encrypted
attachment files. It is gzip-compressed in memory and AES-256-GCM encrypted with
AAD `vault-backup-v1`. Plaintext snapshots are never written to disk. Decoded
encrypted backups are limited to 25 MiB; decompression is limited to 100 MiB.
Backing up history can reach this limit before a single large attachment does;
there is no incremental backup or attachment deduplication yet.

The relay indexes backups by the blind derived lookup token. GET requires that
unguessable capability, while PUT additionally needs a deterministic Ed25519
writer signature and the next version number. Thus discovering a GET URL does
not confer write access. Versions use a transactional compare-and-set. The
relay stores only ciphertext and encrypted fragment 7; it does observe sizes,
timing, lookup tokens, signing public keys, and the associated device proof.
These endpoints need HTTPS outside loopback development, database storage
quotas, monitoring and production abuse controls before public deployment.

Restore verifies and decrypts the backup, validates the SQLCipher database in a
staging directory, replaces all fragments, uploads the new encrypted fragment 7,
and preserves existing local files in `.before-restore-TIMESTAMP`. Relay bearer
tokens are discarded. A newly generated instance token claims the device using
both backup-writer and device-auth signatures. Old relay sessions are deleted;
even after a new challenge-response, the previous instance is rejected by the
relay authorization middleware. Stop sending on the old device before restoring.
Concurrent calls to the local API are serialized to avoid lifecycle races.

Restore is a **single-active-device transfer**, not concurrent device sync.
Messages still only leave the relay queue after local durable acknowledgement.
Backup failures can leave the cloud copy older than delivered messages; the UI
reports failed backup status. Honest-client version checks prevent concurrent
overwrite, but a new device cannot independently detect a dishonest relay
replaying an older correctly signed snapshot. External trusted freshness and
stronger atomic handoff protocols remain security-review work.

Changing the password on a secure unlocked vault asks for the Vault ID and old
password. It stages the new wrapping and shares, uploads under the new lookup
token, verifies deletion of the old relay backup, and preserves local recovery
files before switching. Preserve recovery folders until the new credentials and
backup are verified; they can contain older encrypted state. This does not
promise erasure from relay-provider snapshots or offline copies.

Remote backup intentionally makes historical messages and Signal state
recoverable with the two credentials. It changes the consequences of credential
compromise compared with a vault that never leaves the device. Seven fragments
are a local-unlock requirement; authenticated cloud restore deliberately bypasses
missing old-device fragments.

## Public UIDs and contact approval

UIDs have the form `CP-XXXX-XXXX`. They are deterministically allocated from
account IDs, persisted with a unique constraint, and retried on collisions.
They can be shared via copy/QR. Username and UID requests go through the same
recipient-controlled conversation approval. UID lookup does not return a prekey
bundle or permit ciphertext delivery until acceptance. A 32-bit public UID is a
contact identifier, not an authentication secret or a safety number.

## Android build and USB installation

Install a **full JDK 17+**, Android SDK platform 35, build-tools 35.0.0 and
platform-tools on the computer physically connected to the phone. Set
`ANDROID_HOME` and, if needed, `JAVA_HOME`. The checked-in Gradle wrapper pins
Gradle 8.11.1 and its distribution SHA-256.

```sh
npm ci
npm run build
npm run android:build
# Starts the isolated daemon, configures reverse tunnels, installs and launches:
npm run android:usb
```

The APK is `artifacts/crypto-pigeon-debug.apk`. Build output and packaged UI
assets are ignored. The desktop daemon may continue using its own vault/port.
The USB command uses `CRYPTO_PIGEON_MOBILE_HOME`, defaulting to the ignored
`.crypto_pigeon_mobile` directory, and loopback port 17420. It creates reverse
tunnels for ports 17420 and 8443 and passes the daemon's one-time bootstrap
fragment directly to the explicit Android activity, without printing the secret.
The app restricts navigation to the paired daemon and has no JavaScript bridge
that exposes host keys. Cleartext is allowed only for loopback in the debug app.
The APK includes the built UI assets and uses the daemon-served UI at the same
origin as its APIs; a static WebView alone cannot run the native daemon.

The root `.env` config must point the mobile host daemon at the running relay.
Before USB deployment, verify relay `/readyz` on port 8443. To start only the
mobile daemon, use `npm run dev:daemon:mobile` after building; stop that process
before using `android:usb`, which needs a fresh single-use bootstrap. For multiple
connected phones set `ANDROID_SERIAL` to the selected serial.

If no phone is found:

```sh
adb devices
# or resolve adb from ANDROID_HOME through:
npm run android:usb -- --check
```

Enable Developer options → USB debugging, use a data-capable cable, unlock the
phone, and accept its USB debugging authorization prompt. A phone connected to
your laptop is not automatically visible inside a remote cloud environment.
Run the USB command on the machine whose `adb devices` lists it as `device`.
WebView file selection, downloads and microphone permissions need validation on
the actual target phone; successful APK compilation alone does not verify them.

## Windows quick start with the source bundle

Extract `crypto-pigeon-source.zip` to a **new folder** on the Windows computer
whose `adb devices` lists the phone. Do not overwrite a checkout with unsaved
changes. Install Node 22+, Docker Desktop and Android platform-tools if missing.
The bundle includes a prebuilt debug APK; a full SDK/JDK is only needed to
rebuild that APK.

In PowerShell, from the extracted project folder:

```powershell
npm.cmd ci
npm.cmd run setup:dev
docker compose up -d postgres
npm.cmd run build
npm.cmd run dev:relay
```

Keep that relay terminal open. In a second PowerShell window in the same folder:

```powershell
adb devices
npm.cmd run android:usb
```

The second command installs the bundled APK, starts the isolated mobile daemon,
sets both reverse tunnels, and opens the app with its one-time bootstrap token.
Keep this terminal open as well. For a desktop client in another terminal:

```powershell
npm.cmd run dev:daemon
```

Open the bootstrap address printed by that desktop daemon on the Windows
computer. For separate simultaneous people, create two distinct Vault IDs and
accounts. Restoring one person's vault onto the phone transfers that account;
it does not create a second independent messaging identity.
