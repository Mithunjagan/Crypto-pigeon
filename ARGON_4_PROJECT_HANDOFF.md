# Crypto Pigeon: copy-ready context prompt for Argon 4

You are helping me understand, review and continue an existing project called **Crypto Pigeon**. Treat this as a handoff of an implemented application, not a request to invent a new application or rebuild it from scratch.

This snapshot was prepared on **5 November 2026, Asia/Calcutta**, by inspecting local source, documentation and saved test evidence. Historical device results are identified separately from checks rerun during this handoff. Reverify anything that may have changed.

## 1. What the project is

Crypto Pigeon is an independent privacy-focused, end-to-end encrypted messaging application with a locally encrypted vault, a Windows desktop client, a standalone Android client, and a PostgreSQL-backed relay.

The intended experience is: create a vault using a private Vault ID and master passphrase; save its separate encrypted segment file; obtain a public contact UID; add and approve contacts; exchange encrypted text, files and voice-note payloads; lock and reopen the vault; and optionally export or back up encrypted account/history state.

The relay forwards/stores encrypted envelopes and attachment chunks, handles public prekeys and account/contact workflows, and optionally stores encrypted vault backups. Message encryption/decryption and private-key operations happen on the user's device. Plaintext is displayed in the local UI after local decryption.

This is an unaudited beta/development application. It is not cryptocurrency software despite its name, and it is not an official Signal client or a demonstrated Signal-equivalent privacy system.

## 2. Workspace and architecture

Local repository root: `D:\Crypto pigeon main\Crypto-pigeon-master`.
This copy is a source archive with **no Git metadata**. Do not invent commit history, branches or a clean Git status.

It is an npm workspace monorepo:

- `apps/local-ui`: React 19, TypeScript and Vite. Shared responsive chat/vault UI, with Tailwind/CSS, Framer Motion, Lucide icons, QR generation/scanning and bundled fonts.
- `apps/local-daemon`: Node.js/TypeScript local backend for desktop/browser use. Owns vault lifecycle, SQLCipher, Signal state, attachments, relay communication and local API authentication.
- `apps/desktop`: Electron shell, onboarding, restricted renderer and separately bundled Node daemon. Windows installer packaging exists. Root/desktop package version is 0.1.0.
- `apps/mobile-android/app`: older USB-paired Android WebView client that depends on a host daemon. Keep this distinct from the standalone app.
- `apps/mobile-android/native`: current standalone Android application. Java engine, real on-device libsignal/JNI, SQLCipher, Android Keystore, app-owned loopback API and the shared React UI inside a WebView. Gradle version name is `0.4.0-standalone`; min API 26, target/compile API 36, arm64-v8a and x86_64 builds configured.
- `apps/relay-server`: Fastify 5.12.7, PostgreSQL, WebSocket notifications, account authentication, public prekeys, contact approvals, encrypted queues/blobs, backups and transport/privacy infrastructure.
- `apps/admin-cli`: database-backed administrative tools retained from the original invitation/approval workflow.
- `packages/protocol`: shared Zod 4.6.7 schemas, wire contracts, signing and validation helpers.
- `packages/shared-types`: shared TypeScript types.
- `packages/tests`: cryptographic, vault, attachment and desktop-message regression tests.
- `scripts`: build, deployment, HTTP/integration, Android instrumentation, device and UI verification helpers.
- `deploy`, Dockerfiles and Compose files: local relay/database deployment plus production-oriented HTTPS/Caddy configuration.
- `artifacts`: APKs, Windows builds, device results/screenshots, source checkpoints and local test infrastructure. Some files contain private credentials or vault state; do not publish the directory wholesale.

Desktop path: React/Electron -> authenticated loopback Node daemon -> encrypted local vault and remote relay.
Standalone Android path: React/WebView -> authenticated app-owned loopback Java backend -> on-device encrypted vault and remote relay. A PC daemon is not required for this standalone client.

## 3. Cryptography and vault model already implemented

- Both Node and Android pin libsignal **0.96.4**. Signal identities, prekeys, session establishment and ratchet state are handled through the library. Classical and PQ prekey paths exist. Do not infer verified continuous post-quantum forward secrecy from the version or feature names.
- Vault access uses two exact credentials: a private Vault ID and master passphrase. The public `CP-XXXX-XXXX` UID is a different thing and is not an unlock secret.
- Argon2id baseline: 64 MiB, three iterations, parallelism one. The dual-credential scheme uses a versioned Vault-ID-derived salt; HKDF separates wrapping, lookup, backup, session-mask and backup-signing domains.
- A random 256-bit vault master key is wrapped using AES-256-GCM. Separate subkeys protect SQLCipher and other local domains.
- Seven-fragment protection splits the **authenticated wrapped VMK**, not the plaintext VMK, into seven XOR shares requiring all seven. This is not a threshold scheme permitting fewer shares.
- Fragment locations differ by platform and generation: protected/Keystore-backed storage, metadata storage, encrypted configuration, binary file, browser/WebView storage, masked session share, and either a relay-backed or external seventh fragment. Do not assume every UI label represents a separate hardware boundary.
- The newer standalone creation flow requires saving external segment 07 as `segment-07.cp7`; cold unlock uses the correct Vault ID, passphrase, browser fragment and matching segment. Existing relay-backed vaults remain a compatibility path.
- SQLCipher stores local messages, contacts, account state and Signal records. Private Signal keys and vault secrets belong locally.
- Relay challenge-response uses a separate Ed25519 device-auth identity, not the Signal identity key.
- Local APIs use loopback binding, single-use bootstrap secrets, HttpOnly/SameSite cookies, CSRF and Host/Origin checks. The Android JavaScript file bridge has a restricted export role; do not expose private keys through it.
- TOFU identity pinning and displayed safety numbers exist. First-contact relay substitution still requires out-of-band verification to detect.
- Lock/logout paths invalidate sessions and clear sensitive buffers where the runtime permits. Do not claim guaranteed secure erasure of all managed/native memory.

## 4. Messaging and account work already implemented

- Username signup/activation, public UIDs, copy/QR sharing, contacts and recipient-controlled conversation requests.
- The current consumer flow self-activates without manually entering an administrator-issued code. Older README/admin workflows describe an earlier state; contact acceptance remains a distinct requirement.
- Signal-encrypted text, Unicode messages and per-contact local history.
- Durable encrypted outbox, stable-envelope retry, deduplication, expiry handling and acknowledgement after local persistence.
- Transactional handling intended to keep Signal ratchet changes and message persistence together.
- WebSocket-driven synchronization, reconnect handling and offline queued delivery.
- Encrypted typing controls, profile payloads and sent/delivered/read states. UI statuses must reflect actual peer/transport events.
- Attachment encryption uses fresh per-file AES-256-GCM keys, chunk authentication and digest checks. Durable download retry and encrypted local caches exist. The documented general file limit is 25 MiB; backup/storage-file limits are separate.
- Voice-note recording/playback flows exist. Historical media verification used a generated tone; do not claim a completed physical-microphone acceptance test from that evidence.
- Disappearing-message support is best-effort local expiry/deletion, not protection against copied messages, screenshots or compromised endpoints.

## 5. Backup, external storage and multiple vaults

- Encrypted authenticated snapshots preserve account identity, contacts, messages, Signal sessions and cached attachment bytes.
- Cloud backup uses a derived blind lookup capability, a distinct encryption key, Ed25519 writer signatures and version checks. Restore/account-transfer logic is present.
- Restoring an account is a **single-active-device transfer**, not concurrent linked-device sync. Historical native phone evidence includes restoring each phone's vault onto the other and continuing Signal conversations.
- The newer external-storage mode provides a separate `.cpvault` encrypted storage bundle and `.cp7` segment file, Android document-picker save/import, and optional binding of an external document for updates.
- Android still keeps an encrypted internal working database. Do not describe the external file as the sole storage location or a database edited directly in place.
- New external-mode vaults have automatic cloud database backup **off by default**; users can enable it. Older cloud-backed vault paths differ. Relay message delivery is independent of cloud backup settings.
- External storage import is bounded to 18 MiB in the inspected UI/native implementation.
- Storage switching locks first and authenticates the selected vault. Password rotation and legacy compatibility paths exist; protect recovery folders and old encrypted files until migration is verified.
- Latest 5 November work adds multiple **independent local Android vaults**, each with its own identity and files. A private catalog routes IDs to opaque handles, and browser fragments are stored per vault. This is not multiple simultaneous devices for one account.
- Saved native results show five multi-vault checks passed: original files preserved, wrong credentials/segments and duplicate/unknown IDs rejected, independent switching, restart recovery and password-rotation isolation.
- Four real-UI checks on a physical phone show second-vault creation through the Android file saver, separate relay registration, wrong-passphrase rejection after force-stop and correct reopen without changing the original vault files.

## 6. UI and recent usability work

- Responsive dark/glass-style interface, branded pigeon assets, chat list, search, composer, attachment UI, safety-number/identity views, settings, storage controls and clear error/queued states.
- PIN-based session lock and panic lock/logout flows exist. A PIN is not a replacement for cold vault credentials and the external segment.
- Android autofill suppression and vault-input focus/keyboard fixes exist; saved checks cover username, Vault ID, passphrase and confirmation on a physical phone.
- File-storage gesture entry points exist: the segment-07 control uses a five-tap gesture. Inspect `SovereignStorage.tsx`, `VaultGate.tsx` and `App.tsx` for exact current interactions.
- Latest navigation work shares a Back stack between sheets/dialogs, chat screens, Escape and Android Back. It closes the active surface first; Android hides the keyboard first and backgrounds the activity at the root. Do not equate passing unit checks with full physical gesture acceptance.
- Duress/decoy vault source and UI exist, explicitly labelled experimental and not fully verified on Android.

## 7. Transport/privacy work: exact boundary

Real relay messaging is implemented. **Direct WebRTC/P2P messaging is not connected in the current native application.**

There are signaling schemas/routes, transport interfaces and an `EnvelopeTransportRouter` with relay/hybrid/P2P test modes and deadline/fallback logic. However, `NativeEngine.router()` passes `null` as the direct transport and sets `RELAY_ONLY`. Runtime privacy reports `relayOnly: true` and `activeTransport: "Encrypted Relay"`.

Blind-dropbox routes, rotating derived routing tags and encrypted identity/control payloads are present, with standard relay fallback for compatibility. These reduce some stored routing metadata; they do not establish anonymity from the relay or full sealed-sender equivalence. The relay still authenticates connections and can observe network/timing/size information.

A metadata-free `WAKE_SYNC` notification adapter/interface exists. The inspected app suspends push after a background interval; no completed FCM service integration was established here. Treat reliable killed-app/Doze/background delivery and push acceptance as remaining work.

## 8. Verification evidence and its limits

Historical saved evidence:

- `docs/live-three-phone-2026-11-03.md` and `artifacts/three-phone-live-20261103/`: three physical Vivo phones, independent native vaults and on-device Signal, all six text directions, Tamil/Devanagari/emoji, three exact 150,123-byte attachment transfers, cellular-to-Wi-Fi delivery, offline queue/recovery and matching safety numbers. No `adb reverse`; USB controlled/observed the UI only. The HTTPS relay ran on this PC behind ngrok, so this did not verify independent production hosting or direct P2P.
- The recorded text arrival observations were roughly 0.5–2.7 seconds. They include observation overhead and are not a latency SLA or benchmark.
- `artifacts/hardware-live-results.json`: two native physical phones, cross-phone vault restoration, preserved attachment/history state and continuing ratchets over a LAN relay.
- `artifacts/consumer-validation.json`: signup, typing, encrypted message/receipt behavior and locks. Its fast timing samples used two accounts on one phone; do not present them as a two-phone internet benchmark.
- `artifacts/external-storage-validation.json`: 21 focused checks spanning external storage, gestures, keyboard/UI and daemon behavior. Device scope was one connected phone, not a full device matrix.
- `artifacts/multi-vault-20261105/`: five native and four physical-UI multi-vault checks described above.
- Older beta/foundation reports record Windows packaging, USB phones, JNI/Node interoperability, HTTP/integration checks and a point-in-time zero-production-advisory dependency audit. These counts and checksums are historical, not proof that today's APK/source is identical.

Checks rerun during this handoff are recorded below. No physical-device suite, live relay integration, fresh dependency audit, native APK build or installer rebuild was performed for this handoff. Tests importing `dist` require a fresh workspace build.

## 9. Useful commands

Run from the repository root, using `npm.cmd` in PowerShell if necessary:

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd test
npm.cmd run test:http
npm.cmd run test:integration
node --import tsx --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs
npm.cmd run dev:relay
npm.cmd run dev:daemon
npm.cmd run desktop:dev
npm.cmd run desktop:installer
npm.cmd run android:native:build -- --tests --jvm-tests
npm.cmd run test:android-native
npm.cmd run test:phones:internet
npm.cmd run test:phones:recovery
```

These are available entry points, not a promise that each command needs no setup. Relay/integration gates need suitable PostgreSQL/environment configuration; native/device gates need the Android SDK, JDK 17 and authorized devices. Some scripts use machine-local fixtures. Read scripts before running them against existing data. Inspect `package.json` for the full command list.

APKs include `artifacts/crypto-pigeon-standalone.apk` and `artifacts/crypto-pigeon-debug.apk`. The native build helper currently updates both names with the standalone build; the word `debug` alone does not identify the old USB variant. The Windows installer is under `artifacts/desktop/`. Do not assume old manifests/checksums describe newly overwritten APKs.

## 10. What remains and how to continue

1. Reconcile current regression failures and rerun the relevant gates. Diagnose whether mocks/assertions or implementation are wrong; do not weaken behavior merely to make tests green.
2. Refresh stale docs and artifact manifests. In particular, `docs/native-android-implementation.md` describes an early foundation without a launcher, while current source and later evidence show standalone messaging. Older backup and activation descriptions also lag the consumer/external-storage flows.
3. Complete and test an actual direct transport only if requested; preserve honest relay-only status until real P2P passes on separate devices/networks.
4. Complete reliable Android background/push delivery and lifecycle/device acceptance, including process death, Doze, offline recovery, permissions and physical microphone recording.
5. Review newer multi-vault, credential rotation, storage import, backup and account-transfer races. Preserve working vaults, browser fragments and Signal state.
6. Replace temporary tunnels with stable provisioned HTTPS hosting, operational monitoring, quotas/abuse controls, backup recovery exercises and deliberate infrastructure logging policy.
7. Add production signing/distribution/update infrastructure. Existing Android artifacts are development/debug builds and the recorded Windows installer is unsigned. macOS/Linux targets in configuration are not verified releases.
8. Obtain independent security/cryptographic review. Review malicious-relay behavior, backup rollback/freshness, endpoint/metadata limits, routing capabilities and single-active-instance enforcement.
9. Confirm licensing before distribution; the inspected project has no authoritative distribution license file.

Work incrementally in this codebase. Preserve working behavior and existing vaults. Use checkpoints because this archive lacks Git history. Do not print `.env`, private JSON credentials, actual vault IDs/passphrases, keys or test-account secrets. Distinguish implementation, saved historical evidence, checks you reran, and unverified claims. Do not call the project production-ready or claim anonymity, continuous PQ protection, real P2P, multi-device synchronization or fully verified duress protection without evidence.

Start by explaining the existing system and current state in plain language. If I request a change, inspect the relevant implementation and perform the scoped work with appropriate verification instead of proposing a replacement architecture.

## Current handoff verification

- `npm.cmd run build`: **passed** across the workspaces. Vite reports an existing bundle-size advisory for the roughly 600 kB JavaScript chunk. This build refreshed compiled output/UI assets; it did not rebuild native APKs or the Windows installer.
- `npm.cmd test`, rerun after that fresh build: **3 desktop policy tests passed; 20 core/regression checks passed; 2 desktop-messaging checks failed**. The overall test command exits unsuccessfully.
- `node --import tsx --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs`: **6 passed, 0 failed**.

The two reproducible failures are in `packages/tests/src/desktop-messaging-tests.ts`:

1. `First incoming Signal message creates one named contact and decrypts exactly once`: `TypeError: relayClient.takePushedEnvelopes is not a function`, reached from `apps/local-daemon/dist/messages.js`. The inspected test double supplies `request` but not the newer pushed-envelope method.
2. `Outbox survives restart and retries identical Signal ciphertext after a lost relay response`: exact decrypted-payload assertion expects only `type`, `text` and `disappearingSeconds`, while the current payload also contains `messageId` and `profile`.

These observations suggest test-contract drift, but the failing gates still need proper diagnosis and repair. They do not establish a reproduced failure in the real phone app. No application source fixes were made for this status/handoff request.
