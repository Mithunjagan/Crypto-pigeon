# Crypto Pigeon serverless P2P handoff — paused 5 November 2026

User explicitly asked to pause and continue tomorrow. Do not resume automatically or schedule a reminder. User wants an update after each completed phase and realistic remaining-time estimates.

## Request and guardrails

Original request: `C:/Users/mith1/.codex/attachments/de4c4674-04fc-4aec-b00d-6e4fb6e0ace2/Pasted text.txt`.
Workspace: `D:/Crypto pigeon main/Crypto-pigeon-master`, a source archive without Git metadata. Preserve existing vaults and formats. Before modifying an existing core source file, ensure its original is under `artifacts/checkpoints/pre-serverless-p2p/`. A checkpoint of 219 source/configuration files was made before the architecture edits. New files do not need an original backup. Never print secrets, private keys, vault identifiers, passphrases, environment files, or test credentials. Keep libsignal 0.96.4 and the original Argon2id/HKDF/VMK/7-of-7 fragment formats.

## Completed phases and evidence

1. Phase 1 complete: regression mock implements `takePushedEnvelopes`; outbox assertion checks messageId and profile along with existing payload fields. Full build exit 0 (pre-existing Vite size warning), core tests 22/22 and desktop tests 3/3.
2. Phase 2 implemented and tested: Android app-owned libtor process and Node Tor transport; SQLCipher-persisted ephemeral ADD_ONION identity; authenticated peer HTTP, explicit SOCKS domain requests, durable encrypted inbox/outbox, local encrypted attachment spool with peer fetch, direct/hybrid/relay router modes. Core tests 25/25 + desktop 3/3; APK/JVM gate passed with 11 tests at that point.
3. Phase 3 complete: compressed, signed `pigeon://invite?v=2&data=...&sig=...` fixed-array wire; auth key + identity + signed classical/PQ last-resort prekeys; offline pinning/session creation, verified contacts, repeat import preserves ratchet; UI scan/copy/import and mutual invite instructions. Public cross-language fixture under native src/test/resources. Actual QR generation succeeds: sample 2735 bytes, version 39/L, 173 modules. Core tests 26/26 + desktop 3/3; native build and 13 JVM tests pass, including Android parsing a Node-generated signed invite and request canonical-byte compatibility.
4. Phase 4 implemented: shared PigeonRuntime owns LocalBridge across Activity destruction; foreground service remoteMessaging|specialUse; sticky restart only retains an already-unlocked runtime (cold process/reboot requires unlock); no one-minute background suspension; bounded packet CPU/Wi-Fi leases; generic notifications only after persisted/decrypted text; battery status/request/dismiss and one-time Settings banner. APK/JVM build passed (13 tests); local UI compiled. Real screen-off/Doze/service lifecycle has NOT been tested on a phone.

Additional live proof after Phase 4: `node scripts/tor-live-check.mjs` exited 0 and printed `PASS: two app-owned Tor instances exchanged real Signal messages simultaneously without an application relay.` Two isolated temporary Node vaults, two real Tor processes, real pinned Signal sessions; no app relay, simultaneous reciprocal delivery, empty outboxes, cleanup completed. This is desktop-to-desktop over the public Tor network, NOT two-phone or Android Tor validation. Initial run failed after overlapping bootstrap polls closed control sockets; polls now skip while another command is outstanding. The next run succeeded.

## Phase 5 in progress at pause

Implemented but not yet fully regression-tested:

- Vite manual vendor chunks (React, motion, icons, QR). Latest local-UI build passed with ZERO chunk warnings. Sizes: app 90.12 kB, icons 18.89, motion 144.04, QR 155.74, React 193.84.
- Explicit supported audio MIME selection in MediaRecorder and matching `.webm`/`.ogg`/`.m4a` filenames; native and Node authenticated loopback playback MIME handling updated. Existing Android runtime microphone/camera permission and origin-limited WebChromeClient paths already existed and were inspected. Physical microphone recording/playback NOT tested.
- Message status descriptions updated for direct delivery/background retries.
- README and `docs/native-android-implementation.md` have NOT yet been updated. They contain obsolete architecture claims and need rewriting around the current 0.4.0-standalone paths, .cp7/.cpvault/multi-vault isolation, Tor, foreground service, current validation limits, mutual authentic invite exchange, optional relay fallback.

## Implementation notes and remaining audit items

- Guardian Tor 0.4.9.14 AAR requires compile SDK 37 for its Java service. Current app is SDK 36. Gradle's separate `torBinary` configuration extracts ONLY `libtor.so` arm64-v8a/x86_64 from that pinned AAR; app owns the process/service. jtorctl 0.4.5.7 is separately included. Do not downgrade to older Tor just to bypass metadata. `androidx.core:core:1.17.0` added for NotificationCompat.
- Desktop runtime is downloaded from official Tor Browser 16.0 expert bundle; actual binary reports Tor 0.4.9.15. `scripts/prepare-tor.mjs` verifies its SHA256 and extracts runtime/licenses; `prepare-desktop.mjs` stages it. Desktop packaging itself has NOT been run. It intentionally refuses to overwrite an existing nonempty desktop-runtime directory.
- Crucial concurrency rule: NEVER hold the serialized vault/engine lock across a Tor network wait. Incoming persistence needs that lock. TorRouting queues network sends outside serialization; ack callbacks reacquire it and delete original encrypted outbox bytes. Native sendPersisted similarly schedules the direct future and returns queued; chunk prefetch runs outside locks and persists each encrypted chunk inside them. Keep this property for simultaneous sending/downloading.
- Review hybrid fallback: Node/native retain relay-only behavior, but direct failures after circuits are live currently remain queued rather than fully falling back to relay. Complete explicit hybrid fallback without introducing reciprocal-send deadlocks or changing bytes. For attachments created in hybrid mode, ensure fallback semantics match which encrypted spool holds the blob.
- Persist Node transport-mode selection (currently memory-only), and audit stopTor on quick lock, password replacement/reopen/restore, and process IPC shutdown. Native service and Tor lock paths exist; Node quick-lock currently only sets quickLocked. Audit generation/owner checks so async callbacks cannot access a switched or locked vault.
- Node Tor startup asynchronous SQLCipher reads/writes are serialized after controller setup; verify any remaining startup/initial-schema calls cannot run inside another Signal transaction. Raw inbox ack is after encrypted SQLCipher persistence, decryption occurs later transactionally; failed decryption must remain pending. Old core tests cover rollback and exact retry bytes.
- Check strict pin consistency for existing legacy remote_contacts and identity_changed flags when importing an invite. Invites carry self-authentication, not independent human identity: exchange them in person or through an authenticated channel, and retain Safety Number inspection.
- Consider direct body/ciphertext limits versus maximum Unicode message size: current incoming max 192 KiB body, 96 KiB decoded ciphertext can reject the existing 65536-character limit for non-ASCII. Align bounds without weakening protection.
- Add durable encrypted spool cleanup on message expiry/deletion; current tor_blob/chunk/download tables otherwise retain ciphertext. Enforce sender/contact access on peer chunk GET (implemented) and schema/chunk size bounds (implemented).
- `LocalBridge.entry()` now returns `/` when bootstrap already consumed; session cookies are reused on Activity recreation. Verify real recreate/notification-open flow.
- Service onDestroy stops direct transport; packet locks have timeouts. Request/update errors currently fail closed; UI should accurately distinguish failed service start/notification denial and circuit bootstrap.
- No phone was installed, modified, reset or instrumented during this run. One connected device was observed. Do not treat existing old reports as current acceptance.
- A harmless empty nested directory tree may remain under `packages/tests/apps/...` from an initially misplaced generated public fixture. The actual fixture was moved to native src/test/resources and routine tests no longer write source fixtures.

## Mandatory Phase 6 gates still outstanding on the FINAL code

Run from repository root and save command output, exit codes and test counts under artifacts/serverless-p2p/:

1. `npm.cmd run build` — all workspaces, zero Vite chunk warnings.
2. `npm.cmd test` — existing and new tests all pass.
3. `node --import tsx --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs`.
4. `npm.cmd run android:native:build -- --tests --jvm-tests` — final standalone APK `artifacts/crypto-pigeon-standalone.apk` and all JVM tests. `--tests` builds instrumentation APK; it does NOT execute device instrumentation. Do not claim it does.

Run meaningful extra tests for any fixes, including optional `node scripts/tor-live-check.mjs` after transport changes. Consider extending it for encrypted attachments, offline restart and lost-ACK dedup. Do not overstate physical Android/Tor/microphone/Doze verification.

At completion provide exact created/modified files (checkpoint comparison inventory `changed-files.json`), each mandatory command outcome, final APK link, and practical two-phone manual acceptance steps. Current APK is an INTERMEDIATE build; it predates the last UI/audio/chunk changes. Do not deliver it as final.

Last user-facing estimate before pause was another 1.5–3 hours; revise based on remaining transport audit and verification when work resumes.
