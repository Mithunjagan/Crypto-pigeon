# Crypto Pigeon implementation and verification — 6 November 2026

Implemented the requested upgrade in the existing archive with original source backups under `artifacts/checkpoints/pre-serverless-p2p/`. Libsignal remains 0.96.4. Existing vault cryptography and fragment formats were preserved.

## Delivered behavior

- App-owned Android/Node Tor v3 onion services with per-vault SQLCipher service keys, authenticated peers, SOCKS domain forwarding and actual bootstrap status.
- Durable encrypted message queues and attachment spools; exact-ciphertext retries, local direct acknowledgements, verified chunk retrieval, cleanup, lock cancellation and explicit hybrid/relay compatibility.
- Version-2 compressed signed QR/URI invites, offline prekey verification/pinning, immediate local Signal sessions and session-preserving re-import.
- Android foreground service, shared engine ownership, generic private notifications, bounded packet locks, battery settings and cold-restart unlock requirements.
- Origin-limited runtime microphone permissions, matching recording/playback formats, vendor bundle splitting, updated README/native documentation.

## Mandatory command outputs

| Command | Exit | Result | Full output |
| --- | --- | --- | --- |
| `npm.cmd run build` | 0 | All workspaces passed; zero Vite chunk warnings | [resumed-final-build.log](resumed-final-build.log) |
| `npm.cmd test` | 0 | Core: 28 passed, 0 failed; desktop: 3 passed, 0 failed | [resumed-final-tests.log](resumed-final-tests.log) |
| `node --import tsx --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs` | 0 | 6 passed, 0 failed | [resumed-navigation-fragments.log](resumed-navigation-fragments.log) |
| `npm.cmd run android:native:build -- --offline --tests --jvm-tests` | 0 | Standalone/instrumentation APKs built; 13 JVM tests, zero failures/errors | [lifecycle-native-build.log](lifecycle-native-build.log) |

`--tests` builds instrumentation; it does not execute it on phones. The final Gradle detail is also in `artifacts/native-android/build.log`. Mocked hybrid fallback and persistence tests are repository evidence, not a live credentialed relay test.

## Follow-up live verification — 6 November 2026

**PASS: the full desktop and one-physical-phone/laptop public Tor suites completed.** Final hardware run `b45bfd8c606037b3` exited 0 at 20:20:14 IST. Android instrumentation returned code -1 with nine native checks passed. Total time was 480,245 ms, including setup, deliberate waits, restart recovery and cleanup. See [ONE-PHONE-LIVE-REPORT.md](ONE-PHONE-LIVE-REPORT.md), [raw results](one-phone-b45bfd8c606037b3/results.json) and [timing log](one-phone-acceptance-live.log).

Passed: full-fragment native cold unlock; both onion publications; mutual verified signed invite pinning and Signal sessions; bidirectional Tamil/emoji text and read receipt; visible Direct Tor status and received message; exact file and real microphone voice-payload integrity both ways; foreground-service persistence with display non-interactive at receive time and generic notification; automatic encrypted-outbox recovery/receipt after laptop Tor stopped/restarted; and phone lock stopping service, Tor process and monitor. Existing user vault/catalog/browser-fragment files were preserved. No adb reverse/forward or USB peer traffic was used.

Follow-up fixes cover public-cache/bootstrap/publication timing and async Tor events; request signing after circuit establishment; the misleading unknown-status relay label and stale instrumentation WebView session; Android cleanup prematurely deleting uploaded sender chunks; bounded Tor termination and incoming-socket cancellation; and main-thread lifecycle callbacks blocking behind vault Argon2 work. A real device regression held the engine lock while main-thread callbacks returned in 1 ms. Vault derivation parameters and libsignal 0.96.4 are unchanged.

The app was backgrounded 70 seconds, then the display explicitly slept immediately before the background message. Native PowerManager interactive=false was captured after persistence and before notification posting. The display woke afterward. This is receive-time screen-off evidence, not a claim of 70 continuous seconds asleep or extended Doze reliability. Charging stay-awake was temporarily disabled and restored to its original value 15.

Final warm laptop-to-phone persistence samples were 1,393 and 4,736 ms, including inspection/polling overhead. Automatic restart/re-publication/retry/receipt recovery took 235.140 seconds after queue confirmation. Fresh-service latency varied substantially, including a stopped 651-second initial-exchange attempt. Earlier failures and traces remain preserved in the live report and [PHONE-STARTUP-ERRORS.md](PHONE-STARTUP-ERRORS.md); the functional pass is not a latency guarantee.

Repository gates: full build with zero Vite chunk warnings; 28 core + 3 desktop tests; 6 navigation/fragment tests; 3 Tor regressions; native/instrumentation build and 13 JVM tests with zero failures/errors. Native build includes all final production changes. Backups are under `artifacts/checkpoints/pre-one-phone-tor/` and `artifacts/checkpoints/pre-visible-tor-status/`.

## APK

- `artifacts/crypto-pigeon-standalone.apk`
- Version: 0.4.0-standalone; debug package `app.cryptopigeon.nativeclient.debug`.
- Contains Tor libraries for arm64-v8a and x86_64; required foreground, microphone, notification and battery permissions verified in the packaged manifest.
- Size: 83,914,360 bytes (80.03 MiB).
- SHA256: `62cfcebff4c3230dba53790c92fe82c38a99b7b169dcea3712faa5e162135015`.

This is a debug build, not a signed production release. The existing installer/package variants were not rebuilt.

## Additional live network check and limits

The initial extended `node scripts/tor-live-check.mjs` did not get both Tor instances to 100% bootstrap within four minutes. That failed attempt remains in [tor-live.log](tor-live.log), with the earlier control-timeout attempt in [tor-live-first-attempt.log](tor-live-first-attempt.log). The subsequent staggered/public-cache fix passed the complete extended desktop check in [desktop-staggered-live.log](desktop-staggered-live.log).

A separate live two-desktop simultaneous Signal text exchange also passed on 5 November. The final one-phone/laptop run passed physical Android Tor, receive-time screen-off delivery and actual microphone payload integrity. Extended Doze/battery reliability and speaker playback remain outside the automated run. The connected phone has now been installed/instrumented using an isolated test vault; existing app/vault data was preserved.

Hybrid mode requires a relay that supports the account. Local self-activation does not provision an identity on an arbitrary legacy relay. Direct messaging uses the public Tor network but no application-owned cloud server. Cold process restart/reboot still requires vault unlock; the application does not store a passphrase for automatic reopening.

## Optional future reliability checks

These extend the completed one-phone/laptop task and are not required to repeat its passing result.

1. Preserve existing app data, `.cp7` and `.cpvault` files. Use independent test vaults on two supported phones; save external segment 07, self-activate and grant notifications/unrestricted battery.
2. Disconnect USB networking, use separate Wi-Fi/mobile networks, unlock and wait for real Tor bootstrap. Exchange signed invites **both ways** through an authenticated channel.
3. Send simultaneous messages and check delivery/read receipts. Send files up to 25 MiB, compare downloaded bytes, and record/play actual microphone voice notes.
4. Background both apps with screens off beyond one minute; exercise Doze, network handover, airplane mode and denied permissions. Confirm only generic notifications appear.
5. Queue while the peer is offline; restart/unlock and check single delivery and attachment recovery. Exercise Vault/Panic Lock, cold process restart and multi-vault switching; verify service shutdown and isolated identities/data.

This single-phone functional pass does not establish broad OEM reliability or an independent security audit.

## Exact source files

46 current source/configuration/documentation files: 21 created and 25 modified relative to the original implementation baseline. [changed-files.json](changed-files.json) records each current SHA-256. Generated assets, caches, compiled dist and APKs are build outputs.

### Created

- `apps/local-daemon/src/serverless-contacts.ts`
- `apps/local-daemon/src/tor-routing.ts`
- `apps/local-daemon/src/tor-transport.ts`
- `apps/local-ui/src/BackgroundDelivery.tsx`
- `apps/mobile-android/native/src/androidTest/java/app/cryptopigeon/nativeclient/OnePhoneTorInstrumentation.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/PigeonBootReceiver.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/PigeonForegroundService.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/PigeonRuntime.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/ServerlessInvite.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/TorOnionTransport.java`
- `apps/mobile-android/native/src/test/java/app/cryptopigeon/nativeclient/ServerlessInviteTest.java`
- `apps/mobile-android/native/src/test/resources/serverless-invite.json`
- `packages/protocol/src/serverless-invite.ts`
- `packages/tests/src/serverless-invite-tests.ts`
- `packages/tests/src/tor-routing-tests.ts`
- `scripts/one-phone-laptop-tor-live.mjs`
- `scripts/prepare-tor.mjs`
- `scripts/tor-bootstrap.test.mjs`
- `scripts/tor-http-regression.test.mjs`
- `scripts/tor-live-check.mjs`
- `scripts/tor-live-support.mjs`

### Modified

- `apps/local-daemon/src/messages.ts`
- `apps/local-daemon/src/relay-client.ts`
- `apps/local-daemon/src/server.ts`
- `apps/local-ui/src/App.tsx`
- `apps/local-ui/src/MessageBubble.tsx`
- `apps/local-ui/src/PeerScanner.tsx`
- `apps/local-ui/src/TransportPrivacy.tsx`
- `apps/local-ui/src/UidBadge.tsx`
- `apps/local-ui/vite.config.ts`
- `apps/mobile-android/native/build.gradle`
- `apps/mobile-android/native/src/androidTest/java/app/cryptopigeon/nativeclient/NativeCryptoInstrumentation.java`
- `apps/mobile-android/native/src/main/AndroidManifest.xml`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/LocalBridge.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/MainActivity.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/NativeDatabase.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/NativeEngine.java`
- `apps/mobile-android/native/src/main/java/app/cryptopigeon/nativeclient/transport/EnvelopeTransportRouter.java`
- `apps/mobile-android/native/src/test/java/app/cryptopigeon/nativeclient/TransportRouterTest.java`
- `docs/native-android-implementation.md`
- `packages/protocol/src/index.ts`
- `packages/shared-types/src/index.ts`
- `packages/tests/src/desktop-messaging-tests.ts`
- `packages/tests/src/run-tests.ts`
- `README.md`
- `scripts/prepare-desktop.mjs`
