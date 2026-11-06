# Crypto Pigeon — live Tor verification

**PASS — all three requested phases completed.** Final hardware run: `b45bfd8c606037b3`, completed **6 November 2026, 20:20:14 IST** (`2026-11-06T14:50:14.316Z`). Total runner time: **480,245 ms (8 minutes 0.245 seconds)**.

Runner exit **0**; instrumentation **`INSTRUMENTATION_CODE: -1`**, nine native checks passed. Evidence: [runner log](one-phone-acceptance-live.log), [exact results/events](one-phone-b45bfd8c606037b3/results.json), [instrumentation](one-phone-b45bfd8c606037b3/instrumentation.log), [background evidence](one-phone-b45bfd8c606037b3/background-evidence.json).

## Phase 1 — desktop public Tor

`node scripts/tor-live-check.mjs` exited 0. [Passing log](desktop-staggered-live.log).

| Assertion | Result |
| --- | --- |
| Simultaneous bidirectional Signal text | PASS |
| Maximum-length Tamil/emoji Unicode message | PASS |
| Chunked AES-GCM attachment, exact decrypted bytes | PASS |
| Durable offline retry after both vaults lock/reopen, preserving onion identities | PASS |

The passing desktop run recorded bootstrap/publication at 7/26 seconds for peer 1 and 91/121 seconds for peer 2. Reopened services published at 31 and 91 seconds. These are per-peer waits, not total run time.

The original four-minute timeout was too short: a diagnosed cold peer bootstrapped at 457 seconds and published at 472 seconds. Peers now start sequentially, seed only public directory consensus/certificates/microdescriptors and wait for `HS_DESC UPLOADED` with bounded backoff. Guards, state, cookies, locks and private service keys are never copied. Async 650 events no longer consume pending 250 replies. Peer requests allow 90 seconds, are signed after SOCKS establishment and validate freshness at incoming header arrival; signatures and payload integrity remain enforced.

## Phase 2 — one physical phone and laptop

One authorized Android API36 phone ran `app.cryptopigeon.nativeclient.debug`. The actual NativeEngine, LocalBridge, app-owned Tor and foreground service shared an isolated test vault/runtime. The laptop used the actual Node daemon in a clean temporary home. Microphone, notifications and Doze exemption were granted for the correct debug package. Existing user vault/catalog/browser-fragment files were preserved.

Both peers used `DIRECT_TOR_P2P`, with an invalid loopback application relay URL. All peer messages/media traversed real public Tor v3 onions. No adb reverse/forward or USB peer transport was used; ADB carried installation, local actions, public invites and sanitized inspection only.

| Assertion | Result | Seconds from runner start |
| --- | --- | ---: |
| Both services bootstrapped and published | PASS | 32.672 |
| Mutual signed invites, verified contacts, pinned keys/routes and Signal sessions | PASS | 33.947 |
| Bidirectional Tamil/emoji text, visible WebView conversation, encrypted read receipt | PASS | 74.783 |
| Laptop-to-phone file, exact decrypted size/hash | PASS | 106.474 |
| Both file directions, exact decrypted size/hash | PASS | 125.098 |
| Physical microphone AAC/M4A payload, integrity both ways | PASS | 160.191 |
| Background persistence while display off, generic notification, service running | PASS | 240.020 |
| SQLCipher outbox queued while laptop listener stopped | PASS | 240.945 |
| Automatic recovery and encrypted delivered/read receipt | PASS | 476.085 |
| Phone lock stops foreground service, Tor process and monitor | PASS | 477.053 |
| Full hardware suite and instrumentation succeeded | PASS | 478.379 |
| Original charging stay-awake setting restored to 15 | PASS | 478.610 |

The runner explicitly allowed 20 seconds for fresh descriptor propagation. Recovery plus receipt took **235.140 seconds after the queued-outbox assertion**, including laptop restart/re-publication and retry/receipt traffic. Native lifecycle callbacks returned in **1 ms while the engine lock was held**, passing the one-second regression gate. Actual cold unlock exercised the saved encrypted external segment and complete fragment quorum. Independent inspection after completion found zero isolated test Tor processes; the runner cleaned up its laptop daemon.

## Latency

Final warm laptop-to-phone send-through-native-SQLCipher-persistence samples: **1,393 ms** and **4,736 ms**, including API, polling and ADB inspection overhead. These are two observations, not a latency guarantee or bidirectional distribution.

The complete first exchange/display/read-receipt group finished approximately **20.836 seconds after the intentional propagation pause**; that is not one message's latency. Earlier successful first-exchange groups took 78 and 117 seconds. A separate fresh-service attempt was stopped at 651 seconds during prolonged initial connections. All adverse results remain retained; consistent Tor latency is not established by the functional pass.

## Exact decrypted payloads

| Payload | Bytes | SHA-256 |
| --- | ---: | --- |
| Laptop file → phone | 65,537 | `755d266ef64a7e526bd24499de94c06a01d701020d43d7cf3840d51331d85a36` |
| Phone file → laptop | 98,321 | `78dcf73a28698e6712b4ac5e8d16c50626dc887a150e56edad3cadea9ecb4028` |
| Physical microphone voice payload, both ways | 9,580 | `c9318f1dc7c48de86416a3460163d21141e2e19d55ba65601d65e137095ba480` |

The laptop also compared the received phone fixture byte-for-byte against an independently generated fixture. Both binary files cross the 64-KiB chunk boundary. Voice was recorded on the phone and returned through a new encrypted laptop attachment; audio bytes never crossed ADB. Speaker playback was not automatically asserted.

## Screen-off evidence

The app was backgrounded for 70 seconds. The runner then explicitly slept the display and verified asleep/dozing before sending. Immediately after native persistence and before notification posting, **PowerManager interactive=false**. The receive counter advanced 0→1; the foreground service was running, and in-memory inspection found the app's generic **New encrypted message** notification. Unrelated device notifications were not saved.

The display became interactive after notification posting; this is recorded separately. This proves screen-off receipt/persistence after 70 seconds of app backgrounding, not 70 continuous seconds asleep or extended Doze/battery reliability. Charging stay-awake was temporarily changed 15→0 and restored to 15, including on failed attempts.

## Failures found and fixed

- **Misleading visible relay status:** unknown status now says Checking connection. The driver refreshes WebView after native session rotation, opens the actual paired chat and verifies the Direct Tor indicator and received text.
- **Android sender chunks deleted before send:** upload linked a blob before message/attachment metadata existed; cleanup deleted its chunks on the next API call. The link now commits with metadata in send's transaction. Sender-spool assertions and live file/voice integrity passed.
- **Tor briefly survived lock:** shutdown now waits within a bounded deadline, forces termination if needed, and tracks/closes incoming sockets. Final lock assertions passed.
- **Foreground-service startup deadline:** a captured main-thread onPause waited for the engine monitor during Argon2 derivation. Foreground engine work, service validation and destruction cleanup now run off main. The busy-engine callback regression and hardware startup passed; derivation parameters remain unchanged.
- **Incorrect screen-test postcondition:** the display may wake after notification posting. The test now measures actual native receive-time state, preserves pre-send asleep verification and records post-notification state separately. Notifications were not suppressed or downgraded.

Backups: `artifacts/checkpoints/pre-one-phone-tor/` and `artifacts/checkpoints/pre-visible-tor-status/`. [Sanitized startup/error history](PHONE-STARTUP-ERRORS.md) preserves Keystore stalls and service exceptions. The earlier Keystore backend-busy condition was not separately proven eliminated; subsequent vault creation and cold unlock succeeded without weaker encryption or software-key fallback.

Adverse runs retained: `65d63f7fce8b46f3` (reverse chunks); `4885d05266313b06` and `d86b648d92d3ab80` (old post-notification screen condition); `59d33474847cb864` (prolonged first exchange, operator stop); `415fd3836efc7f42` (captured startup crash); `475cff3c8932265b` (display woke during old pre-send idle condition). The earlier user-requested charging stop is documented separately. Failed/interrupted runs are not counted as successful complete suites.

## Phase 3 — APK and repository gates

- APK: `artifacts/crypto-pigeon-standalone.apk`, **83,914,360 bytes**, version `0.4.0-standalone`, debug package `app.cryptopigeon.nativeclient.debug`.
- SHA-256: **`62cfcebff4c3230dba53790c92fe82c38a99b7b169dcea3712faa5e162135015`**. Installed-APK reuse verified this hash before the passing run.
- All workspaces built; zero Vite chunk warnings: [build](resumed-final-build.log).
- Core **28/28**, desktop **3/3**: [tests](resumed-final-tests.log).
- Navigation/fragment regressions **6/6**: [tests](resumed-navigation-fragments.log).
- Tor cache/control/HTTP regressions **3/3**: [tests](resumed-tor-regressions.log). The local SOCKS unit fixture is separate from real Tor proof.
- Final native/instrumentation APK build and JVM **13 tests, zero failures/errors**: [build](lifecycle-native-build.log), plus `artifacts/native-android/build.log`.
- [Current source digests](changed-files.json): **46 source/configuration/documentation files**, 21 created and 25 modified. Generated assets, caches, compiled dist and APKs are build outputs.

Reproduce with `node scripts/one-phone-laptop-tor-live.mjs` (builds first). For matching prebuilt APKs: `node scripts/one-phone-laptop-tor-live.mjs --skip-build --reuse-installed-apk`; reuse checks the installed APK hash and must not replace rebuilding changed native/UI source.

Coverage is one phone and one laptop, instrumented native API actions, and explicit visible connection/chat checks. Extended OEM process killing, reboot/automatic unlock, network handover, all supported attachment sizes, independent security review and speaker playback are outside this run. Production release signing and credentialed legacy relay integration were not performed.
