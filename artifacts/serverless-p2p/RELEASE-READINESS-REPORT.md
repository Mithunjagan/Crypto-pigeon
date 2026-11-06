# Crypto Pigeon release packaging and recovery verification

Prepared 6 November 2026 (IST). Existing serverless implementation and user data
were preserved. This report separates build/regression evidence from physical
network-handover acceptance, which was not performed for this release.

## Source baseline

- Repository: `D:\Crypto pigeon main\Crypto-pigeon-master`.
- Baseline commit: `f50afa5ea582686119c803176c29ebb857a687ef`.
- Commit subject: `feat: serverless Tor v3 P2P, signed v2 invites, and release packaging`.
- 272 source, configuration, test and documentation files committed. No remote or
  push was configured. A subsequent documentation commit adds this report.
- The staged-blob audit passed with zero findings: forbidden local-data paths,
  signing material, private-key/credential patterns, exact local environment
  secret matches, large unexpected files and symlinks were checked. Evidence:
  `release-secret-audit.json`. This is a focused local audit, not an independent
  security review.
- `.env*`, signing files, vault files, generated Android crypto fixtures, tools,
  checkpoints, hardware-run data and binary build outputs are ignored. Only
  Markdown reports from `artifacts/serverless-p2p/` are tracked there.
- Source and previous desktop runtime checkpoint:
  `artifacts/checkpoints/pre-release-packaging/20261106-213627/`.

## Phase 1: network recovery

Android now registers a default-network callback while unlocked direct delivery
and its foreground service are active, unregistering on lock/service shutdown.
Network replacement or validation loss/regain clears reconnect backoff, cancels
obsolete outbound sockets and schedules `SETCONF DisableNetwork=0` and
`SIGNAL NEWNYM` on the Tor monitor. Requests coalesce with a ten-second cooldown
and a trailing request. The callback uses supplied capability state rather than
synchronous connectivity lookups; stale loss events for the previous network
cannot disconnect the replacement network. The first validation callback does
not duplicate the initial availability recovery request.

Circuit readiness/bootstrap/publication wakes a serialized native queue pass.
Desktop first publication, bootstrap completion and circuit/liveness recovery
likewise schedule an immediate serialized queue pass; event bursts coalesce and
locked/closed/session-changed state remains guarded. The periodic retry remains.
Existing direct queues already used roughly five-second polling; their durable
rows did not contain a long exponential retry timer. The reset reconnect backoff
also covers the relay socket. No Signal re-encryption, identity reset, weaker
signature validation or relay fallback in direct mode was introduced.

Regression evidence:

- `release-tor-regressions.log`: 4/4 passed, including immediate readiness-driven
  scheduling, burst coalescing, resume and shutdown cancellation.
- `NetworkHandoverTest`: replacement-network handling, repeated callbacks,
  validation loss/regain and stale old-network events passed as part of 14 JVM tests.
- Real desktop public Tor rerun: **PASS**, exit 0. Simultaneous bidirectional
  Signal messages, maximum-length Unicode, exact encrypted attachment bytes and
  durable offline retry after both vaults reopened with unchanged onion identities
  all passed. Evidence: `release-desktop-tor-live.log`.

There is no new physical Wi-Fi/mobile handover timing measurement. These checks
do not establish a reduction from the earlier 235-second recovery observation.
Remote-peer outages, Tor circuit construction and descriptor propagation can
still delay delivery; NEWNYM is a recovery request, not a latency guarantee.

## Phase 2: signed Android release

- File: `artifacts/crypto-pigeon-release.apk`.
- Size: **56,725,694 bytes**.
- SHA-256: **`bd2e2aa947eda6b7355c6957c7ce5c11f071bb15fff60604befcb9f11c94918f`**.
- Application ID: `app.cryptopigeon.nativeclient`; version code **2**, version
  name `0.4.0-standalone`; debugging disabled and minification disabled.
- `apksigner verify --verbose --print-certs`: **PASS**, one RSA-4096 signer,
  APK Signature Scheme v2 verified. Evidence: `release-apksigner.log`.
- Certificate SHA-256:
  `4b8b04abc0121685caad1aed95bfb59ee762b5e72617ee84ff2ce4400107b678`.
- ZIP inspection confirmed **libtor.so, libsignal_jni.so and libsqlcipher.so**
  for **arm64-v8a and x86_64**. Native Java/JNI/WebView entry points are not shrunk.
- A new RSA-4096 JKS with 10,000-day validity was generated at
  `artifacts/keys/crypto-pigeon-release.jks`; credentials reside only in the
  ignored `release-signing.properties`. The signing directory's Windows ACL
  grants only the current account access. No credentials were printed or committed.
  The preparation script validates/reuses this identity on later runs. Securely
  preserve both local signing files for future updates.

The production ID and the debug ID `app.cryptopigeon.nativeclient.debug` have
separate Android sandboxes and Keystore identities. The release can coexist with
debug, but it **does not migrate debug vaults or update that package in place**.
Future production updates must keep the production ID and signing identity;
another preexisting production signing identity cannot be overwritten by this key.
No app was uninstalled, data cleared, vault migrated or APK installed during this
release task. See [Android signing documentation](https://developer.android.com/studio/publish/app-signing).

The standard debug gate still writes `artifacts/crypto-pigeon-standalone.apk`
(66,427,107 bytes; SHA-256
`1928e040de916930ef1dbca6115c2b526e655274298b8bb9837d54cca5b21ba4`).
The exact APK used in the earlier passing physical run is preserved as
`artifacts/checkpoints/pre-release-packaging/20261106-213627/crypto-pigeon-standalone-hardware-passed.apk`
with its original SHA-256
`62cfcebff4c3230dba53790c92fe82c38a99b7b169dcea3712faa5e162135015`.
The earlier live report's hash describes that historical APK, not the rebuilt debug APK.

## Phase 3: Windows standalone installer

- File: `artifacts/desktop/Crypto-Pigeon-Setup-0.1.0-x64.exe`.
- Size: **164,098,970 bytes**.
- SHA-256: **`140155a495a6e79b356d5d7d72d56acec2c8c4b5945ee0df054ec9522b6f705e`**.
- `npm.cmd run desktop:installer` passed. After the final daemon diagnostic
  refinement, compiled daemon staging was refreshed from the final workspace
  build and Electron Builder repackaged the final installer.
- Bundled imports for `tor-transport`, `tor-routing`, `serverless-contacts` and
  `tor-recovery` loaded successfully in bundled Node. Bundled `tor.exe --version`
  succeeded. The packaged daemon runs with its resource root as working directory,
  resolving `artifacts/tor/tor.exe` inside the installed application.
- Packaged `tor-transport`, `tor-routing`, `serverless-contacts`, `tor-recovery`
  and `server.js` hashes match the final compiled workspace files exactly.
- Fresh profiles have a **Start with Tor** option that requires no application
  relay. Existing relay onboarding/profile behavior remains available.
- Outside-checkout smoke checks passed direct onboarding, renderer sandbox and
  origin isolation, local API authentication, browser-storage persistence across
  restart and daemon shutdown. Final refresh result recorded below.
- **Windows Authenticode signing is not configured.** The installer is unsigned;
  Android signing does not sign the Windows executable. No installer was run on
  the user's existing desktop profile.

## Phase 5: final required gates

| Gate | Result | Evidence |
| --- | --- | --- |
| `npm.cmd run build` | PASS; all workspaces, zero Vite chunk warnings | `release-final-build.log` |
| `npm.cmd test` | PASS; 28 core + 3 desktop | `release-final-tests.log` |
| Navigation and vault-fragment Node tests | PASS; 6/6 | `release-navigation-fragments.log` |
| Tor bootstrap/control/HTTP Node tests | PASS; 4/4 | `release-tor-regressions.log` |
| `npm.cmd run android:native:build -- --tests --jvm-tests` | PASS; debug/instrumentation APKs; 14 JVM tests, zero failures/errors | `release-final-native-gate.log`, native XML results |
| Signed release build with JVM tests | PASS | `release-native-build.log` |
| APK signature and native-library inspection | PASS | `release-apksigner.log`, `release-artifacts.json` |
| Final desktop package/smoke refresh | PASS; installer exit 0, setup/launch/restart smoke modes passed | `release-desktop-final-package.log`, `release-desktop-smoke.log` |
| Real desktop public Tor rerun | PASS; exit 0, text/Unicode/media/cold-reopen offline retry | `release-desktop-tor-live.log` |
| Staged secret audit before baseline commit | PASS; 272 files, zero findings | `release-secret-audit.json` |

## Retained adverse results and limits

The first native build/test attempt overlapped a final network-validation logic
and test refinement and failed the new assertion; the stable-source release
rebuild and final debug/instrumentation/JVM gate passed. The first outside-checkout
desktop smoke attempt exhausted its ten-second onboarding wait under concurrent
build/compression load; with a wait covering the app's existing 30-second startup
deadline, all three smoke modes passed. Earlier logs are retained with
`first-attempt` filenames and are not counted as passing gates.

The first additional desktop Tor rerun passed messaging, maximum Unicode and
media, then failed with `TOR_CONTROL_FAILED` during reopen. The control diagnostic
now preserves only the numeric response status, never response content or keys.
That first failure's exact response/root cause was not captured and is not claimed
fixed merely by a subsequent pass. Its log remains
`release-desktop-tor-live-first-attempt.log`.

The earlier physical-phone run `b45bfd8c606037b3` remains historical evidence.
The new signed release was not installed or hardware-tested, and no new physical
network switch, extended OEM/Doze/battery behavior, speaker playback, production
relay integration, automatic updater or independent security review was performed.
Build/signature/regression completion alone does not establish broad daily-driver
reliability. See `docs/release-packaging.md` for reproducible commands and update constraints.
