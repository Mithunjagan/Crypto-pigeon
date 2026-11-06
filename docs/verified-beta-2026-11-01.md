# Verified beta — 1 November 2026

This is a tested Windows desktop and USB-paired Android beta. **It is not a
standalone Android product or a public production release.** Both supplied
physical phones were used; each has its own host daemon, vault and account.

## What changed

- Incoming Signal ratchet changes and message persistence now commit together.
  A simulated database write failure leaves the envelope retryable instead of
  consuming the ratchet state without saving its message.
- Attachment downloads have a durable queue in the encrypted database and retry
  after an outage or restart. Download completion updates the existing row.
- Sent and received files are cached inside their own vault. New cached files
  use AES-256-GCM with an attachment-specific authenticated context. Legacy CBC
  files remain readable, with size and digest validation.
- Backup/restore includes attachment bytes and relocates their paths. Relay
  chunk uploads enforce ownership, bounds and ciphertext/nonce lengths.
- Expired messages are excluded from history and from outgoing delivery, even
  before the cleanup job runs. Cleanup shares the API serialization queue.
- Android pairing survives force-stop/relaunch while its daemon session remains
  valid. Sessions expire after 24 hours and are revoked by lock or daemon
  restart. CSRF refresh no longer breaks another tab's valid requests.
- Android accepts pairing through an explicit intent extra, supports distinct
  daemon ports, persists cookies, requests microphone access when needed, and
  displays a reconnection screen. Downloads preserve their filenames.
- The UI prevents duplicate submit taps, checks both upload and send responses,
  avoids showing a late message response in another conversation, provides
  search, clearer account setup, mobile back navigation, scrollable dialogs,
  dismissible notices and voice-note playback. Successful notices clear.
- Windows packaging includes the app's paper-plane icon and nested workspace
  dependencies. Native libraries remain in a separate bundled Node runtime.

## Security dependencies

The initial production audit reported eight advisories: six high and two
moderate. Fastify is now pinned to 5.12.7 and Zod to 4.6.7. Record schemas were
migrated to the two-argument form, following the
[Zod migration guide](https://zod.dev/v4/changelog).

The general static-file plugin was removed. The daemon serves only known build
assets from an in-memory map; request paths never become filesystem paths.
The final `npm audit --omit=dev` result is **zero known production advisories**.
This point-in-time package audit does not establish cryptographic security.
Development and packaging dependencies are outside that production audit.

## Verification

| Gate | Result and scope |
|---|---|
| Workspace build | TypeScript and Vite build pass |
| `npm test` | 22 core/regression checks and 3 desktop policy tests pass |
| PostgreSQL integration | 10 checks pass, including attachment restore, backup signatures, account transfer and password rotation |
| HTTP checks | 4 checks pass: UI assets, encoded traversal rejection, pairing/origin checks and CSRF/single-use bootstrap |
| Two physical phones | 21 checks pass through the actual WebViews, libsignal, daemons and PostgreSQL-backed relay |
| Native downloads and media | Both phones save exact file bytes; a generated tone records, encrypts, delivers, decrypts and decodes as playable WebM |
| Android build and lint | Debug APK compiles; lint has 0 errors and 2 warnings |
| APK signature | v2 signature verifies; this is a debug signature |
| Windows package smoke | Onboarding, launch, restart, renderer isolation, persistent storage and daemon shutdown checked outside the source checkout |

The two-phone run includes recipient-controlled approval, Unicode in both
directions, multi-chunk attachments with matching sender/recipient hashes,
force-stop/relaunch on both devices, relay interruption, durable queued delivery,
chronological history, ciphertext inspection and backup recovery after outage.

Voice-note testing used a generated tone, not the physical microphones. The
native microphone permission flow compiles but has not had a complete physical
microphone acceptance test. Real room audio was not captured.

## Builds and evidence

- [Android debug APK](../artifacts/crypto-pigeon-debug.apk)
- [Windows x64 installer](../artifacts/desktop/Crypto-Pigeon-Setup-0.1.0-x64.exe)
- [Checksums and build manifest](../artifacts/release-manifest.json)
- [Production dependency audit](../artifacts/dependency-audit-after.json)
- [Native downloads and synthetic audio results](../artifacts/two-phone-media/results.json)
- [HTTP security checks](../artifacts/daemon-http-check.json)

The release manifest identifies the final phone evidence directory. Intermediate
failed runs and rollback checkpoints were retained separately. Test vaults and
test credentials are under ignored artifacts and are excluded from the source
archive. The source archive also excludes real vaults, `.env`, SDKs, caches and
production secrets.

Both phones are left connected to disposable demo accounts for review. Their
host processes and USB cables must stay connected. Use distinct stable vault
directories and ports when pairing real profiles; see
[Android setup](vault-backup-and-android.md).


Native Android work continues separately: [implementation and device evidence](native-android-implementation.md). The shipped USB beta remains unchanged.

## Remaining release gates

1. Standalone on-device vault storage and cryptography, secure mobile key storage,
   background delivery and push notifications. The current APK depends on a PC.
2. A provisioned HTTPS production relay, operational monitoring, quotas and
   tested infrastructure backup/restore. USB loopback testing does not verify
   communication across two real external networks.
3. Production signing identities, distribution/update infrastructure and store
   release materials. The Windows installer is unsigned; Android is debug-signed.
4. Independent cryptographic/security review and broader device/network testing.

No public server was deployed and no store release was published in this run.
Existing application vaults and Docker volumes were preserved.

## Reproduce

```powershell
npm ci
npm run build
npm test
npm run test:http
# Requires a PostgreSQL connection in DATABASE_URL:
npm run test:integration
# Requires the bundled local test PostgreSQL fixture and both connected devices:
$env:ANDROID_SERIALS = '10BEAN0MX8001J4,1396271662000T1'
npm run test:phones -- --skip-install
npm run test:phone-media
```

For the tested SDK installation, APK compilation used the existing
`artifacts/android-test/Use-AndroidSdk.ps1` environment and extension-SDK init
script. These machine-local tools are not part of the source archive. A standard
Android SDK and full JDK can use the documented `npm run android:build` command.
