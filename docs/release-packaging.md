# Local release packaging

## Android

Run `node scripts/prepare-release-signing.mjs` once. It reuses an existing key,
otherwise creates an RSA-4096 JKS valid for 10,000 days under `artifacts/keys/`.
Generated credentials stay in `release-signing.properties`; Windows directory
access is restricted to the current account. Neither file belongs in Git.
Back up both files securely: losing the key prevents updates signed by that identity.

Run `npm run android:native:build -- --release` to build the signed
`artifacts/crypto-pigeon-release.apk`. Release builds disable debugging and code
shrinking, retain the native JNI/WebView bridges, and package arm64-v8a/x86_64 Tor.
The SDK's `apksigner verify --verbose --print-certs` verifies the finished artifact.
Version code is 2; increase it for future distributed updates.

The production application ID is `app.cryptopigeon.nativeclient`. The debug ID
is `app.cryptopigeon.nativeclient.debug`. They are separate Android sandboxes:
the production app cannot read debug app data or its Keystore identity. Installing
the production package alongside debug preserves debug data, but does not migrate
it. Do not uninstall, clear data, copy device-bound key material, or promise an
in-place debug-to-production upgrade. Subsequent production updates must retain
the production application ID and signing identity. Existing installations signed
with another key cannot be overwritten with this key.

The standard native build command still produces debug standalone and
instrumentation APKs. Release builds write a separate filename and preserve them.

## Windows

`npm run desktop:installer` builds workspaces, stages the Node daemon and UI,
installs locked production dependencies, validates native modules and Tor modules,
and packages Tor with its licenses. The packaged daemon's working directory is
its resource root, so its `artifacts/tor/tor.exe` path resolves inside the install.
Archive a previous nonempty `artifacts/desktop-runtime` before rebuilding; staging
deliberately refuses to overwrite it.

The installer is `artifacts/desktop/Crypto-Pigeon-Setup-0.1.0-x64.exe`.
Fresh profiles can choose **Start with Tor** without contacting an application
relay. Existing profile files and relay onboarding remain supported. Native
dependencies run in bundled Node rather than Electron's ABI. Windows Authenticode
signing is separate from Android signing and is not configured by this workflow.

`npm run desktop:smoke` copies packaged resources outside this checkout and checks
Tor onboarding, renderer isolation, local authentication, persistent browser
storage and daemon shutdown using an isolated profile and hidden windows.

## Recovery

Android registers a default-network callback while unlocked direct delivery and
the foreground service are active; lock/service shutdown unregisters it. Network
switches and validation recovery cancel stale outbound sockets, clear reconnect
backoff and request `DisableNetwork=0`/`NEWNYM` with a ten-second cooldown and a
trailing request. Circuit/publication readiness wakes the existing encrypted queue.
No onion identity, Signal session or durable ciphertext is replaced.

Desktop bootstrap, first descriptor publication and circuit/liveness recovery
events schedule an immediate serialized queue pass. Event bursts coalesce and
vault state is checked inside the pass. Periodic retries remain as a fallback.

Regression checks prove scheduling and state transitions, not a measured
Wi-Fi/mobile handover latency. Public Tor propagation and an offline remote peer
can still delay delivery. See the release readiness report for actual validation.
