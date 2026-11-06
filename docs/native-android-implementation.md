# Standalone Android 0.4.0 implementation

The native APK contains the React WebView UI, authenticated loopback API, vault engine, SQLCipher, libsignal and embedded Tor. Direct messaging needs no laptop, home relay, application cloud server, Firebase, Google Play Services or Orbot. Both phones still need internet access to the public Tor network. Relay and cloud backup are optional.

## Vault compatibility and isolation

Libsignal stays at **0.96.4** in Node and Android. The engine preserves Argon2id at **64 MiB, 3 iterations, parallelism 1**, existing HKDF domain separation, AES-256-GCM VMK wrapping and the seven-way XOR model requiring **all seven fragments**. Existing vault and opaque Signal records remain readable.

New standalone vaults save `segment-07.cp7` through the document picker. Creation is confirmed after that save. A cold unlock still requires the external seventh segment, existing local/browser fragments and credentials. An exported `.cpvault` is encrypted external storage; it does not bypass reconstruction. Save replacement external files after password rotation as prompted.

`NativeVaultCatalog` separates Android vault roots, browser fragments, device-key aliases, databases, attachments, transport preferences, Tor data and onion identities. Switching closes the previous transport and invalidates its asynchronous callbacks. Preserve app data and external files during upgrades.

Direct-mode self-activation creates the account and public `CP-XXXX-XXXX` UID locally after username selection, without relay registration. A UID alone cannot route a serverless message.

## Embedded Tor and routing

`TorOnionTransport.java` launches app-owned `libtor.so` with per-vault internal data, loopback SOCKS/control ports, cookie authentication and safe logging. Gradle extracts only arm64-v8a and x86_64 native binaries from Guardian Project's pinned Tor Android AAR. Its Java service is not packaged: Crypto Pigeon owns the process and service lifecycle on API 26â€“36.

The controller uses `ADD_ONION` to create an ephemeral v3 service mapping virtual port 80 to a separate loopback peer listener. Its private key is persisted inside SQLCipher, not a plaintext hidden-service directory. Unlocking the same vault restores the same address; another vault gets its own address.

Outbound SOCKS requests use domain-name forwarding, so onion hosts never reach system DNS. Every peer request signs a domain-separated tuple binding sender device, time, nonce, method, path and exact body. The peer listener accepts only pinned device-auth keys and exposes no vault/settings API.

| Mode | Behavior |
| --- | --- |
| `DIRECT_TOR_P2P` | Default. Only onion delivery; unreachable peers leave messages queued. |
| `HYBRID_TOR_RELAY` | Prefer Tor, with configured relay fallback for accounts supported by that relay. |
| `RELAY_ONLY` | Preserve the existing activated relay-account workflow. |

Purely local activation does not register an identity on an arbitrary legacy relay. Existing registered relay accounts retain their IDs/credentials. Selecting hybrid mode cannot make an unsupported relay authenticate a standalone account.

Status reports mode, active transport and real bootstrap percentage. Bootstrap reaching 100% does not prove a particular peer is online or its onion descriptor has propagated.

## Signed invites and contact pinning

The URI is `pigeon://invite?v=2&data=...&sig=...`. Bounded raw-deflate encodes a fixed ordered array containing public UID, username, onion address, account/device IDs, registration ID, Ed25519 device-auth key, Signal identity, signed classical prekey and signed Kyber last-resort prekey. Reusable QR invites deliberately use the reusable signed PQ fallback.

Both platforms verify the same canonical device signature and the Signal prekey signatures. Import stores the endpoint/bundle in SQLCipher, establishes the session locally and marks the contact verified. Re-import preserves the existing session. Changed pins and pending identity-change warnings cannot be silently overwritten. The Safety Number screen remains available.

**Both people import each other's invite.** Exchange it in person or through an authenticated channel: a self-signature binds fields and keys, but cannot identify a human if an attacker substitutes another signed invite. A public UID alone is insufficient.

The UI supports camera/image scanning, copy and paste of complete signed invites, and high-resolution level-L QR generation. The public interoperability fixture in `native/src/test/resources/serverless-invite.json` contains no private key or vault credential.

## Durable messages and attachments

Signal ratchet advances and exact encrypted retry bytes commit before sending. The direct HTTP acknowledgement follows encrypted SQLCipher inbox persistence; transactional decryption, deduplication and message persistence then generate encrypted control receipts. Failed decryption stays pending. Lost acknowledgements retry the original ID/ciphertext.

Attachments retain the **25 MiB** limit, per-file AES-256-GCM keys and authenticated 64 KiB chunks. The sender spools encrypted chunks locally without needing the recipient online. The recipient fetches authorized chunks from the sender and checks nonces, tags, size and digest before caching an encrypted local file. Durable manifests/chunks support retries. Sender availability is required until attachment retrieval completes.

Tor socket waits execute outside the serialized engine lock, allowing simultaneous sending and receiving. Completion callbacks verify the active vault/transport before modifying records. Expiration removes related local ciphertext spools.

## Foreground service and notifications

`PigeonRuntime` owns the process-scoped `LocalBridge`; the activity and foreground service share it. Closing the WebView does not close an unlocked engine. `PigeonForegroundService` declares `remoteMessaging|specialUse`, posts an ongoing status notification and uses `START_STICKY` while the unlocked runtime exists. Bounded CPU/Wi-Fi leases cover bootstrap and packets.

There is no intentional one-minute background suspension. Vault Lock, Panic Lock, vault switching and shutdown close the old transport. A killed process or reboot loses unlocked keys and requires unlock again; credentials are not saved to reopen a vault automatically. Android force-stop, OEM battery restrictions and unavailable networks can still interrupt delivery.

After successful decryption and message commit, background text/attachment messages produce **New encrypted message** notifications. Neither sender nor plaintext appears. Plaintext previews are not enabled. Android notification permission is requested separately.

`/api/power/status` reports battery exemption, service and notification state. Settings offers a one-time banner, explicit `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` flow, dismissal and later settings access. OEM unrestricted-battery/auto-start settings may also be needed.

## Microphone and media

The manifest declares `RECORD_AUDIO`. The WebChromeClient grants audio/video capture only to the exact loopback origin after runtime permission; unsupported resources and other origins are denied. Recording requests permission through `getUserMedia`.

The UI selects a supported recording MIME type and matching WebM/Ogg/M4A filename. Voice notes follow the attachment encryption/integrity path. Playback uses the authenticated loopback handler with the correct audio MIME, not an external plaintext URL.

## Reproduce verification

Use Node 22+, JDK 17, Android SDK platform 36 and the existing Gradle wrapper. Do not print environment files or credentials.

```powershell
npm.cmd run build
npm.cmd test
node --import tsx --test scripts/back-navigation.test.mjs scripts/vault-fragments.test.mjs
npm.cmd run android:native:build -- --tests --jvm-tests
```

Output: `artifacts/crypto-pigeon-standalone.apk`. Gradle log: `artifacts/native-android/build.log`. JVM results: `native/build/test-results/testDebugUnitTest`. **--tests builds the instrumentation APK; it does not execute physical-device tests.**

Optional `node scripts/tor-live-check.mjs` uses isolated desktop vaults and real app-owned Tor processes. Desktop success is not Android device acceptance. Historical archive reports do not certify the new Tor/service code.

## Two-phone acceptance still required

Use separate test vaults and preserve existing external files. Install on two supported phones, allow notifications/unrestricted battery, unlock, wait for bootstrap and exchange signed invites both ways. Disconnect USB networking; use different Wi-Fi/mobile networks. Check simultaneous messages, encrypted delivery/read receipts, files and actual microphone voice-note recording/playback.

Turn both screens off and leave the apps backgrounded beyond one minute. Confirm generic notifications and delivery. Exercise Doze, network handover, airplane mode, queued restart/unlock retries, duplicate suppression, lost acknowledgements, 25 MiB attachment integrity and denied permissions. Vault/Panic Lock must stop delivery, cold process restart must require unlock, and switching vaults must keep addresses, contacts and callbacks isolated.

Device acceptance, release signing, distribution licensing and independent security review remain separate from repository/JVM checks.
