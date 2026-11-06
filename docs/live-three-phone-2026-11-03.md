# Three-phone live internet verification — 3 November 2026

Real standalone Android messaging passed on all three supplied physical phones.
**Direct peer-to-peer transport could not be tested: the current native engine
constructs its router with no direct transport and forces `RELAY_ONLY`.**
The results below are real public-internet relay delivery, not WebRTC P2P.

| Test phone | Model | Serial | Separate test UID |
|---|---|---|---|
| 0 | vivo V2336 | 10BE7802KH0012D | CP-0196-784B |
| 1 | vivo V2422 | 10BEAN0MX8001J4 | CP-30F7-0740 |
| 2 | vivo V2152 | 1396271662000T1 | CP-C8E7-96C3 |

The native app and instrumentation APKs were built from this source checkout
and installed on each device. Each device created a different encrypted vault,
saved its seventh segment through Android's document picker, registered its own
identity and performed its own Signal encryption/decryption. Existing user vaults
were kept separate: test roots use `no_backup/live-phones-live-mw0zr4ym`.
The two previously installed APKs were saved in the evidence folder before updating.

Phones connected to the public HTTPS relay at
`https://rethink-wrinkle-balancing.ngrok-free.dev` using their own networking.
Every device had an empty `adb reverse --list`. USB provided UI control and
observations only; no PC vault daemon performed cryptography or delivered messages
through a USB network tunnel. The public relay itself is hosted on this computer
behind ngrok, so this is not a test of independently hosted production infrastructure.

## Live results

| Check | Result |
|---|---|
| 0 → 1 | Pass; recipient UI observation in 1,476 ms |
| 1 → 2 | Pass; 2,163 ms |
| 2 → 0 | Pass; 2,663 ms |
| 1 → 0 | Pass; 492 ms |
| 2 → 1 | Pass; 1,190 ms |
| 0 → 2 | Pass; approximately 940 ms |
| Unicode Tamil, Devanagari and emoji | Pass in all six directions |
| Three 150,123-byte attachments, 0 → 1, 1 → 2 and 2 → 0 | Pass; receiver bytes exactly match sender bytes |
| Phone 0 cellular only ↔ Phone 1 Wi-Fi | Pass in both directions |
| Phone 0 Wi-Fi and mobile data both disabled | Message queued locally; absent from receiver |
| Restore cellular data | Message automatically delivered once; sender queued state cleared |
| Safety numbers for all three contact pairs | Match after live traffic |
| AndroidRuntime crash log inspected on each phone | No crash entries returned |

Each of the six text messages appeared exactly once in the recipient's decrypted
UI. Message arrival used the app's own synchronization; the harness did not call
the recipient's fetch endpoint or reload its page to cause delivery. The timings
are individual UI observations including USB polling overhead, not a latency benchmark.
The cellular-only route recorded for Phone 0 contained `rmnet_data2` and no Wi-Fi
interface. Its Wi-Fi and mobile-data settings were restored after the recovery test.

No application messaging failure was reproduced in these checks, so no production
Java or React source was changed. SHA/byte comparison against the initial checkpoint
confirmed both source trees remained unchanged. Test-controller startup handling
and attachment selectors were corrected during the run; the earlier selector failure
is retained as `recovery-harness-selector-attempt.json` and was not an app failure.

The new repeatable device harness is test-only. Native assembly, instrumentation
assembly and all nine native JVM tests passed. The JavaScript harnesses passed
syntax checks. This source archive has no Git metadata.

## Evidence and reproduction

Evidence directory: `artifacts/three-phone-live-20261103/`.

- `results.json`: six-direction native messaging results and device transport status.
- `recovery-results.json`: attachment hashes, cellular routing and offline recovery.
- `phone-0-final.png`, `phone-1-final.png`, `phone-2-final.png`: actual device WebView screenshots.
- `source-scope.json`: comparison against the initial production-source checkpoint.
- `instrumentation-0.log` through `instrumentation-2.log`: separate on-device sessions.

Credentials, rollback APKs and source checkpoints are local artifacts; credentials
are kept in `credentials.private.json` and are not included in this report.

With these three authorized devices connected and the same public relay running:

```powershell
node scripts/android-native-build.mjs --offline --tests --jvm-tests
npm run test:phones:internet
npm run test:phones:recovery
```

The test harness leaves the isolated chats visible for inspection, with a bounded
45-minute on-device session. `--attach` reconnects the message runner to sessions
that are still open. A normal new run creates fresh vault credentials and test
accounts. The recovery runner must run while the three live sessions are open.

All three runtime privacy endpoints reported `relayOnly: true` and
`activeTransport: "Encrypted Relay"`. Signaling schemas and a router interface
exist, but the native application has no connected WebRTC transport. These tests
therefore do not establish a direct P2P success.
