# Sanitized Android startup evidence — 6 November 2026

No credentials, Vault IDs, private keys, message plaintext or unrelated device notifications are included.

## Initial attempts: secure Keystore wait

The on-device method-only sample in `one-phone-97bb226be7c02e07/native-method-stacks.json` captured a thread in `TIMED_WAITING`:

```text
java.lang.Thread.sleep(Native Method)
android.security.KeyStoreSecurityLevel.interruptedPreservingSleep(KeyStoreSecurityLevel.java:239)
android.security.KeyStoreSecurityLevel.createOperation(KeyStoreSecurityLevel.java:138)
android.security.keystore2.AndroidKeyStoreCipherSpiBase.ensureKeystoreOperationInitialized(AndroidKeyStoreCipherSpiBase.java:355)
android.security.keystore2.AndroidKeyStoreCipherSpiBase.engineInit(AndroidKeyStoreCipherSpiBase.java:188)
javax.crypto.Cipher.init(Cipher.java:1103)
app.cryptopigeon.nativeclient.DeviceKeyStore.wrap(DeviceKeyStore.java:32)
```

Other local API threads were waiting for the bridge monitor or a loopback HTTP response. The UI displayed `Opening your private space…`. This is a captured blocking call, not proof of a permanent Keystore failure. The user restarted/unlocked the phone; later vault creation and cold unlock passed.

## Post-restart attempt: Android foreground-service deadline

Actual crash-buffer exception, captured from PID 19586 at device local time 10:13:47.746:

```text
android.app.RemoteServiceException$ForegroundServiceDidNotStartInTimeException:
Context.startForegroundService() did not then call Service.startForeground():
ServiceRecord{10e9678 u0 app.cryptopigeon.nativeclient.debug/app.cryptopigeon.nativeclient.PigeonForegroundService c:app.cryptopigeon.nativeclient.debug}
  at android.app.ActivityThread.generateForegroundServiceDidNotStartInTimeException(ActivityThread.java:2926)
  at android.app.ActivityThread.throwRemoteServiceException(ActivityThread.java:2894)
```

`one-phone-fce7599322a39217/instrumentation.log`:

```text
INSTRUMENTATION_RESULT: shortMsg=Process crashed.
INSTRUMENTATION_CODE: 0
```

Runner `one-phone-after-restart.log` ended at 121 seconds with `PHONE_INSTRUMENTATION_EXITED`. Root cause of the missed foreground deadline has not been confirmed. Do not call this fixed because a later attempt progressed further.

## Earlier morning attempt: user-requested stop, distinct from the above crash

`one-phone-lifecycle-diagnostic.log`:

```text
[0s] One authorized physical phone detected
[6s] APKs installed; microphone, notifications and Doze exemption granted
[8s] Clean laptop daemon vault self-activated in direct mode
[8s] Tor bootstrap laptop/phone 0/0
[12s] Tor bootstrap laptop/phone 14/0
[13s] Phone stage vault_create
[16s] Tor bootstrap laptop/phone 100/0
[20s] Phone stage vault_cold_open
[23s] Phone stage tor_bootstrap
[26s] Tor bootstrap laptop/phone 100/5
[30s] Tor bootstrap laptop/phone 100/100
[30s] Verification failed
```

Native `device-checks.json` records `Isolated native vault cold-unlocked with all fragments and local activation`, PASS, 11,317 ms. The user requested stopping to charge the phone during this run. `am force-stop` was used, preserving app data; this explains the latest `Process crashed`, instrumentation code 0 and false suite result. It is not a passing complete hardware suite or evidence of a new spontaneous crash.

The runner finished with exit 1 after the requested stop, saved results in `one-phone-4016b930e63a1256/`, stopped its laptop daemon, and inspection confirmed no target app process and zero isolated test Tor processes.

## Resumed evening startup trace and lifecycle fix

Run `one-phone-415fd3836efc7f42` reproduced the foreground-service startup exception at device time 19:57:49. Its `native-method-stacks.json` captured the loopback API worker inside Argon2 derivation in `NativeVault.createExternal`, while the **main activity thread was BLOCKED in `NativeEngine.foreground`, called from `MainActivity.onPause`**. This explains how long vault work could delay the main thread servicing Android's foreground-service deadline. The sanitized exception is retained in that run's `service-startup-error.txt`.

The fix makes activity/screen foreground updates immediate and moves serialized engine work to its existing background executor. Foreground-service validation now runs on a service worker after the notification is posted; destruction schedules guarded engine cleanup rather than blocking the main thread. A device regression check holds the engine lock while invoking foreground/background callbacks on the actual main thread and requires them to return in under one second. The new APK and that hardware regression require successful revalidation before claiming the startup issue resolved.

## Attachment and screen-off findings during resumed verification

- Run `one-phone-65d63f7fce8b46f3` exposed Android upload cleanup deleting sender chunks before the attachment message existed. The link is now created transactionally with message metadata. Later runs `one-phone-4885d05266313b06` and `one-phone-d86b648d92d3ab80` passed exact file hashes and actual microphone voice payloads both ways. Their sender-spool assertions also passed.
- Native lock originally returned before the Tor process exited (`TOR_PROCESS_SURVIVED_LOCK`). Bounded termination and tracked incoming sockets fixed that check in subsequent hardware runs.
- `one-phone-d86b648d92d3ab80` confirmed 70 seconds asleep before sending, native persistence and a generic notification, then failed the old post-notification `PHONE_NOT_ASLEEP` condition. Its wake timestamp followed notification receipt. The revised check samples Android's interactive state immediately after native persistence and before posting the notification, and records whether the screen is interactive afterward separately. Charging stay-awake is temporarily disabled and restored by the runner. This verifies the required receive-time state without assuming the phone must remain asleep after a notification appears.
- That run's warm laptop-to-phone persistence samples were **1,315 ms** and **3,254 ms**, including inspection/polling overhead. They are two observations, not a general latency guarantee. A separate run `one-phone-59d33474847cb864` was stopped at 651 seconds during a prolonged initial Tor exchange; it remains failed/interrupted evidence.

## Final revalidation — completed

The full run `one-phone-b45bfd8c606037b3` subsequently passed with runner exit 0 and instrumentation code -1. It included the 1 ms main-thread callback regression while the engine lock was held, actual native startup/cold unlock, exact file and microphone integrity both ways, receive-time non-interactive screen state and generic notification, automatic encrypted outbox recovery/receipt, and final foreground-service/Tor-process/monitor shutdown. See ONE-PHONE-LIVE-REPORT.md for exact timings, hashes and the retained limitations. Earlier pending-revalidation statements above describe the investigation chronology and are superseded by this final result.
