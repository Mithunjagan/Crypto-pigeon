package app.cryptopigeon.nativeclient;

import org.json.JSONObject;

/** Authenticated loopback long-poll cursor. No identifiers or plaintext leave the engine. */
final class ChangeSignal {
    private long revision;
    private String type = "READY";
    synchronized void publish(String reason) { revision++; type = reason; notifyAll(); }
    synchronized JSONObject after(long cursor) throws Exception {
        long deadline = android.os.SystemClock.elapsedRealtime() + 25000;
        while (revision <= cursor) {
            long remaining = deadline - android.os.SystemClock.elapsedRealtime();
            if (remaining <= 0) break;
            wait(remaining);
        }
        return new JSONObject().put("revision", revision).put("type", type);
    }
}
