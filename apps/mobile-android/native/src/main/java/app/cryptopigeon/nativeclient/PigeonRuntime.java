package app.cryptopigeon.nativeclient;
import android.content.Context;
/** Process-scoped engine owner shared by the activity and foreground service. */
final class PigeonRuntime {
    private static LocalBridge bridge;
    static synchronized LocalBridge bridge(Context context) throws Exception {if(bridge==null)bridge=new LocalBridge(context.getApplicationContext());return bridge;}
    static synchronized LocalBridge current(){return bridge;}
}
