package app.cryptopigeon.nativeclient;
import android.content.*;
/** A reboot never unlocks a vault or stores its passphrase for background use. */
public final class PigeonBootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context,Intent intent){if(Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())||Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction()))WakeupNotificationReceiver.notifyLocked(context);}
}
