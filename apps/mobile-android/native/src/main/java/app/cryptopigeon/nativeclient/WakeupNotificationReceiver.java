package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;

/** Dependency-isolated FCM adapter: accept only a metadata-free WAKE_SYNC data poke. */
public interface WakeupNotificationReceiver {
    void onWakeSync();
    static boolean accepts(java.util.Map<String,String> data){return data.size()==1&&"WAKE_SYNC".equals(data.get("type"));}
    static void notifyLocked(Context context){
        NotificationManager manager=context.getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("encrypted_activity","Encrypted activity",NotificationManager.IMPORTANCE_DEFAULT));
        Intent intent=new Intent(context,MainActivity.class);PendingIntent open=PendingIntent.getActivity(context,0,intent,PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        try{manager.notify(71,new Notification.Builder(context,"encrypted_activity").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Crypto Pigeon").setContentText("New encrypted activity — Unlock vault to view").setContentIntent(open).setAutoCancel(true).build());}catch(SecurityException permissionNotGranted){}
    }
}
