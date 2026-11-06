package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.wifi.WifiManager;
import android.os.*;
import androidx.core.app.NotificationCompat;

/** No Firebase or Play Services: the unlocked engine itself listens over Tor. */
public final class PigeonForegroundService extends Service {
    private static volatile boolean requested,running;
    private ActivityLease bootstrapLease;
    private final java.util.concurrent.ExecutorService lifecycle=java.util.concurrent.Executors.newSingleThreadExecutor();
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile boolean destroyed;
    private int activeStartId;
    static synchronized void update(Context context,boolean enabled){
        if(requested==enabled)return;requested=enabled;
        try{Intent intent=new Intent(context,PigeonForegroundService.class);if(enabled)context.startForegroundService(intent);else context.stopService(intent);}catch(RuntimeException unavailable){requested=false;}
    }
    static boolean running(){return running;}
    private static PendingIntent open(Context context){return PendingIntent.getActivity(context,0,new Intent(context,MainActivity.class),PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);}
    private static void channels(Context context){NotificationManager manager=context.getSystemService(NotificationManager.class);manager.createNotificationChannel(new NotificationChannel("pigeon_delivery","Background delivery",NotificationManager.IMPORTANCE_LOW));manager.createNotificationChannel(new NotificationChannel("pigeon_messages","Encrypted messages",NotificationManager.IMPORTANCE_HIGH));}
    static void message(Context context){
        channels(context);Notification notification=new NotificationCompat.Builder(context,"pigeon_messages").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Crypto Pigeon").setContentText("New encrypted message").setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setPublicVersion(new NotificationCompat.Builder(context,"pigeon_messages").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Crypto Pigeon").setContentText("New encrypted message").build()).setPriority(NotificationCompat.PRIORITY_HIGH).setContentIntent(open(context)).setAutoCancel(true).build();
        try{context.getSystemService(NotificationManager.class).notify(73,notification);}catch(SecurityException notificationPermissionDenied){}
    }
    @Override public void onCreate(){super.onCreate();channels(this);Notification notification=new NotificationCompat.Builder(this,"pigeon_delivery").setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Crypto Pigeon").setContentText("Listening for encrypted messages over Tor").setOngoing(true).setContentIntent(open(this)).setVisibility(NotificationCompat.VISIBILITY_PRIVATE).build();
        if(Build.VERSION.SDK_INT>=34)startForeground(72,notification,ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING|ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);else startForeground(72,notification);
        running=true;bootstrapLease=packet(this,120000);
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        activeStartId=startId;
        lifecycle.execute(()->{LocalBridge bridge=PigeonRuntime.current();boolean enabled=bridge!=null&&bridge.deliveryEnabled();if(!enabled)main.post(()->{if(destroyed||activeStartId!=startId)return;WakeupNotificationReceiver.notifyLocked(this);requested=false;stopSelfResult(startId);});});
        return START_STICKY;
    }
    @Override public IBinder onBind(Intent intent){return null;}
    @Override public void onDestroy(){destroyed=true;running=false;requested=false;lifecycle.shutdownNow();if(bootstrapLease!=null)bootstrapLease.close();LocalBridge bridge=PigeonRuntime.current();if(bridge!=null)bridge.deliveryStopped();stopForeground(STOP_FOREGROUND_REMOVE);super.onDestroy();}
    static ActivityLease packet(Context context){return packet(context,180000);}
    private static ActivityLease packet(Context context,long timeout){return new ActivityLease(context,timeout);}
    static final class ActivityLease implements AutoCloseable {
        private final PowerManager.WakeLock cpu;private final WifiManager.WifiLock wifi;
        ActivityLease(Context context,long timeout){
            cpu=context.getSystemService(PowerManager.class).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,"CryptoPigeon:packet");cpu.setReferenceCounted(false);cpu.acquire(timeout);
            WifiManager manager=(WifiManager)context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);wifi=manager==null?null:manager.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF,"CryptoPigeon:packet");
            if(wifi!=null){wifi.setReferenceCounted(false);wifi.acquire();new Handler(Looper.getMainLooper()).postDelayed(this::close,timeout);}
        }
        @Override public synchronized void close(){if(cpu.isHeld())cpu.release();if(wifi!=null&&wifi.isHeld())wifi.release();}
    }
}
