package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.WebView;
import java.io.File;
import java.lang.reflect.Field;
import org.json.JSONArray;
import org.json.JSONObject;

/** A visible, isolated app on each physical phone. The host drives UI only;
 * all vault, Signal, storage and internet transport work stays on the device. */
final class LivePhonesInstrumentation {
    JSONArray run(Instrumentation runner, Bundle args) throws Exception {
        Context context=runner.getTargetContext();
        String tag=args.getString("runTag","");
        if(!tag.matches("[a-zA-Z0-9-]{1,64}"))throw new IllegalArgumentException("Invalid live test tag");
        String relay=args.getString("relayUrl",BuildConfig.RELAY_URL);
        if(!relay.startsWith("https://"))throw new IllegalArgumentException("Live phone tests require public HTTPS");
        File root=new File(context.getNoBackupFilesDir(),"live-phones-"+tag);
        MainActivity activity=(MainActivity)runner.startActivitySync(new Intent(context,MainActivity.class)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK));
        Field webField=MainActivity.class.getDeclaredField("view"),bridgeField=MainActivity.class.getDeclaredField("bridge");
        webField.setAccessible(true);bridgeField.setAccessible(true);
        WebView web=(WebView)webField.get(activity);
        LocalBridge previous=(LocalBridge)bridgeField.get(activity);
        NativeEngine engine=new NativeEngine(context,root,relay);
        LocalBridge bridge=new LocalBridge(context,engine,false);
        runner.runOnMainSync(()->{
            try{
                bridgeField.set(activity,bridge);
                activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
                WebView.setWebContentsDebuggingEnabled(true);
                web.loadUrl(bridge.entry());
            }catch(Exception error){throw new IllegalStateException(error);}
        });
        previous.close();
        Bundle status=new Bundle();status.putString("stream","LIVE_PHONES_READY: "+tag+"\n");runner.sendStatus(0,status);
        File stop=new File(context.getFilesDir(),"live-phones-stop-"+tag);
        long deadline=System.currentTimeMillis()+45*60*1000L;
        while(!stop.exists()&&System.currentTimeMillis()<deadline)Thread.sleep(500);
        bridge.close();
        if(stop.exists())stop.delete();
        runner.runOnMainSync(activity::finish);
        return new JSONArray().put(new JSONObject().put("name","Isolated live phone session ended").put("status","pass"));
    }
}
