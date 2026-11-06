package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.os.*;
import android.view.*;
import android.webkit.*;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import org.json.*;

/** Real system document dialogs, cancelled without choosing or changing user files. */
final class FileGesturesInstrumentation {
    private Instrumentation runner;private MainActivity activity;private WebView web;
    private String js(String code) throws Exception {String[] result={null};CountDownLatch ready=new CountDownLatch(1);runner.runOnMainSync(()->web.evaluateJavascript(code,value->{result[0]=value;ready.countDown();}));if(!ready.await(8,TimeUnit.SECONDS))throw new AssertionError("WebView timeout");return result[0];}
    private Object field(String name) throws Exception {Field f=MainActivity.class.getDeclaredField(name);f.setAccessible(true);return f.get(activity);}
    private void tap(String selector,int count) throws Exception {
        boolean[] foreground={false};runner.runOnMainSync(()->foreground[0]=activity.hasWindowFocus());if(!foreground[0])throw new AssertionError("PHONE_UI_IN_USE: Crypto Pigeon lost focus; no taps sent");
        js("document.querySelector("+JSONObject.quote(selector)+").scrollIntoView({block:'center'});true");Thread.sleep(400);
        JSONObject rect=new JSONObject(js("(()=>{const r=document.querySelector("+JSONObject.quote(selector)+").getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2-(visualViewport?.offsetTop||0),width:innerWidth}})()"));
        int[] origin=new int[2];runner.runOnMainSync(()->web.getLocationOnScreen(origin));float scale=web.getWidth()/(float)rect.getDouble("width"),x=origin[0]+(float)rect.getDouble("x")*scale,y=origin[1]+(float)rect.getDouble("y")*scale;
        for(int i=0;i<count;i++){runner.runOnMainSync(()->foreground[0]=activity.hasWindowFocus());if(!foreground[0])throw new AssertionError("PHONE_UI_IN_USE: no further taps sent");long now=SystemClock.uptimeMillis();MotionEvent down=MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,x,y,0),up=MotionEvent.obtain(now,now+40,MotionEvent.ACTION_UP,x,y,0);runner.sendPointerSync(down);runner.sendPointerSync(up);down.recycle();up.recycle();Thread.sleep(90);}
    }
    private void cancel() throws Exception {
        String top="";try(ParcelFileDescriptor command=runner.getUiAutomation().executeShellCommand("dumpsys activity activities");java.io.InputStream input=new ParcelFileDescriptor.AutoCloseInputStream(command)){String dump=new String(NativeIo.read(input,2*1024*1024),java.nio.charset.StandardCharsets.UTF_8);for(String line:dump.split("\n"))if(line.contains("topResumedActivity"))top=line;}
        if(!top.toLowerCase(java.util.Locale.ROOT).matches(".*(documentsui|documentsactivity|filemanager).*"))throw new AssertionError("PHONE_UI_IN_USE: system file dialog is no longer foreground; no Back event sent");
        try(ParcelFileDescriptor command=runner.getUiAutomation().executeShellCommand("input keyevent KEYCODE_BACK")){Thread.sleep(800);}long until=System.currentTimeMillis()+4000;while(field("fileSelection")!=null&&System.currentTimeMillis()<until)Thread.sleep(100);
    }
    private static JSONObject pass(String name) throws Exception {return new JSONObject().put("name",name).put("status","pass");}
    JSONArray run(Instrumentation runner) throws Exception {
        this.runner=runner;activity=(MainActivity)runner.startActivitySync(new Intent(runner.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));web=(WebView)field("view");
        long until=System.currentTimeMillis()+15000;while(!"true".equals(js("!!document.querySelector('.vault-gate')"))&&System.currentTimeMillis()<until)Thread.sleep(100);
        if(!"true".equals(js("!!document.querySelector('.vault-gate')")))throw new AssertionError("Locked gate unavailable; no user vault operations attempted");
        js("Array.from(document.querySelectorAll('[role=tab]')).find(e=>e.textContent==='Unlock').click();true");Thread.sleep(400);
        js("window.__tapTrace=[];document.addEventListener('click',e=>window.__tapTrace.push({target:e.target.getAttribute('class'),time:performance.now()}),true);true");
        JSONArray results=new JSONArray();IntentFilter open=new IntentFilter(Intent.ACTION_OPEN_DOCUMENT);Instrumentation.ActivityMonitor monitor=runner.addMonitor(open,null,false);
        try{
            tap(".segment-hit-zone",4);if(field("fileSelection")!=null)throw new AssertionError("Picker opened before fifth tap");tap(".segment-hit-zone",1);Thread.sleep(600);
            if(field("fileSelection")==null)throw new AssertionError("Five taps did not open the file chooser: taps="+js("JSON.stringify(window.__tapTrace)"));cancel();results.put(pass("Five taps on segment 07 launch native ACTION_OPEN_DOCUMENT; four taps do not"));
            int prior=monitor.getHits();tap(".gate-topbar .brand",3);if(field("fileSelection")!=null)throw new AssertionError("Storage picker opened before fourth tap");tap(".gate-topbar .brand",1);Thread.sleep(600);
            if(field("fileSelection")==null)throw new AssertionError("Four logo taps did not launch storage picker");cancel();results.put(pass("Four logo taps launch native app-storage document picker; three taps do not"));
            IntentFilter create=new IntentFilter(Intent.ACTION_CREATE_DOCUMENT);Instrumentation.ActivityMonitor saver=runner.addMonitor(create,null,false);
            try{js("window.__fileSaveResult=null;window.addEventListener('cp-file-saved',e=>window.__fileSaveResult=e.detail);window.CryptoPigeonFiles.save('shard7','fixture-cancel-save');true");Thread.sleep(700);
                if(field("sovereignRequest")==null)throw new AssertionError("Native save chooser did not open");cancel();
                if(!"true".equals(js("window.__fileSaveResult?.error==='SAVE_CANCELLED'&&window.__fileSaveResult?.ok===false")))throw new AssertionError("Save cancellation did not reach UI");
                results.put(pass("Segment save launches ACTION_CREATE_DOCUMENT and cancellation is reported without creating a file"));
            }finally{runner.removeMonitor(saver);}
        }finally{runner.removeMonitor(monitor);}
        return results;
    }
    JSONArray runUnlocked(Instrumentation runner) throws Exception {
        this.runner=runner;activity=(MainActivity)runner.startActivitySync(new Intent(runner.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));web=(WebView)field("view");
        Context context=runner.getTargetContext();String suffix=java.util.UUID.randomUUID().toString();java.io.File root=new java.io.File(context.getNoBackupFilesDir(),"ui-external-"+suffix);
        NativeEngine engine=new NativeEngine(context,root,"http://127.0.0.1:9");LocalBridge replacement=null;android.net.Uri document=null;JSONArray results=new JSONArray();byte[] expected=null;
        try{
            JSONObject created=(JSONObject)engine.handle("POST","/api/vault/create",new JSONObject().put("vaultId","UI-fixture-"+suffix).put("password","UIFixture-Password123!"),java.util.Collections.emptyMap());
            expected=Crypto.unb64(created.getString("shard7FileBytes"));engine.handle("POST","/api/vault/shard7/saved",new JSONObject(),java.util.Collections.emptyMap());
            replacement=new LocalBridge(context,engine,false);LocalBridge next=replacement,previous=(LocalBridge)field("bridge");Field bridgeField=MainActivity.class.getDeclaredField("bridge");bridgeField.setAccessible(true);
            runner.runOnMainSync(()->{try{bridgeField.set(activity,next);web.loadUrl(next.entry());}catch(Exception failure){throw new IllegalStateException(failure);}});previous.close();
            long until=System.currentTimeMillis()+15000;while(!"true".equals(js("!!document.querySelector('.inbox-topbar .brand')"))&&System.currentTimeMillis()<until)Thread.sleep(100);
            if(!"true".equals(js("!!document.querySelector('.inbox-topbar .brand')")))throw new AssertionError("Fixture messenger did not load");
            tap(".inbox-topbar .brand",3);if("true".equals(js("!!document.querySelector('[aria-label=\"Sovereign App Storage\"]')")))throw new AssertionError("Storage sheet opened before fourth tap");tap(".inbox-topbar .brand",1);Thread.sleep(500);
            if(!"true".equals(js("!!document.querySelector('[aria-label=\"Sovereign App Storage\"]')&&document.querySelector('input[aria-label=\"Automatic Cloud Backup\"]')?.checked===false")))throw new AssertionError("Unlocked storage sheet or OFF toggle missing");
            results.put(pass("Four logo taps while unlocked open Sovereign App Storage with cloud backup OFF"));
            android.content.ContentValues details=new android.content.ContentValues();details.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME,"cp-segment-fixture-"+suffix+".cp7");details.put(android.provider.MediaStore.MediaColumns.MIME_TYPE,"application/octet-stream");details.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH,"Download/CryptoPigeon-test-fixtures");
            document=context.getContentResolver().insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,details);if(document==null)throw new AssertionError("Fixture document unavailable");
            IntentFilter filter=new IntentFilter(Intent.ACTION_CREATE_DOCUMENT);filter.addDataType("application/octet-stream");filter.addCategory(Intent.CATEGORY_OPENABLE);
            Instrumentation.ActivityMonitor save=runner.addMonitor(filter,new Instrumentation.ActivityResult(Activity.RESULT_OK,new Intent().setData(document)),true);
            try{
                js("window.__fixtureSaved=null;window.addEventListener('cp-file-saved',e=>{if(e.detail.id==='fixture-real-save')window.__fixtureSaved=e.detail});window.CryptoPigeonFiles.save('shard7','fixture-real-save');true");
                until=System.currentTimeMillis()+10000;while(!"true".equals(js("window.__fixtureSaved?.ok===true"))&&System.currentTimeMillis()<until)Thread.sleep(100);
                if(!"true".equals(js("window.__fixtureSaved?.ok===true")))throw new AssertionError("Native selected-document save did not complete: monitor="+save.getHits()+", result="+js("JSON.stringify(window.__fixtureSaved)"));
                byte[] saved=NativeIo.read(context.getContentResolver().openInputStream(document),2048);try{if(!java.security.MessageDigest.isEqual(expected,saved))throw new AssertionError("Saved segment bytes differ from creation capsule");}finally{Crypto.wipe(saved);}
                results.put(pass("Native file-save bridge writes the exact creation capsule to a real external document and confirms completion"));
            }finally{runner.removeMonitor(save);}
        }finally{
            Crypto.wipe(expected);if(document!=null)context.getContentResolver().delete(document,null,null);if(replacement!=null)replacement.close();else engine.close();runner.runOnMainSync(()->activity.finish());if(root.exists())NativeIo.deleteTree(root,context.getNoBackupFilesDir());
        }
        return results;
    }
}
