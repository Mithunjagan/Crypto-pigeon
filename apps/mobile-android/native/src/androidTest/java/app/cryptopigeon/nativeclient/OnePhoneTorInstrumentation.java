package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.database.Cursor;
import android.media.MediaRecorder;
import android.os.*;
import android.webkit.CookieManager;
import java.io.*;
import java.lang.reflect.Field;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** On-device control/inspection only. Peer envelopes and media always use production Tor. */
final class OnePhoneTorInstrumentation {
    private Instrumentation runner;private Context context;private NativeEngine engine;private LocalBridge bridge;private MainActivity activity;
    private File controlDir;private String cookie,csrf,runId,conversation,peerLabel="",pausePin;private long started;private boolean finish;private volatile boolean stopWatchdog;
    private final JSONArray results=new JSONArray();
    private void stage(String value) throws Exception {write("stage.json",new JSONObject().put("stage",value).put("elapsedMs",SystemClock.elapsedRealtime()-started));}
    private static void check(boolean value,String code){if(!value)throw new AssertionError(code);}
    private static Object field(Object owner,String name) throws Exception {Field f=owner.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(owner);}
    private void write(String name,JSONObject object) throws Exception {NativeIo.atomic(new File(controlDir,name),Crypto.utf8(object.toString()));}
    private JSONObject ok() throws Exception{return new JSONObject().put("ok",true);}
    private void refreshVisibleSession() throws Exception {
        String sessionCookie=cookie;
        runner.runOnMainSync(()->{try{CookieManager.getInstance().setCookie(bridge.origin,sessionCookie+"; HttpOnly; SameSite=Strict; Path=/");CookieManager.getInstance().flush();((android.webkit.WebView)field(activity,"view")).loadUrl(bridge.origin+"/");}catch(Exception error){throw new IllegalStateException("TEST_UI_REFRESH_FAILED",error);}});
    }
    private boolean visible(String expression) throws Exception {
        java.util.concurrent.CountDownLatch done=new java.util.concurrent.CountDownLatch(1);String[] value={"false"};
        runner.runOnMainSync(()->{try{((android.webkit.WebView)field(activity,"view")).evaluateJavascript(expression,result->{value[0]=result;done.countDown();});}catch(Exception error){done.countDown();}});
        return done.await(5,java.util.concurrent.TimeUnit.SECONDS)&&"true".equals(value[0]);
    }
    private void awaitVisible(String expression,String code) throws Exception {long deadline=SystemClock.elapsedRealtime()+30000;while(SystemClock.elapsedRealtime()<deadline){if(visible(expression))return;Thread.sleep(250);}throw new AssertionError(code);}
    private void verifyLifecycleDoesNotWaitForEngine() throws Exception {
        java.util.concurrent.CountDownLatch held=new java.util.concurrent.CountDownLatch(1),release=new java.util.concurrent.CountDownLatch(1);
        Thread holder=new Thread(()->{synchronized(engine){held.countDown();try{release.await(4,java.util.concurrent.TimeUnit.SECONDS);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}}},"cp-lifecycle-regression");
        holder.start();long[] elapsed={Long.MAX_VALUE};
        try{check(held.await(5,java.util.concurrent.TimeUnit.SECONDS),"ENGINE_LOCK_TEST_SETUP_FAILED");runner.runOnMainSync(()->{long begin=SystemClock.elapsedRealtime();engine.foreground(false);engine.foreground(true);elapsed[0]=SystemClock.elapsedRealtime()-begin;});}
        finally{release.countDown();holder.join(5000);}
        check(elapsed[0]<1000,"MAIN_LIFECYCLE_WAITED_FOR_ENGINE");pass("Main-thread foreground callbacks returned while engine was busy ("+elapsed[0]+" ms)");
    }
    private void pass(String name) throws Exception {results.put(new JSONObject().put("name",name).put("status","pass").put("elapsedMs",SystemClock.elapsedRealtime()-started));write("checks.json",new JSONObject().put("results",results));}
    private byte[] read(InputStream input,int limit) throws Exception {try(InputStream in=input){return NativeIo.read(in,limit);}}
    private JSONObject call(String path,JSONObject body) throws Exception {
        HttpURLConnection connection=(HttpURLConnection)new URL(bridge.origin+path).openConnection();
        try{connection.setConnectTimeout(5000);connection.setReadTimeout(120000);connection.setRequestMethod(body==null?"GET":"POST");connection.setRequestProperty("Origin",bridge.origin);if(cookie!=null)connection.setRequestProperty("Cookie",cookie);if(csrf!=null)connection.setRequestProperty("X-CSRF-Token",csrf);
            if(body!=null){connection.setDoOutput(true);connection.setRequestProperty("Content-Type","application/json");byte[] bytes=Crypto.utf8(body.toString());try(OutputStream output=connection.getOutputStream()){output.write(bytes);}finally{Crypto.wipe(bytes);}}
            int status=connection.getResponseCode();byte[] bytes=read(status<400?connection.getInputStream():connection.getErrorStream(),40*1024*1024);JSONObject result;
            try{result=new JSONObject(new String(bytes,StandardCharsets.UTF_8));}finally{Crypto.wipe(bytes);}
            if(status!=200)throw new IOException("LOCAL_API_FAILED_"+status);
            String set=connection.getHeaderField("Set-Cookie");if(set!=null)cookie=set.split(";",2)[0];if(result.has("csrfToken"))csrf=result.getString("csrfToken");
            if(result.has("bootstrapSecret")){bootstrap(result.getString("bootstrapSecret"));}
            return result;
        }finally{connection.disconnect();}
    }
    private void bootstrap(String secret) throws Exception {csrf=null;cookie=null;call("/api/bootstrap",new JSONObject().put("secret",secret));}
    private NativeVault vault() throws Exception{return (NativeVault)field(engine,"vault");}
    private JSONObject snapshot() throws Exception {
        synchronized(engine){JSONObject out=ok().put("serviceRunning",PigeonForegroundService.running()).put("vaultState",engine.state());
            out.put("backgroundReceiveSequence",field(engine,"backgroundReceiveSequence")).put("lastBackgroundReceiveElapsedMs",field(engine,"lastBackgroundReceiveElapsedMs")).put("lastBackgroundReceiveInteractive",field(engine,"lastBackgroundReceiveInteractive"));
            if("quick_locked".equals(engine.state())){java.lang.reflect.Method status=NativeEngine.class.getDeclaredMethod("transportStatus");status.setAccessible(true);out.put("transport",status.invoke(engine));}else out.put("transport",engine.handle("GET","/api/transport/status",null,Collections.emptyMap()));if(!engine.deliveryEnabled())return out;
            NativeVault owner=vault();NativeDatabase db=owner.database();JSONArray messages=new JSONArray();
            try(Cursor cursor=db.query("SELECT m.message_id,m.direction,m.plaintext,m.status,a.attachment_id,a.encrypted_local_path FROM messages m LEFT JOIN attachments a ON a.message_id=m.message_id ORDER BY m.rowid")){
                while(cursor.moveToNext()){JSONObject row=new JSONObject().put("direction",cursor.getString(1)).put("textSha256",Crypto.hex(Crypto.sha256(Crypto.utf8(cursor.getString(2))))).put("status",cursor.getString(3));
                    if(!cursor.isNull(4)&&!cursor.isNull(5)){byte[] data=NativeAttachmentCache.read(owner,cursor.getString(4));try{row.put("attachmentBytes",data.length).put("attachmentSha256",Crypto.hex(Crypto.sha256(data)));}finally{Crypto.wipe(data);}}messages.put(row);}
            }
            out.put("messages",messages).put("outbox",Integer.parseInt(db.text("SELECT count(*) FROM message_outbox"))).put("verifiedContacts",Integer.parseInt(db.text("SELECT count(*) FROM contacts WHERE verified=1 AND identity_changed=0"))).put("pinnedRoutes",Integer.parseInt(db.text("SELECT count(*) FROM peer_onions"))).put("signalSessions",Integer.parseInt(db.text("SELECT count(*) FROM signal_sessions")));
            return out;
        }
    }
    private JSONObject sendText(String text) throws Exception {return call("/api/send",new JSONObject().put("conversationId",conversation).put("plaintext",text));}
    private String phoneText(String label){check(!peerLabel.isEmpty(),"TWO_PHONE_ROLE_REQUIRED");return "Phone "+peerLabel+" "+label+" தமிழ் 🌍🕊️ "+runId;}
    private JSONObject sendFile(byte[] bytes,String filename,String mime,String label) throws Exception {
        JSONObject manifest=call("/api/attachments/encrypt",new JSONObject().put("filedataB64",Crypto.b64(bytes)).put("filename",filename).put("mimeType",mime));
        JSONObject sent=call("/api/send",new JSONObject().put("conversationId",conversation).put("plaintext",label).put("attachmentManifest",manifest));
        synchronized(engine){NativeDatabase db=vault().database();String blob=manifest.getString("blobId");check(db.exists("SELECT 1 FROM tor_blobs WHERE blob_id=?",blob)&&Integer.parseInt(db.text("SELECT count(*) FROM tor_chunks WHERE blob_id=?",blob))==manifest.getInt("chunkCount")&&db.exists("SELECT 1 FROM tor_attachment_links WHERE attachment_id=? AND blob_id=?",manifest.getString("attachmentId"),blob),"SENDER_CIPHERTEXT_SPOOL_MISSING_AFTER_SEND");}
        return ok().put("bytes",bytes.length).put("sha256",Crypto.hex(Crypto.sha256(bytes))).put("queued",sent.optString("status").equals("queued"));
    }
    private JSONObject command(JSONObject input) throws Exception {
        String action=input.getString("action");
        if(action.equals("PAIR")){JSONObject result=call("/api/contacts/import",new JSONObject().put("uri",input.getString("invite")));conversation=result.getString("conversationId");JSONObject state=snapshot();check(state.getInt("verifiedContacts")==1&&state.getInt("pinnedRoutes")==1&&state.getInt("signalSessions")==1,"PINNING_FAILED");refreshVisibleSession();awaitVisible("(()=>{const row=document.querySelector('.contact-row');if(!row)return false;row.click();return true})()","PAIRED_CONVERSATION_NOT_VISIBLE");pass("Signed peer invite pinned locally with verified contact and Signal session; conversation opened in the real UI");return state;}
        if(action.equals("PHONE_TEXT")){sendText(phoneText("to peer"));return snapshot();}
        if(action.equals("PROBE_TEXT")){int sample=input.getInt("sample");check(sample>=1&&sample<=2,"INVALID_LATENCY_SAMPLE");sendText(phoneText("latency sample "+sample));return ok();}
        if(action.equals("BACKGROUND_TEXT")){sendText(phoneText("screen-off delivery"));return ok();}
        if(action.equals("PHONE_FILE")){check(!peerLabel.isEmpty(),"TWO_PHONE_ROLE_REQUIRED");int size=peerLabel.equals("A")?65537:98321,seed=peerLabel.equals("A")?17:7;byte[] data=new byte[size];for(int i=0;i<size;i++)data[i]=(byte)(i*31+seed);try{return sendFile(data,"phone-"+peerLabel+".bin","application/octet-stream",phoneText("encrypted file"));}finally{Crypto.wipe(data);}}
        if(action.equals("MAX_TEXT")){String unit="வணக்கம் 🌍🕊️ ";StringBuilder text=new StringBuilder();while(text.length()<65536)text.append(unit);text.setLength(65536);if(Character.isHighSurrogate(text.charAt(65535)))text.setCharAt(65535,'A');sendText(text.toString());return ok().put("codeUnits",text.length()).put("sha256",Crypto.hex(Crypto.sha256(Crypto.utf8(text.toString()))));}
        if(action.equals("SEND_TEXT")){sendText("Phone to laptop வணக்கம் 🌍🕊️ "+runId);return snapshot();}
        if(action.equals("SEND_FILE")){byte[] data=new byte[98321];for(int i=0;i<data.length;i++)data[i]=(byte)(i*31+7);try{return sendFile(data,"phone-test.bin","application/octet-stream","Phone encrypted file "+runId);}finally{Crypto.wipe(data);}}
        if(action.equals("VOICE")){
            File audio=new File(controlDir,"voice-capture.m4a");MediaRecorder recorder=Build.VERSION.SDK_INT>=31?new MediaRecorder(context):new MediaRecorder();
            try{recorder.setAudioSource(MediaRecorder.AudioSource.MIC);recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4);recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);recorder.setAudioSamplingRate(16000);recorder.setAudioEncodingBitRate(32000);recorder.setOutputFile(audio.getAbsolutePath());recorder.prepare();recorder.start();Thread.sleep(1600);recorder.stop();}finally{recorder.release();}
            byte[] data=NativeIo.read(audio,1024*1024);try{check(data.length>100,"MICROPHONE_CAPTURE_EMPTY");JSONObject result=sendFile(data,"voice-note.m4a","audio/mp4",peerLabel.isEmpty()?"Voice note":phoneText("voice"));pass("Physical microphone captured an AAC voice-note payload for Tor delivery");return result;}finally{Crypto.wipe(data);audio.delete();}
        }
        if(action.equals("READ")){call("/api/control",new JSONObject().put("type","read_receipt").put("conversationId",conversation));return ok();}
        if(action.equals("UI_RECEIVED")){String expected=peerLabel.isEmpty()?"Laptop to phone வணக்கம் 🌍🕊️ "+runId:"Phone "+(peerLabel.equals("A")?"B":"A")+" to peer தமிழ் 🌍🕊️ "+runId;awaitVisible("document.body.textContent.includes("+JSONObject.quote(expected)+")","RECEIVED_TEXT_NOT_VISIBLE");pass("Real WebView displays the live peer Tamil and emoji message");return ok();}
        if(action.equals("ARM_BACKGROUND")){context.getSystemService(NotificationManager.class).cancel(73);return snapshot();}
        if(action.equals("OFFLINE_SEND")){sendText(peerLabel.isEmpty()?"Phone offline recovery தமிழ் "+runId:phoneText("offline recovery"));JSONObject state=snapshot();check(state.getInt("outbox")>0,"OUTBOX_NOT_PERSISTED");pass("Phone persisted encrypted outbox while peer listener was stopped");return state;}
        if(action.equals("PAUSE_PEER")){TorOnionTransport old=(TorOnionTransport)field(engine,"tor");java.lang.Process process=old==null?null:(java.lang.Process)field(old,"process");pausePin=String.format(Locale.ROOT,"%04d",new java.security.SecureRandom().nextInt(10000));call("/api/session/pin",new JSONObject().put("pin",pausePin));call("/api/session/lock",new JSONObject());long end=SystemClock.elapsedRealtime()+10000;while(PigeonForegroundService.running()&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);check(!engine.deliveryEnabled()&&!PigeonForegroundService.running()&&(process==null||!process.isAlive())&&(old==null||old.stopped()),"PAUSED_PEER_STILL_ACTIVE");pass("PIN pause stopped the native onion listener and foreground service");return snapshot();}
        if(action.equals("RESUME_PEER")){check(pausePin!=null,"PEER_NOT_PAUSED");call("/api/session/unlock",new JSONObject().put("pin",pausePin));pausePin=null;return snapshot();}
        if(action.equals("SNAPSHOT"))return snapshot();
        if(action.equals("LOCK")){
            TorOnionTransport old=(TorOnionTransport)field(engine,"tor");java.lang.Process process=old==null?null:(java.lang.Process)field(old,"process");call("/api/vault/lock",new JSONObject());long end=SystemClock.elapsedRealtime()+10000;while(PigeonForegroundService.running()&&SystemClock.elapsedRealtime()<end)Thread.sleep(100);
            check(!PigeonForegroundService.running()&&!engine.deliveryEnabled(),"SERVICE_STILL_ACTIVE_AFTER_LOCK");check(old==null||old.stopped(),"TOR_NOT_STOPPED");check(process==null||!process.isAlive(),"TOR_PROCESS_SURVIVED_LOCK");check(old==null||((java.util.concurrent.ScheduledExecutorService)field(old,"monitor")).isShutdown(),"TOR_MONITOR_SURVIVED_LOCK");pass("Vault lock stopped foreground service, Tor process and Tor monitor");return snapshot();
        }
        if(action.equals("FINISH")){finish=true;return ok();}
        throw new IOException("UNKNOWN_TEST_ACTION");
    }
    JSONArray run(Instrumentation runner,Bundle arguments) throws Exception {
        this.runner=runner;context=runner.getTargetContext();runId=arguments.getString("runId","");peerLabel=arguments.getString("peerLabel","");check(peerLabel.isEmpty()||peerLabel.matches("[AB]"),"INVALID_TWO_PHONE_ROLE");check(runId.matches("[a-f0-9]{16}"),"INVALID_TEST_RUN");started=SystemClock.elapsedRealtime();controlDir=new File(context.getFilesDir(),"one-phone-tor-"+runId);check(controlDir.mkdirs()||controlDir.isDirectory(),"CONTROL_DIRECTORY_FAILED");
        Thread watchdog=new Thread(()->{while(!stopWatchdog){try{Thread.sleep(2000);JSONArray threads=new JSONArray();for(Map.Entry<Thread,StackTraceElement[]> entry:Thread.getAllStackTraces().entrySet()){JSONArray frames=new JSONArray();boolean relevant=false;for(StackTraceElement frame:entry.getValue()){if(frame.getClassName().startsWith("app.cryptopigeon."))relevant=true;frames.put(frame.toString());}if(relevant)threads.put(new JSONObject().put("state",entry.getKey().getState().name()).put("frames",frames));}write("stacks.json",new JSONObject().put("threads",threads));}catch(Exception ignored){}}},"cp-test-watchdog");watchdog.setDaemon(true);watchdog.start();
        stage("native_engine");File root=new File(context.getNoBackupFilesDir(),"one-phone-tor-"+runId);engine=new NativeEngine(context,root,"http://127.0.0.1:9");bridge=new LocalBridge(context,engine,true);
        Field runtime=PigeonRuntime.class.getDeclaredField("bridge");runtime.setAccessible(true);check(runtime.get(null)==null,"EXISTING_TEST_RUNTIME");runtime.set(null,bridge);
        String id="Hardware-"+UUID.randomUUID(),password=Crypto.hex(Crypto.random(24))+"Aa1!";byte[] capsule=null;String shard;
        try{
            stage("lifecycle_regression");verifyLifecycleDoesNotWaitForEngine();
            stage("loopback_bootstrap");bootstrap(URI.create(bridge.entry()).getFragment());String sessionCookie=cookie;stage("webview_cookie");runner.runOnMainSync(()->{CookieManager.getInstance().setCookie(bridge.origin,sessionCookie+"; HttpOnly; SameSite=Strict; Path=/");CookieManager.getInstance().flush();});
            stage("activity_start");
            activity=(MainActivity)runner.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            runner.runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
            stage("vault_create");
            JSONObject created=call("/api/vault/create",new JSONObject().put("vaultId",id).put("password",password));stage("vault_created");shard=created.getString("clientShard");capsule=Crypto.unb64(created.getString("shard7FileBytes"));NativeIo.atomic(new File(controlDir,"segment-07.cp7"),capsule);call("/api/vault/shard7/saved",new JSONObject());stage("vault_segment_confirmed");call("/api/vault/lock",new JSONObject());stage("vault_locked");Thread.sleep(1000);
            stage("vault_cold_open");call("/api/vault/open",new JSONObject().put("vaultId",id).put("password",password).put("clientShard",shard).put("shard7Payload",Crypto.b64(capsule)));
            File torDir=new File((File)field(engine,"vaultRoot"),"tor");check(torDir.mkdirs()||torDir.isDirectory(),"TOR_DIRECTORY_FAILED");
            String[] publicFiles=runner.getContext().getAssets().list("tor-public-cache");if(publicFiles!=null)for(String name:publicFiles)if(Arrays.asList("cached-certs","cached-microdesc-consensus","cached-microdescs","cached-microdescs.new","cached-descriptors","cached-descriptors.new").contains(name)){try(InputStream in=runner.getContext().getAssets().open("tor-public-cache/"+name)){NativeIo.atomic(new File(torDir,name),NativeIo.read(in,32*1024*1024));}}
            engine.startBackgroundDelivery();call("/api/access/apply",new JSONObject().put("username","phone_"+(peerLabel.isEmpty()?"":peerLabel.toLowerCase(Locale.ROOT)+"_")+runId.substring(0,8)));pass("Isolated native vault cold-unlocked with all fragments and local activation");
            refreshVisibleSession();
            stage("tor_bootstrap");long deadline=SystemClock.elapsedRealtime()+12*60000;while(SystemClock.elapsedRealtime()<deadline){check(!new File(controlDir,"cancel").exists(),"TEST_CANCELLED");JSONObject status=call("/api/transport/status",null);write("progress.json",status);if(status.optBoolean("serverless")&&status.optBoolean("descriptorPublished"))break;Thread.sleep(2500);}
            JSONObject status=call("/api/transport/status",null);check(status.optBoolean("serverless")&&status.optBoolean("descriptorPublished"),"PHONE_TOR_BOOTSTRAP_TIMEOUT");String invite=call("/api/contacts/invite",null).getString("uri");check(PigeonForegroundService.running(),"FOREGROUND_SERVICE_NOT_RUNNING");awaitVisible("document.querySelector('[aria-label=\"Connection status: Direct Tor Onion P2P\"]') !== null","DIRECT_TOR_STATUS_NOT_VISIBLE");pass("Visible UI reports Direct Tor Onion P2P");write("ready.json",ok().put("invite",invite).put("transport",status));pass("Embedded Android Tor bootstrapped and published a v3 service with foreground delivery active");
            String last="";long testDeadline=SystemClock.elapsedRealtime()+45*60000;
            while(!finish&&SystemClock.elapsedRealtime()<testDeadline){File file=new File(controlDir,"command.json");if(file.isFile())try{JSONObject input=NativeIo.json(file,16384);String next=input.getString("id");if(!next.equals(last)){last=next;try{JSONObject result=command(input);write("response.json",ok().put("id",next).put("result",result));}catch(Throwable error){write("response.json",new JSONObject().put("id",next).put("ok",false).put("error",error.getClass().getSimpleName()));throw error;}}}catch(org.json.JSONException partial){/* ADB control write may still be completing. */}Thread.sleep(200);}
            check(finish,"PHONE_TEST_DEADLINE");return results;
        }finally{stopWatchdog=true;Crypto.wipe(capsule);password=null;id=null;try{if(engine.deliveryEnabled())call("/api/vault/lock",new JSONObject());}catch(Exception ignored){}bridge.close();runtime.set(null,null);if(activity!=null)runner.runOnMainSync(()->activity.finish());}
    }
}
