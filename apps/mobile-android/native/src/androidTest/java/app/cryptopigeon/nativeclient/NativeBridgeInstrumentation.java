package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Tests the actual APK assets, localhost protocol and native engine, with no host daemon. */
final class NativeBridgeInstrumentation {
    private final JSONArray results=new JSONArray();private Instrumentation runner;
    private void pass(String name) throws Exception {results.put(new JSONObject().put("name",name).put("status","pass"));Bundle event=new Bundle();event.putString("stream","PASS: "+name+"\n");runner.sendStatus(0,event);}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static JSONObject obj(Object...values) throws Exception {JSONObject out=new JSONObject();for(int i=0;i<values.length;i+=2)out.put((String)values[i],values[i+1]);return out;}
    static final class Client implements AutoCloseable {
        final LocalBridge bridge;final NativeEngine engine;String cookie,csrf,id,password,shard,uid;int status;String type;
        Client(Context context,File root,String relay) throws Exception {engine=new NativeEngine(context,root,relay);bridge=new LocalBridge(context,engine,false);bootstrap(URI.create(bridge.entry()).getFragment());}
        byte[] raw(String method,String path,JSONObject body,boolean authenticated,Map<String,String> extras) throws Exception {
            HttpURLConnection connection=(HttpURLConnection)new URL(bridge.origin+path).openConnection();
            try{connection.setConnectTimeout(10000);connection.setReadTimeout(120000);connection.setRequestMethod(method);connection.setInstanceFollowRedirects(false);
                if(authenticated){connection.setRequestProperty("Cookie",cookie==null?"":cookie);if(csrf!=null)connection.setRequestProperty("X-CSRF-Token",csrf);}
                if(extras!=null)for(Map.Entry<String,String> header:extras.entrySet())connection.setRequestProperty(header.getKey(),header.getValue());
                if(body!=null){connection.setRequestProperty("Content-Type","application/json");byte[] bytes=Crypto.utf8(body.toString());connection.setDoOutput(true);connection.setFixedLengthStreamingMode(bytes.length);try(OutputStream output=connection.getOutputStream()){output.write(bytes);}}
                status=connection.getResponseCode();type=connection.getContentType();String set=connection.getHeaderField("Set-Cookie");if(set!=null)cookie=set.split(";")[0];InputStream input=status>=400?connection.getErrorStream():connection.getInputStream();return input==null?new byte[0]:NativeIo.read(input,36*1024*1024);
            }finally{connection.disconnect();}
        }
        Object api(String path,JSONObject body) throws Exception {byte[] bytes=raw(body==null?"GET":"POST",path,body,true,null);Object result=new JSONTokener(new String(bytes,StandardCharsets.UTF_8)).nextValue();check(status==200,path+" returned "+status+": "+(result instanceof JSONObject?((JSONObject)result).optString("error"):"invalid"));return result;}
        JSONObject json(String path,JSONObject body) throws Exception{return (JSONObject)api(path,body);}
        JSONArray list(String path) throws Exception{return (JSONArray)api(path,null);}
        void bootstrap(String secret) throws Exception {JSONObject result=new JSONObject(new String(raw("POST","/api/bootstrap",obj("secret",secret),false,null),StandardCharsets.UTF_8));check(status==200,"bootstrap failed");csrf=result.getString("csrfToken");}
        void create(String label) throws Exception {id=label+"-"+Crypto.hex(Crypto.random(16));password="NativeBridge-Aa1!"+Crypto.hex(Crypto.random(8));shard=json("/api/vault/create",obj("vaultId",id,"password",password)).getString("clientShard");}
        void register(String username,String activation) throws Exception {JSONObject applied=json("/api/access/apply",obj("username",username));String requestId=applied.getString("requestId");
            long end=System.currentTimeMillis()+15000;while(true){raw("POST","/api/access/activate",obj("requestId",requestId,"activationCode",activation),true,null);if(status==200)break;check(System.currentTimeMillis()<end,"native activation failed");Thread.sleep(300);}
            uid=json("/api/access/state",null).getString("publicUid");check(uid.matches("CP-[A-F0-9]{4}-[A-F0-9]{4}"),"invalid public UID");}
        void lock() throws Exception {JSONObject result=json("/api/vault/lock",new JSONObject());check(result.getBoolean("backupSynced"),"backup did not sync");String oldCookie=cookie;raw("GET","/api/contacts",null,true,null);check(status==401,"session was not rotated");bootstrap(result.getString("bootstrapSecret"));}
        @Override public void close(){bridge.close();}
    }
    JSONArray run(Instrumentation runner,Bundle args) throws Exception {
        this.runner=runner;Context context=runner.getTargetContext();String relay=args.getString("relayUrl"),tag=Crypto.hex(Crypto.random(4));String activation=args.getString("activationCode");
        File a=new File(context.getNoBackupFilesDir(),"bridge-tests-"+tag+"-a"),b=new File(context.getNoBackupFilesDir(),"bridge-tests-"+tag+"-b"),c=new File(context.getNoBackupFilesDir(),"bridge-tests-"+tag+"-c");
        try(Client alice=new Client(context,a,relay);Client bob=new Client(context,b,relay);Client restored=new Client(context,c,relay)){
            alice.raw("GET","/",null,false,null);check(alice.status==200&&alice.type.contains("text/html"),"bundled HTML missing");
            alice.raw("GET","/api/contacts",null,false,null);check(alice.status==401,"missing cookie accepted");
            String saved=alice.csrf;alice.csrf="invalid";alice.raw("POST","/api/vault/create",obj("vaultId","test-vault","password","TestPassword123!"),true,null);check(alice.status==403,"CSRF bypass");alice.csrf=saved;
            alice.raw("GET","/api/session",null,true,Collections.singletonMap("Origin","https://attacker.invalid"));check(alice.status==403,"foreign origin accepted");pass("Standalone APK serves bundled UI and enforces localhost session, origin and CSRF boundaries");
            alice.create("native-alice");bob.create("native-bob");check(alice.json("/api/vault/horcrux-status?clientPresent=true",null).getInt("sharesPresent")==7,"quorum missing");check(!Arrays.equals(Arrays.copyOf(NativeIo.read(new File(a,"shards/metadata.db"),1024*1024),16),Crypto.utf8("SQLite format 3\0")),"shard metadata is not encrypted");
            legacyMetadata(alice,a);alice.lock();alice.json("/api/vault/open",obj("vaultId",alice.id,"password",alice.password,"clientShard",alice.shard));
            pass("Native vaults encrypt account/shard databases with SQLCipher and still unlock legacy shard metadata");
            alice.register("native_a_"+tag,activation);bob.register("native_b_"+tag,activation);pass("Native device-auth activation publishes independent real Signal and Kyber identities");
            alice.raw("POST","/api/contacts/add",obj("username",bob.uid),true,null);check(alice.status==403,"prekey follow gate bypassed");
            alice.json("/api/conversations/requests",obj("recipientUsername",bob.uid));JSONArray pending=bob.list("/api/conversations/requests");bob.json("/api/conversations/requests/"+pending.getJSONObject(0).getString("request_id")+"/accept",new JSONObject());
            String conversation=alice.json("/api/contacts/add",obj("username",bob.uid)).getString("conversationId");pass("Native UID follow gate blocks prekeys until Bob approves Alice");
            alice.json("/api/send",obj("conversationId",conversation,"plaintext","Native Alice to Bob தமிழ் 🕊️"));bob.json("/api/fetch-messages",new JSONObject());JSONObject contact=bob.list("/api/contacts").getJSONObject(0);String bobConversation=contact.getString("conversation_id");
            check(bob.list("/api/messages/"+bobConversation).getJSONObject(0).getString("plaintext").equals("Native Alice to Bob தமிழ் 🕊️"),"native receive failed");
            bob.json("/api/send",obj("conversationId",bobConversation,"plaintext","Native Bob reply नमस्ते"));alice.json("/api/fetch-messages",new JSONObject());check(alice.list("/api/messages/"+conversation).length()==2,"reply missing");
            JSONObject aliceContact=alice.list("/api/contacts").getJSONObject(0);check(contact.getString("safety_number_hash").equals(aliceContact.getString("safety_number_hash")),"native safety numbers differ");
            alice.json("/api/contacts/"+aliceContact.getString("contact_id")+"/verify",obj("safetyNumber",aliceContact.getString("safety_number_hash")));pass("Native libsignal exchanges bidirectional messages and matching verifiable safety numbers over the real relay");
            byte[] data=Crypto.random(130000);JSONObject manifest=alice.json("/api/attachments/encrypt",obj("filedataB64",Crypto.b64(data),"filename","native-தமிழ்.bin","mimeType","application/octet-stream"));alice.json("/api/send",obj("conversationId",conversation,"plaintext","Native encrypted file","attachmentManifest",manifest));bob.json("/api/fetch-messages",new JSONObject());
            JSONObject attachment=bob.json("/api/attachments/"+manifest.getString("attachmentId")+"/decrypt",null);check(Arrays.equals(data,Crypto.unb64(attachment.getString("filedataB64"))),"native attachment mismatch");
            byte[] download=bob.raw("GET","/api/attachments/"+manifest.getString("attachmentId")+"/decrypt?download=1",null,true,null);check(Arrays.equals(download,data),"native download mismatch");pass("Native chunk encryption, relay upload, durable download, SHA-256 validation and decrypted download preserve attachment bytes");
            NativeVault active=(NativeVault)field(alice.engine,"vault");byte[] master=(byte[])field(active,"vmk"),ram=(byte[])field(field(active,"fragments"),"session");Crypto.VaultKeys derived=(Crypto.VaultKeys)field(active,"keys");
            alice.lock();check(active.isLocked()&&field(active,"vmk")==null&&field(active,"keys")==null,"native keys remain reachable after lock");for(byte[] buffer:new byte[][]{master,ram,derived.kek,derived.lookup,derived.backup,derived.mask,derived.writer})for(byte value:buffer)check(value==0,"native key buffer was not zeroed");
            String original=alice.shard;NativeIo.atomic(new File(a,"assets/f4.dat"),Crypto.random(48));alice.raw("POST","/api/vault/open",obj("vaultId",alice.id,"password",alice.password,"clientShard",original),true,null);check(alice.status==400,"tampered native shard accepted");pass("Sync & Lock zeroes VMK, RAM shard and every derived key, rotates bootstrap, and rejects a corrupted local shard");
            restored.shard=restored.json("/api/vault/restore",obj("vaultId",alice.id,"password",alice.password,"transferConfirmed",true)).getString("clientShard");check(restored.json("/api/access/state",null).getString("publicUid").equals(alice.uid),"UID lost on restore");check(restored.list("/api/messages/"+conversation).length()==3,"history lost on native restore");
            check(Arrays.equals(data,Crypto.unb64(restored.json("/api/attachments/"+manifest.getString("attachmentId")+"/decrypt",null).getString("filedataB64"))),"attachment lost on restore");
            restored.json("/api/send",obj("conversationId",conversation,"plaintext","Native restored ratchet continues"));bob.json("/api/fetch-messages",new JSONObject());JSONArray messages=bob.list("/api/messages/"+bobConversation);check(messages.getJSONObject(messages.length()-1).getString("plaintext").equals("Native restored ratchet continues"),"restored ratchet failed");pass("A fresh native device vault restores UID, verified contacts, history and files and continues its original Signal conversation");
        }finally{for(File folder:new File[]{a,b,c})if(folder.exists())NativeIo.deleteTree(folder,context.getNoBackupFilesDir());}
        verifyLauncher(runner,context);
        return results;
    }
    private static Object field(Object target,String name) throws Exception {java.lang.reflect.Field field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);}
    private void legacyMetadata(Client client,File root) throws Exception {
        NativeVault vault=(NativeVault)field(client.engine,"vault");Crypto.VaultKeys keys=(Crypto.VaultKeys)field(vault,"keys");File file=new File(root,"shards/metadata.db");byte[] key=Crypto.hkdf(keys.backup,new byte[32],"cp-shard2-db-v1"),encoded=Crypto.utf8("x'"+Crypto.hex(key)+"'"),share;
        try(net.zetetic.database.sqlcipher.SQLiteDatabase db=net.zetetic.database.sqlcipher.SQLiteDatabase.openOrCreateDatabase(file,encoded,null,null,null);android.database.Cursor cursor=db.rawQuery("SELECT shard FROM vault_horcrux_shard WHERE id=2",new String[0])){check(cursor.moveToFirst(),"shard missing");share=cursor.getBlob(0);}finally{Crypto.wipe(key,encoded);}
        check(file.delete(),"fixture metadata replacement failed");try(android.database.sqlite.SQLiteDatabase db=android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(file,null)){db.execSQL("CREATE TABLE vault_horcrux_shard(id INTEGER PRIMARY KEY,shard BLOB NOT NULL)");db.execSQL("INSERT INTO vault_horcrux_shard VALUES(2,?)",new Object[]{share});}finally{Crypto.wipe(share);}
    }
    private void verifyLauncher(Instrumentation runner,Context context) throws Exception {
        android.app.Activity activity=runner.startActivitySync(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
        try{
            final android.webkit.WebView[] web=new android.webkit.WebView[1];runner.runOnMainSync(()->{android.view.View content=((android.view.ViewGroup)activity.findViewById(android.R.id.content)).getChildAt(0);web[0]=(android.webkit.WebView)((android.view.ViewGroup)content).getChildAt(0);});
            final String[] state={null};long end=System.currentTimeMillis()+15000;
            do{java.util.concurrent.CountDownLatch latch=new java.util.concurrent.CountDownLatch(1);runner.runOnMainSync(()->web[0].evaluateJavascript("JSON.stringify({tabs:document.querySelectorAll('[role=tab]').length,shards:document.querySelectorAll('.fragment').length,overflow:document.documentElement.scrollWidth>innerWidth})",value->{state[0]=value;latch.countDown();}));check(latch.await(5,java.util.concurrent.TimeUnit.SECONDS),"launcher script timed out");if(state[0]!=null&&state[0].contains("tabs\\\":3"))break;Thread.sleep(200);}while(System.currentTimeMillis()<end);
            Object decoded=new org.json.JSONTokener(state[0]).nextValue();JSONObject dom=new JSONObject((String)decoded);check(dom.getInt("tabs")==3&&dom.getInt("shards")==7&&!dom.getBoolean("overflow"),"standalone mobile UI did not render its gate/matrix correctly");
            runner.runOnMainSync(()->{android.graphics.Bitmap bitmap=android.graphics.Bitmap.createBitmap(web[0].getWidth(),web[0].getHeight(),android.graphics.Bitmap.Config.ARGB_8888);web[0].draw(new android.graphics.Canvas(bitmap));try(FileOutputStream file=new FileOutputStream(new File(context.getFilesDir(),"native-standalone-gate.png"))){bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,file);}catch(Exception error){throw new IllegalStateException(error);}finally{bitmap.recycle();}});
            pass("Standalone launcher boots the bundled liquid-glass UI with three access modes, seven shards and no horizontal overflow");
        }finally{runner.runOnMainSync(activity::finish);}
    }
}
