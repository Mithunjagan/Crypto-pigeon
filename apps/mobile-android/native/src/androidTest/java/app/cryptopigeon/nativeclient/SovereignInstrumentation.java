package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.File;
import java.lang.reflect.*;
import java.util.*;
import org.json.*;
import org.signal.libsignal.protocol.*;

/** Targeted final-device checks on isolated vaults and a temporary real relay database. */
final class SovereignInstrumentation {
    private static Object field(Object value,String name) throws Exception {Field f=value.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(value);}
    private static void check(boolean ok,String reason){if(!ok)throw new AssertionError(reason);}
    private static boolean zero(byte[] value){for(byte b:value)if(b!=0)return false;return true;}
    private static void mark(Instrumentation runner,String text){Bundle b=new Bundle();b.putString("stream",text+"\n");runner.sendStatus(0,b);}
    JSONArray run(Instrumentation runner,Bundle args) throws Exception {
        Thread checked=Thread.currentThread();Thread watchdog=new Thread(()->{try{Thread.sleep(15000);StringBuilder trace=new StringBuilder("Sovereign diagnostic stack:");for(StackTraceElement frame:checked.getStackTrace())trace.append("\n").append(frame.toString());mark(runner,trace.toString());}catch(Exception ignored){}},"sovereign-watchdog");watchdog.setDaemon(true);watchdog.start();
        Context context=runner.getTargetContext();String suffix=UUID.randomUUID().toString();File root=new File(context.getNoBackupFilesDir(),"sovereign-"+suffix),bobFile=new File(root,"bob.db");
        JSONArray results=new JSONArray();mark(runner,"Sovereign fixture: initialize");NativeEngine engine=new NativeEngine(context,root,args.getString("relayUrl"));String decoyFolder=null;
        try{
            String id="primary-"+suffix,password="SovereignFixturePassword123!",duress="duress-"+suffix;
            mark(runner,"Sovereign fixture: create primary");JSONObject created=(JSONObject)engine.handle("POST","/api/vault/create",new JSONObject().put("vaultId",id).put("password",password),Collections.emptyMap());
            mark(runner,"Sovereign fixture: Signal identities");NativeVault primary=(NativeVault)field(engine,"vault");NativeSignalStore alice=new NativeSignalStore(primary.database());JSONObject aliceBundle=alice.ensureIdentity();alice.setAccount(UUID.randomUUID().toString());
            byte[] key=Crypto.random(32);try(NativeDatabase bob=new NativeDatabase(context,bobFile,key)){
                NativeSignalStore sender=new NativeSignalStore(bob);JSONObject bundle=sender.ensureIdentity();sender.setAccount(UUID.randomUUID().toString());
                JSONObject destination=new JSONObject(aliceBundle.toString()).put("recipientUserId",alice.userId()).put("oneTimePrekey",aliceBundle.getJSONArray("oneTimePrekeys").getJSONObject(0)).put("pqOneTimePrekey",aliceBundle.getJSONArray("pqOneTimePrekeys").getJSONObject(0));sender.establish(destination);
                SignalProtocolAddress address=new SignalProtocolAddress(sender.userId(),1);alice.saveIdentity(address,new IdentityKey(Crypto.unb64(bundle.getString("identityPublicKey")),0));String contact=sender.userId()+".1";
                primary.database().db().execSQL("INSERT INTO remote_contacts VALUES(?,?,?,1)",new Object[]{contact,sender.userId(),sender.deviceId()});
                JSONObject payload=new JSONObject().put("type","text").put("messageId",UUID.randomUUID().toString()).put("text","durable fixture message");
                byte[] encrypted=sender.encrypt(new SignalProtocolAddress(alice.userId(),1),Crypto.utf8(payload.toString()));String envelopeId=UUID.randomUUID().toString();
                JSONObject envelope=new JSONObject().put("version",1).put("senderId",sender.deviceId()).put("envelopeId",envelopeId).put("ciphertext",Crypto.b64(encrypted));
                Method consume=NativeEngine.class.getDeclaredMethod("consumeIncoming",JSONArray.class,JSONArray.class);consume.setAccessible(true);
                consume.invoke(engine,new JSONArray().put(envelope),new JSONArray());String state=Crypto.hex(Crypto.sha256(primary.database().blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",contact)));
                envelope.put("envelopeId",envelopeId.replace("-",""));consume.invoke(engine,new JSONArray().put(envelope),new JSONArray());
                check("1".equals(primary.database().text("SELECT count(*) FROM messages")),"Duplicate bubble");check(state.equals(Crypto.hex(Crypto.sha256(primary.database().blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",contact)))),"Double ratchet step");
                results.put(new JSONObject().put("status","pass").put("name","UUID/hex retry yields one SQLCipher message and one Signal ratchet step"));
            }finally{Crypto.wipe(key);}
            mark(runner,"Sovereign fixture: duplicate checks complete");byte[] master=(byte[])field(primary,"vmk");
            mark(runner,"Sovereign fixture: configure decoy");JSONObject configured=(JSONObject)engine.handle("POST","/api/duress/config",new JSONObject().put("duressId",duress),Collections.emptyMap());
            mark(runner,"Sovereign fixture: unlock decoy");String tag=context.getSharedPreferences("duress-"+root.getName(),0).getString("tag","");decoyFolder="decoy-"+tag.substring(0,24);
            engine.handle("POST","/api/vault/open",new JSONObject().put("vaultId",duress).put("password","arbitrary").put("decoyClientShard",configured.getString("decoyClientShard")),Collections.emptyMap());
            check(primary.isLocked()&&zero(master),"Primary RAM was not wiped");NativeVault decoy=(NativeVault)field(engine,"vault");check(decoy!=primary&&"3".equals(decoy.database().text("SELECT count(*) FROM messages")),"Decoy not isolated");check(decoy.status(true).getInt("sharesPresent")==7,"Decoy lacks real remote quorum");
            results.put(new JSONObject().put("status","pass").put("name","Duress closes primary SQLCipher, zeroes master key and opens isolated three-note seven-fragment vault"));
            engine.handle("POST","/api/vault/open",new JSONObject().put("vaultId",id).put("password",password).put("clientShard",created.getString("clientShard")),Collections.emptyMap());
            check("1".equals(((NativeVault)field(engine,"vault")).database().text("SELECT count(*) FROM messages")),"Primary history changed");
            results.put(new JSONObject().put("status","pass").put("name","Primary cold unlock restores original history after decoy session"));
        }finally{engine.close();context.getSharedPreferences("duress-"+root.getName(),0).edit().clear().commit();if(root.exists())NativeIo.deleteTree(root,context.getNoBackupFilesDir());if(decoyFolder!=null){File decoy=new File(context.getNoBackupFilesDir(),decoyFolder);if(decoy.exists())NativeIo.deleteTree(decoy,context.getNoBackupFilesDir());}}
        return results;
    }
}
