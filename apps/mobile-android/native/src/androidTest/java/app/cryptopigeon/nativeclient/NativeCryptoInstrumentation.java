package app.cryptopigeon.nativeclient;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.UUID;
import org.json.*;
import org.signal.libsignal.protocol.*;
import org.signal.libsignal.protocol.ecc.*;

/** Device tests use public fixtures in a separate application ID; no real vaults. */
public final class NativeCryptoInstrumentation extends Instrumentation {
    private String phase;
    private final JSONArray results=new JSONArray();
    private Context target;
    private JSONObject fixture;
    private File directory;
    private Bundle arguments;
    @Override public void onCreate(Bundle args){super.onCreate(args);arguments=args==null?new Bundle():new Bundle(args);phase=arguments.getString("phase","foundation");start();}
    @Override public void onStart(){
        Bundle report=new Bundle();int code=Activity.RESULT_OK;
        try {
            target=getTargetContext();directory=new File(target.getNoBackupFilesDir(),"native-interop-fixture");
            fixture=new JSONObject(readAsset("native-fixture.json"));
            if(phase.equals("one-phone-tor")){
                JSONArray live=new OnePhoneTorInstrumentation().run(this,arguments);for(int i=0;i<live.length();i++)results.put(live.get(i));
            }else if(phase.equals("navigation")){
                JSONArray navigation=new BackNavigationInstrumentation().run(this);for(int i=0;i<navigation.length();i++)results.put(navigation.get(i));
            }else if(phase.equals("multi-vault")){
                JSONArray multiple=new MultiVaultInstrumentation().run(this);for(int i=0;i<multiple.length();i++)results.put(multiple.get(i));
            }else if(phase.equals("live-phones")){
                JSONArray live=new LivePhonesInstrumentation().run(this,arguments);for(int i=0;i<live.length();i++)results.put(live.get(i));
            }else if(phase.equals("visual-demo")){
                JSONArray demo=new VisualDemoInstrumentation().run(this,arguments);for(int i=0;i<demo.length();i++)results.put(demo.get(i));
            }else if(phase.equals("file-storage-ui")){
                JSONArray storageUi=new FileGesturesInstrumentation().runUnlocked(this);for(int i=0;i<storageUi.length();i++)results.put(storageUi.get(i));
            }else if(phase.equals("file-gestures")){
                JSONArray gestures=new FileGesturesInstrumentation().run(this);for(int i=0;i<gestures.length();i++)results.put(gestures.get(i));
            }else if(phase.equals("external-storage")){
                JSONArray external=new ExternalStorageInstrumentation().run(this);for(int i=0;i<external.length();i++)results.put(external.get(i));
            }else if(phase.equals("keyboard")){
                JSONArray keyboard=new KeyboardInstrumentation().run(this);for(int i=0;i<keyboard.length();i++)results.put(keyboard.get(i));
            }else if(phase.equals("sovereign")){
                JSONArray sovereign=new SovereignInstrumentation().run(this,arguments);for(int i=0;i<sovereign.length();i++)results.put(sovereign.get(i));
            }else if(phase.equals("backup-stage1")){
                JSONArray backupResults=new BackupStage1Instrumentation().run(this);for(int i=0;i<backupResults.length();i++)results.put(backupResults.get(i));
            }else if(phase.equals("consumer")){
                JSONArray consumerResults=new ConsumerInstrumentation().run(this,arguments);for(int i=0;i<consumerResults.length();i++)results.put(consumerResults.get(i));
            }else if(phase.equals("bridge")){
                JSONArray bridgeResults=new NativeBridgeInstrumentation().run(this,arguments);for(int i=0;i<bridgeResults.length();i++)results.put(bridgeResults.get(i));
            }else if(phase.startsWith("vault-")){
                JSONArray vaultResults=new NativeVaultInstrumentation().run(this,arguments,phase);
                for(int i=0;i<vaultResults.length();i++)results.put(vaultResults.get(i));
            }else if("reply".equals(phase))reply();else foundation();
            report.putString("stream","Native "+phase+" checks passed: "+results.length()+"\n");
        }catch(Throwable error){
            code=Activity.RESULT_CANCELED;
            try{results.put(new JSONObject().put("status","fail").put("name",error.getClass().getSimpleName()+": "+error.getMessage()));}catch(Exception ignored){}
            report.putString("stream","Native "+phase+" failed: "+error.getClass().getSimpleName()+": "+error.getMessage()+"\n");
        }finally{
            try{write(new File(target.getFilesDir(),"native-test-"+phase+".json"),new JSONObject().put("phase",phase).put("results",results).toString().getBytes(StandardCharsets.UTF_8));}catch(Exception ignored){}
            report.putString("results",results.toString());finish(code,report);
        }
    }
    private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    private void pass(String name) throws Exception {results.put(new JSONObject().put("name",name).put("status","pass"));Bundle event=new Bundle();event.putString("stream","PASS: "+name+"\n");sendStatus(0,event);}
    private static byte[] read(InputStream input) throws Exception {try(InputStream stream=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[] buffer=new byte[8192];int n;while((n=stream.read(buffer))!=-1)out.write(buffer,0,n);return out.toByteArray();}}
    private String readAsset(String name) throws Exception {return new String(read(getContext().getAssets().open(name)),StandardCharsets.UTF_8);}
    private static void write(File file,byte[] bytes) throws Exception {if(!file.getParentFile().isDirectory()&&!file.getParentFile().mkdirs())throw new IOException("fixture_directory");try(FileOutputStream output=new FileOutputStream(file)){output.write(bytes);}}
    private static void rejects(Checked operation) throws Exception {boolean failed=false;try{operation.run();}catch(Exception expected){failed=true;}check(failed,"Expected operation to reject");}
    private interface Checked {void run() throws Exception;}
    private byte[] sqlKey() throws Exception {return Crypto.unb64(fixture.getString("sqlKey"));}
    private void clearFixture(File file) throws Exception {
        String root=new File(target.getNoBackupFilesDir(),"native-interop-fixture").getCanonicalPath();
        if(!file.getCanonicalPath().equals(root)&&!file.getCanonicalPath().startsWith(root+File.separator))throw new SecurityException("fixture_path");
        if(file.isDirectory()){File[] children=file.listFiles();if(children!=null)for(File child:children)clearFixture(child);}
        if(file.exists()&&!file.delete())throw new IOException("fixture_cleanup");
    }
    private static JSONObject relayBundle(JSONObject published,String userId) throws Exception {
        return new JSONObject(published.toString()).put("recipientUserId",userId).put("recipientDeviceId",published.getString("deviceId"))
            .put("oneTimePrekey",published.getJSONArray("oneTimePrekeys").getJSONObject(0)).put("pqOneTimePrekey",published.getJSONArray("pqOneTimePrekeys").getJSONObject(0));
    }
    private void foundation() throws Exception {
        File oldKey=new File(directory,"device-fragment.json");
        if(oldKey.isFile()){
            JSONObject old=new JSONObject(new String(Files.readAllBytes(oldKey.toPath()),StandardCharsets.UTF_8));
            String alias=old.getString("alias");check(alias.startsWith("cp-fixture-fragment-v1-"),"fixture alias expected");new DeviceKeyStore(alias).delete();
        }
        clearFixture(directory);if(!directory.mkdirs())throw new IOException("fixture_directory");
        String alias="cp-fixture-fragment-v1-"+UUID.randomUUID().toString().replace("-","");
        DeviceKeyStore deviceKey=new DeviceKeyStore(alias);byte[] share=Crypto.random(48);
        Crypto.Sealed protectedShare=deviceKey.wrap(share,"cp-native-fixture-fragment-v1");
        check(Arrays.equals(share,deviceKey.unwrap(protectedShare,"cp-native-fixture-fragment-v1")),"device fragment unwrap");
        rejects(()->deviceKey.unwrap(protectedShare,"wrong-context"));
        write(new File(directory,"device-fragment.json"),Crypto.utf8(new JSONObject().put("alias",alias).put("nonce",Crypto.b64(protectedShare.nonce)).put("ciphertext",Crypto.b64(protectedShare.ciphertext)).put("expected",Crypto.b64(share)).toString()));
        Crypto.wipe(share);pass("Android Keystore wraps the local fragment and binds its authenticated context; hardware-backed="+deviceKey.hardwareBacked());
        char[] password=fixture.getString("password").toCharArray();
        try(Crypto.VaultKeys keys=Crypto.deriveVaultKeys(fixture.getString("vaultId"),password)){
            JSONObject expected=fixture.getJSONObject("keys");
            check(Crypto.b64(keys.kek).equals(expected.getString("kek")),"KEK differs from Node");
            check(Crypto.b64(keys.lookup).equals(expected.getString("lookup")),"lookup differs from Node");
            check(Crypto.b64(keys.backup).equals(expected.getString("backup")),"backup differs from Node");
            check(Crypto.b64(keys.mask).equals(expected.getString("mask")),"mask differs from Node");
            check(Crypto.b64(keys.writer).equals(expected.getString("writer")),"writer differs from Node");
            pass("On-device Argon2id/HKDF matches all five Node key domains with exact Unicode credentials");
            JSONObject aead=fixture.getJSONObject("aead");byte[] plaintext=Crypto.unb64(aead.getString("plaintext")),nonce=Crypto.unb64(aead.getString("nonce"));
            Crypto.Sealed sealed=Crypto.sealWithNonce(plaintext,keys.kek,"vmk-wrap-v1",nonce);
            check(Crypto.b64(sealed.ciphertext).equals(aead.getString("ciphertext")),"GCM differs from Node");
            check(Arrays.equals(plaintext,Crypto.unseal(sealed.ciphertext,keys.kek,"vmk-wrap-v1",nonce)),"GCM roundtrip");
            byte[] damaged=sealed.ciphertext.clone();damaged[0]^=1;
            rejects(()->Crypto.unseal(damaged,keys.kek,"vmk-wrap-v1",nonce));rejects(()->Crypto.unseal(sealed.ciphertext,keys.kek,"wrong-context",nonce));
            pass("On-device AES-GCM matches Node and rejects tampering or wrong authenticated context");
            JSONObject writer=fixture.getJSONObject("writer");byte[] message=Crypto.unb64(writer.getString("message"));
            check(Crypto.b64(Crypto.edPublicSpki(keys.writer)).equals(writer.getString("publicKey")),"SPKI differs");
            check(Crypto.b64(Crypto.edSign(keys.writer,message)).equals(writer.getString("signature")),"Ed25519 signature differs");
            check(Crypto.edVerifySpki(Crypto.edPublicSpki(keys.writer),message,Crypto.edSign(keys.writer,message)),"Ed verify");
            pass("Separate Ed25519 writer/auth primitives match Node signatures and DER encoding");
        }finally{Arrays.fill(password,'\0');}
        byte[] vmk=Crypto.unb64(fixture.getString("vmk")),salt=Crypto.unb64(fixture.getString("salt"));
        check(Arrays.equals(Crypto.hkdf(vmk,salt,"sqlcipher-key-v1"),sqlKey()),"SQLCipher key domain differs");Crypto.wipe(vmk,salt);
        File imported=new File(directory,"node.db");write(imported,read(getContext().getAssets().open("node-fixture.db")));
        try(NativeDatabase db=new NativeDatabase(target,imported,sqlKey())){
            check("node-persistent-value".equals(db.text("SELECT value FROM native_interop")),"Node SQLCipher database not readable");
            db.db().execSQL("INSERT INTO native_interop(value) VALUES('android-persistent-value')");db.checkpoint();
        }
        rejects(()->{try(NativeDatabase ignored=new NativeDatabase(target,imported,Crypto.random(32))) {}});
        try(NativeDatabase db=new NativeDatabase(target,imported,sqlKey())){check(db.exists("SELECT 1 FROM native_interop WHERE value='android-persistent-value'"),"SQLCipher reopen lost data");}
        check(!new String(Arrays.copyOf(Files.readAllBytes(imported.toPath()),16),StandardCharsets.US_ASCII).startsWith("SQLite format"),"database is plaintext");
        pass("Real Android SQLCipher opens the Node database, persists changes and rejects a wrong key");

        try(NativeDatabase a=new NativeDatabase(target,new File(directory,"alice.db"),sqlKey());NativeDatabase b=new NativeDatabase(target,new File(directory,"bob.db"),sqlKey())){
            NativeSignalStore alice=new NativeSignalStore(a),bob=new NativeSignalStore(b);
            JSONObject alicePublished=alice.ensureIdentity(),bobPublished=bob.ensureIdentity();
            String aliceId=UUID.randomUUID().toString(),bobId=UUID.randomUUID().toString();alice.setAccount(aliceId);bob.setAccount(bobId);
            SignalProtocolAddress bobAddress=alice.establish(relayBundle(bobPublished,bobId));
            byte[] before=a.blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",bobId+".1");
            a.db().beginTransaction();try{alice.encrypt(bobAddress,Crypto.utf8("must roll back"));}finally{a.db().endTransaction();}
            check(Arrays.equals(before,a.blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",bobId+".1")),"ratchet rollback failed");
            pass("On-device Signal ratchet advance rolls back with its SQLCipher transaction");
            byte[] encrypted=alice.encrypt(bobAddress,Crypto.utf8("Native to native தமிழ் 🕊️"));
            SignalProtocolAddress aliceAddress=alice.localAddress();
            check(new String(bob.decrypt(aliceAddress,encrypted),StandardCharsets.UTF_8).equals("Native to native தமிழ் 🕊️"),"native Signal decrypt failed");
            check(!bob.containsPreKey(1)&&!bob.containsKyberPreKey(2)&&bob.containsKyberPreKey(1),"one-time prekeys not consumed");
            check(new String(alice.decrypt(bobAddress,bob.encrypt(aliceAddress,Crypto.utf8("Native reply"))),StandardCharsets.UTF_8).equals("Native reply"),"native Signal reply failed");
            pass("Pinned libsignal JNI establishes PQ sessions, exchanges messages and consumes one-time keys on-device");
            rejects(()->bob.decrypt(aliceAddress,encrypted));
            check(!alice.isTrustedIdentity(bobAddress,IdentityKeyPair.generate().getPublicKey(),org.signal.libsignal.protocol.state.IdentityKeyStore.Direction.SENDING),"changed identity accepted");
            check(Arrays.equals(alice.getIdentity(bobAddress).serialize(),Crypto.unb64(bobPublished.getString("identityPublicKey"))),"pinned identity overwritten");
            pass("Duplicate messages and changed identities are rejected without replacing the identity pin");
            ECPublicKey base=ECPrivateKey.generate().publicKey();bob.markKyberPreKeyUsed(1,1,base);rejects(()->bob.markKyberPreKeyUsed(1,1,base));
            pass("Last-resort PQ prekeys reject reuse of the same signed-prekey/base-key tuple");

            JSONObject nodeBob=fixture.getJSONObject("bob");SignalProtocolAddress nodeAddress=alice.establish(nodeBob);
            byte[] frame=alice.encrypt(nodeAddress,Crypto.utf8("{\"type\":\"text\",\"text\":\"Android to Node தமிழ் 🕊️\"}"));
            JSONObject result=new JSONObject().put("aliceId",aliceId).put("aliceBundle",alicePublished).put("ciphertext",Crypto.b64(frame)).put("bobId",nodeBob.getString("recipientUserId"));
            write(new File(target.getFilesDir(),"native-interop-result.json"),Crypto.utf8(result.toString()));a.checkpoint();b.checkpoint();
            pass("Native Signal identity and encrypted envelope exported for independent Node interoperability verification");
        }
    }
    private void reply() throws Exception {
        JSONObject fragment=new JSONObject(new String(Files.readAllBytes(new File(directory,"device-fragment.json").toPath()),StandardCharsets.UTF_8));
        DeviceKeyStore key=new DeviceKeyStore(fragment.getString("alias"));
        byte[] recovered=key.unwrap(new Crypto.Sealed(Crypto.unb64(fragment.getString("nonce")),Crypto.unb64(fragment.getString("ciphertext"))),"cp-native-fixture-fragment-v1");
        check(Arrays.equals(recovered,Crypto.unb64(fragment.getString("expected"))),"device fragment lost after process restart");Crypto.wipe(recovered);
        pass("Device-bound fragment unwraps after process restart without exporting its Keystore key");
        JSONObject reply=new JSONObject(new String(Files.readAllBytes(new File(target.getFilesDir(),"native-interop-reply.json").toPath()),StandardCharsets.UTF_8));
        try(NativeDatabase db=new NativeDatabase(target,new File(directory,"alice.db"),sqlKey())){
            NativeSignalStore alice=new NativeSignalStore(db);
            byte[] plaintext=alice.decrypt(new SignalProtocolAddress(reply.getString("bobId"),1),Crypto.unb64(reply.getString("ciphertext")));
            check(new String(plaintext,StandardCharsets.UTF_8).equals("{\"type\":\"text\",\"text\":\"Node to Android नमस्ते 🕊️\"}"),"Node reply did not decrypt");
            db.checkpoint();pass("Persisted on-device Signal session decrypts a real Node reply after process restart");
        }
    }
}
