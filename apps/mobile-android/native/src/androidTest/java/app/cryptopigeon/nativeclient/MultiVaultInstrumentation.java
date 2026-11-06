package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exercises real JNI, encrypted files and authenticated local API on one phone. */
final class MultiVaultInstrumentation {
    private final JSONArray results=new JSONArray();
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private void pass(String name) throws Exception {results.put(new JSONObject().put("name",name).put("status","pass"));}
    private static JSONObject body(Object... values) throws Exception {JSONObject out=new JSONObject();for(int i=0;i<values.length;i+=2)out.put((String)values[i],values[i+1]);return out;}
    private static NativeVault active(NativeEngine engine) throws Exception {Field f=NativeEngine.class.getDeclaredField("vault");f.setAccessible(true);return (NativeVault)f.get(engine);}
    private static String device(NativeVault vault) throws Exception {NativeSignalStore store=new NativeSignalStore(vault.database());store.ensureIdentity();return store.deviceId();}
    private static void locked(NativeBridgeInstrumentation.Client client) throws Exception {check(client.json("/api/vault/status",null).getString("vaultState").equals("locked"),"Rejected credentials opened a vault");}
    private static void rejectOpen(NativeBridgeInstrumentation.Client client,JSONObject input) throws Exception {client.raw("POST","/api/vault/open",input,true,null);check(client.status!=200,"Wrong credentials or segment accepted");locked(client);}
    JSONArray run(Instrumentation runner) throws Exception {
        Context context=runner.getTargetContext();
        runner.startActivitySync(new android.content.Intent(context,MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
        String tag=UUID.randomUUID().toString().replace("-",""),idA="Existing-"+tag,idB="Second-"+tag;
        String passwordA="OriginalVault-Aa123!",passwordB="SecondVault-Aa123!",newPasswordA="ChangedVault-Aa123!";
        File root=new File(context.getNoBackupFilesDir(),"multi-fixture-"+tag);
        VaultBackupRelay noNetwork=new VaultBackupRelay(){
            public JSONObject getBackup(String token){throw new AssertionError("Offline vault unexpectedly read relay");}
            public void putBackup(JSONObject value){throw new AssertionError("Offline vault unexpectedly uploaded");}
            public void deleteBackup(String token,long version,byte[] writer){throw new AssertionError("Offline vault unexpectedly deleted backup");}
        };
        NativeBridgeInstrumentation.Client client=null;byte[] capsuleA=null,capsuleB=null;
        try{
            String shardA,identityA;
            // Start with the exact old single-vault layout, without a catalog.
            try(NativeVault original=new NativeVault(context,root,noNetwork)){
                shardA=original.createExternal(idA,passwordA.toCharArray());capsuleA=original.shard7File();original.confirmShard7Saved();
                original.database().db().execSQL("INSERT INTO consumer_profile(singleton,display_name,status_line) VALUES(1,'Original private data','Alpha')");
                identityA=device(original);
            }
            byte[] originalConfig=NativeIo.read(new File(root,"config.json"),16384),originalDb=Crypto.sha256(NativeIo.read(new File(root,"data/chat.db"),4*1024*1024));
            client=new NativeBridgeInstrumentation.Client(context,root,"https://example.invalid");
            JSONObject created=client.json("/api/vault/create",body("vaultId",idB,"password",passwordB));
            String handleB=created.getString("vaultHandle"),shardB=created.getString("clientShard");capsuleB=Crypto.unb64(created.getString("shard7FileBytes"));
            client.json("/api/vault/shard7/saved",new JSONObject());
            check(!handleB.equals("legacy"),"Second vault reused original directory");
            check(Arrays.equals(originalConfig,NativeIo.read(new File(root,"config.json"),16384)),"Creating second vault modified original config");
            check(Arrays.equals(originalDb,Crypto.sha256(NativeIo.read(new File(root,"data/chat.db"),4*1024*1024))),"Creating second vault modified original database");
            client.json("/api/profile",body("displayName","Second private data","statusLine","Beta"));String identityB=device(active(client.engine));
            check(!identityA.equals(identityB),"Vaults reused a Signal/device identity");
            JSONObject shards=body("legacy",shardA,handleB,shardB);
            pass("Creating a second vault preserves original config/database bytes and creates a separate native identity");
            client.lock();
            client.raw("POST","/api/vault/create",body("vaultId",idB,"password",passwordA),true,null);
            check(client.status==409,"Duplicate Vault ID did not reject creation");locked(client);
            rejectOpen(client,body("vaultId",idB,"password",passwordA,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleB)));
            rejectOpen(client,body("vaultId",idB,"password",passwordB,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleA)));
            rejectOpen(client,body("vaultId","Unknown-"+tag,"password",passwordB,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleB)));
            pass("Duplicate IDs, wrong master passphrases, wrong segment files and unknown IDs cannot open or overwrite a vault");
            client.json("/api/vault/open",body("vaultId",idA,"password",passwordA,"clientShard",shardB,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleA)));
            check(client.json("/api/profile",null).getString("displayName").equals("Original private data"),"Legacy profile missing");
            check(device(active(client.engine)).equals(identityA),"Original identity changed");
            pass("Correct original credentials select the legacy vault despite a different active browser fragment");
            client.lock();
            client.json("/api/vault/open",body("vaultId",idB,"password",passwordB,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleB)));
            check(client.json("/api/profile",null).getString("displayName").equals("Second private data"),"Second vault profile mixed with original");
            check(device(active(client.engine)).equals(identityB),"Second identity changed");
            client.close();client=new NativeBridgeInstrumentation.Client(context,root,"https://example.invalid");locked(client);
            client.json("/api/vault/open",body("vaultId",idA,"password",passwordA,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleA)));
            check(device(active(client.engine)).equals(identityA),"Restart lost original identity");
            pass("Both vaults switch independently and remain locked/reopenable after engine and local-session restart");
            JSONObject changed=client.json("/api/vault/change-password",body("vaultId",idA,"oldPassword",passwordA,"newPassword",newPasswordA));
            Crypto.wipe(capsuleA);capsuleA=Crypto.unb64(changed.getString("shard7FileBytes"));shards.put("legacy",changed.getString("clientShard"));
            client.lock();
            rejectOpen(client,body("vaultId",idA,"password",passwordA,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleA)));
            client.json("/api/vault/open",body("vaultId",idA,"password",newPasswordA,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleA)));
            check(client.json("/api/profile",null).getString("displayName").equals("Original private data"),"Rotation lost original data");client.lock();
            client.json("/api/vault/open",body("vaultId",idB,"password",passwordB,"clientShards",shards,"shard7Payload",Crypto.b64(capsuleB)));
            check(client.json("/api/profile",null).getString("displayName").equals("Second private data"),"Rotation changed another vault");
            String catalog=new String(NativeIo.read(new File(root.getParentFile(),root.getName()+".vaults.json"),128*1024),java.nio.charset.StandardCharsets.UTF_8);
            check(!catalog.contains(idA)&&!catalog.contains(idB)&&!catalog.contains(passwordA)&&!catalog.contains(passwordB),"Catalog stores credential plaintext");
            pass("Changing one master passphrase invalidates the old passphrase and preserves the other vault; catalog contains no plaintext credentials");
        }finally{
            if(client!=null)client.close();Crypto.wipe(capsuleA,capsuleB);
            File[] fixtures=root.getParentFile().listFiles(file->file.getName().equals(root.getName())||file.getName().startsWith(root.getName()+"."));
            if(fixtures!=null)for(File fixture:fixtures)NativeIo.deleteTree(fixture,context.getNoBackupFilesDir());
        }
        return results;
    }
}
