package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.File;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;

/** Isolated, narrow device tests. Uses real SQLCipher/Keystore; no consumer vault access. */
final class BackupStage1Instrumentation {
    private final JSONArray results=new JSONArray();
    private Instrumentation runner;
    private void pass(String name) throws Exception {
        results.put(new JSONObject().put("name",name).put("status","pass"));
        Bundle event=new Bundle();event.putString("stream","PASS: "+name+"\n");runner.sendStatus(0,event);
    }
    private static void check(boolean condition,String reason){if(!condition)throw new AssertionError(reason);}
    private static final class MemoryRelay implements VaultBackupRelay {
        JSONObject backup;int uploads;boolean offline;
        public JSONObject getBackup(String token) throws Exception {
            if(offline)throw new java.io.IOException("offline");
            return backup==null?null:new JSONObject(backup.toString());
        }
        public void putBackup(JSONObject body) throws Exception {
            if(offline)throw new java.io.IOException("offline");
            uploads++;backup=new JSONObject(body.toString());
        }
        public void deleteBackup(String token,long version,byte[] writer){backup=null;}
    }
    JSONArray run(Instrumentation runner) throws Exception {
        this.runner=runner;Context context=runner.getTargetContext();MemoryRelay relay=new MemoryRelay();
        File root=new File(context.getNoBackupFilesDir(),"stage1-backup-"+UUID.randomUUID());
        String id="stage1-vault-"+UUID.randomUUID(),password="Stage1BackupPassword123!",browser;
        try(NativeVault vault=new NativeVault(context,root,relay)){
            browser=vault.create(id,password.toCharArray());
            JSONObject config=NativeIo.json(new File(root,"config.json"),16384);
            check(!config.has("fragment7Shard"),"Shard 7 persisted in config");
            check(config.getString("lastUploadedBackupSha256").matches("[a-f0-9]{64}"),"Missing ciphertext digest");
            check(!config.getBoolean("vaultDirty"),"Initial upload did not clear dirty state");
            check(vault.prepareBackgroundBackup()==null,"Unchanged vault prepared a redundant backup");
            check(relay.uploads==1,"Unchanged vault uploaded again");
            pass("Unchanged vault skips background upload; SHA-256 metadata exists and Shard 7 stays off disk");
            vault.database().db().execSQL("CREATE TABLE stage1_fixture(value TEXT)");
            vault.database().db().execSQL("INSERT INTO stage1_fixture(value) VALUES('before-snapshot')");vault.markDirty();
            NativeVault.PreparedBackup prepared=vault.prepareBackgroundBackup();check(prepared!=null,"Mutation did not dirty vault");
            vault.database().db().execSQL("INSERT INTO stage1_fixture(value) VALUES('during-upload')");vault.markDirty();
            vault.uploadPreparedBackup(prepared);
            check(NativeIo.json(new File(root,"config.json"),16384).getBoolean("vaultDirty"),"In-flight mutation lost dirty flag");
            NativeVault.PreparedBackup next=vault.prepareBackgroundBackup();check(next!=null,"New mutation skipped");vault.uploadPreparedBackup(next);
            check(vault.prepareBackgroundBackup()==null,"Completed snapshot did not settle");
            pass("Mutation during an upload stays dirty until the next encrypted snapshot is uploaded");
            vault.database().db().execSQL("INSERT INTO stage1_fixture(value) VALUES('lock-flush')");vault.markDirty();
            int before=relay.uploads;check(vault.syncAndLock().getBoolean("backupSynced"),"Lock backup did not sync");
            check(vault.isLocked()&&relay.uploads==before+1,"Lock did not synchronously upload and close");
            relay.offline=true;boolean rejected=false;
            try{vault.open(id,password.toCharArray(),browser);}catch(Exception expected){rejected=true;}
            check(rejected&&vault.isLocked(),"Cold unlock bypassed the remote seventh fragment");
            relay.offline=false;vault.open(id,password.toCharArray(),browser);
            check(vault.database().exists("SELECT 1 FROM stage1_fixture WHERE value='lock-flush'"),"Lock lost SQLCipher mutation");
            check(!NativeIo.json(new File(root,"config.json"),16384).has("fragment7Shard"),"Unlock cached Shard 7");
            pass("Explicit lock synchronously syncs; cold unlock fails offline and succeeds only after remote Shard 7 verification");
        } finally {
            File config=new File(root,"config.json");
            if(config.isFile())new DeviceKeyStore(NativeIo.json(config,16384).getString("deviceKeyAlias")).delete();
            NativeIo.deleteTree(root,context.getNoBackupFilesDir());
        }
        return results;
    }
}
