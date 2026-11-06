package app.cryptopigeon.nativeclient;

import android.content.Context;
import android.database.Cursor;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.json.*;

/** Synchronized Android vault lifecycle using the desktop's signed backup format. */
public final class NativeVault implements AutoCloseable {
    private final Context context;private final File root;private VaultBackupRelay relay;
    private final Object uploadLock=new Object();
    private final Set<PreparedBackup> pendingUploads=new HashSet<>();
    private JSONObject config;private Crypto.VaultKeys keys;private byte[] vmk;private NativeDatabase database;private NativeFragments fragments;
    private boolean clientPresent,relayPresent;
    private byte[] remoteFragment7;
    private long dirtyGeneration,lastBackedUpChanges=-1;
    private long backupSyncSkippedCount,backupSyncUploadedBytes;
    public NativeVault(Context context,File root,VaultBackupRelay relay) throws Exception {
        this.context=context.getApplicationContext();this.root=root.getCanonicalFile();this.relay=relay;
        String allowed=context.getNoBackupFilesDir().getCanonicalPath()+File.separator;
        if(!this.root.getPath().startsWith(allowed)||!this.root.getName().matches("[A-Za-z0-9_.-]{1,128}"))throw new SecurityException("invalid_vault_root");
        recoverCommit();initialize();
    }
    private File file(String path) throws Exception {return NativeIo.child(root,path);}
    private File configFile() throws Exception {return file("config.json");}
    private void initialize() throws Exception {
        initialize(false);
    }
    private void initialize(boolean pendingCreation) throws Exception {
        config=null;fragments=null;
        if(configFile().isFile()){
            config=NativeIo.json(configFile(),16384);
            if(config.optBoolean("creationPending",false)&&!pendingCreation){config=null;return;}
            // Migrate the old sealed Shard 7 cache away. Cold unlock always downloads it.
            if(config.has("fragment7Shard")){config.remove("fragment7Shard");saveConfig();}
            if(config.getInt("secureVersion")!=3||Crypto.unb64(config.getString("vmkNonce")).length!=12||Crypto.unb64(config.getString("hkdfSalt")).length!=16||config.getJSONArray("hashes").length()!=7)throw new IOException("invalid_vault_config");
            for(int i=0;i<7;i++)if(!config.getJSONArray("hashes").getString(i).matches("[a-f0-9]{64}"))throw new IOException("invalid_vault_config");
            fragments=new NativeFragments(context,root,config.getString("deviceKeyAlias"));
        }
    }
    private void saveConfig() throws Exception {NativeIo.atomic(configFile(),config);}
    public synchronized boolean exists(){return config!=null;}
    public synchronized boolean isLocked(){return database==null;}
    public synchronized NativeDatabase database(){if(database==null)throw new IllegalStateException("vault_locked");return database;}
    public synchronized byte[] attachmentKey(){if(vmk==null)throw new IllegalStateException("vault_locked");return Crypto.hkdf(vmk,Crypto.unb64(config.optString("hkdfSalt")),"attachment-meta-v1");}
    public synchronized File attachmentPath(String id) throws Exception {if(!id.matches("[a-f0-9]{32}"))throw new IllegalArgumentException("invalid_attachment_id");return file("attachments/"+id);}
    public synchronized JSONObject status(boolean browserPresent) throws Exception {
        if(fragments==null)return new JSONObject().put("totalShares",7).put("sharesPresent",0).put("locations",new JSONObject()).put("isReconstructable",false).put("hardwareBacked",false);
        return fragments.status(browserPresent,relayPresent,config!=null).put("externalShard7","external".equals(config.optString("shard7Mode")));
    }
    private static void credentials(String id,char[] password,boolean creating){
        if(id==null||id.length()<8||id.length()>256||password==null||password.length<12||password.length>1024)throw new IllegalArgumentException("INVALID_VAULT_CREDENTIALS");
        if(creating){String value=new String(password);if(!value.matches("(?s).*[A-Z].*")||!value.matches("(?s).*[a-z].*")||!value.matches("(?s).*[0-9].*"))throw new IllegalArgumentException("Password should contain uppercase, lowercase, and numbers.");
            if(Arrays.asList("password","password123","123456789","12345678","qwertyuiop","adminadmin","letmein123","iloveyou","p@ssword","changeit").contains(value.toLowerCase(Locale.ROOT)))throw new IllegalArgumentException("Password is too common/weak.");}
    }
    private JSONObject download(Crypto.VaultKeys candidate) throws Exception {
        String lookup=Crypto.hex(candidate.lookup);JSONObject remote=relay.getBackup(lookup);if(remote==null)return null;
        if(!lookup.equals(remote.getString("lookupToken"))||remote.getLong("version")<1||remote.getLong("version")>2147483647L||Crypto.unb64(remote.getString("nonce")).length!=12||remote.getString("ciphertext").length()>86*1024*1024||remote.getString("fragment7Shard").length()>256)throw new IOException("INVALID_BACKUP_ENVELOPE");
        byte[] expected=Crypto.edPublicSpki(candidate.writer),signature=Crypto.unb64(remote.getString("signature"));
        if(!MessageDigest.isEqual(expected,Crypto.unb64(remote.getString("writerPublicKey")))||signature.length!=64||!Crypto.edVerifySpki(expected,VaultWire.signingPayload(remote),signature))throw new IOException("INVALID_BACKUP_SIGNATURE");
        return remote;
    }
    private String provision(byte[] master,Crypto.VaultKeys derived,String salt) throws Exception {
        return provision(master,derived,salt,null);
    }
    private String provision(byte[] master,Crypto.VaultKeys derived,String salt,byte[] externalSeventh) throws Exception {
        Crypto.Sealed wrapped=Crypto.seal(master,derived.kek,"vmk-wrap-v1");
        String alias="cp-vault-fragment-v1-"+UUID.randomUUID().toString().replace("-","");
        fragments=new NativeFragments(context,root,alias);
        try{
            JSONObject split=fragments.scatter(wrapped.ciphertext,derived,externalSeventh);
            config=new JSONObject().put("version",2).put("secureVersion",3).put("nativeFormat",1).put("vmkVersion",1).put("wrappedVmk","")
                .put("vmkNonce",Crypto.b64(wrapped.nonce)).put("hkdfSalt",salt).put("createdAt",Instant.now().toString()).put("backupVersion",0)
                .put("deviceKeyAlias",alias).put("hashes",split.getJSONArray("hashes")).put("vaultDirty",true);
            Crypto.wipe(remoteFragment7);remoteFragment7=Crypto.utf8(split.getString("fragment7Shard"));
            keys=derived;vmk=master.clone();clientPresent=true;openDatabase();return split.getString("clientShard");
        }finally{Crypto.wipe(wrapped.ciphertext);}
    }
    private void openDatabase() throws Exception {
        byte[] key=Crypto.hkdf(vmk,Crypto.unb64(config.getString("hkdfSalt")),"sqlcipher-key-v1");
        try{database=new NativeDatabase(context,file("data/chat.db"),key);}finally{Crypto.wipe(key);}
    }
    public synchronized String create(String vaultId,char[] password) throws Exception {
        if(exists())throw new IllegalStateException("vault_already_exists");credentials(vaultId,password,true);
        File stage=stage("create");NativeVault staged=new NativeVault(context,stage,relay);boolean uploaded=false;
        Crypto.VaultKeys derived=Crypto.deriveVaultKeys(vaultId,password),createdKeys=null;byte[] master=Crypto.random(32);
        try{
            if(download(derived)!=null)throw new IllegalStateException("VAULT_ID_ALREADY_EXISTS_USE_RESTORE");
            String browser=staged.provision(master,derived,Crypto.b64(Crypto.random(16)));staged.config.put("cloudBackupEnabled",true);staged.syncBackup();uploaded=true;
            createdKeys=new Crypto.VaultKeys(derived);staged.close();commit(stage,"create");initialize();
            // Verify the remote seventh fragment even immediately after creation.
            JSONObject remote=download(createdKeys);if(remote==null)throw new IOException("HORCRUX_INCOMPLETE_RESTORE_REQUIRED");
            remoteFragment7=Crypto.unb64(remote.getString("fragment7Shard"));
            byte[] wrapped=fragments.collect(browser,new String(remoteFragment7,StandardCharsets.UTF_8),createdKeys,config.getJSONArray("hashes"));
            try{byte[] verified=Crypto.unseal(wrapped,createdKeys.kek,"vmk-wrap-v1",Crypto.unb64(config.getString("vmkNonce")));
                try{if(!MessageDigest.isEqual(master,verified))throw new SecurityException("invalid_created_vmk");}finally{Crypto.wipe(verified);}
            }finally{Crypto.wipe(wrapped);}
            keys=createdKeys;createdKeys=null;vmk=master.clone();openDatabase();lastBackedUpChanges=databaseChanges();clientPresent=true;relayPresent=true;return browser;
        }finally{Crypto.wipe(master);staged.close();derived.close();if(createdKeys!=null)createdKeys.close();if(stage.exists()&&!uploaded)cleanup(staged);}
    }
    public synchronized void open(String vaultId,char[] password,String browser) throws Exception {
        open(vaultId,password,browser,null);
    }
    public synchronized void open(String vaultId,char[] password,String browser,byte[] capsule) throws Exception {
        if(!isLocked())throw new IllegalStateException("vault_already_unlocked");if(!exists())throw new IllegalStateException("vault_not_configured");credentials(vaultId,password,false);
        Crypto.VaultKeys derived=Crypto.deriveVaultKeys(vaultId,password);byte[] wrapped=null,master=null;
        try{
            if("external".equals(config.optString("shard7Mode"))){
                if(capsule==null)throw new IOException("SHARD7_FILE_REQUIRED");
                byte[] share=SovereignFiles.seventh(capsule,derived),sealed=SovereignFiles.envelope(capsule,SovereignFiles.SHARD_HEADER,2048);
                try{
                    if(!Crypto.hex(Crypto.sha256(share)).equals(config.getJSONArray("hashes").getString(6)))throw new IOException("SHARD7_FILE_MISMATCH");
                    wrapped=fragments.collect(browser,new String(sealed,StandardCharsets.UTF_8),derived,config.getJSONArray("hashes"));
                    master=Crypto.unseal(wrapped,derived.kek,"vmk-wrap-v1",Crypto.unb64(config.getString("vmkNonce")));
                    keys=derived;vmk=master.clone();openDatabase();remoteFragment7=sealed.clone();clientPresent=true;relayPresent=true;return;
                }finally{Crypto.wipe(share,sealed);}
            }
            JSONObject remote;
            try{remote=download(derived);}catch(IOException invalid){if("INVALID_BACKUP_SIGNATURE".equals(invalid.getMessage())||"INVALID_BACKUP_ENVELOPE".equals(invalid.getMessage()))throw new IOException("HORCRUX_INCOMPLETE_RESTORE_REQUIRED");throw invalid;}
            if(remote==null)throw new IOException("BACKUP_NOT_FOUND_OR_INVALID_CREDENTIALS");
            String seventh=new String(Crypto.unb64(remote.getString("fragment7Shard")),StandardCharsets.UTF_8);
            wrapped=fragments.collect(browser,seventh,derived,config.getJSONArray("hashes"));
            master=Crypto.unseal(wrapped,derived.kek,"vmk-wrap-v1",Crypto.unb64(config.getString("vmkNonce")));
            if(master.length!=32)throw new IOException("invalid_snapshot_key");keys=derived;vmk=master.clone();openDatabase();
            Crypto.wipe(remoteFragment7);remoteFragment7=Crypto.utf8(seventh);lastBackedUpChanges=-1;
            config.put("backupVersion",remote.getLong("version"));saveConfig();clientPresent=true;relayPresent=true;
        }catch(Exception failure){close();derived.close();throw failure;}finally{Crypto.wipe(wrapped,master);}
    }
    private JSONObject prepareBackup(boolean claim) throws Exception {
        NativeDatabase active=database();if(keys==null||vmk==null)throw new IllegalStateException("vault_locked");
        String instance=active.text("SELECT token FROM vault_instance WHERE singleton=1");
        if(instance==null){instance=Crypto.hex(Crypto.random(32));active.db().execSQL("INSERT INTO vault_instance(singleton,token) VALUES(1,?)",new Object[]{instance});}
        active.checkpoint();byte[] compressed=SnapshotCodec.encode(active.file,file("attachments"),vmk,config.getString("hkdfSalt"));
        try{
            Crypto.Sealed encrypted=Crypto.seal(compressed,keys.backup,"vault-backup-v1");
            try{
                JSONObject body=new JSONObject().put("lookupToken",Crypto.hex(keys.lookup)).put("version",config.getLong("backupVersion")+1)
                    .put("nonce",Crypto.b64(encrypted.nonce)).put("ciphertext",Crypto.b64(encrypted.ciphertext)).put("updatedAt",Instant.now().toString())
                    .put("fragment7Shard",Crypto.b64(requireRemoteFragment())).put("writerPublicKey",Crypto.b64(Crypto.edPublicSpki(keys.writer))).put("claim",claim);
                NativeSignalStore store=new NativeSignalStore(active);
                if(active.exists("SELECT 1 FROM signal_account WHERE singleton=1 AND user_id IS NOT NULL")){
                    String hash=Crypto.hex(Crypto.sha256(Crypto.utf8(instance)));
                    body.put("deviceId",store.deviceId()).put("instanceHash",hash).put("deviceSignature",Crypto.b64(store.signDeviceMessage(Crypto.utf8("cp-vault-instance-v1:"+hash))));
                }
                body.put("signature",Crypto.b64(Crypto.edSign(keys.writer,VaultWire.signingPayload(body))));return body;
            }finally{Crypto.wipe(encrypted.ciphertext);}
        }finally{Crypto.wipe(compressed);}
    }
    static final class PreparedBackup {
        final JSONObject body;final byte[] writer;final long generation,changes;
        PreparedBackup(JSONObject body,byte[] writer,long generation,long changes){this.body=body;this.writer=writer;this.generation=generation;this.changes=changes;}
    }
    private byte[] requireRemoteFragment(){if(remoteFragment7==null)throw new IllegalStateException("REMOTE_FRAGMENT_REQUIRED");return remoteFragment7;}
    private long databaseChanges(){return Long.parseLong(database().text("SELECT total_changes()"));}
    synchronized void markDirty(){
        if(config==null||isLocked())return;dirtyGeneration++;
        if(!config.optBoolean("vaultDirty",true))try{config.put("vaultDirty",true);saveConfig();}catch(Exception failed){throw new IllegalStateException("BACKUP_METADATA_FAILED",failed);}
    }
    private void skipped(){backupSyncSkippedCount++;android.util.Log.i("CryptoPigeonPerf","backupSyncSkippedCount="+backupSyncSkippedCount+" backupSyncUploadedBytes="+backupSyncUploadedBytes);}
    synchronized PreparedBackup prepareBackgroundBackup() throws Exception {
        if(!cloudBackupEnabled())return null;
        if(!config.optBoolean("vaultDirty",true)&&lastBackedUpChanges==databaseChanges()){skipped();return null;}
        return prepareUpload(false);
    }
    private PreparedBackup prepareUpload(boolean claim) throws Exception {
        JSONObject body=prepareBackup(claim);
        PreparedBackup prepared=new PreparedBackup(body,keys.writer.clone(),dirtyGeneration,databaseChanges());pendingUploads.add(prepared);return prepared;
    }
    JSONObject uploadPreparedBackup(PreparedBackup prepared) throws Exception {
        if(prepared==null)return new JSONObject().put("ok",true).put("skipped",true);
        try { synchronized(uploadLock) {
            String digest=Crypto.hex(Crypto.sha256(Crypto.unb64(prepared.body.getString("ciphertext"))));
            synchronized(this) {
                if(!prepared.body.optBoolean("claim")&&digest.equals(config.optString("lastUploadedBackupSha256"))){skipped();return new JSONObject().put("ok",true).put("skipped",true);}
                prepared.body.put("version",config.getLong("backupVersion")+1);
                prepared.body.put("signature",Crypto.b64(Crypto.edSign(prepared.writer,VaultWire.signingPayload(prepared.body))));
            }
            relay.putBackup(prepared.body);
            synchronized(this){
                config.put("backupVersion",prepared.body.getLong("version")).put("lastUploadedBackupSha256",digest);
                if(dirtyGeneration==prepared.generation&&(database==null||databaseChanges()==prepared.changes)){
                    config.put("vaultDirty",false);lastBackedUpChanges=prepared.changes;
                }
                saveConfig();relayPresent=true;backupSyncUploadedBytes+=Crypto.unb64(prepared.body.getString("ciphertext")).length;
                android.util.Log.i("CryptoPigeonPerf","backupSyncSkippedCount="+backupSyncSkippedCount+" backupSyncUploadedBytes="+backupSyncUploadedBytes);
            }
            return new JSONObject().put("ok",true).put("version",prepared.body.getLong("version"));
        }} finally {synchronized(this){pendingUploads.remove(prepared);}Crypto.wipe(prepared.writer);}
    }
    public JSONObject syncBackup() throws Exception {return syncBackup(false);}
    private JSONObject syncBackup(boolean claim) throws Exception {
        synchronized(this){if(!cloudBackupEnabled())return new JSONObject().put("ok",true).put("skipped",true).put("cloudBackupEnabled",false);}
        PreparedBackup prepared;synchronized(this){prepared=prepareUpload(claim);}return uploadPreparedBackup(prepared);
    }
    synchronized void setRelay(VaultBackupRelay next){relay=next;}
    synchronized void destroyRam(){for(PreparedBackup pending:pendingUploads)Crypto.wipe(pending.writer);pendingUploads.clear();close();}
    public JSONObject syncAndLock() throws Exception {return syncAndLock(null);}
    JSONObject syncAndLock(java.util.concurrent.CompletableFuture<Void> previous) throws Exception {
        PreparedBackup prepared=null;
        boolean localSaved=false;String localError=null,localUri;byte[] localBytes=null;
        synchronized(this){localUri=storageUri();try{if(localUri!=null)localBytes=exportStorage();if(cloudBackupEnabled())prepared=prepareUpload(false);}catch(Exception failed){localError="LOCAL_STORAGE_SAVE_FAILED";}finally{close();}}
        // Provider/network I/O must never keep the live VMK or Shards 6/7 alive.
        try{if(localUri!=null&&localBytes!=null)writeStorage(localUri,localBytes);localSaved=localError==null;}catch(Exception unavailable){localError="LOCAL_STORAGE_SAVE_FAILED";}finally{Crypto.wipe(localBytes);}
        if(previous!=null)try{previous.get();}catch(Exception ignored){}
        boolean synced=false;
        if(prepared!=null)try{uploadPreparedBackup(prepared);synced=true;}catch(Exception unavailable){}
        return new JSONObject().put("ok",true).put("backupSynced",synced||!cloudBackupEnabled()).put("localStorageSaved",localSaved).put("localStorageError",localError==null?JSONObject.NULL:localError);
    }
    synchronized boolean cloudBackupEnabled(){return config!=null&&config.optBoolean("cloudBackupEnabled",false);}
    synchronized JSONObject storageStatus() throws Exception {return new JSONObject().put("cloudBackupEnabled",cloudBackupEnabled()).put("externalShard7","external".equals(config==null?null:config.optString("shard7Mode"))).put("storageBound",storageUri()!=null);}
    synchronized void setCloudBackup(boolean enabled) throws Exception {database();config.put("cloudBackupEnabled",enabled);saveConfig();}
    private android.content.SharedPreferences storagePreferences(){return context.getSharedPreferences("storage-"+root.getName(),0);}
    private String storageUri(){return storagePreferences().getString("uri",null);}
    synchronized void bindStorage(android.net.Uri uri) throws Exception {database();if(!storagePreferences().edit().putString("uri",uri.toString()).commit())throw new IOException("LOCAL_SETTINGS_FAILED");}
    synchronized byte[] shard7File() throws Exception {database();return SovereignFiles.capsule(requireRemoteFragment());}
    synchronized void confirmShard7Saved() throws Exception {database();config.put("shard7Mode","external").put("cloudBackupEnabled",false).put("creationPending",false);saveConfig();}
    synchronized byte[] exportStorage() throws Exception {
        database().checkpoint();byte[] snapshot=SnapshotCodec.encode(database().file,file("attachments"),vmk,config.getString("hkdfSalt")),capsule=shard7File();
        try{return SovereignFiles.encode(snapshot,capsule,keys);}finally{Crypto.wipe(snapshot,capsule);}
    }
    synchronized void persistStorage() throws Exception {
        String uri=storageUri();if(uri==null)return;byte[] bytes=exportStorage();
        try{writeStorage(uri,bytes);}finally{Crypto.wipe(bytes);}
    }
    private void writeStorage(String uri,byte[] bytes) throws Exception {try(java.io.OutputStream output=context.getContentResolver().openOutputStream(android.net.Uri.parse(uri),"wt")){if(output==null)throw new IOException("STORAGE_FILE_UNAVAILABLE");output.write(bytes);output.flush();}}
    public synchronized String createExternal(String id,char[] password) throws Exception {
        if(exists())throw new IllegalStateException("vault_already_exists");credentials(id,password,true);
        File stage=stage("create");NativeVault staged=new NativeVault(context,stage,relay);Crypto.VaultKeys derived=Crypto.deriveVaultKeys(id,password);byte[] master=Crypto.random(32),capsule=null;
        try{
            String browser=staged.provision(master,derived,Crypto.b64(Crypto.random(16)));
            staged.config.put("shard7Mode","external").put("cloudBackupEnabled",false).put("creationPending",true);staged.saveConfig();capsule=staged.shard7File();
            staged.close();commit(stage,"create");initialize(true);open(id,password,browser,capsule);return browser;
        }finally{Crypto.wipe(master,capsule);staged.close();derived.close();if(stage.exists())cleanup(staged);}
    }
    public synchronized String importStorage(byte[] storage,String id,char[] password,byte[] capsule) throws Exception {
        if(!isLocked())throw new IOException("LOCK_BEFORE_STORAGE_SWITCH");credentials(id,password,false);
        Crypto.VaultKeys derived=Crypto.deriveVaultKeys(id,password);byte[] snapshot=null,seventh=null;File stage=stage("restore");NativeVault staged=new NativeVault(context,stage,relay);
        try{
            snapshot=SovereignFiles.decode(storage,capsule,derived);seventh=SovereignFiles.seventh(capsule,derived);
            try(SnapshotCodec.Snapshot decoded=SnapshotCodec.decode(snapshot,stage)){
                String browser=staged.provision(decoded.vmk,derived,decoded.salt,seventh);
                staged.config.put("shard7Mode","external").put("cloudBackupEnabled",false);
                Crypto.wipe(staged.remoteFragment7);staged.remoteFragment7=SovereignFiles.envelope(capsule,SovereignFiles.SHARD_HEADER,2048);
                staged.relocateAttachments(root);staged.saveConfig();staged.database().checkpoint();staged.close();
                commit(stage,"restore");initialize();open(id,password,browser,capsule);storagePreferences().edit().remove("uri").commit();return browser;
            }
        }finally{Crypto.wipe(snapshot,seventh);derived.close();staged.close();if(stage.exists())cleanup(staged);}
    }
    public synchronized String restore(String vaultId,char[] password) throws Exception {
        if(!isLocked())throw new IllegalStateException("LOCK_BEFORE_RESTORE");credentials(vaultId,password,false);
        File stage=stage("restore");NativeVault staged=new NativeVault(context,stage,relay);Crypto.VaultKeys derived=Crypto.deriveVaultKeys(vaultId,password);
        byte[] compressed=null;boolean uploaded=false;
        try{
            JSONObject remote=download(derived);if(remote==null)throw new IOException("BACKUP_NOT_FOUND_OR_INVALID_CREDENTIALS");
            compressed=Crypto.unseal(Crypto.unb64(remote.getString("ciphertext")),derived.backup,"vault-backup-v1",Crypto.unb64(remote.getString("nonce")));
            try(SnapshotCodec.Snapshot snapshot=SnapshotCodec.decode(compressed,stage)){
                String browser=staged.provision(snapshot.vmk,derived,snapshot.salt);
                staged.database().db().execSQL("DELETE FROM relay_auth");staged.database().db().execSQL("DELETE FROM vault_instance");
                staged.relocateAttachments(root);staged.config.put("backupVersion",remote.getLong("version")).put("shard7Mode","external").put("cloudBackupEnabled",false);
                staged.saveConfig();byte[] capsule=staged.shard7File();try{staged.close();commit(stage,"restore");initialize();open(vaultId,password,browser,capsule);return browser;}finally{Crypto.wipe(capsule);}
            }
        }finally{Crypto.wipe(compressed);staged.close();derived.close();if(stage.exists()&&!uploaded)cleanup(staged);}
    }
    private void relocateAttachments(File destination) throws Exception {
        try(Cursor rows=database().query("SELECT attachment_id FROM attachments WHERE encrypted_local_path IS NOT NULL")){
            while(rows.moveToNext()){String id=rows.getString(0);if(!id.matches("[a-f0-9]{32}"))throw new IOException("invalid_snapshot_path");
                if(!new File(root,"attachments/"+id).isFile())throw new IOException("BACKUP_ATTACHMENT_MISSING");
                database().db().execSQL("UPDATE attachments SET encrypted_local_path=? WHERE attachment_id=?",new Object[]{new File(destination,"attachments/"+id).getAbsolutePath(),id});
            }
        }
    }
    public synchronized String changePassword(String vaultId,char[] oldPassword,char[] nextPassword) throws Exception {
        database();credentials(vaultId,oldPassword,false);credentials(vaultId,nextPassword,true);
        Crypto.VaultKeys old=Crypto.deriveVaultKeys(vaultId,oldPassword),next=Crypto.deriveVaultKeys(vaultId,nextPassword);
        File stage=stage("rotate");NativeVault staged=new NativeVault(context,stage,relay);boolean uploaded=false,oldDeleted=false;
        try{
            if(!MessageDigest.isEqual(old.kek,keys.kek))throw new IOException("invalid_vault_password");
            if(MessageDigest.isEqual(old.lookup,next.lookup))throw new IOException("NEW_PASSWORD_MUST_DIFFER");
            if("external".equals(config.optString("shard7Mode"))||!cloudBackupEnabled()){
                database().checkpoint();NativeIo.copyTree(root,stage);String browser=staged.provision(vmk,next,config.getString("hkdfSalt"));
                staged.config.put("shard7Mode","external").put("cloudBackupEnabled",false);staged.relocateAttachments(root);staged.saveConfig();byte[] capsule=staged.shard7File();
                try{staged.close();close();commit(stage,"rotate");initialize();open(vaultId,nextPassword,browser,capsule);return browser;}finally{Crypto.wipe(capsule);}
            }
            if(download(next)!=null)throw new IOException("NEW_CREDENTIALS_ALREADY_IN_USE");syncBackup();database().checkpoint();
            NativeIo.copyTree(root,stage);String browser=staged.provision(vmk,next,config.getString("hkdfSalt"));staged.relocateAttachments(root);
            staged.config.put("cloudBackupEnabled",true);staged.syncBackup();uploaded=true;
            try{relay.deleteBackup(Crypto.hex(old.lookup),config.getLong("backupVersion"),old.writer);oldDeleted=true;}
            catch(Exception failure){
                try{relay.deleteBackup(Crypto.hex(next.lookup),staged.config.getLong("backupVersion"),next.writer);uploaded=false;}
                catch(Exception cleanup){throw new IOException("PASSWORD_UNCHANGED_NEW_BACKUP_RECOVERY_PRESERVED",failure);}
                throw failure;
            }
            staged.close();close();commit(stage,"rotate");initialize();open(vaultId,nextPassword,browser);return browser;
        }finally{staged.close();old.close();next.close();if(stage.exists()&&!uploaded&&!oldDeleted)cleanup(staged);}
    }
    private File stage(String operation) throws Exception {return NativeIo.child(root.getParentFile(),root.getName()+"."+operation+"-"+Crypto.hex(Crypto.random(8)));}
    private File journal() throws Exception {return NativeIo.child(root.getParentFile(),"."+root.getName()+".pending-commit.json");}
    private void commit(File stage,String operation) throws Exception {
        if(!stage.getName().matches(java.util.regex.Pattern.quote(root.getName())+"\\.(create|restore|rotate)-[a-f0-9]{16}"))throw new SecurityException("invalid_stage_path");
        String recovery=root.getName()+".before-"+operation+"-"+Crypto.hex(Crypto.random(8));
        NativeIo.atomic(journal(),new JSONObject().put("stage",stage.getName()).put("recovery",recovery));recoverCommit();
    }
    private void recoverCommit() throws Exception {
        File journal=journal();if(!journal.isFile())return;JSONObject state=NativeIo.json(journal,1024);
        String prefix=java.util.regex.Pattern.quote(root.getName()),stageName=state.getString("stage"),oldName=state.getString("recovery");
        if(!stageName.matches(prefix+"\\.(create|restore|rotate)-[a-f0-9]{16}")||!oldName.matches(prefix+"\\.before-(create|restore|rotate)-[a-f0-9]{16}"))throw new SecurityException("invalid_commit_journal");
        File stage=NativeIo.child(root.getParentFile(),stageName),old=NativeIo.child(root.getParentFile(),oldName);
        if(stage.isDirectory()){
            if(root.exists()){if(old.exists())throw new IOException("LOCAL_RECOVERY_CONFLICT");NativeIo.move(root,old);}
            NativeIo.move(stage,root);
        }else if(!root.exists()){
            if(!old.isDirectory())throw new IOException("LOCAL_VAULT_RECOVERY_REQUIRED");NativeIo.move(old,root);
        }
        if(!journal.delete())throw new IOException("commit_journal_cleanup_failed");
    }
    private void cleanup(NativeVault staged) throws Exception {
        staged.close();NativeIo.deleteTree(staged.root,context.getNoBackupFilesDir());if(staged.fragments!=null)staged.fragments.deleteDeviceKey();
    }
    @Override public synchronized void close(){if(database!=null){database.close();database=null;}if(fragments!=null)fragments.close();if(keys!=null){keys.close();keys=null;}Crypto.wipe(vmk,remoteFragment7);vmk=null;remoteFragment7=null;clientPresent=false;relayPresent=false;}
}
