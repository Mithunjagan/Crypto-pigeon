package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import java.io.File;
import java.lang.reflect.Field;
import java.util.*;
import org.json.*;

/** Focused offline tests; isolated roots, no relay and no real account writes. */
final class ExternalStorageInstrumentation {
    private static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
    private static Object field(Object object,String name) throws Exception {Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private static boolean zero(byte[] bytes){for(byte value:bytes)if(value!=0)return false;return true;}
    private static void rejects(Checked action) throws Exception {boolean failed=false;try{action.run();}catch(Exception expected){failed=true;}check(failed,"Invalid file or credentials accepted");}
    interface Checked{void run() throws Exception;}
    JSONArray run(Instrumentation runner) throws Exception {
        // Vivo freezes background processes even during instrumentation. Keep the
        // locked activity foreground; all vault operations still use fixture roots.
        runner.startActivitySync(new android.content.Intent(runner.getTargetContext(),MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
        Context context=runner.getTargetContext();String suffix=UUID.randomUUID().toString();File root=new File(context.getNoBackupFilesDir(),"external-fixture-"+suffix),target=new File(context.getNoBackupFilesDir(),"external-import-"+suffix);
        final int[] reads={0},uploads={0};VaultBackupRelay relay=new VaultBackupRelay(){public JSONObject getBackup(String token){reads[0]++;throw new AssertionError("Unexpected relay read");}public void putBackup(JSONObject body){uploads[0]++;}public void deleteBackup(String token,long version,byte[] writer){throw new AssertionError("Unexpected relay delete");}};
        JSONArray results=new JSONArray();byte[] capsule=null,storage=null;android.net.Uri document=null;
        NativeVault vault=new NativeVault(context,root,relay),imported=new NativeVault(context,target,relay);
        String id="ExternalFixture-"+suffix,password="FixturePassphrase-Aa12345!",contact=UUID.randomUUID().toString(),conversation=UUID.randomUUID().toString(),message=UUID.randomUUID().toString();
        try{
            String browser=vault.createExternal(id,password.toCharArray());capsule=vault.shard7File();vault.confirmShard7Saved();final byte[] savedCapsule=capsule;
            check(!vault.cloudBackupEnabled(),"Cloud enabled by default");check(reads[0]==0&&uploads[0]==0,"Creation contacted relay");
            NativeSignalStore store=new NativeSignalStore(vault.database());store.ensureIdentity();String user=UUID.randomUUID().toString();store.setAccount(user);
            vault.database().db().execSQL("INSERT INTO account_public(singleton,public_uid) VALUES(1,'CP-ABCD-1234')");
            vault.database().db().execSQL("INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES(?,?,?,?)",new Object[]{contact,"fixture_contact",Crypto.random(33),System.currentTimeMillis()});
            vault.database().db().execSQL("INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)",new Object[]{conversation,contact,System.currentTimeMillis()});
            vault.database().db().execSQL("INSERT INTO messages(message_id,conversation_id,direction,plaintext,received_at,status) VALUES(?,?,'received','preserve this message',?,'received')",new Object[]{message,conversation,System.currentTimeMillis()});
            vault.database().db().execSQL("INSERT INTO signal_sessions(contact_id,ratchet_state,updated_at) VALUES(?,?,?)",new Object[]{contact,Crypto.utf8("fixture-ratchet-bytes"),System.currentTimeMillis()});
            NativeIo.atomic(new File(root,"attachments/0123456789abcdef0123456789abcdef"),Crypto.utf8("encrypted-fixture-file"));
            storage=vault.exportStorage();check(!new String(storage,java.nio.charset.StandardCharsets.UTF_8).contains("preserve this message"),"Plaintext in export");
            results.put(pass("Offline creation returns authenticated external Shard 7 and cloud backup defaults OFF"));
            android.content.ContentValues details=new android.content.ContentValues();details.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME,"cp-storage-fixture-"+suffix+".cpvault");details.put(android.provider.MediaStore.MediaColumns.MIME_TYPE,"application/octet-stream");details.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH,"Download/CryptoPigeon-test-fixtures");
            document=context.getContentResolver().insert(android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,details);check(document!=null,"Could not create fixture document");vault.bindStorage(document);vault.persistStorage();
            vault.database().db().execSQL("INSERT INTO consumer_profile VALUES(1,'saved on lock','fixture')");
            byte[] master=(byte[])field(vault,"vmk"),seventh=(byte[])field(vault,"remoteFragment7"),sixth=(byte[])field(field(vault,"fragments"),"session");vault.syncAndLock();
            Crypto.wipe(storage);storage=NativeIo.read(context.getContentResolver().openInputStream(document),SovereignFiles.MAX_STORAGE);
            check(zero(master)&&zero(seventh)&&zero(sixth),"RAM key or fragment survived lock");
            rejects(()->vault.open(id,password.toCharArray(),browser));
            rejects(()->vault.open(id,(password+"wrong").toCharArray(),browser,savedCapsule));
            vault.open(id,password.toCharArray(),browser,capsule);check(vault.status(true).getInt("sharesPresent")==7,"Quorum incomplete");
            check("preserve this message".equals(vault.database().text("SELECT plaintext FROM messages WHERE message_id=?",message)),"History changed on unlock");
            results.put(pass("Cold unlock needs the correct file and credentials; lock zeroes VMK and Shards 6/7"));
            String importedBrowser=imported.importStorage(storage,id,password.toCharArray(),capsule);
            check(user.equals(new NativeSignalStore(imported.database()).userId()),"Account identity changed");
            check("CP-ABCD-1234".equals(imported.database().text("SELECT public_uid FROM account_public WHERE singleton=1")),"Public UID changed");
            check("fixture_contact".equals(imported.database().text("SELECT username FROM contacts WHERE contact_id=?",contact)),"Contact changed");
            check("preserve this message".equals(imported.database().text("SELECT plaintext FROM messages WHERE message_id=?",message)),"Messages changed");
            check("saved on lock".equals(imported.database().text("SELECT display_name FROM consumer_profile WHERE singleton=1")),"Bound external document missed final changes at lock");
            check(Arrays.equals(Crypto.utf8("fixture-ratchet-bytes"),imported.database().blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",contact)),"Ratchet changed");
            check(new File(target,"attachments/0123456789abcdef0123456789abcdef").isFile(),"Encrypted attachment missing");
            imported.close();imported.open(id,password.toCharArray(),importedBrowser,capsule);
            results.put(pass("Offline storage import preserves account, UID, contacts, messages, ratchet bytes and attachments; original segment file reopens it"));
            results.put(pass("Real external document export and lock-time update preserve the latest encrypted profile data"));
            imported.close();final byte[] damaged=storage.clone();damaged[damaged.length-3]^=1;
            rejects(()->imported.importStorage(damaged,id,password.toCharArray(),savedCapsule));
            imported.open(id,password.toCharArray(),importedBrowser,capsule);check("1".equals(imported.database().text("SELECT count(*) FROM messages")),"Failed import damaged active storage");
            check(imported.syncBackup().optBoolean("skipped"),"Disabled backup not skipped");check(reads[0]==0&&uploads[0]==0,"Offline operation contacted relay");
            results.put(pass("Tampered import preserves active vault and OFF blocks all backup uploads"));
            imported.setCloudBackup(true);imported.syncBackup();check(uploads[0]==1,"Opt-in backup did not upload exactly once");imported.setCloudBackup(false);imported.syncBackup();check(uploads[0]==1,"OFF still uploaded");
            results.put(pass("Cloud backup uploads only after explicit opt-in and stops when disabled"));
        }finally{vault.close();imported.close();Crypto.wipe(capsule,storage);if(document!=null)context.getContentResolver().delete(document,null,null);for(File folder:new File[]{root,target})if(folder.exists())NativeIo.deleteTree(folder,context.getNoBackupFilesDir());}
        return results;
    }
    private static JSONObject pass(String name) throws Exception{return new JSONObject().put("status","pass").put("name",name);}
}
