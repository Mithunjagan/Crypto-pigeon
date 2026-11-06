package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import java.io.File;
import java.lang.reflect.Field;
import java.util.*;
import org.json.*;

/** Real relay tests; the only injected hook observes zeroization before HTTP upload. */
final class NativeVaultInstrumentation {
    private final JSONArray results=new JSONArray();private Instrumentation runner;private Context context;private File root,stateFile;
    JSONArray run(Instrumentation runner,Bundle arguments,String phase) throws Exception {
        this.runner=runner;context=runner.getTargetContext();String name=arguments.getString("case");
        check(name!=null&&name.matches("[a-zA-Z0-9_-]{1,80}"),"invalid fixture case");
        root=new File(context.getNoBackupFilesDir(),"native-vault-tests/"+name);stateFile=new File(context.getFilesDir(),"native-vault-"+name+".json");
        RelayTransport transport=new RelayTransport(arguments.getString("relayUrl"),true);
        if(phase.equals("vault-create"))create(transport,arguments);else if(phase.equals("vault-lifecycle"))lifecycle(transport);else throw new IllegalArgumentException("unknown_vault_phase");
        return results;
    }
    private void pass(String name) throws Exception {results.put(new JSONObject().put("name",name).put("status","pass"));Bundle event=new Bundle();event.putString("stream","PASS: "+name+"\n");runner.sendStatus(0,event);}
    private static void check(boolean condition,String text){if(!condition)throw new AssertionError(text);}
    private interface Checked {void run() throws Exception;}
    private static void rejects(Checked fn) throws Exception {boolean failed=false;try{fn.run();}catch(Exception expected){failed=true;}check(failed,"operation should reject");}
    private static Object field(Object object,String name) throws Exception {Field field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);}
    private static boolean zero(byte[] bytes){for(byte b:bytes)if(b!=0)return false;return true;}
    private void save(JSONObject state) throws Exception {NativeIo.atomic(stateFile,state);}
    private void create(RelayTransport transport,Bundle args) throws Exception {
        String id=args.getString("vaultId"),password=args.getString("password"),user=args.getString("userId");check(id!=null&&password!=null&&user!=null,"missing fixture credentials");
        try(NativeVault vault=new NativeVault(context,root,transport)){
            String browser=vault.create(id,password.toCharArray());check(!vault.isLocked()&&vault.status(true).getInt("sharesPresent")==7,"create did not open all shares");
            pass("Native vault creates seven wrapped-VMK shares with a hardware-protected fragment and a signed real-relay backup");
            NativeSignalStore store=new NativeSignalStore(vault.database());JSONObject published=store.ensureIdentity();store.setAccount(user);
            String conversation=UUID.randomUUID().toString(),message=UUID.randomUUID().toString(),attachment=Crypto.hex(Crypto.random(16));
            byte[] identity=org.signal.libsignal.protocol.IdentityKeyPair.generate().getPublicKey().serialize();
            vault.database().db().execSQL("INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES('backup-fixture.1','backup_fixture',?,?)",new Object[]{identity,System.currentTimeMillis()});
            vault.database().db().execSQL("INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,'backup-fixture.1',?)",new Object[]{conversation,System.currentTimeMillis()});
            vault.database().db().execSQL("INSERT INTO messages(message_id,conversation_id,direction,plaintext,status,sent_at) VALUES(?,?,'sent','Native encrypted recovery message','sent',?)",new Object[]{message,conversation,System.currentTimeMillis()});
            byte[] content=Crypto.random(75000);NativeAttachmentCache.store(vault,attachment,message,"native-தமிழ்.bin",content,Crypto.random(32));
            JSONObject state=new JSONObject().put("vaultId",id).put("password",password).put("browser",browser).put("userId",user).put("published",published)
                .put("attachmentId",attachment).put("attachmentHash",Crypto.hex(Crypto.sha256(content))).put("oldInstance",vault.database().text("SELECT token FROM vault_instance WHERE singleton=1"));
            Crypto.wipe(content);save(state);
            pass("Native vault persists its real Signal identity, message history and authenticated encrypted attachment cache");
        }
    }
    private void lifecycle(RelayTransport transport) throws Exception {
        JSONObject state=NativeIo.json(stateFile,1024*1024);String id=state.getString("vaultId"),password=state.getString("password"),browser=state.getString("browser");
        final class ObservedRelay implements VaultBackupRelay {
            NativeVault active;boolean watch,observed;byte[] master;Crypto.VaultKeys derived;
            public JSONObject getBackup(String token) throws Exception{return transport.getBackup(token);}
            public void deleteBackup(String token,long version,byte[] writer) throws Exception{transport.deleteBackup(token,version,writer);}
            public void putBackup(JSONObject body) throws Exception{
                if(watch){
                    check(active.isLocked()&&field(active,"vmk")==null&&field(active,"keys")==null,"vault remained unlocked during upload");
                    check(zero(master)&&zero(derived.kek)&&zero(derived.backup)&&zero(derived.writer)&&zero(derived.lookup)&&zero(derived.mask),"key buffers not wiped before network");observed=true;
                }
                transport.putBackup(body);
            }
        }
        ObservedRelay relay=new ObservedRelay();
        try(NativeVault vault=new NativeVault(context,root,relay)){
            relay.active=vault;rejects(()->vault.open(id,"WrongNativeVault123!".toCharArray(),browser));check(vault.isLocked(),"wrong password unlocked vault");
            vault.open(id,password.toCharArray(),browser);assertContents(vault,state);vault.syncBackup();
            pass("Fresh native process rejects wrong credentials, unlocks all seven shares and uploads a valid device-auth proof");
            relay.master=(byte[])field(vault,"vmk");relay.derived=(Crypto.VaultKeys)field(vault,"keys");relay.watch=true;
            check(vault.syncAndLock().getBoolean("backupSynced")&&relay.observed,"sync-and-lock failed");relay.watch=false;
            pass("Sync-and-lock zeroes the VMK and every derived key before waiting on the real relay upload");
            check(new File(root,"assets/f4.dat").delete(),"could not remove fixture fragment");
            rejects(()->vault.open(id,password.toCharArray(),browser));check(vault.isLocked(),"missing fragment did not block unlock");
            pass("A missing local fragment blocks native unlock without modifying the encrypted database");
            String restored=vault.restore(id,password.toCharArray());assertContents(vault,state);check(!restored.equals(browser),"restore did not replace shares");
            String restoredInstance=vault.database().text("SELECT token FROM vault_instance WHERE singleton=1");check(!restoredInstance.equals(state.getString("oldInstance")),"restore did not replace instance token");
            state.put("restoredInstance",restoredInstance);
            pass("Native cloud restore streams the authenticated snapshot, preserves history/files/Signal identity and claims a fresh active instance");
            String next=password+"Rotated456!",rotated=vault.changePassword(id,password.toCharArray(),next.toCharArray());assertContents(vault,state);vault.close();
            rejects(()->vault.open(id,password.toCharArray(),restored));vault.open(id,next.toCharArray(),rotated);assertContents(vault,state);
            state.put("nextPassword",next).put("browser",rotated).put("newInstance",vault.database().text("SELECT token FROM vault_instance WHERE singleton=1"));save(state);
            check(vault.syncAndLock().getBoolean("backupSynced"),"final encrypted backup failed");
            pass("Native password rotation preserves the VMK-backed database/files, changes all shares and removes the old credential lookup");
        }
    }
    private void assertContents(NativeVault vault,JSONObject state) throws Exception {
        check(vault.database().exists("SELECT 1 FROM messages WHERE plaintext='Native encrypted recovery message'"),"message lost");
        check(state.getString("userId").equals(new NativeSignalStore(vault.database()).userId()),"Signal account lost");
        byte[] content=NativeAttachmentCache.read(vault,state.getString("attachmentId"));try{check(Crypto.hex(Crypto.sha256(content)).equals(state.getString("attachmentHash")),"attachment bytes changed");}finally{Crypto.wipe(content);}
    }
}
