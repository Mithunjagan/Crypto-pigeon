package app.cryptopigeon.nativeclient;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;

/** Private routing metadata only. Authentication remains NativeVault.open().
 * Existing single-vault files stay at their original path. */
final class NativeVaultCatalog {
    static final String LEGACY="legacy";
    private final File legacy,managed,file;
    private JSONObject state;
    NativeVaultCatalog(Context context,File legacy) throws Exception {
        this.legacy=legacy.getCanonicalFile();
        String allowed=context.getNoBackupFilesDir().getCanonicalPath()+File.separator;
        if(!this.legacy.getPath().startsWith(allowed))throw new SecurityException("invalid_vault_root");
        managed=NativeIo.child(this.legacy.getParentFile(),this.legacy.getName()+".vaults");
        file=NativeIo.child(this.legacy.getParentFile(),this.legacy.getName()+".vaults.json");
        state=file.isFile()?NativeIo.json(file,128*1024):new JSONObject().put("version",1)
            .put("selectorKey",Crypto.b64(Crypto.random(32))).put("entries",new JSONObject()).put("active",LEGACY);
        if(state.getInt("version")!=1||Crypto.unb64(state.getString("selectorKey")).length!=32)throw new IOException("INVALID_VAULT_CATALOG");
        JSONObject entries=state.getJSONObject("entries");
        for(Iterator<String> it=entries.keys();it.hasNext();){String key=it.next();if(!key.matches("[a-f0-9]{64}"))throw new IOException("INVALID_VAULT_CATALOG");JSONArray handles=entries.getJSONArray(key);for(int i=0;i<handles.length();i++)root(handles.getString(i));}
        root(active());
    }
    String active(){return state.optString("active",LEGACY);}
    File root(String handle) throws Exception {
        if(LEGACY.equals(handle))return legacy;
        if(!handle.matches("[a-f0-9]{32}"))throw new IOException("INVALID_VAULT_CATALOG");
        return NativeIo.child(managed,handle);
    }
    private String tag(String id) throws Exception {
        if(id==null||id.length()<8||id.length()>256)throw new IllegalArgumentException("INVALID_VAULT_CREDENTIALS");
        byte[] key=Crypto.unb64(state.getString("selectorKey"));
        try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));return Crypto.hex(mac.doFinal(Crypto.utf8("cp-local-vault-id-v1:"+id)));}finally{Crypto.wipe(key);}
    }
    boolean known(String id) throws Exception {return state.getJSONObject("entries").has(tag(id));}
    List<String> candidates(String id) throws Exception {
        List<String> result=new ArrayList<>();JSONObject entries=state.getJSONObject("entries");
        JSONArray selected=entries.optJSONArray(tag(id));
        if(selected!=null)for(int i=selected.length()-1;i>=0;i--)result.add(selected.getString(i));
        // The old vault's private ID is unknown until its first successful unlock.
        boolean legacyIndexed=false;
        for(Iterator<String> it=entries.keys();it.hasNext();){JSONArray values=entries.getJSONArray(it.next());for(int i=0;i<values.length();i++)if(LEGACY.equals(values.getString(i)))legacyIndexed=true;}
        if(!legacyIndexed&&!result.contains(LEGACY))result.add(LEGACY);
        return result;
    }
    String allocate() throws Exception {
        if(!new File(legacy,"config.json").isFile()&&state.getJSONObject("entries").length()==0)return LEGACY;
        return Crypto.hex(Crypto.random(16));
    }
    void select(String id,String handle) throws Exception {
        root(handle);String key=tag(id);JSONObject next=new JSONObject(state.toString()),entries=next.getJSONObject("entries");
        JSONArray handles=entries.optJSONArray(key);if(handles==null)handles=new JSONArray();
        boolean found=false;for(int i=0;i<handles.length();i++)if(handle.equals(handles.getString(i)))found=true;
        if(!found)handles.put(handle);entries.put(key,handles);next.put("active",handle);
        NativeIo.atomic(file,next);state=next;
    }
    void verifyId(String id,String handle) throws Exception {
        for(String candidate:candidates(id))if(candidate.equals(handle))return;
        throw new IllegalArgumentException("INVALID_VAULT_CREDENTIALS");
    }
}
