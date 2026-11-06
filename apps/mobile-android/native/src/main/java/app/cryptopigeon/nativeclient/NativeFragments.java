package app.cryptopigeon.nativeclient;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import java.io.File;
import java.security.MessageDigest;
import org.json.JSONArray;
import org.json.JSONObject;

/** Seven shares protect the authenticated wrapped VMK; the VMK itself is never split. */
final class NativeFragments implements AutoCloseable {
    static {System.loadLibrary("sqlcipher");}
    private final File root;private final DeviceKeyStore device;private final String alias;private byte[] session;private final android.content.SharedPreferences preferences;
    NativeFragments(android.content.Context context,File root,String alias){this.root=root;this.alias=alias;this.device=new DeviceKeyStore(alias);preferences=context.getSharedPreferences("fragment-"+alias,0);}
    private File file(String relative) throws Exception {return NativeIo.child(root,relative);}
    private SQLiteDatabase metadata(boolean create) throws Exception {
        File path=file("shards/metadata.db");if(!create&&!path.isFile())throw new IllegalStateException("fragment_missing");NativeIo.directory(path.getParentFile());
        SQLiteDatabase database=SQLiteDatabase.openOrCreateDatabase(path,null);database.execSQL("CREATE TABLE IF NOT EXISTS vault_horcrux_shard(id INTEGER PRIMARY KEY CHECK(id=2),shard BLOB NOT NULL)");return database;
    }
    private net.zetetic.database.sqlcipher.SQLiteDatabase encryptedMetadata(Crypto.VaultKeys keys) throws Exception {
        File path=file("shards/metadata.db");NativeIo.directory(path.getParentFile());byte[] key=Crypto.hkdf(keys.backup,new byte[32],"cp-shard2-db-v1"),encoded=Crypto.utf8("x'"+Crypto.hex(key)+"'");
        try{net.zetetic.database.sqlcipher.SQLiteDatabase db=net.zetetic.database.sqlcipher.SQLiteDatabase.openOrCreateDatabase(path,encoded,null,null,null);try{db.execSQL("CREATE TABLE IF NOT EXISTS vault_horcrux_shard(id INTEGER PRIMARY KEY CHECK(id=2),shard BLOB NOT NULL)");return db;}catch(Exception failure){db.close();throw failure;}}finally{Crypto.wipe(key,encoded);}
    }
    private byte[] readMetadata(Crypto.VaultKeys keys) throws Exception {
        File path=file("shards/metadata.db");if(!path.isFile())throw new IllegalStateException("fragment_missing");byte[] header=new byte[16];
        try(java.io.InputStream input=new java.io.FileInputStream(path)){if(input.read(header)!=16)throw new IllegalStateException("fragment_invalid");}
        if(MessageDigest.isEqual(header,Crypto.utf8("SQLite format 3\0"))){try(SQLiteDatabase db=metadata(false);Cursor cursor=db.rawQuery("SELECT shard FROM vault_horcrux_shard WHERE id=2",null)){return cursor.moveToFirst()?cursor.getBlob(0):null;}}
        try(net.zetetic.database.sqlcipher.SQLiteDatabase db=encryptedMetadata(keys);Cursor cursor=db.rawQuery("SELECT shard FROM vault_horcrux_shard WHERE id=2",new String[0])){return cursor.moveToFirst()?cursor.getBlob(0):null;}
    }
    JSONObject scatter(byte[] wrapped,Crypto.VaultKeys keys) throws Exception {
        return scatter(wrapped,keys,null);
    }
    JSONObject scatter(byte[] wrapped,Crypto.VaultKeys keys,byte[] externalSeventh) throws Exception {
        byte[][] shares=SevenShares.split(wrapped);
        try{
            if(externalSeventh!=null){if(externalSeventh.length!=48)throw new IllegalArgumentException("INVALID_SHARD7_FILE");for(int j=0;j<48;j++)shares[5][j]^=shares[6][j]^externalSeventh[j];Crypto.wipe(shares[6]);shares[6]=externalSeventh.clone();}
            NativeIo.atomic(file("shards/f1.json"),NativeIo.sealed(device.wrap(shares[0],"cp-shard1-native-v1:"+alias)));
            for(String suffix:new String[]{"","-wal","-shm","-journal"}){File old=file("shards/metadata.db"+suffix);if(old.exists()&&!old.delete())throw new java.io.IOException("fragment_rotation_failed");}
            try(net.zetetic.database.sqlcipher.SQLiteDatabase db=encryptedMetadata(keys)){db.execSQL("INSERT OR REPLACE INTO vault_horcrux_shard(id,shard) VALUES(2,?)",new Object[]{shares[1]});}
            if(!preferences.edit().putString("shard3",NativeIo.sealed(Crypto.seal(shares[2],keys.backup,"cp-shard3-v1")).toString()).commit())throw new java.io.IOException("LOCAL_SETTINGS_FAILED");
            File oldPreferences=file("config/f3.json");if(oldPreferences.exists()&&!oldPreferences.delete())throw new java.io.IOException("fragment_rotation_failed");
            NativeIo.atomic(file("assets/f4.dat"),shares[3]);
            NativeIo.atomic(file("shards/f6.masked"),NativeIo.sealed(Crypto.seal(shares[5],keys.mask,"cp-shard6-v1")));
            close();session=shares[5].clone();JSONArray hashes=new JSONArray();for(byte[] share:shares)hashes.put(Crypto.hex(Crypto.sha256(share)));
            return new JSONObject().put("clientShard",Crypto.b64(shares[4])).put("hashes",hashes)
                .put("fragment7Shard",NativeIo.sealed(Crypto.seal(shares[6],keys.backup,"cp-shard7-v1")).toString());
        }finally{Crypto.wipe(shares);}
    }
    byte[] collect(String client,String relay,Crypto.VaultKeys keys,JSONArray hashes) throws Exception {
        byte[][] shares=new byte[7][];
        try{
            shares[0]=device.unwrap(NativeIo.sealed(NativeIo.json(file("shards/f1.json"),2048)),"cp-shard1-native-v1:"+alias);
            shares[1]=readMetadata(keys);
            String saved=preferences.getString("shard3",null);Crypto.Sealed preferenceShard=NativeIo.sealed(saved==null?NativeIo.json(file("config/f3.json"),2048):new JSONObject(saved));shares[2]=Crypto.unseal(preferenceShard.ciphertext,keys.backup,"cp-shard3-v1",preferenceShard.nonce);
            shares[3]=NativeIo.read(file("assets/f4.dat"),48);
            if(client==null||client.length()!=64)throw new IllegalStateException("fragment_missing");shares[4]=Crypto.unb64(client);
            Crypto.Sealed masked=NativeIo.sealed(NativeIo.json(file("shards/f6.masked"),2048));shares[5]=Crypto.unseal(masked.ciphertext,keys.mask,"cp-shard6-v1",masked.nonce);
            Crypto.Sealed remote=NativeIo.sealed(new JSONObject(relay));shares[6]=Crypto.unseal(remote.ciphertext,keys.backup,"cp-shard7-v1",remote.nonce);
            if(hashes.length()!=7)throw new IllegalStateException("fragment_hashes_missing");
            byte[][] expected=new byte[7][];for(int i=0;i<7;i++)expected[i]=Crypto.unhex(hashes.getString(i));
            byte[] result=SevenShares.collect(shares,expected);
            close();session=shares[5].clone();return result;
        }catch(Exception invalid){close();throw new IllegalStateException("HORCRUX_INCOMPLETE_RESTORE_REQUIRED",invalid);}
        finally{Crypto.wipe(shares);}
    }
    JSONObject status(boolean client,boolean relay,boolean configured) throws Exception {
        String[] names={"Hardware shard","SQLite shard","Preferences shard","Binary shard","WebView shard","RAM session shard","Relay shard"};
        boolean[] present={file("shards/f1.json").isFile(),file("shards/metadata.db").isFile(),preferences.contains("shard3")||file("config/f3.json").isFile(),file("assets/f4.dat").isFile(),client,session!=null,relay};
        JSONObject locations=new JSONObject();int count=0;for(int i=0;i<7;i++){boolean found=configured&&present[i];locations.put(names[i],found);if(found)count++;}
        boolean hardware=false;try{hardware=present[0]&&device.hardwareBacked();}catch(Exception missing){}
        return new JSONObject().put("totalShares",7).put("sharesPresent",count).put("locations",locations).put("isReconstructable",count==7).put("hardwareBacked",hardware);
    }
    @Override public void close(){Crypto.wipe(session);session=null;}
    void deleteDeviceKey() throws Exception {device.delete();preferences.edit().clear().commit();}
}
