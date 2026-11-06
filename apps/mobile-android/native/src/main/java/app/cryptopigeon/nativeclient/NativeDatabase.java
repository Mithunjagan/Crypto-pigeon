package app.cryptopigeon.nativeclient;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import java.io.File;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import net.zetetic.database.sqlcipher.SQLiteDatabase;

/** SQLCipher with the desktop raw-key format, stored in the app's no-backup area. */
public final class NativeDatabase implements AutoCloseable {
    static {System.loadLibrary("sqlcipher");}
    public final File file;
    private SQLiteDatabase database;
    public NativeDatabase(Context context,File file,byte[] sqlKey) throws Exception {
        if(sqlKey.length!=32)throw new IllegalArgumentException("invalid_database_key");
        this.file=file;
        File parent=file.getParentFile();if(!parent.isDirectory()&&!parent.mkdirs())throw new IOException("vault_directory_unavailable");
        byte[] rawKey=Crypto.utf8("x'"+Crypto.hex(sqlKey)+"'");
        try {
            database=SQLiteDatabase.openOrCreateDatabase(file,rawKey,null,null,null);
            try(Cursor cursor=database.rawQuery("SELECT count(*) FROM sqlite_master",new String[0])){cursor.moveToFirst();}
            database.setForeignKeyConstraintsEnabled(true);
            database.rawExecSQL("PRAGMA synchronous=FULL");
            database.enableWriteAheadLogging();
            String schema;
            try(InputStream input=context.getAssets().open("vault-schema.sql");ByteArrayOutputStream output=new ByteArrayOutputStream()){
                byte[] buffer=new byte[4096];int count;while((count=input.read(buffer))!=-1)output.write(buffer,0,count);
                schema=new String(output.toByteArray(),StandardCharsets.UTF_8);
            }
            for(String sql:schema.split(";"))if(!sql.trim().isEmpty())database.execSQL(sql);
            database.execSQL("CREATE TABLE IF NOT EXISTS signal_kyber_used(prekey_id INTEGER NOT NULL,signed_prekey_id INTEGER NOT NULL,base_key BLOB NOT NULL,PRIMARY KEY(prekey_id,signed_prekey_id,base_key))");
            database.execSQL("CREATE TABLE IF NOT EXISTS access_claim(singleton INTEGER PRIMARY KEY CHECK(singleton=1),request_id TEXT NOT NULL,username TEXT NOT NULL,token TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS consumer_profile(singleton INTEGER PRIMARY KEY CHECK(singleton=1),display_name TEXT NOT NULL,status_line TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS peer_profiles(contact_id TEXT PRIMARY KEY,display_name TEXT NOT NULL,status_line TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS message_links(message_id TEXT PRIMARY KEY REFERENCES messages(message_id) ON DELETE CASCADE,remote_id TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS control_outbox(envelope_id TEXT PRIMARY KEY,contact_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,ciphertext TEXT NOT NULL,created_at INTEGER NOT NULL)");
            boolean hasExpiry=false;
            try(Cursor columns=database.rawQuery("PRAGMA table_info(control_outbox)",new String[0])){while(columns.moveToNext())if("expires_at".equals(columns.getString(1)))hasExpiry=true;}
            if(!hasExpiry)database.execSQL("ALTER TABLE control_outbox ADD COLUMN expires_at INTEGER");
            database.execSQL("CREATE TABLE IF NOT EXISTS session_pin(singleton INTEGER PRIMARY KEY CHECK(singleton=1),salt BLOB NOT NULL,digest BLOB NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS signal_sender_keys(sender TEXT NOT NULL,distribution_id TEXT NOT NULL,record BLOB NOT NULL,PRIMARY KEY(sender,distribution_id))");
            database.execSQL("CREATE TABLE IF NOT EXISTS outbox_envelopes(envelope_id TEXT PRIMARY KEY,recipient_uid TEXT NOT NULL,envelope_type TEXT NOT NULL,serialized_encrypted_payload BLOB NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS processed_envelope_ids(envelope_id TEXT PRIMARY KEY,received_at INTEGER NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS contact_routing(contact_id TEXT PRIMARY KEY,receive_secret BLOB NOT NULL,send_secret BLOB)");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),private_key TEXT NOT NULL,onion TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS peer_onions(device_id TEXT PRIMARY KEY,contact_id TEXT NOT NULL,onion TEXT NOT NULL,auth_key TEXT NOT NULL,invite TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_inbox(envelope_id TEXT PRIMARY KEY,envelope TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_attachment_links(attachment_id TEXT PRIMARY KEY,blob_id TEXT NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_blobs(blob_id TEXT PRIMARY KEY,chunk_count INTEGER NOT NULL,total_size INTEGER NOT NULL,created_at INTEGER NOT NULL)");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_chunks(blob_id TEXT NOT NULL REFERENCES tor_blobs(blob_id) ON DELETE CASCADE,chunk_index INTEGER NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(blob_id,chunk_index))");
            database.execSQL("CREATE TABLE IF NOT EXISTS tor_download_chunks(blob_id TEXT NOT NULL,chunk_index INTEGER NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(blob_id,chunk_index))");
            database.execSQL("INSERT OR IGNORE INTO processed_envelope_ids SELECT replace(envelope_id,'-',''),received_at FROM seen_envelope_ids");
            database.execSQL("DELETE FROM processed_envelope_ids WHERE received_at < ?",new Object[]{System.currentTimeMillis()-30L*86400000});
        }catch(Exception error){close();throw error;}finally{Crypto.wipe(rawKey);}
    }
    public SQLiteDatabase db(){if(database==null)throw new IllegalStateException("vault_locked");return database;}
    public Cursor query(String sql,String... parameters){return db().rawQuery(sql,parameters);}
    public byte[] blob(String sql,String... parameters){try(Cursor cursor=query(sql,parameters)){return cursor.moveToFirst()?cursor.getBlob(0):null;}}
    public String text(String sql,String... parameters){try(Cursor cursor=query(sql,parameters)){return cursor.moveToFirst()?cursor.getString(0):null;}}
    public boolean exists(String sql,String... parameters){try(Cursor cursor=query(sql,parameters)){return cursor.moveToFirst();}}
    public long insert(String table,ContentValues values){return db().insertOrThrow(table,null,values);}
    public void checkpoint(){try(Cursor cursor=query("PRAGMA wal_checkpoint(TRUNCATE)")){cursor.moveToFirst();}}
    @Override public void close(){if(database!=null){database.close();database=null;}}
}
