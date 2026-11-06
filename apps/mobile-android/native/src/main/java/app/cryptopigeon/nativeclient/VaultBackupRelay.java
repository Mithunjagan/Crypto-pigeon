package app.cryptopigeon.nativeclient;

import org.json.JSONObject;

public interface VaultBackupRelay {
    JSONObject getBackup(String token) throws Exception;
    void putBackup(JSONObject body) throws Exception;
    void deleteBackup(String token,long version,byte[] writer) throws Exception;
}
