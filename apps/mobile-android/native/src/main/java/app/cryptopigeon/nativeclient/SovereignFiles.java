package app.cryptopigeon.nativeclient;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.json.JSONObject;

/** Versioned, authenticated files. Neither file contains the other file's key. */
final class SovereignFiles {
    static final String SHARD_HEADER="CPSHR701\n",STORAGE_HEADER="CPVAULT1\n";
    static final int MAX_STORAGE=64*1024*1024;
    static byte[] capsule(byte[] sealed){return Crypto.concat(Crypto.utf8(SHARD_HEADER),sealed);}
    static byte[] envelope(byte[] file,String header,int maximum) throws Exception {
        byte[] prefix=Crypto.utf8(header);
        if(file==null||file.length<=prefix.length||file.length>maximum||!MessageDigest.isEqual(prefix,Arrays.copyOf(file,prefix.length)))throw new IOException("INVALID_SOVEREIGN_FILE");
        return Arrays.copyOfRange(file,prefix.length,file.length);
    }
    static byte[] seventh(byte[] capsule,Crypto.VaultKeys keys) throws Exception {
        byte[] json=envelope(capsule,SHARD_HEADER,2048);
        try{Crypto.Sealed sealed=sealed(json);byte[] share=Crypto.unseal(sealed.ciphertext,keys.backup,"cp-shard7-v1",sealed.nonce);if(share.length!=48){Crypto.wipe(share);throw new IOException("INVALID_SHARD7_FILE");}return share;}finally{Crypto.wipe(json);}
    }
    private static Crypto.Sealed sealed(byte[] json) throws Exception {JSONObject value=new JSONObject(new String(json,java.nio.charset.StandardCharsets.UTF_8));Crypto.Sealed sealed=NativeIo.sealed(value);if(sealed.nonce.length!=12||sealed.ciphertext.length<16||!Crypto.b64(sealed.nonce).equals(value.getString("nonce"))||!Crypto.b64(sealed.ciphertext).equals(value.getString("ciphertext")))throw new IOException("INVALID_SOVEREIGN_FILE");return sealed;}
    static byte[] storageKey(byte[] capsule,Crypto.VaultKeys keys) throws Exception {
        byte[] share=seventh(capsule,keys);try{return Crypto.hkdf(keys.backup,Crypto.sha256(share),"cp-app-storage-v1");}finally{Crypto.wipe(share);}
    }
    static byte[] encode(byte[] snapshot,byte[] capsule,Crypto.VaultKeys keys) throws Exception {
        byte[] key=storageKey(capsule,keys);try{Crypto.Sealed sealed=Crypto.seal(snapshot,key,"cp-app-storage-v1");try{return Crypto.concat(Crypto.utf8(STORAGE_HEADER),Crypto.utf8(NativeIo.sealed(sealed).toString()));}finally{Crypto.wipe(sealed.ciphertext);}}finally{Crypto.wipe(key);}
    }
    static byte[] decode(byte[] storage,byte[] capsule,Crypto.VaultKeys keys) throws Exception {
        byte[] json=envelope(storage,STORAGE_HEADER,MAX_STORAGE),key=storageKey(capsule,keys);
        try{Crypto.Sealed sealed=sealed(json);return Crypto.unseal(sealed.ciphertext,key,"cp-app-storage-v1",sealed.nonce);}finally{Crypto.wipe(json,key);}
    }
}
