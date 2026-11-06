package app.cryptopigeon.nativeclient;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

/** Desktop-compatible authenticated attachment cache; filenames stay in SQLCipher. */
public final class NativeAttachmentCache {
    private NativeAttachmentCache(){}
    private static final byte[] MAGIC=Crypto.utf8("CPAGCM1:");
    public static void store(NativeVault vault,String id,String messageId,String filename,byte[] bytes,byte[] remoteKey) throws Exception {
        if(bytes.length>25*1024*1024||remoteKey.length!=32)throw new IllegalArgumentException("invalid_attachment");
        byte[] key=vault.attachmentKey(),filenameIv=Crypto.random(16);
        try{
            Crypto.Sealed sealed=Crypto.seal(bytes,key,"cp-local-attachment-v1:"+id);int length=sealed.ciphertext.length;
            JSONObject file=new JSONObject().put("version",1).put("nonce",Crypto.b64(sealed.nonce)).put("tag",Crypto.b64(Arrays.copyOfRange(sealed.ciphertext,length-16,length)))
                .put("ciphertext",Crypto.b64(Arrays.copyOf(sealed.ciphertext,length-16)));
            NativeIo.atomic(vault.attachmentPath(id),Crypto.concat(MAGIC,Crypto.utf8(file.toString())));Crypto.wipe(sealed.ciphertext);
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(filenameIv));
            byte[] encryptedFilename=Crypto.concat(filenameIv,cipher.doFinal(Crypto.utf8(filename)));
            vault.database().db().execSQL("INSERT INTO attachments(attachment_id,message_id,encrypted_local_path,file_name_encrypted,file_size,file_hash,file_key) VALUES(?,?,?,?,?,?,?)",
                new Object[]{id,messageId,vault.attachmentPath(id).getAbsolutePath(),encryptedFilename,bytes.length,Crypto.sha256(bytes),remoteKey});
        }finally{Crypto.wipe(key,filenameIv);}
    }
    public static byte[] read(NativeVault vault,String id) throws Exception {
        File file=vault.attachmentPath(id);byte[] key=vault.attachmentKey();
        try{
            byte[] stored=NativeIo.read(file,36*1024*1024),plaintext;
            if(stored.length>=MAGIC.length&&MessageDigest.isEqual(MAGIC,Arrays.copyOf(stored,MAGIC.length))){
                JSONObject local=new JSONObject(new String(stored,MAGIC.length,stored.length-MAGIC.length,StandardCharsets.UTF_8));if(local.getInt("version")!=1)throw new IllegalArgumentException("invalid_attachment_version");
                plaintext=Crypto.unseal(Crypto.concat(Crypto.unb64(local.getString("ciphertext")),Crypto.unb64(local.getString("tag"))),key,"cp-local-attachment-v1:"+id,Crypto.unb64(local.getString("nonce")));
            }else{
                if(stored.length<32)throw new IllegalArgumentException("invalid_attachment");
                Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(Arrays.copyOf(stored,16)));plaintext=cipher.doFinal(stored,16,stored.length-16);
            }
            byte[] hash=vault.database().blob("SELECT file_hash FROM attachments WHERE attachment_id=?",id);
            String size=vault.database().text("SELECT file_size FROM attachments WHERE attachment_id=?",id);
            if(hash==null||size==null||plaintext.length!=Long.parseLong(size)||!MessageDigest.isEqual(hash,Crypto.sha256(plaintext))){Crypto.wipe(plaintext);throw new SecurityException("attachment_integrity_failed");}
            return plaintext;
        }finally{Crypto.wipe(key);}
    }
}
