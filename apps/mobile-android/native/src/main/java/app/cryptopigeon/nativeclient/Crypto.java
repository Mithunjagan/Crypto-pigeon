package app.cryptopigeon.nativeclient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/** The same versioned key domains and wire encodings as the desktop vault. */
public final class Crypto {
    private Crypto() {}
    private static final SecureRandom RANDOM=new SecureRandom();
    public static byte[] utf8(String value){return value.getBytes(StandardCharsets.UTF_8);}
    public static byte[] random(int length){byte[] bytes=new byte[length];RANDOM.nextBytes(bytes);return bytes;}
    public static String b64(byte[] bytes){return Base64.getEncoder().encodeToString(bytes);}
    public static byte[] unb64(String value){return Base64.getDecoder().decode(value);}
    public static void wipe(byte[]... buffers){for(byte[] buffer:buffers)if(buffer!=null)Arrays.fill(buffer,(byte)0);}
    public static String hex(byte[] bytes){StringBuilder out=new StringBuilder(bytes.length*2);for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
    public static byte[] unhex(String value){
        if(value.length()%2!=0||!value.matches("[a-fA-F0-9]*"))throw new IllegalArgumentException("invalid_hex");
        byte[] out=new byte[value.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(value.substring(i*2,i*2+2),16);return out;
    }
    public static byte[] concat(byte[]... buffers){int size=0;for(byte[] b:buffers)size+=b.length;byte[] out=new byte[size];int offset=0;for(byte[] b:buffers){System.arraycopy(b,0,out,offset,b.length);offset+=b.length;}return out;}
    public static byte[] sha256(byte[] bytes){try{return MessageDigest.getInstance("SHA-256").digest(bytes);}catch(Exception e){throw new IllegalStateException(e);}}
    public static byte[] hkdf(byte[] material,byte[] salt,String context){
        byte[] prk=null;
        try{
            Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(salt,"HmacSHA256"));prk=mac.doFinal(material);
            mac.init(new SecretKeySpec(prk,"HmacSHA256"));return mac.doFinal(concat(utf8(context),new byte[]{1}));
        }catch(Exception e){throw new IllegalStateException(e);}finally{wipe(prk);}
    }
    public static final class VaultKeys implements AutoCloseable {
        public final byte[] kek,lookup,backup,mask,writer;
        VaultKeys(byte[] root,byte[] salt){
            kek=hkdf(root,salt,"cp-vault-kek-v1");lookup=hkdf(root,salt,"cp-vault-lookup-v1");
            backup=hkdf(root,salt,"cp-vault-backup-cipher-v1");mask=hkdf(root,salt,"cp-horcrux-share6-mask-v1");
            writer=hkdf(root,salt,"cp-vault-backup-writer-v1");
        }
        VaultKeys(VaultKeys source){kek=source.kek.clone();lookup=source.lookup.clone();backup=source.backup.clone();mask=source.mask.clone();writer=source.writer.clone();}
        @Override public void close(){wipe(kek,lookup,backup,mask,writer);}
    }
    public static VaultKeys deriveVaultKeys(String vaultId,char[] password){
        byte[] salt=sha256(concat(utf8("cp-vault-root-v1\0"),utf8(vaultId))),root=new byte[32];
        byte[] passwordBytes=null;
        try{
            passwordBytes=utf8(new String(password));
            Argon2Parameters parameters=new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(65536)
                .withIterations(3).withParallelism(1).withSalt(salt).build();
            Argon2BytesGenerator generator=new Argon2BytesGenerator();generator.init(parameters);
            generator.generateBytes(passwordBytes,root);
            parameters.clear();
            return new VaultKeys(root,salt);
        }finally{wipe(root,salt,passwordBytes);}
    }
    public static final class Sealed {
        public final byte[] nonce,ciphertext;
        Sealed(byte[] nonce,byte[] ciphertext){this.nonce=nonce;this.ciphertext=ciphertext;}
    }
    public static Sealed seal(byte[] plaintext,byte[] key,String aad){return sealWithNonce(plaintext,key,aad,random(12));}
    static Sealed sealWithNonce(byte[] plaintext,byte[] key,String aad,byte[] nonce){
        try{
            if(key.length!=32||nonce.length!=12)throw new IllegalArgumentException("invalid_key_or_nonce");
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            cipher.updateAAD(utf8(aad));return new Sealed(nonce.clone(),cipher.doFinal(plaintext));
        }catch(Exception e){throw new IllegalStateException("encryption_failed",e);}
    }
    public static byte[] unseal(byte[] ciphertext,byte[] key,String aad,byte[] nonce) throws Exception {
        if(key.length!=32||nonce.length!=12||ciphertext.length<16)throw new IllegalArgumentException("invalid_ciphertext");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
        cipher.updateAAD(utf8(aad));return cipher.doFinal(ciphertext);
    }
    public static byte[] edPublic(byte[] seed){return new Ed25519PrivateKeyParameters(seed,0).generatePublicKey().getEncoded();}
    public static byte[] edPublicSpki(byte[] seed){return concat(unhex("302a300506032b6570032100"),edPublic(seed));}
    public static byte[] edPrivatePkcs8(byte[] seed){if(seed.length!=32)throw new IllegalArgumentException("invalid_seed");return concat(unhex("302e020100300506032b657004220420"),seed);}
    public static byte[] edSign(byte[] seed,byte[] message){Ed25519Signer signer=new Ed25519Signer();signer.init(true,new Ed25519PrivateKeyParameters(seed,0));signer.update(message,0,message.length);return signer.generateSignature();}
    public static boolean edVerifySpki(byte[] publicKey,byte[] message,byte[] signature){
        byte[] prefix=unhex("302a300506032b6570032100");
        if(publicKey.length!=44||!MessageDigest.isEqual(prefix,Arrays.copyOf(publicKey,prefix.length)))return false;
        Ed25519Signer signer=new Ed25519Signer();signer.init(false,new Ed25519PublicKeyParameters(publicKey,12));signer.update(message,0,message.length);return signer.verifySignature(signature);
    }
}
