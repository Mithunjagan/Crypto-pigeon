package app.cryptopigeon.nativeclient;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/** Device-bound wrapping key. It never exposes an encoded key to application code. */
public final class DeviceKeyStore {
    private final String alias;
    public DeviceKeyStore(String alias){
        if(!alias.matches("cp-(?:vault|fixture)-fragment-v1-[a-f0-9]{32}"))throw new IllegalArgumentException("invalid_keystore_alias");
        this.alias=alias;
    }
    private synchronized SecretKey key(boolean create) throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        if(!store.containsAlias(alias)){
            if(!create)throw new IllegalStateException("device_fragment_key_missing");
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build());generator.generateKey();
        }
        return (SecretKey)store.getKey(alias,null);
    }
    public Crypto.Sealed wrap(byte[] share,String context) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key(true));cipher.updateAAD(Crypto.utf8(context));
        return new Crypto.Sealed(cipher.getIV(),cipher.doFinal(share));
    }
    public byte[] unwrap(Crypto.Sealed value,String context) throws Exception {
        if(value.nonce.length!=12||value.ciphertext.length<16)throw new IllegalArgumentException("invalid_fragment_ciphertext");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,value.nonce));cipher.updateAAD(Crypto.utf8(context));return cipher.doFinal(value.ciphertext);
    }
    public boolean hardwareBacked() throws Exception {
        SecretKeyFactory factory=SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        KeyInfo info=(KeyInfo)factory.getKeySpec(key(false),KeyInfo.class);return info.isInsideSecureHardware();
    }
    public void delete() throws Exception {KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);store.deleteEntry(alias);}
}
