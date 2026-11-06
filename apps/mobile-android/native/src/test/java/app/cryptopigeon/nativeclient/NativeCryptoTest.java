package app.cryptopigeon.nativeclient;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;
import java.nio.file.*;
import java.util.*;

public final class NativeCryptoTest {
    private JSONObject fixture() throws Exception {return new JSONObject(new String(Files.readAllBytes(Paths.get("src/androidTest/assets/native-fixture.json")),java.nio.charset.StandardCharsets.UTF_8));}
    @Test public void nativeArgon2AndAllHkdfDomainsMatchNodeVectors() throws Exception {
        JSONObject f=fixture(),expected=f.getJSONObject("keys");
        try(Crypto.VaultKeys keys=Crypto.deriveVaultKeys(f.getString("vaultId"),f.getString("password").toCharArray())){
            assertArrayEquals(Crypto.unb64(expected.getString("kek")),keys.kek);assertArrayEquals(Crypto.unb64(expected.getString("lookup")),keys.lookup);assertArrayEquals(Crypto.unb64(expected.getString("backup")),keys.backup);assertArrayEquals(Crypto.unb64(expected.getString("mask")),keys.mask);assertArrayEquals(Crypto.unb64(expected.getString("writer")),keys.writer);
            try(Crypto.VaultKeys other=Crypto.deriveVaultKeys(f.getString("vaultId")+"x",f.getString("password").toCharArray())){assertFalse(Arrays.equals(keys.kek,other.kek));}
            try(Crypto.VaultKeys other=Crypto.deriveVaultKeys(f.getString("vaultId"),(f.getString("password")+"x").toCharArray())){assertFalse(Arrays.equals(keys.lookup,other.lookup));}
        }
    }
    @Test public void nativeAesGcmMatchesNodeAndRejectsTamperAndWrongDomain() throws Exception {
        JSONObject f=fixture(),aead=f.getJSONObject("aead");byte[] key=Crypto.unb64(f.getJSONObject("keys").getString("kek")),nonce=Crypto.unb64(aead.getString("nonce")),plain=Crypto.unb64(aead.getString("plaintext")),cipher=Crypto.unb64(aead.getString("ciphertext"));
        assertArrayEquals(cipher,Crypto.sealWithNonce(plain,key,"vmk-wrap-v1",nonce).ciphertext);assertArrayEquals(plain,Crypto.unseal(cipher,key,"vmk-wrap-v1",nonce));
        assertThrows(Exception.class,()->Crypto.unseal(cipher,key,"vault-backup-v1",nonce));cipher[0]^=1;assertThrows(Exception.class,()->Crypto.unseal(cipher,key,"vmk-wrap-v1",nonce));
    }
    @Test public void everyMissingAndCorruptedShardBlocksNativeReconstruction(){
        byte[] wrapped=Crypto.random(48);byte[][] shares=SevenShares.split(wrapped),hashes=new byte[7][];for(int i=0;i<7;i++)hashes[i]=Crypto.sha256(shares[i]);assertArrayEquals(wrapped,SevenShares.collect(shares,hashes));
        for(int i=0;i<7;i++){byte[] saved=shares[i];shares[i]=null;assertThrows(IllegalStateException.class,()->SevenShares.collect(shares,hashes));shares[i]=saved;shares[i][0]^=1;assertThrows(IllegalStateException.class,()->SevenShares.collect(shares,hashes));shares[i][0]^=1;}
        assertArrayEquals(wrapped,SevenShares.collect(shares,hashes));Crypto.wipe(shares);
    }
    @Test public void ed25519WriterMatchesNodeAndRejectsModifiedBackup() throws Exception {
        JSONObject f=fixture(),writer=f.getJSONObject("writer");byte[] key=Crypto.unb64(f.getJSONObject("keys").getString("writer")),message=Crypto.unb64(writer.getString("message")),signature=Crypto.unb64(writer.getString("signature")),pub=Crypto.unb64(writer.getString("publicKey"));
        assertArrayEquals(pub,Crypto.edPublicSpki(key));assertArrayEquals(signature,Crypto.edSign(key,message));assertTrue(Crypto.edVerifySpki(pub,message,signature));message[0]^=1;assertFalse(Crypto.edVerifySpki(pub,message,signature));
    }
    @Test public void closingDerivedKeysZeroesEveryDomain(){
        Crypto.VaultKeys keys=Crypto.deriveVaultKeys("host-native-test-vault","HostNativePassword123!".toCharArray());keys.close();for(byte[] bytes:new byte[][]{keys.kek,keys.lookup,keys.backup,keys.mask,keys.writer})assertArrayEquals(new byte[32],bytes);
    }
    @Test public void relayValidationSupportsConfiguredLanAndHttpsWithoutCredentials(){
        assertEquals("http://192.168.1.20:8443",new RelayTransport("http://192.168.1.20:8443",true).origin);assertEquals("https://relay.example.com",new RelayTransport("https://relay.example.com").origin);
        for(String invalid:Arrays.asList("https://user:pass@relay.example.com","https://relay.example.com/path","https://relay.example.com?secret=value","file:///private/vault"))assertThrows(IllegalArgumentException.class,()->new RelayTransport(invalid,true));
    }
}
