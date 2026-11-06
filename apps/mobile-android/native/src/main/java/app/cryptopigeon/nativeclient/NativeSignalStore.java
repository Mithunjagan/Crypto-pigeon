package app.cryptopigeon.nativeclient;

import android.database.Cursor;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONObject;
import org.signal.libsignal.protocol.*;
import org.signal.libsignal.protocol.ecc.*;
import org.signal.libsignal.protocol.kem.*;
import org.signal.libsignal.protocol.message.*;
import org.signal.libsignal.protocol.state.*;
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;

/** libsignal records remain opaque and share the desktop SQLCipher schema. */
public final class NativeSignalStore implements SignalProtocolStore {
    private final NativeDatabase vault;
    public NativeSignalStore(NativeDatabase vault){this.vault=vault;}
    private static String address(SignalProtocolAddress address){return address.getName()+"."+address.getDeviceId();}
    private void exec(String sql,Object... values){vault.db().execSQL(sql,values);}
    private static IllegalStateException corrupt(Exception error){return new IllegalStateException("invalid_signal_record",error);}
    private byte[] record(String table,int id){return vault.blob("SELECT record FROM "+table+" WHERE prekey_id=?",String.valueOf(id));}
    private void saveRecord(String table,int id,byte[] bytes){exec("INSERT INTO "+table+"(prekey_id,record) VALUES(?,?) ON CONFLICT(prekey_id) DO UPDATE SET record=excluded.record",id,bytes);}

    public JSONObject ensureIdentity() throws Exception {
        if(!vault.exists("SELECT 1 FROM signal_account WHERE singleton=1")){
            IdentityKeyPair identity=IdentityKeyPair.generate();
            byte[] authSeed=Crypto.random(32);long now=System.currentTimeMillis();
            vault.db().beginTransaction();
            try {
                exec("INSERT INTO signal_account(singleton,identity_key_pair,registration_id,device_id,created_at) VALUES(1,?,?,?,?)",
                    identity.serialize(),1+new SecureRandom().nextInt(0x3ffffffe),UUID.randomUUID().toString(),now);
                exec("INSERT INTO device_auth_key(singleton,private_key,public_key) VALUES(1,?,?)",Crypto.edPrivatePkcs8(authSeed),Crypto.edPublicSpki(authSeed));
                ECPrivateKey signedPrivate=ECPrivateKey.generate();
                SignedPreKeyRecord signed=new SignedPreKeyRecord(1,now,new ECKeyPair(signedPrivate.publicKey(),signedPrivate),identity.getPrivateKey().calculateSignature(signedPrivate.publicKey().serialize()));
                storeSignedPreKey(1,signed);
                for(int id=1;id<=20;id++){
                    ECPrivateKey key=ECPrivateKey.generate();storePreKey(id,new PreKeyRecord(id,new ECKeyPair(key.publicKey(),key)));
                }
                for(int id=1;id<=21;id++){
                    KEMKeyPair key=KEMKeyPair.generate(KEMKeyType.KYBER_1024);
                    storeKyberPreKey(id,new KyberPreKeyRecord(id,now,key,identity.getPrivateKey().calculateSignature(key.getPublicKey().serialize())));
                }
                vault.db().setTransactionSuccessful();
            }finally{vault.db().endTransaction();Crypto.wipe(authSeed);}
        }
        IdentityKeyPair identity=getIdentityKeyPair();SignedPreKeyRecord signed=loadSignedPreKey(1);KyberPreKeyRecord fallback=loadKyberPreKey(1);
        JSONObject out=new JSONObject().put("deviceId",deviceId()).put("signalDeviceId",1).put("registrationId",getLocalRegistrationId())
            .put("identityPublicKey",Crypto.b64(identity.getPublicKey().serialize())).put("deviceAuthPublicKey",Crypto.b64(vault.blob("SELECT public_key FROM device_auth_key WHERE singleton=1")))
            .put("signedPrekey",new JSONObject().put("id",signed.getId()).put("publicKey",Crypto.b64(signed.getKeyPair().getPublicKey().serialize())).put("signature",Crypto.b64(signed.getSignature())))
            .put("pqLastResortPrekey",kyberJson(fallback));
        JSONArray classical=new JSONArray(),pq=new JSONArray();
        try(Cursor cursor=vault.query("SELECT prekey_id FROM signal_prekeys ORDER BY prekey_id LIMIT 100")){
            while(cursor.moveToNext()){PreKeyRecord key=loadPreKey(cursor.getInt(0));classical.put(new JSONObject().put("id",key.getId()).put("publicKey",Crypto.b64(key.getKeyPair().getPublicKey().serialize())));}
        }
        try(Cursor cursor=vault.query("SELECT prekey_id FROM signal_kyber_prekeys WHERE prekey_id>=2 ORDER BY prekey_id LIMIT 100")){
            while(cursor.moveToNext())pq.put(kyberJson(loadKyberPreKey(cursor.getInt(0))));
        }
        return out.put("oneTimePrekeys",classical).put("pqOneTimePrekeys",pq);
    }
    private JSONObject kyberJson(KyberPreKeyRecord record) throws Exception {
        return new JSONObject().put("id",record.getId()).put("publicKey",Crypto.b64(record.getKeyPair().getPublicKey().serialize())).put("signature",Crypto.b64(record.getSignature()));
    }
    public String deviceId(){return vault.text("SELECT device_id FROM signal_account WHERE singleton=1");}
    public String userId(){return vault.text("SELECT user_id FROM signal_account WHERE singleton=1");}
    public void setAccount(String userId){UUID.fromString(userId);exec("UPDATE signal_account SET user_id=? WHERE singleton=1",userId);}
    public SignalProtocolAddress localAddress(){String id=userId();if(id==null)throw new IllegalStateException("DEVICE_NOT_REGISTERED");return new SignalProtocolAddress(id,1);}
    public byte[] signDeviceMessage(byte[] message){
        byte[] encoded=vault.blob("SELECT private_key FROM device_auth_key WHERE singleton=1");
        byte[] prefix=Crypto.unhex("302e020100300506032b657004220420");
        if(encoded==null||encoded.length!=48||!MessageDigest.isEqual(prefix,java.util.Arrays.copyOf(encoded,16)))throw new IllegalStateException("invalid_device_auth_key");
        byte[] seed=java.util.Arrays.copyOfRange(encoded,16,48);
        try{return Crypto.edSign(seed,message);}finally{Crypto.wipe(encoded,seed);}
    }
    public SignalProtocolAddress establish(JSONObject bundle) throws Exception {
        SignalProtocolAddress remote=new SignalProtocolAddress(bundle.getString("recipientUserId"),bundle.getInt("signalDeviceId"));
        IdentityKey identity=new IdentityKey(Crypto.unb64(bundle.getString("identityPublicKey")),0);
        if(!isTrustedIdentity(remote,identity,Direction.SENDING))throw new SecurityException("identity_changed_blocked");
        saveIdentity(remote,identity);
        JSONObject signed=bundle.getJSONObject("signedPrekey"),one=bundle.optJSONObject("oneTimePrekey"),pq=bundle.optJSONObject("pqOneTimePrekey");
        if(pq==null)pq=bundle.getJSONObject("pqLastResortPrekey");
        PreKeyBundle prekeys=new PreKeyBundle(bundle.getInt("registrationId"),remote.getDeviceId(),one==null?-1:one.getInt("id"),one==null?null:new ECPublicKey(Crypto.unb64(one.getString("publicKey"))),
            signed.getInt("id"),new ECPublicKey(Crypto.unb64(signed.getString("publicKey"))),Crypto.unb64(signed.getString("signature")),identity,
            pq.getInt("id"),new KEMPublicKey(Crypto.unb64(pq.getString("publicKey"))),Crypto.unb64(pq.getString("signature")));
        new SessionBuilder(this,remote,localAddress()).process(prekeys);
        return remote;
    }
    public byte[] encrypt(SignalProtocolAddress remote,byte[] payload) throws Exception {
        CiphertextMessage encrypted=new SessionCipher(this,localAddress(),remote).encrypt(payload);
        return Crypto.concat(new byte[]{(byte)encrypted.getType()},encrypted.serialize());
    }
    public byte[] decrypt(SignalProtocolAddress remote,byte[] envelope) throws Exception {
        if(envelope.length<2)throw new IllegalArgumentException("invalid_signal_envelope");
        byte[] bytes=java.util.Arrays.copyOfRange(envelope,1,envelope.length);
        SessionCipher cipher=new SessionCipher(this,localAddress(),remote);
        if(envelope[0]==CiphertextMessage.PREKEY_TYPE){
            PreKeySignalMessage message=new PreKeySignalMessage(bytes);
            if(!isTrustedIdentity(remote,message.getIdentityKey(),Direction.RECEIVING))throw new SecurityException("identity_changed_blocked");
            saveIdentity(remote,message.getIdentityKey());
            return cipher.decrypt(message);
        }
        if(envelope[0]==CiphertextMessage.WHISPER_TYPE)return cipher.decrypt(new SignalMessage(bytes));
        throw new IllegalArgumentException("unsupported_signal_message");
    }
    @Override public IdentityKeyPair getIdentityKeyPair(){try{return new IdentityKeyPair(vault.blob("SELECT identity_key_pair FROM signal_account WHERE singleton=1"));}catch(Exception e){throw corrupt(e);}}
    @Override public int getLocalRegistrationId(){return Integer.parseInt(vault.text("SELECT registration_id FROM signal_account WHERE singleton=1"));}
    @Override public IdentityChange saveIdentity(SignalProtocolAddress remote,IdentityKey key){
        byte[] current=vault.blob("SELECT identity_public_key FROM contacts WHERE contact_id=?",address(remote));
        if(current!=null&&!MessageDigest.isEqual(current,key.serialize())){
            exec("UPDATE contacts SET identity_changed=1,verified=0 WHERE contact_id=?",address(remote));throw new SecurityException("identity_changed_blocked");
        }
        if(current==null)exec("INSERT INTO contacts(contact_id,username,identity_public_key,verified,identity_changed,created_at) VALUES(?,?,?,0,0,?)",address(remote),remote.getName(),key.serialize(),System.currentTimeMillis());
        return IdentityChange.NEW_OR_UNCHANGED;
    }
    @Override public boolean isTrustedIdentity(SignalProtocolAddress remote,IdentityKey key,Direction direction){
        byte[] current=vault.blob("SELECT identity_public_key FROM contacts WHERE contact_id=?",address(remote));
        if(current==null||MessageDigest.isEqual(current,key.serialize()))return true;
        exec("UPDATE contacts SET identity_changed=1,verified=0 WHERE contact_id=?",address(remote));return false;
    }
    @Override public IdentityKey getIdentity(SignalProtocolAddress remote){byte[] bytes=vault.blob("SELECT identity_public_key FROM contacts WHERE contact_id=?",address(remote));try{return bytes==null?null:new IdentityKey(bytes,0);}catch(Exception e){throw corrupt(e);}}
    @Override public SessionRecord loadSession(SignalProtocolAddress remote){byte[] bytes=vault.blob("SELECT ratchet_state FROM signal_sessions WHERE contact_id=?",address(remote));try{return bytes==null?new SessionRecord():new SessionRecord(bytes);}catch(Exception e){throw corrupt(e);}}
    @Override public List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses) throws NoSessionException {List<SessionRecord> out=new ArrayList<>();for(SignalProtocolAddress remote:addresses){if(!containsSession(remote))throw new NoSessionException("session_missing");out.add(loadSession(remote));}return out;}
    @Override public List<Integer> getSubDeviceSessions(String name){List<Integer> out=new ArrayList<>();try(Cursor cursor=vault.query("SELECT contact_id FROM signal_sessions")){while(cursor.moveToNext()){String id=cursor.getString(0);if(id.startsWith(name+".")){int device=Integer.parseInt(id.substring(name.length()+1));if(device!=1)out.add(device);}}}return out;}
    @Override public void storeSession(SignalProtocolAddress remote,SessionRecord record){exec("INSERT INTO signal_sessions(contact_id,ratchet_state,updated_at) VALUES(?,?,?) ON CONFLICT(contact_id) DO UPDATE SET ratchet_state=excluded.ratchet_state,updated_at=excluded.updated_at",address(remote),record.serialize(),System.currentTimeMillis());}
    @Override public boolean containsSession(SignalProtocolAddress remote){return vault.exists("SELECT 1 FROM signal_sessions WHERE contact_id=?",address(remote))&&loadSession(remote).hasSenderChain(0.0);}
    @Override public void deleteSession(SignalProtocolAddress remote){exec("DELETE FROM signal_sessions WHERE contact_id=?",address(remote));}
    @Override public void deleteAllSessions(String name){exec("DELETE FROM signal_sessions WHERE contact_id LIKE ?",name+".%");}
    @Override public PreKeyRecord loadPreKey(int id) throws InvalidKeyIdException {byte[] bytes=record("signal_prekeys",id);if(bytes==null)throw new InvalidKeyIdException("prekey_missing");try{return new PreKeyRecord(bytes);}catch(Exception e){throw new InvalidKeyIdException(e);}}
    @Override public void storePreKey(int id,PreKeyRecord record){saveRecord("signal_prekeys",id,record.serialize());}
    @Override public boolean containsPreKey(int id){return record("signal_prekeys",id)!=null;}
    @Override public void removePreKey(int id){exec("DELETE FROM signal_prekeys WHERE prekey_id=?",id);}
    @Override public SignedPreKeyRecord loadSignedPreKey(int id) throws InvalidKeyIdException {byte[] bytes=record("signal_signed_prekeys",id);if(bytes==null)throw new InvalidKeyIdException("signed_prekey_missing");try{return new SignedPreKeyRecord(bytes);}catch(Exception e){throw new InvalidKeyIdException(e);}}
    @Override public List<SignedPreKeyRecord> loadSignedPreKeys(){List<SignedPreKeyRecord> out=new ArrayList<>();try(Cursor cursor=vault.query("SELECT record FROM signal_signed_prekeys")){while(cursor.moveToNext())out.add(new SignedPreKeyRecord(cursor.getBlob(0)));}catch(Exception e){throw corrupt(e);}return out;}
    @Override public void storeSignedPreKey(int id,SignedPreKeyRecord record){saveRecord("signal_signed_prekeys",id,record.serialize());}
    @Override public boolean containsSignedPreKey(int id){return record("signal_signed_prekeys",id)!=null;}
    @Override public void removeSignedPreKey(int id){exec("DELETE FROM signal_signed_prekeys WHERE prekey_id=?",id);}
    @Override public KyberPreKeyRecord loadKyberPreKey(int id) throws InvalidKeyIdException {byte[] bytes=record("signal_kyber_prekeys",id);if(bytes==null)throw new InvalidKeyIdException("kyber_prekey_missing");try{return new KyberPreKeyRecord(bytes);}catch(Exception e){throw new InvalidKeyIdException(e);}}
    @Override public List<KyberPreKeyRecord> loadKyberPreKeys(){List<KyberPreKeyRecord> out=new ArrayList<>();try(Cursor cursor=vault.query("SELECT record FROM signal_kyber_prekeys")){while(cursor.moveToNext())out.add(new KyberPreKeyRecord(cursor.getBlob(0)));}catch(Exception e){throw corrupt(e);}return out;}
    @Override public void storeKyberPreKey(int id,KyberPreKeyRecord record){saveRecord("signal_kyber_prekeys",id,record.serialize());}
    @Override public boolean containsKyberPreKey(int id){return record("signal_kyber_prekeys",id)!=null;}
    @Override public void markKyberPreKeyUsed(int id,int signedId,ECPublicKey base) throws ReusedBaseKeyException {
        if(id>=2){exec("DELETE FROM signal_kyber_prekeys WHERE prekey_id=?",id);return;}
        try{exec("INSERT INTO signal_kyber_used(prekey_id,signed_prekey_id,base_key) VALUES(?,?,?)",id,signedId,base.serialize());}
        catch(android.database.SQLException duplicate){throw new ReusedBaseKeyException("kyber_base_key_reused");}
    }
    @Override public void storeSenderKey(SignalProtocolAddress sender,UUID distribution,SenderKeyRecord record){exec("INSERT INTO signal_sender_keys(sender,distribution_id,record) VALUES(?,?,?) ON CONFLICT(sender,distribution_id) DO UPDATE SET record=excluded.record",address(sender),distribution.toString(),record.serialize());}
    @Override public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender,UUID distribution){byte[] bytes=vault.blob("SELECT record FROM signal_sender_keys WHERE sender=? AND distribution_id=?",address(sender),distribution.toString());try{return bytes==null?null:new SenderKeyRecord(bytes);}catch(Exception e){throw corrupt(e);}}
}
