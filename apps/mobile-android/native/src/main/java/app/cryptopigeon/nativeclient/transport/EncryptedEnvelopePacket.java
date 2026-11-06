package app.cryptopigeon.nativeclient.transport;

import java.util.Objects;

/** Immutable transport input. Encryption happens before construction, never in a transport. */
public final class EncryptedEnvelopePacket {
    public final String envelopeId,recipientUid,envelopeType;
    public final long createdAtMs,expiresAtMs;
    private final byte[] payload;
    public EncryptedEnvelopePacket(String id,String recipient,String type,byte[] encrypted,long created,long expires){
        envelopeId=Objects.requireNonNull(id);recipientUid=Objects.requireNonNull(recipient);envelopeType=Objects.requireNonNull(type);
        if(encrypted==null||encrypted.length==0||expires<created)throw new IllegalArgumentException("invalid_envelope");
        payload=encrypted.clone();createdAtMs=created;expiresAtMs=expires;
    }
    public byte[] serializedEncryptedPayload(){return payload.clone();}
}
