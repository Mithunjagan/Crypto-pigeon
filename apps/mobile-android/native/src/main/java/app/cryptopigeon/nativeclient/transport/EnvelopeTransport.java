package app.cryptopigeon.nativeclient.transport;
import java.util.concurrent.CompletableFuture;
public interface EnvelopeTransport {
    CompletableFuture<TransportSendResult> sendEnvelope(EncryptedEnvelopePacket packet,long timeoutMs);
    boolean isReadyForPeer(String peerUid);
    String transportName();
}
