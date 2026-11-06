package app.cryptopigeon.nativeclient.transport;
import java.util.concurrent.CompletableFuture;
public final class RelayEnvelopeTransport implements EnvelopeTransport {
    public interface Sender {void send(EncryptedEnvelopePacket packet) throws Exception;}
    private final Sender sender;
    public RelayEnvelopeTransport(Sender sender){this.sender=sender;}
    public CompletableFuture<TransportSendResult> sendEnvelope(EncryptedEnvelopePacket packet,long timeoutMs){
        CompletableFuture<TransportSendResult> result=new CompletableFuture<>();
        try{sender.send(packet);result.complete(new TransportSendResult(true,transportName()));}catch(Exception failed){result.completeExceptionally(failed);}return result;
    }
    public boolean isReadyForPeer(String uid){return true;}
    public String transportName(){return "RELAY_HTTPS";}
}
