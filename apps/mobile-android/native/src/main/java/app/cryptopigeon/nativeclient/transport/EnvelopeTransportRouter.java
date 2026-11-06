package app.cryptopigeon.nativeclient.transport;

import java.util.concurrent.*;
import java.util.function.Predicate;

/** A single deadline covers cold setup AND commit ACK. Every fallback uses the same packet. */
public final class EnvelopeTransportRouter implements AutoCloseable {
    public enum TransportMode {RELAY_ONLY,HYBRID_P2P_PREFERRED,P2P_ONLY_TEST,DIRECT_TOR_P2P,HYBRID_TOR_RELAY}
    public interface Direct extends EnvelopeTransport {void connectPeer(String uid);boolean isKnownOffline(String uid);}
    public static final long P2P_WARMUP_BUDGET_MS=800,OPEN_ACK_TIMEOUT_MS=1200;
    private final EnvelopeTransport relay;private final Direct direct;private final Predicate<String> relayOnly;
    private final ScheduledExecutorService clock=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"cp-transport-deadlines");t.setDaemon(true);return t;});
    private volatile TransportMode mode=TransportMode.HYBRID_P2P_PREFERRED;
    public EnvelopeTransportRouter(EnvelopeTransport relay,Direct direct,Predicate<String> relayOnly){this.relay=relay;this.direct=direct;this.relayOnly=relayOnly;}
    public void setMode(TransportMode next){mode=next;}
    public CompletableFuture<TransportSendResult> sendEnvelope(EncryptedEnvelopePacket packet){
        if(System.currentTimeMillis()>=packet.expiresAtMs)return CompletableFuture.completedFuture(new TransportSendResult(false,"EXPIRED"));
        TransportMode selected=mode;
        if(selected==TransportMode.DIRECT_TOR_P2P||selected==TransportMode.HYBRID_TOR_RELAY){
            if(direct==null)return selected==TransportMode.DIRECT_TOR_P2P?CompletableFuture.completedFuture(new TransportSendResult(false,"DIRECT_TOR_P2P")):relay.sendEnvelope(packet,30000);
            CompletableFuture<TransportSendResult> attempt=direct.sendEnvelope(packet,90000).orTimeout(91,TimeUnit.SECONDS).exceptionally(e->new TransportSendResult(false,"DIRECT_TOR_P2P"));
            return attempt.thenCompose(result->result.accepted||selected==TransportMode.DIRECT_TOR_P2P?CompletableFuture.completedFuture(result):relay.sendEnvelope(packet,30000));
        }
        if(selected==TransportMode.RELAY_ONLY||relayOnly.test(packet.recipientUid)||direct==null||direct.isKnownOffline(packet.recipientUid)){
            if(selected==TransportMode.P2P_ONLY_TEST)return CompletableFuture.completedFuture(new TransportSendResult(false,"P2P_WEBRTC"));
            return relay.sendEnvelope(packet,30000);
        }
        CompletableFuture<TransportSendResult> attempt=new CompletableFuture<>();
        long budget=direct.isReadyForPeer(packet.recipientUid)?OPEN_ACK_TIMEOUT_MS:P2P_WARMUP_BUDGET_MS;
        ScheduledFuture<?> deadline=clock.schedule(()->attempt.complete(new TransportSendResult(false,"P2P_WEBRTC")),budget,TimeUnit.MILLISECONDS);
        attempt.whenComplete((r,e)->deadline.cancel(false));
        CompletableFuture.runAsync(()->{try{
            if(!direct.isReadyForPeer(packet.recipientUid))direct.connectPeer(packet.recipientUid);
            direct.sendEnvelope(packet,budget).whenComplete((r,e)->{if(e!=null)attempt.complete(new TransportSendResult(false,"P2P_WEBRTC"));else attempt.complete(r);});
        }catch(Exception failed){attempt.complete(new TransportSendResult(false,"P2P_WEBRTC"));}});
        return attempt.thenComposeAsync(result->result.accepted||selected==TransportMode.P2P_ONLY_TEST?CompletableFuture.completedFuture(result):relay.sendEnvelope(packet,30000));
    }
    public void close(){clock.shutdownNow();}
}
