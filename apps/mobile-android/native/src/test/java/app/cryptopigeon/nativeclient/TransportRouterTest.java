package app.cryptopigeon.nativeclient;
import app.cryptopigeon.nativeclient.transport.*;
import java.util.concurrent.*;
import org.junit.Test;
import static org.junit.Assert.*;

public final class TransportRouterTest {
    @Test public void torDirectNeverFallsBackEvenWhenUnavailable() throws Exception {
        try(EnvelopeTransportRouter router=new EnvelopeTransportRouter(new RelayEnvelopeTransport(p->{throw new AssertionError("Unexpected relay send");}),null,uid->false)){
            router.setMode(EnvelopeTransportRouter.TransportMode.DIRECT_TOR_P2P);assertFalse(router.sendEnvelope(packet()).get().accepted);
        }
    }
    @Test public void torAckRequiresRecipientPersistenceAndHybridReusesPacket() throws Exception {
        Peer peer=new Peer();EncryptedEnvelopePacket packet=packet();java.util.List<EncryptedEnvelopePacket> sent=new java.util.ArrayList<>();
        try(EnvelopeTransportRouter router=new EnvelopeTransportRouter(new RelayEnvelopeTransport(sent::add),peer,uid->false)){
            router.setMode(EnvelopeTransportRouter.TransportMode.HYBRID_TOR_RELAY);CompletableFuture<TransportSendResult> attempt=router.sendEnvelope(packet);assertFalse(attempt.isDone());peer.pending.complete(new TransportSendResult(false,"DIRECT_TOR_P2P"));assertTrue(attempt.get().accepted);assertSame(packet,sent.get(0));
        }
    }
    private EncryptedEnvelopePacket packet(){return new EncryptedEnvelopePacket("test-envelope","CP-AAAA-BBBB","MESSAGE",new byte[]{1,2,3},System.currentTimeMillis(),System.currentTimeMillis()+60000);}
    private static final class Peer implements EnvelopeTransportRouter.Direct {
        boolean ready,connect;CompletableFuture<TransportSendResult> pending=new CompletableFuture<>();
        public void connectPeer(String uid){connect=true;}
        public boolean isKnownOffline(String uid){return false;}
        public boolean isReadyForPeer(String uid){return ready;}
        public String transportName(){return "P2P_WEBRTC";}
        public CompletableFuture<TransportSendResult> sendEnvelope(EncryptedEnvelopePacket p,long timeout){return pending;}
    }
    @Test public void coldTimeoutReusesExactPacketAndLateAckCannotSendAgain() throws Exception {
        EncryptedEnvelopePacket packet=packet();Peer peer=new Peer();java.util.List<EncryptedEnvelopePacket> sent=new java.util.ArrayList<>();
        try(EnvelopeTransportRouter router=new EnvelopeTransportRouter(new RelayEnvelopeTransport(sent::add),peer,uid->false)){
            long started=System.nanoTime();assertTrue(router.sendEnvelope(packet).get(2,TimeUnit.SECONDS).accepted);
            long elapsed=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started);assertTrue(elapsed>=750&&elapsed<1100);assertTrue(peer.connect);
            assertEquals(1,sent.size());assertSame(packet,sent.get(0));peer.pending.complete(new TransportSendResult(true,"P2P_WEBRTC"));assertEquals(1,sent.size());
        }
    }
    @Test public void privacyModeDoesNotStartIceAndPayloadIsImmutable() throws Exception {
        Peer peer=new Peer();EncryptedEnvelopePacket packet=packet();byte[] bytes=packet.serializedEncryptedPayload();bytes[0]=99;assertEquals(1,packet.serializedEncryptedPayload()[0]);
        try(EnvelopeTransportRouter router=new EnvelopeTransportRouter(new RelayEnvelopeTransport(p->{}),peer,uid->false)){
            router.setMode(EnvelopeTransportRouter.TransportMode.RELAY_ONLY);assertTrue(router.sendEnvelope(packet).get().accepted);assertFalse(peer.connect);
        }
    }
    @Test public void warmDirectAckDoesNotReachRelay() throws Exception {
        Peer peer=new Peer();peer.ready=true;peer.pending.complete(new TransportSendResult(true,"P2P_WEBRTC"));
        try(EnvelopeTransportRouter router=new EnvelopeTransportRouter(new RelayEnvelopeTransport(p->{throw new AssertionError("Unexpected relay send");}),peer,uid->false)){
            assertEquals("P2P_WEBRTC",router.sendEnvelope(packet()).get().transport);assertFalse(peer.connect);
        }
    }
}
