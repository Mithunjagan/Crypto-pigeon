package app.cryptopigeon.nativeclient;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
public final class ServerlessInviteTest {
    private JSONObject fixture() throws Exception{return new JSONObject(new String(Files.readAllBytes(Paths.get("src/test/resources/serverless-invite.json")),StandardCharsets.UTF_8));}
    @Test public void nodeInviteVerifiesAndCanonicalBytesMatchAndroid() throws Exception {
        JSONObject fixture=fixture(),invite=ServerlessInvite.parse(fixture.getString("uri"));assertEquals("partner",invite.getString("username"));assertArrayEquals(Crypto.unb64(fixture.getString("canonical")),ServerlessInvite.canonical(invite));
        assertArrayEquals(Crypto.unb64(fixture.getString("requestCanonical")),TorOnionTransport.signingBytes(fixture.getString("device"),1000,"a".repeat(32),"POST","/p2p/v1/envelopes","{\"ciphertext\":\"a/b+\"}"));
    }
    @Test public void malformedVersionAndDuplicateFieldsAreRejected() throws Exception {
        String uri=fixture().getString("uri");assertThrows(Exception.class,()->ServerlessInvite.parse(uri.replace("v=2","v=1")));assertThrows(Exception.class,()->ServerlessInvite.parse(uri+"&v=2"));assertThrows(Exception.class,()->ServerlessInvite.parse(uri+"#untrusted"));
    }
}
