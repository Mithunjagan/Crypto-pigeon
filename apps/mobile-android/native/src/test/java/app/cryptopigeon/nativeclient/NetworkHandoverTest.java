package app.cryptopigeon.nativeclient;

import org.junit.Test;
import static org.junit.Assert.*;

public class NetworkHandoverTest {
    @Test public void switchingAndValidationRecoverWithoutStaleLoss(){
        NetworkHandover state=new NetworkHandover();
        assertTrue(state.available("wifi"));assertFalse(state.available("wifi"));
        assertFalse(state.capabilities("wifi",true));assertFalse(state.capabilities("wifi",true));
        assertTrue(state.available("mobile"));assertFalse(state.lost("wifi"));
        assertFalse(state.capabilities("wifi",true));assertFalse(state.capabilities("mobile",true));
        assertFalse(state.capabilities("mobile",false));assertTrue(state.capabilities("mobile",true));
        assertTrue(state.lost("mobile"));assertTrue(state.available("mobile"));
    }
}
