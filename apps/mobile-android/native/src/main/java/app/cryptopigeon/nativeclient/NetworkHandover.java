package app.cryptopigeon.nativeclient;

/** Default-network state only; callback capability data avoids synchronous Android queries. */
final class NetworkHandover {
    private String current;
    private boolean validated;
    private boolean capabilitiesSeen;
    synchronized boolean available(String network){
        if(network.equals(current))return false;
        current=network;validated=false;capabilitiesSeen=false;return true;
    }
    synchronized boolean capabilities(String network,boolean valid){
        if(!network.equals(current))return false;
        // onAvailable already requested recovery. Only subsequent validation loss
        // and regain on the same network needs another request.
        boolean recovered=capabilitiesSeen&&valid&&!validated;
        capabilitiesSeen=true;validated=valid;return recovered;
    }
    synchronized boolean lost(String network){
        if(!network.equals(current))return false;
        current=null;validated=false;return true;
    }
}
