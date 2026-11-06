package app.cryptopigeon.nativeclient;

import java.net.URI;
import java.util.concurrent.TimeUnit;
import okhttp3.*;
import org.json.JSONObject;

/** Discovery uses one operator-configured HTTPS document; no credentials leave the vault. */
final class RelayDiscovery {
    private static final OkHttpClient http=new OkHttpClient.Builder().connectTimeout(4,TimeUnit.SECONDS).readTimeout(4,TimeUnit.SECONDS).callTimeout(6,TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).build();
    static boolean ready(String origin) throws Exception {
        try(Response response=http.newCall(new Request.Builder().url(origin+"/readyz").header("ngrok-skip-browser-warning","1").build()).execute()){
            return response.isSuccessful()&&response.body()!=null&&new JSONObject(new String(NativeIo.read(response.body().byteStream(),8192),java.nio.charset.StandardCharsets.UTF_8)).optBoolean("ok");
        }
    }
    static String lookup(String endpoint) throws Exception {
        URI uri=new URI(endpoint);
        if(!"https".equals(uri.getScheme())||uri.getHost()==null||uri.getUserInfo()!=null||uri.getFragment()!=null)throw new IllegalArgumentException("INVALID_DISCOVERY_URL");
        try(Response response=http.newCall(new Request.Builder().url(endpoint).header("ngrok-skip-browser-warning","1").header("Cache-Control","no-cache").build()).execute()){
            if(!response.isSuccessful()||response.body()==null||response.body().contentLength()>8192)throw new IllegalStateException("DISCOVERY_UNAVAILABLE");
            JSONObject document=new JSONObject(new String(NativeIo.read(response.body().byteStream(),8192),java.nio.charset.StandardCharsets.UTF_8));
            RelayTransport relay=new RelayTransport(document.getString("relayUrl"),false);
            try{return relay.origin;}finally{relay.close();}
        }
    }
}
