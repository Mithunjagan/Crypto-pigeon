package app.cryptopigeon.nativeclient;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import org.json.JSONObject;
import okhttp3.*;
import java.util.concurrent.TimeUnit;

/** HTTPS by default, bounded bodies, no redirects and no credential-bearing logs. */
public final class RelayTransport implements VaultBackupRelay {
    public static final int MAX_JSON=90*1024*1024;
    public final String origin;
    private final OkHttpClient http = new OkHttpClient.Builder().connectTimeout(15,TimeUnit.SECONDS)
        .readTimeout(30,TimeUnit.SECONDS).callTimeout(30,TimeUnit.SECONDS)
        .followRedirects(false).followSslRedirects(false).pingInterval(20,TimeUnit.SECONDS).build();
    WebSocket events(String token,String instance,WebSocketListener listener) {
        Request.Builder request=new Request.Builder().url(origin+"/ws").header("ngrok-skip-browser-warning","1").header("Authorization","Bearer "+token);
        if(instance!=null)request.header("X-Vault-Instance",instance);
        return http.newWebSocket(request.build(),listener);
    }
    void close(){http.dispatcher().cancelAll();http.connectionPool().evictAll();}
    public RelayTransport(String origin){this(origin,false);}
    RelayTransport(String value,boolean allowDebugLoopback){
        try{
            URI uri=new URI(value);String scheme=uri.getScheme()==null?"":uri.getScheme().toLowerCase(Locale.ROOT),host=uri.getHost();
            boolean local=host!=null&&(host.equalsIgnoreCase("localhost")||host.equals("127.0.0.1")||host.equals("[::1]")||host.equals("::1")||host.startsWith("10.")||host.startsWith("192.168.")||host.matches("172\\.(1[6-9]|2[0-9]|3[01])\\..*")||host.matches("(?i)\\[?f[cd][a-f0-9]{2}:.*"));
            if(host==null||uri.getUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null||(!uri.getPath().isEmpty()&&!uri.getPath().equals("/"))
                ||(!scheme.equals("https")&&!(allowDebugLoopback&&local&&scheme.equals("http"))))throw new IllegalArgumentException("RELAY_REQUIRES_HTTPS_ORIGIN");
            this.origin=new URI(scheme,null,host.toLowerCase(Locale.ROOT),uri.getPort(),null,null,null).toString();
        }catch(Exception invalid){throw new IllegalArgumentException("RELAY_REQUIRES_HTTPS_ORIGIN");}
    }
    public static final class Response {
        public final int status;public final byte[] bytes;
        Response(int status,byte[] bytes){this.status=status;this.bytes=bytes;}
        public boolean ok(){return status>=200&&status<300;}
        public JSONObject object() throws Exception {return new JSONObject(new String(bytes,StandardCharsets.UTF_8));}
    }
    public Response request(String method,String path,JSONObject body,Map<String,String> headers) throws Exception {
        return request(method,path,body,headers,30000);
    }
    public Response request(String method,String path,JSONObject body,Map<String,String> headers,long timeoutMs) throws Exception {
        if(!path.startsWith("/api/")||path.contains("#")||path.contains("\r")||path.contains("\n"))throw new IllegalArgumentException("invalid_relay_path");
        byte[] encoded=body==null?null:Crypto.utf8(body.toString());
        try {
            if(encoded!=null&&encoded.length>MAX_JSON)throw new IOException("backup_too_large");
            RequestBody payload=encoded==null?null:RequestBody.create(encoded,MediaType.get("application/json"));
            if(payload==null&&!method.equals("GET")&&!method.equals("HEAD"))payload=RequestBody.create(new byte[0],null);
            Request.Builder request=new Request.Builder().url(origin+path).method(method,payload)
                .header("ngrok-skip-browser-warning","1").header("Accept","application/json").header("Cache-Control","no-store");
            if(headers!=null)for(Map.Entry<String,String> header:headers.entrySet())request.header(header.getKey(),header.getValue());
            try(okhttp3.Response response=(timeoutMs==30000?http:http.newBuilder().callTimeout(timeoutMs,TimeUnit.MILLISECONDS).build()).newCall(request.build()).execute()) {
                if(response.code()>=300&&response.code()<400)throw new IOException("RELAY_REDIRECT_REJECTED");
                ResponseBody content=response.body();if(content!=null&&content.contentLength()>MAX_JSON)throw new IOException("backup_too_large");
                return new Response(response.code(),content==null?new byte[0]:NativeIo.read(content.byteStream(),MAX_JSON));
            }
        } finally {Crypto.wipe(encoded);}
    }

    @Override public JSONObject getBackup(String token) throws Exception {
        validateToken(token);Response response=request("GET","/api/vault-backup/"+token,null,null);
        if(response.status==404){
            // A stopped tunnel returns an HTML 404, not the relay's JSON reply.
            // Never describe a tunnel outage as a missing local vault fragment.
            try{if("BACKUP_NOT_FOUND".equals(response.object().optString("error")))return null;}catch(Exception offline){}
            throw new IOException("RELAY_BACKUP_UNAVAILABLE");
        }
        if(!response.ok())throw new IOException("RELAY_BACKUP_UNAVAILABLE");return response.object();
    }
    @Override public void putBackup(JSONObject body) throws Exception {
        String token=body.getString("lookupToken");validateToken(token);
        String digest=Crypto.hex(Crypto.sha256(Crypto.unb64(body.getString("ciphertext"))));
        Response response=request("PUT","/api/vault-backup/"+token,body,java.util.Collections.singletonMap("X-Backup-Sha256",digest));
        if(!response.ok())throw new IOException(response.status==409?"BACKUP_CONFLICT_RESTORE_REQUIRED":"RELAY_BACKUP_UNAVAILABLE");
        JSONObject ack=response.object();long version=ack.getLong("version");
        if(version!=body.getLong("version")&&!(ack.optBoolean("skipped")&&version==body.getLong("version")-1))throw new IOException("INVALID_BACKUP_ACKNOWLEDGEMENT");
        body.put("version",version);
    }
    @Override public void deleteBackup(String token,long version,byte[] writer) throws Exception {
        validateToken(token);byte[] signature=Crypto.edSign(writer,Crypto.utf8("cp-backup-delete-v1:"+token+":"+version));
        Response response=request("DELETE","/api/vault-backup/"+token,new JSONObject().put("version",version).put("signature",Crypto.b64(signature)),null);
        if(!response.ok())throw new IOException("OLD_BACKUP_REMOVAL_FAILED_PASSWORD_UNCHANGED");
    }
    static void validateToken(String token){if(!token.matches("[a-f0-9]{64}"))throw new IllegalArgumentException("invalid_lookup_token");}
}
