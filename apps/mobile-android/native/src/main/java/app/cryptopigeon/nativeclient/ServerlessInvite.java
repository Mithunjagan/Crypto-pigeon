package app.cryptopigeon.nativeclient;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.signal.libsignal.protocol.IdentityKey;

/** Version 2 uses a fixed signed array and bounded raw-deflate for a single Kyber QR. */
final class ServerlessInvite {
    private static String url64(byte[] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
    private static byte[] unurl64(String value){if(!value.matches("[A-Za-z0-9_-]+"))throw new IllegalArgumentException("INVALID_INVITE");return Base64.getUrlDecoder().decode(value);}
    static byte[] canonical(JSONObject v) throws Exception {
        JSONObject s=v.getJSONObject("signedPrekey"),pq=v.getJSONObject("pqLastResortPrekey");
        return Crypto.utf8(new JSONArray().put("cp-invite-v2").put(v.getString("publicUid")).put(v.getString("username")).put(v.getString("onion")).put(v.getString("userId")).put(v.getString("deviceId")).put(v.getInt("signalDeviceId")).put(v.getInt("registrationId")).put(v.getString("deviceAuthPublicKey")).put(v.getString("identityPublicKey")).put(s.getInt("id")).put(s.getString("publicKey")).put(s.getString("signature")).put(pq.getInt("id")).put(pq.getString("publicKey")).put(pq.getString("signature")).toString().replace("\\/","/"));
    }
    static String create(JSONObject invite,NativeSignalStore store) throws Exception {
        byte[] bytes=canonical(invite);Deflater deflater=new Deflater(9,true);deflater.setInput(bytes);deflater.finish();ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[1024];
        try{while(!deflater.finished()){int n=deflater.deflate(buffer);out.write(buffer,0,n);}}finally{deflater.end();}
        String uri="pigeon://invite?v=2&data="+url64(out.toByteArray())+"&sig="+url64(store.signDeviceMessage(bytes));if(uri.length()>2953)throw new IllegalArgumentException("INVITE_TOO_LARGE");return uri;
    }
    static JSONObject parse(String text) throws Exception {
        if(text.length()>4096)throw new IllegalArgumentException("INVALID_INVITE");URI uri=new URI(text);Map<String,String> query=new HashMap<>();
        if(!"pigeon".equals(uri.getScheme())||!"invite".equals(uri.getHost())||!uri.getPath().isEmpty()||uri.getUserInfo()!=null||uri.getPort()!=-1||uri.getFragment()!=null||uri.getRawQuery()==null)throw new IllegalArgumentException("INVALID_INVITE");
        for(String item:uri.getRawQuery().split("&")){String[] pair=item.split("=",2);if(pair.length!=2||query.put(pair[0],pair[1])!=null)throw new IllegalArgumentException("INVALID_INVITE");}
        if(query.size()!=3||!"2".equals(query.get("v"))||!query.containsKey("data")||!query.getOrDefault("sig","").matches("[A-Za-z0-9_-]{86}"))throw new IllegalArgumentException("INVALID_INVITE");
        Inflater inflater=new Inflater(true);inflater.setInput(unurl64(query.get("data")));ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[1024];
        try{while(!inflater.finished()){int n=inflater.inflate(buffer);if(n==0||out.size()+n>8192)throw new IllegalArgumentException("INVALID_INVITE");out.write(buffer,0,n);}}finally{inflater.end();}
        JSONArray a=new JSONArray(new String(out.toByteArray(),java.nio.charset.StandardCharsets.UTF_8));if(a.length()!=16||!"cp-invite-v2".equals(a.getString(0)))throw new IllegalArgumentException("INVALID_INVITE");
        JSONObject v=new JSONObject().put("version",2).put("publicUid",a.getString(1)).put("username",a.getString(2)).put("onion",a.getString(3)).put("userId",a.getString(4)).put("deviceId",a.getString(5)).put("signalDeviceId",a.getInt(6)).put("registrationId",a.getInt(7)).put("deviceAuthPublicKey",a.getString(8)).put("identityPublicKey",a.getString(9))
            .put("signedPrekey",new JSONObject().put("id",a.getInt(10)).put("publicKey",a.getString(11)).put("signature",a.getString(12)))
            .put("pqLastResortPrekey",new JSONObject().put("id",a.getInt(13)).put("publicKey",a.getString(14)).put("signature",a.getString(15)));
        if(!v.getString("publicUid").matches("CP-[A-F0-9]{4}-[A-F0-9]{4}")||!v.getString("username").matches("[a-z0-9_]{3,32}")||!v.getString("onion").matches("[a-z2-7]{56}\\.onion")||v.getInt("signalDeviceId")<1||v.getInt("signalDeviceId")>127||v.getInt("registrationId")<1||v.getInt("registrationId")>1073741823)throw new IllegalArgumentException("INVALID_INVITE");
        UUID.fromString(v.getString("deviceId"));UUID.fromString(v.getString("userId"));check64(v.getString("deviceAuthPublicKey"),44);check64(v.getString("identityPublicKey"),33);
        if(!Crypto.edVerifySpki(Crypto.unb64(v.getString("deviceAuthPublicKey")),canonical(v),unurl64(query.get("sig"))))throw new SecurityException("INVALID_INVITE_SIGNATURE");
        IdentityKey identity=new IdentityKey(Crypto.unb64(v.getString("identityPublicKey")),0);
        for(String name:new String[]{"signedPrekey","pqLastResortPrekey"}){JSONObject prekey=v.getJSONObject(name);if(prekey.getInt("id")<0)throw new IllegalArgumentException("INVALID_INVITE");check64(prekey.getString("publicKey"),name.equals("signedPrekey")?33:1569);check64(prekey.getString("signature"),64);if(!identity.getPublicKey().verifySignature(Crypto.unb64(prekey.getString("publicKey")),Crypto.unb64(prekey.getString("signature"))))throw new SecurityException("INVALID_SIGNAL_PREKEY_SIGNATURE");}
        return v;
    }
    private static void check64(String value,int size){byte[] bytes=Crypto.unb64(value);if(bytes.length!=size||!Crypto.b64(bytes).equals(value))throw new IllegalArgumentException("INVALID_INVITE");}
}
