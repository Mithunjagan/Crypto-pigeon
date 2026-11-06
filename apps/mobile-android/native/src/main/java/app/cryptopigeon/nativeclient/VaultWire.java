package app.cryptopigeon.nativeclient;

import java.util.Locale;
import org.json.JSONObject;

/** Byte-compatible JSON.stringify encoding for the signed backup array. */
final class VaultWire {
    private VaultWire(){}
    static String quote(String value){
        StringBuilder out=new StringBuilder(value.length()+2).append('"');
        for(int i=0;i<value.length();i++){
            char c=value.charAt(i);
            switch(c){case '"':out.append("\\\"");break;case '\\':out.append("\\\\");break;case '\b':out.append("\\b");break;case '\f':out.append("\\f");break;case '\n':out.append("\\n");break;case '\r':out.append("\\r");break;case '\t':out.append("\\t");break;
                default:
                    boolean unpaired=Character.isSurrogate(c)&&!(Character.isHighSurrogate(c)&&i+1<value.length()&&Character.isLowSurrogate(value.charAt(i+1)))&&!(Character.isLowSurrogate(c)&&i>0&&Character.isHighSurrogate(value.charAt(i-1)));
                    if(c<32||unpaired)out.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else out.append(c);
            }
        }
        return out.append('"').toString();
    }
    static byte[] signingPayload(JSONObject body) throws Exception {
        String[] strings={"lookupToken","nonce","ciphertext","updatedAt","fragment7Shard","writerPublicKey","deviceId","instanceHash","deviceSignature"};
        StringBuilder out=new StringBuilder("[\"cp-backup-write-v1\",").append(quote(body.getString(strings[0]))).append(',').append(body.getLong("version"));
        for(int i=1;i<strings.length;i++){String key=strings[i];out.append(',').append(body.isNull(key)?"null":quote(body.getString(key)));}
        return Crypto.utf8(out.append(',').append(body.optBoolean("claim",false)).append(']').toString());
    }
}
