package app.cryptopigeon.nativeclient;

import android.content.Context;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;

/** Loopback only. The native host never exposes keys or a JavaScript interface to WebView. */
final class LocalBridge implements AutoCloseable {
    private final Context context;private final NativeEngine engine;private final ServerSocket server;
    private final ExecutorService clients=Executors.newFixedThreadPool(6);
    private String bootstrap=random(),cookie,csrf;private long expires;
    private volatile boolean closed;final String origin;final int port;
    private final boolean serviceLifecycle;
    LocalBridge(Context context) throws Exception {
        this(context,new NativeEngine(context),true);
    }
    LocalBridge(Context context,NativeEngine engine,boolean persist) throws Exception {
        serviceLifecycle=persist;
        this.context=context.getApplicationContext();this.engine=engine;
        int saved=persist?context.getSharedPreferences("bridge",0).getInt("port",0):0;
        server=new ServerSocket();server.setReuseAddress(true);server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),saved),16);port=server.getLocalPort();origin="http://127.0.0.1:"+port;
        if(persist&&!context.getSharedPreferences("bridge",0).edit().putInt("port",port).commit())throw new IOException("LOCAL_SETTINGS_FAILED");
        Thread accept=new Thread(()->{while(!closed)try{Socket socket=server.accept();clients.execute(()->serve(socket));}catch(IOException stopped){if(closed)return;}},"cp-loopback");accept.setDaemon(true);accept.start();
    }
    private static String random(){return Crypto.hex(Crypto.random(32));}
    synchronized String entry(){return bootstrap==null?origin+"/":origin+"/#"+bootstrap;}
    long fileEpoch(){return engine.fileEpoch();}
    byte[] exportFile(String kind,long epoch) throws Exception{return engine.exportFile(kind,epoch);}
    void fileSaved(String kind,long epoch,android.net.Uri uri) throws Exception{engine.fileSaved(kind,epoch,uri);}
    private static boolean equal(String a,String b){return a!=null&&b!=null&&MessageDigest.isEqual(Crypto.utf8(a),Crypto.utf8(b));}
    private static String line(InputStream input) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();int value;while((value=input.read())!=-1){if(value=='\n')break;if(value!='\r')out.write(value);if(out.size()>8192)throw new IOException("header_too_large");}return value==-1&&out.size()==0?null:out.toString("US-ASCII");
    }
    private void serve(Socket socket) {
        try(Socket client=socket){client.setSoTimeout(15000);InputStream input=new BufferedInputStream(client.getInputStream());OutputStream out=client.getOutputStream();String first=line(input);if(first==null)return;
            String[] start=first.split(" ");if(start.length!=3)return;String method=start[0],target=start[1];Map<String,String> headers=new HashMap<>();String next;int length=0,total=0;
            while((next=line(input))!=null&&!next.isEmpty()){total+=next.length();if(total>32768)throw new IOException("headers_too_large");int colon=next.indexOf(':');if(colon<=0)throw new IOException("invalid_header");String name=next.substring(0,colon).toLowerCase(Locale.ROOT),value=next.substring(colon+1).trim();if(headers.put(name,value)!=null)throw new IOException("duplicate_header");}
            if(!("127.0.0.1:"+port).equals(headers.get("host"))||(headers.containsKey("origin")&&!origin.equals(headers.get("origin")))){respond(out,403,"application/json",jsonError("invalid_origin_header"),null);return;}
            if(headers.containsKey("transfer-encoding")){respond(out,400,"application/json",jsonError("INVALID_REQUEST"),null);return;}
            if(headers.containsKey("content-length"))length=Integer.parseInt(headers.get("content-length"));if(length<0||length>36*1024*1024){respond(out,413,"application/json",jsonError("BODY_TOO_LARGE"),null);return;}
            byte[] encoded=new byte[length];int offset=0;while(offset<length){int read=input.read(encoded,offset,length-offset);if(read<0)throw new EOFException();offset+=read;}
            URI uri=new URI(target);String path=uri.getRawPath();if(uri.isAbsolute()||path==null)throw new IOException("invalid_path");
            if(!path.startsWith("/api/")){
                if(!method.equals("GET")||!(path.equals("/")||path.matches("/assets/[A-Za-z0-9_.-]+\\.(js|css|png|svg|woff2?)"))){respond(out,404,"application/json",jsonError("NOT_FOUND"),null);return;}
                String asset=path.equals("/")?"ui/index.html":"ui"+path;
                try(InputStream file=context.getAssets().open(asset)){byte[] bytes=NativeIo.read(file,4*1024*1024);String mime=path.endsWith(".js")?"application/javascript":path.endsWith(".css")?"text/css":path.endsWith(".svg")?"image/svg+xml":path.endsWith(".png")?"image/png":path.endsWith(".woff2")?"font/woff2":"text/html";respond(out,200,mime,bytes,null);}catch(FileNotFoundException missing){respond(out,404,"application/json",jsonError("NOT_FOUND"),null);}return;
            }
            Map<String,String> query=new HashMap<>();if(uri.getRawQuery()!=null)for(String item:uri.getRawQuery().split("&")){String[] pair=item.split("=",2);query.put(URLDecoder.decode(pair[0],"UTF-8"),pair.length==2?URLDecoder.decode(pair[1],"UTF-8"):"");}
            if(path.equals("/api/events")&&method.equals("GET")){
                synchronized(this){
                    String session=headers.getOrDefault("cookie","");String value=null;
                    for(String item:session.split(";")){String[] pair=item.trim().split("=",2);if(pair.length==2&&pair[0].equals("crypto_pigeon_session"))value=pair[1];}
                    if(System.currentTimeMillis()>=expires||!equal(cookie,value)){respond(out,401,"application/json",jsonError("unauthorized_local_session"),null);return;}
                }
                long after=Long.parseLong(query.getOrDefault("after","0"));
                respond(out,200,"application/json",Crypto.utf8(engine.events.after(Math.max(0,after)).toString()),null);return;
            }
            synchronized(this){
                try{
                    JSONObject body=length==0?null:new JSONObject(new String(encoded,StandardCharsets.UTF_8));Crypto.wipe(encoded);
                    if(path.equals("/api/bootstrap")&&method.equals("POST")){
                        if(bootstrap==null||!equal(body==null?null:body.optString("secret"),bootstrap)){respond(out,401,"application/json",jsonError("invalid_bootstrap_secret"),null);return;}
                        bootstrap=null;cookie=random();csrf=random();expires=System.currentTimeMillis()+86400000L;
                        respond(out,200,"application/json",Crypto.utf8(new JSONObject().put("csrfToken",csrf).put("vaultState",engine.state()).toString()),"Set-Cookie: crypto_pigeon_session="+cookie+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400\r\n");return;
                    }
                    String receivedCookie=null;for(String part:headers.getOrDefault("cookie","").split(";")){String[] pair=part.trim().split("=",2);if(pair.length==2&&pair[0].equals("crypto_pigeon_session"))receivedCookie=pair[1];}
                    if(System.currentTimeMillis()>=expires||!equal(cookie,receivedCookie)){respond(out,401,"application/json",jsonError("unauthorized_local_session"),null);return;}
                    if(!Arrays.asList("GET","POST").contains(method)){respond(out,405,"application/json",jsonError("METHOD_NOT_ALLOWED"),null);return;}
                    if(method.equals("POST")&&!equal(csrf,headers.get("x-csrf-token"))){respond(out,403,"application/json",jsonError("invalid_csrf_token"),null);return;}
                    if(method.equals("POST")&&length>0&&!headers.getOrDefault("content-type","").startsWith("application/json")){respond(out,415,"application/json",jsonError("JSON_REQUIRED"),null);return;}
                    if(path.equals("/api/session")){respond(out,200,"application/json",Crypto.utf8(new JSONObject().put("csrfToken",csrf).put("vaultState",engine.state()).toString()),null);return;}
                    if(method.equals("GET")&&path.matches("/api/vault/files/(shard7|storage)")){
                        byte[] bytes=engine.exportFile(path.endsWith("shard7")?"shard7":"storage",engine.fileEpoch());
                        try{respond(out,200,"application/octet-stream",bytes,null);}finally{Crypto.wipe(bytes);}return;
                    }
                    if(method.equals("GET")&&path.matches("/api/attachments/[a-f0-9]{32}/decrypt")&&(query.containsKey("download")||query.containsKey("play"))){
                        String id=path.split("/")[3],filename=engine.attachmentName(id);byte[] bytes=engine.attachment(id);
                        try{boolean play="1".equals(query.get("play"))&&filename.matches("voice-note\\.(webm|ogg|m4a)");String mime=filename.endsWith(".m4a")?"audio/mp4":filename.endsWith(".ogg")?"audio/ogg":"audio/webm";respond(out,200,play?mime:"application/octet-stream",bytes,play?null:"Content-Disposition: attachment; filename=\""+filename.replaceAll("[^a-zA-Z0-9._ -]","_")+"\"; filename*=UTF-8''"+URLEncoder.encode(filename,"UTF-8").replace("+","%20")+"\r\n");}finally{Crypto.wipe(bytes);}return;
                    }
                    if(method.equals("GET")&&!Arrays.asList("/api/vault/storage","/api/profile","/api/relay/config","/api/transport/status","/api/transport/privacy","/api/vault/status","/api/vault/horcrux-status","/api/access/state","/api/contacts","/api/contacts/invite","/api/power/status","/api/conversations/requests").contains(path)&&!path.matches("/api/messages/[a-f0-9-]{36}")&&!path.matches("/api/attachments/[a-f0-9]{32}/decrypt")){respond(out,405,"application/json",jsonError("METHOD_NOT_ALLOWED"),null);return;}
                    Object result;
                    try{result=engine.handle(method,path,body,query);}finally{if(serviceLifecycle)PigeonForegroundService.update(context,engine.deliveryEnabled());}
                    if(path.equals("/api/vault/lock")){bootstrap=random();cookie=null;csrf=null;((JSONObject)result).put("bootstrapSecret",bootstrap);}
                    respond(out,200,"application/json",Crypto.utf8(result.toString()),null);
                }catch(NativeEngine.ApiError error){respond(out,error.status,"application/json",jsonError(error.getMessage()),null);}
                catch(Exception error){String code=error.getMessage();if(code==null||!code.matches("[A-Za-z0-9_ .:/-]{1,100}"))code="LOCAL_OPERATION_FAILED";respond(out,400,"application/json",jsonError(code),null);}
            }
        }catch(Exception ignored){/* Never log request bodies, identifiers, credentials, or decrypted content. */}
    }
    private static byte[] jsonError(String code){try{return Crypto.utf8(new JSONObject().put("error",code).toString());}catch(Exception impossible){return Crypto.utf8("{\"error\":\"LOCAL_OPERATION_FAILED\"}");}}
    private void respond(OutputStream out,int status,String mime,byte[] bytes,String extra) throws IOException {
        String csp="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
        String header="HTTP/1.1 "+status+" "+(status==200?"OK":"Error")+"\r\nContent-Type: "+mime+"\r\nContent-Length: "+bytes.length+"\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: "+csp+"\r\nConnection: close\r\n"+(extra==null?"":extra)+"\r\n";
        out.write(header.getBytes(StandardCharsets.US_ASCII));out.write(bytes);out.flush();
    }
    @Override public void close(){closed=true;try{server.close();}catch(IOException ignored){}clients.shutdownNow();engine.close();}
    void foreground(boolean value){engine.foreground(value);}
    void wakeup(){engine.wakeup();}
    boolean deliveryEnabled(){return engine.deliveryEnabled();}
    void deliveryStopped(){engine.deliveryStopped();}
}
