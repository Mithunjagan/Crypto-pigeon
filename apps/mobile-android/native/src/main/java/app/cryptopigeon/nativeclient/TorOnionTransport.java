package app.cryptopigeon.nativeclient;

import app.cryptopigeon.nativeclient.transport.*;
import android.content.Context;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.*;

/** App-owned libtor executable, cookie control, and SQLCipher-backed ephemeral v3 service. */
final class TorOnionTransport implements EnvelopeTransportRouter.Direct,AutoCloseable {
    interface Host {
        JSONObject receive(String method,String path,String sender,long time,String nonce,String signature,String body) throws Exception;
        void identity(String key,String onion) throws Exception;
        default void ready(){}
    }
    private final Host host;private final Context context;private final String deviceId;private final byte[] authSeed;
    private final ExecutorService io=Executors.newFixedThreadPool(4);
    private final ScheduledExecutorService monitor=Executors.newSingleThreadScheduledExecutor();
    private final ServerSocket incoming;private final int socksPort,controlPort;private final File directory;
    private volatile boolean closed;private volatile int bootstrap;private volatile String onion="";
    private volatile boolean descriptorPublished;
    private volatile boolean controlReady,circuitReady;
    private long lastNetworkWake=-10000;
    private final java.util.concurrent.atomic.AtomicBoolean recoveryQueued=new java.util.concurrent.atomic.AtomicBoolean();
    private final Set<Socket> outgoingSockets=ConcurrentHashMap.newKeySet();
    private final Set<Socket> activeSockets=ConcurrentHashMap.newKeySet();
    private Process process;private Socket control;private BufferedReader controlInput;private BufferedWriter controlOutput;
    private static void stopProcess(Process owner){
        if(owner==null)return;owner.destroy();
        try{if(!owner.waitFor(2,TimeUnit.SECONDS)){owner.destroyForcibly();owner.waitFor(2,TimeUnit.SECONDS);}}
        catch(InterruptedException interrupted){owner.destroyForcibly();Thread.currentThread().interrupt();}
    }
    TorOnionTransport(Context context,File root,String deviceId,byte[] pkcs8,String savedKey,String savedOnion,Host host) throws Exception {
        this.host=host;this.context=context.getApplicationContext();this.deviceId=deviceId;authSeed=Arrays.copyOfRange(pkcs8,pkcs8.length-32,pkcs8.length);
        directory=new File(root,"tor");if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("TOR_STORAGE_UNAVAILABLE");
        socksPort=freePort();controlPort=freePort();incoming=new ServerSocket(0,16,InetAddress.getByName("127.0.0.1"));
        Thread accept=new Thread(()->{while(!closed)try{Socket socket=incoming.accept();activeSockets.add(socket);if(closed){socket.close();activeSockets.remove(socket);return;}try{io.execute(()->receive(socket));}catch(RuntimeException rejected){socket.close();activeSockets.remove(socket);if(closed)return;}}catch(Exception stopped){if(closed)return;}},"cp-onion-http");accept.setDaemon(true);accept.start();
        String binary=new File(context.getApplicationInfo().nativeLibraryDir,"libtor.so").getAbsolutePath();
        io.execute(()->{try{start(binary,savedKey,savedOnion);}catch(Exception failed){close();}});
    }
    private static int freePort() throws IOException {try(ServerSocket server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))){return server.getLocalPort();}}
    private void start(String binary,String key,String savedOnion) throws Exception {
        File cookie=new File(directory,"control.cookie");
        process=new ProcessBuilder(binary,"--DataDirectory",directory.getAbsolutePath(),"--SocksPort","127.0.0.1:"+socksPort,"--ControlPort","127.0.0.1:"+controlPort,"--CookieAuthentication","1","--CookieAuthFile",cookie.getAbsolutePath(),"--Log","err stdout","--SafeLogging","1")
            .redirectErrorStream(true).redirectOutput(new File("/dev/null")).start();
        if(closed){stopProcess(process);return;}
        for(int i=0;i<100&&!closed;i++){
            try{if(!cookie.isFile())throw new IOException();control=new Socket();control.connect(new InetSocketAddress("127.0.0.1",controlPort),500);break;}catch(IOException retry){if(control!=null)control.close();control=null;Thread.sleep(200);}
        }
        if(closed||control==null)throw new IOException("TOR_START_FAILED");control.setSoTimeout(30000);
        controlInput=new BufferedReader(new InputStreamReader(control.getInputStream(),StandardCharsets.US_ASCII));controlOutput=new BufferedWriter(new OutputStreamWriter(control.getOutputStream(),StandardCharsets.US_ASCII));
        byte[] cookieBytes;try(InputStream input=new FileInputStream(cookie)){cookieBytes=NativeIo.read(input,64);}
        try{command("AUTHENTICATE "+Crypto.hex(cookieBytes));}finally{Crypto.wipe(cookieBytes);}
        command("SETEVENTS STATUS_CLIENT HS_DESC CIRC NETWORK_LIVENESS");
        List<String> answer=command("ADD_ONION "+(key==null?"NEW:ED25519-V3":key)+" Port=80,127.0.0.1:"+incoming.getLocalPort());
        String address=null,secret=null;
        for(String line:answer){if(line.startsWith("250-ServiceID="))address=line.substring(14)+".onion";if(line.startsWith("250-PrivateKey="))secret=line.substring(15);}
        if(address==null||!address.matches("[a-z2-7]{56}\\.onion")||savedOnion!=null&&!savedOnion.equals(address))throw new IOException("TOR_IDENTITY_MISMATCH");
        if(key==null){if(secret==null||!secret.matches("ED25519-V3:[A-Za-z0-9+/]{86}=="))throw new IOException("TOR_INVALID_KEY");host.identity(secret,address);}
        if(closed)return;onion=address;controlReady=true;
        monitor.scheduleWithFixedDelay(()->{try{
            String state=String.join(" ",command("GETINFO status/bootstrap-phase status/circuit-established"));
            java.util.regex.Matcher m=java.util.regex.Pattern.compile("PROGRESS=(\\d+)").matcher(state);
            int next=m.find()?Math.min(100,Integer.parseInt(m.group(1))):0;boolean wake=bootstrap!=100&&next==100;bootstrap=next;
            if(state.contains("status/circuit-established=1")&&!circuitReady){circuitReady=true;wake=true;}
            if(wake&&live())host.ready();
        }catch(Exception stopped){close();}},0,3,TimeUnit.SECONDS);
    }
    void networkChanged(){
        if(closed||!recoveryQueued.compareAndSet(false,true))return;
        // Cancel only obsolete outbound requests; durable ciphertext stays in SQLCipher.
        for(Socket socket:outgoingSockets)try{socket.close();}catch(IOException ignored){}
        try{monitor.execute(this::recoverNetwork);}catch(RejectedExecutionException stopped){recoveryQueued.set(false);}
    }
    private void recoverNetwork(){
        if(closed){recoveryQueued.set(false);return;}
        long delay=Math.max(controlReady?0:1000,10000-(android.os.SystemClock.elapsedRealtime()-lastNetworkWake));
        if(delay>0){monitor.schedule(this::recoverNetwork,delay,TimeUnit.MILLISECONDS);return;}
        try{circuitReady=false;descriptorPublished=false;command("SETCONF DisableNetwork=0");command("SIGNAL NEWNYM");lastNetworkWake=android.os.SystemClock.elapsedRealtime();}
        catch(IOException unavailable){/* The control monitor handles closure; periodic retry remains. */}
        finally{recoveryQueued.set(false);}
    }
    private synchronized List<String> command(String text) throws IOException {
        if(closed||controlOutput==null)throw new IOException("TOR_CLOSED");controlOutput.write(text+"\r\n");controlOutput.flush();
        List<String> lines=new ArrayList<>();String line;while((line=controlInput.readLine())!=null){if(line.length()>8192||lines.size()>100)throw new IOException("TOR_CONTROL_INVALID");if(line.startsWith("650")){
            boolean wake=false;
            if(!onion.isEmpty()&&line.startsWith("650 HS_DESC UPLOADED "+onion.replace(".onion",""))){wake=!descriptorPublished;descriptorPublished=true;}
            if(line.startsWith("650 NETWORK_LIVENESS DOWN")){circuitReady=false;descriptorPublished=false;}
            if((line.matches("650 CIRC [0-9]+ BUILT.*")||line.startsWith("650 NETWORK_LIVENESS UP"))&&!circuitReady){circuitReady=true;wake=true;}
            if(wake&&live())host.ready();continue;
        }lines.add(line);if(line.matches("[0-9]{3} .*")){if(!line.startsWith("250 "))throw new IOException("TOR_CONTROL_FAILED");return lines;}}throw new EOFException();
    }
    int bootstrap(){return bootstrap;}String address(){if(onion.isEmpty())throw new IllegalStateException("TOR_NOT_READY");return onion;}
    boolean live(){return !closed&&bootstrap==100&&!onion.isEmpty();}boolean stopped(){return closed;}
    boolean published(){return !closed&&descriptorPublished;}
    public String transportName(){return "DIRECT_TOR_P2P";}
    public boolean isKnownOffline(String peer){return false;}
    public boolean isReadyForPeer(String peer){return live();}
    public void connectPeer(String peer){}
    private final Map<String,String> peers=new ConcurrentHashMap<>();
    void peer(String device,String onion){if(!onion.matches("[a-z2-7]{56}\\.onion"))throw new IllegalArgumentException("INVALID_ONION");peers.put(device,onion);}
    public CompletableFuture<TransportSendResult> sendEnvelope(EncryptedEnvelopePacket packet,long timeout){
        String peer=peers.get(packet.recipientUid);
        if(peer==null||!live())return CompletableFuture.completedFuture(new TransportSendResult(false,transportName()));
        return CompletableFuture.supplyAsync(()->{try{
            JSONObject wire=new JSONObject().put("version",1).put("envelopeId",packet.envelopeId).put("mailboxId",packet.recipientUid).put("ciphertext",Crypto.b64(packet.serializedEncryptedPayload()));
            JSONObject ack=request(peer,"POST","/p2p/v1/envelopes",wire.toString(),(int)Math.min(90000,timeout));
            return new TransportSendResult(ack.optBoolean("accepted"),transportName());
        }catch(Exception offline){return new TransportSendResult(false,transportName());}},io);
    }
    static byte[] signingBytes(String device,long time,String nonce,String method,String path,String body) throws Exception {
        return Crypto.utf8(new JSONArray().put("cp-onion-request-v1").put(device).put(time).put(nonce).put(method).put(path).put(Crypto.b64(Crypto.utf8(body))).toString().replace("\\/","/"));
    }
    JSONObject request(String onion,String method,String path,String body,int timeout) throws Exception {
        if(!live()||!onion.matches("[a-z2-7]{56}\\.onion")||!path.startsWith("/p2p/v1/"))throw new IOException("TOR_NOT_READY");
        // SOCKS domain form: never send onion hostnames to system DNS.
        try(PigeonForegroundService.ActivityLease lease=PigeonForegroundService.packet(context);Socket socket=new Socket()){
            activeSockets.add(socket);outgoingSockets.add(socket);if(closed)throw new IOException("TOR_CLOSED");
            socket.connect(new InetSocketAddress("127.0.0.1",socksPort),5000);socket.setSoTimeout(Math.max(1000,timeout));
            InputStream in=new BufferedInputStream(socket.getInputStream());OutputStream out=socket.getOutputStream();out.write(new byte[]{5,1,0});out.flush();
            if(in.read()!=5||in.read()!=0)throw new IOException("SOCKS_AUTH_FAILED");byte[] name=onion.getBytes(StandardCharsets.US_ASCII);
            out.write(new byte[]{5,1,0,3,(byte)name.length});out.write(name);out.write(new byte[]{0,80});out.flush();
            if(in.read()!=5||in.read()!=0||in.read()!=0)throw new IOException("TOR_PEER_OFFLINE");int type=in.read(),length=type==1?4:type==4?16:type==3?in.read():-1;if(length<0)throw new IOException("SOCKS_INVALID");read(in,length+2);
            long time=System.currentTimeMillis();String nonce=Crypto.hex(Crypto.random(16));String signature;
            synchronized(authSeed){if(closed)throw new IOException("TOR_CLOSED");signature=Crypto.b64(Crypto.edSign(authSeed,signingBytes(deviceId,time,nonce,method,path,body)));}
            byte[] bytes=Crypto.utf8(body);String header=method+" "+path+" HTTP/1.1\r\nHost: "+onion+"\r\nContent-Type: application/json\r\nContent-Length: "+bytes.length+"\r\nX-Pigeon-Sender: "+deviceId+"\r\nX-Pigeon-Time: "+time+"\r\nX-Pigeon-Nonce: "+nonce+"\r\nX-Pigeon-Signature: "+signature+"\r\nConnection: close\r\n\r\n";
            out.write(header.getBytes(StandardCharsets.US_ASCII));out.write(bytes);out.flush();String status=line(in);if(status==null||!status.matches("HTTP/1\\.[01] 200 .*"))throw new IOException("PEER_REJECTED");
            Map<String,String> headers=headers(in);int size=Integer.parseInt(headers.getOrDefault("content-length","-1"));if(size<0||size>192*1024)throw new IOException("INVALID_RESPONSE");return new JSONObject(new String(read(in,size),StandardCharsets.UTF_8));
        }finally{activeSockets.removeIf(Socket::isClosed);outgoingSockets.removeIf(Socket::isClosed);}
    }
    private void receive(Socket socket){try(PigeonForegroundService.ActivityLease lease=PigeonForegroundService.packet(context);Socket client=socket){client.setSoTimeout(90000);InputStream in=new BufferedInputStream(client.getInputStream());OutputStream out=client.getOutputStream();
        try{String first=line(in);if(first==null)return;String[] parts=first.split(" ");if(parts.length!=3)throw new IOException();Map<String,String> headers=headers(in);if(headers.containsKey("transfer-encoding"))throw new IOException();
            long arrived=System.currentTimeMillis(),time=Long.parseLong(headers.getOrDefault("x-pigeon-time","0"));if(time<arrived-120000||time>arrived+120000)throw new SecurityException();
            int size=Integer.parseInt(headers.getOrDefault("content-length","0"));if(size<0||size>768*1024)throw new IOException();String body=new String(read(in,size),StandardCharsets.UTF_8);
            JSONObject result=host.receive(parts[0],parts[1],headers.get("x-pigeon-sender"),time,headers.get("x-pigeon-nonce"),headers.get("x-pigeon-signature"),body);
            byte[] bytes=Crypto.utf8(result.toString());out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "+bytes.length+"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(bytes);out.flush();
        }catch(Exception invalid){out.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));}
    }catch(Exception stopped){}finally{activeSockets.remove(socket);}}
    private static Map<String,String> headers(InputStream in) throws IOException {Map<String,String> headers=new HashMap<>();String next;int size=0;while((next=line(in))!=null&&!next.isEmpty()){size+=next.length();int colon=next.indexOf(':');if(size>16384||colon<=0)throw new IOException();if(headers.put(next.substring(0,colon).toLowerCase(Locale.ROOT),next.substring(colon+1).trim())!=null)throw new IOException();}return headers;}
    private static String line(InputStream in) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();int c;while((c=in.read())!=-1){if(c=='\n')break;if(c!='\r')out.write(c);if(out.size()>8192)throw new IOException();}return c<0&&out.size()==0?null:out.toString("US-ASCII");}
    private static byte[] read(InputStream in,int length) throws IOException {byte[] bytes=new byte[length];int offset=0,n;while(offset<length){n=in.read(bytes,offset,length-offset);if(n<0)throw new EOFException();offset+=n;}return bytes;}
    public void close(){if(closed)return;closed=true;bootstrap=0;onion="";try{incoming.close();}catch(Exception ignored){}for(Socket socket:activeSockets)try{socket.close();}catch(Exception ignored){}activeSockets.clear();try{if(control!=null)control.close();}catch(Exception ignored){}monitor.shutdownNow();io.shutdownNow();stopProcess(process);synchronized(authSeed){Crypto.wipe(authSeed);}peers.clear();}
}
