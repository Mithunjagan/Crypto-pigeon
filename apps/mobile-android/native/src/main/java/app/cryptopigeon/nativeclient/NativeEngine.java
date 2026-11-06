package app.cryptopigeon.nativeclient;

import android.content.Context;
import android.database.Cursor;
import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.json.*;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator;
import app.cryptopigeon.nativeclient.transport.*;

/** The local API contract, executed entirely on the phone. Calls are serialized by LocalBridge. */
final class NativeEngine implements AutoCloseable {
    final Context context;private File vaultRoot;private NativeVault vault;private RelayTransport relay;
    private final NativeVaultCatalog vaultCatalog;
    private String vaultHandle,pendingVaultId;
    final ChangeSignal events=new ChangeSignal();
    private final ScheduledExecutorService background=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"cp-background");t.setDaemon(true);return t;});
    private ScheduledFuture<?> backupTimer;
    private CompletableFuture<Void> backupInFlight;
    private boolean backupDirty,closed;
    private byte[] pendingStorage;
    private android.net.Uri pendingStorageUri;
    private long fileEpoch;
    synchronized long fileEpoch(){return fileEpoch;}
    synchronized byte[] exportFile(String kind,long epoch) throws Exception {if(epoch!=fileEpoch||quickLocked||vault.isLocked())throw new IOException("VAULT_SESSION_CHANGED");return kind.equals("shard7")?vault.shard7File():vault.exportStorage();}
    synchronized void fileSaved(String kind,long epoch,android.net.Uri uri) throws Exception {if(epoch!=fileEpoch||quickLocked||vault.isLocked())throw new IOException("VAULT_SESSION_CHANGED");if(kind.equals("shard7"))confirmVaultCreation();else vault.bindStorage(uri);}
    private void confirmVaultCreation() throws Exception {
        vault.confirmShard7Saved();
        if(pendingVaultId!=null){vaultCatalog.select(pendingVaultId,vaultHandle);pendingVaultId=null;}
    }
    private String browserShard(JSONObject body,String handle){
        JSONObject shards=body.optJSONObject("clientShards");
        if(shards!=null&&shards.has(handle))return shards.optString(handle,null);
        return NativeVaultCatalog.LEGACY.equals(handle)?body.optString("clientShard",null):null;
    }
    private void adoptVault(NativeVault candidate,String handle) throws Exception {
        stopDirect();cancelBackup();drainBackup();clearAuth();
        if(localStorageTimer!=null)localStorageTimer.cancel(false);
        if(reconnectTask!=null)reconnectTask.cancel(false);
        if(transportRouter!=null){transportRouter.close();transportRouter=null;}
        typingUntil.clear();blindRoutingUsed=false;quickLocked=false;pendingVaultId=null;
        if(vault!=candidate)vault.close();vault=candidate;vaultHandle=handle;vaultRoot=vaultCatalog.root(handle);fileEpoch++;
        events.publish("VAULT_CHANGED");
    }
    private JSONObject openVault(String id,char[] password,JSONObject body,byte[] capsule) throws Exception {
        Exception failure=null;
        for(String handle:vaultCatalog.candidates(id)){
            NativeVault candidate=new NativeVault(context,vaultCatalog.root(handle),relay);
            if(!candidate.exists()){candidate.close();continue;}
            try{
                candidate.open(id,password,browserShard(body,handle),capsule);
                vaultCatalog.select(id,handle);adoptVault(candidate,handle);
                return ok().put("vaultHandle",handle);
            }catch(Exception rejected){
                candidate.close();
                if(failure==null){failure=rejected;for(Throwable cause=rejected;cause!=null;cause=cause.getCause())if(cause instanceof javax.crypto.BadPaddingException){failure=new ApiError(401,"INVALID_VAULT_CREDENTIALS");break;}}
            }
        }
        if(failure!=null)throw failure;
        throw new ApiError(401,"INVALID_VAULT_CREDENTIALS");
    }
    private ScheduledFuture<?> localStorageTimer;
    private String accessToken;private long accessExpires;
    private volatile WebSocket pushSocket;private volatile boolean pushConnected;private volatile long reconnectAt;
    private final ConcurrentLinkedQueue<JSONObject> pushedEnvelopes=new ConcurrentLinkedQueue<>();
    private boolean quickLocked;private int pinFailures;private long pinRetryAt;
    private EnvelopeTransportRouter transportRouter;
    private TorOnionTransport tor;
    private final Set<String> torJobs=new HashSet<>();
    private String transportMode(){return context.getSharedPreferences("transport-"+vaultRoot.getName(),0).getString("mode","DIRECT_TOR_P2P");}
    private boolean directOnly(){return transportMode().equals("DIRECT_TOR_P2P");}
    private JSONObject transportStatus() throws Exception {boolean live=tor!=null&&tor.live();return ok().put("mode",transportMode()).put("activeTransport",transportMode().equals("RELAY_ONLY")?"Encrypted Relay":live?"Direct Tor Onion P2P":"Tor connecting").put("serverless",live&&directOnly()).put("bootstrapPercent",tor==null?0:tor.bootstrap()).put("descriptorPublished",tor!=null&&tor.published());}
    private void ensureTor() throws Exception {
        if(closed||vault.isLocked()||quickLocked||decoySession||transportMode().equals("RELAY_ONLY"))return;
        if(PigeonForegroundService.running()&&networkCallback==null)registerConnectivity();
        if(tor!=null&&!tor.stopped())return;
        store().ensureIdentity();final NativeVault owner=vault;
        byte[] auth=db().blob("SELECT private_key FROM device_auth_key WHERE singleton=1");
        try{tor=new TorOnionTransport(context,vaultRoot,store().deviceId(),auth,db().text("SELECT private_key FROM tor_identity WHERE singleton=1"),db().text("SELECT onion FROM tor_identity WHERE singleton=1"),new TorOnionTransport.Host(){
            public void ready(){queueTorRetry(owner);}
            public void identity(String key,String onion) throws Exception {synchronized(NativeEngine.this){if(vault!=owner||owner.isLocked()||quickLocked||closed)throw new IOException("VAULT_SESSION_CHANGED");exec("INSERT INTO tor_identity VALUES(1,?,?)",key,onion);scheduleBackup();}}
            public JSONObject receive(String method,String path,String sender,long time,String nonce,String signature,String body) throws Exception {synchronized(NativeEngine.this){
                if(vault!=owner||owner.isLocked()||quickLocked||closed||sender==null||nonce==null||!nonce.matches("[a-f0-9]{32}"))throw new SecurityException();
                String key=db().text("SELECT auth_key FROM peer_onions WHERE device_id=?",sender);
                if(key==null||signature==null||!Crypto.edVerifySpki(Crypto.unb64(key),TorOnionTransport.signingBytes(sender,time,nonce,method,path,body),Crypto.unb64(signature)))throw new SecurityException();
                if(db().exists("SELECT 1 FROM peer_onions p JOIN contacts c ON c.contact_id=p.contact_id WHERE p.device_id=? AND c.identity_changed=1",sender))throw new SecurityException("IDENTITY_CHANGED");
                if(method.equals("POST")&&path.equals("/p2p/v1/envelopes")){
                    JSONObject packet=new JSONObject(body);String id=packet.getString("envelopeId");
                    if(packet.getInt("version")!=1||!id.replace("-","").matches("[a-f0-9]{32}")||!packet.getString("mailboxId").equals(store().deviceId())||Crypto.unb64(packet.getString("ciphertext")).length>512*1024)throw new SecurityException();
                    packet.put("senderId",sender);exec("INSERT OR IGNORE INTO tor_inbox VALUES(?,?)",id,packet.toString());events.publish("NEW_ENVELOPE");return ok().put("accepted",true);
                }
                java.util.regex.Matcher match=java.util.regex.Pattern.compile("/p2p/v1/attachments/([a-f0-9-]{36})/chunks/(\\d{1,3})").matcher(path);
                if(method.equals("GET")&&match.matches()){
                    String contact=db().text("SELECT contact_id FROM peer_onions WHERE device_id=?",sender);
                    if(!db().exists("SELECT 1 FROM attachments a JOIN messages m ON m.message_id=a.message_id JOIN conversations c ON c.conversation_id=m.conversation_id JOIN tor_attachment_links l ON l.attachment_id=a.attachment_id WHERE c.contact_id=? AND m.direction='sent' AND (m.disappear_at IS NULL OR m.disappear_at>?) AND l.blob_id=?",contact,String.valueOf(System.currentTimeMillis()),match.group(1)))throw new SecurityException();
                    JSONArray found=rows("SELECT nonce,ciphertext FROM tor_chunks WHERE blob_id=? AND chunk_index=?",match.group(1),match.group(2));if(found.length()!=1)throw new IOException("CHUNK_MISSING");return found.getJSONObject(0);
                }throw new IOException("NOT_FOUND");
            }}
        });}finally{Crypto.wipe(auth);}
        JSONArray peers=rows("SELECT device_id,onion FROM peer_onions");for(int i=0;i<peers.length();i++)tor.peer(peers.getJSONObject(i).getString("device_id"),peers.getJSONObject(i).getString("onion"));
        if(transportRouter!=null){transportRouter.close();transportRouter=null;}
    }
    private void transportTick(){synchronized(this){if(closed||vault.isLocked()||quickLocked||decoySession||!appForeground&&!PigeonForegroundService.running())return;try{expire();ensureTor();if(!directOnly()||tor!=null&&tor.live()){sync(null);events.publish("TRANSPORT_CHANGED");}}catch(Exception offline){/* Durable queues retry on the next tick. */}}}
    synchronized boolean deliveryEnabled(){return !closed&&!vault.isLocked()&&!quickLocked&&!decoySession;}
    void deliveryStopped(){try{background.execute(()->{synchronized(this){if(!PigeonForegroundService.running())stopDirect();}});}catch(RejectedExecutionException closing){/* close() already stopped direct transport. */}}
    private volatile boolean appForeground=true,networkAvailable=true;
    private long backgroundReceiveSequence,lastBackgroundReceiveElapsedMs;
    private boolean lastBackgroundReceiveInteractive=true;
    private volatile boolean backgroundSuspended;
    private android.net.ConnectivityManager connectivity;private android.net.ConnectivityManager.NetworkCallback networkCallback;
    private ScheduledFuture<?> suspendTimer;
    private volatile long transportEpoch;
    private void stopDirect(){transportEpoch++;unregisterConnectivity();if(tor!=null){tor.close();tor=null;}if(transportRouter!=null){transportRouter.close();transportRouter=null;}}
    private final java.util.concurrent.atomic.AtomicBoolean torRetryQueued=new java.util.concurrent.atomic.AtomicBoolean();
    private void queueTorRetry(NativeVault owner){
        if(!torRetryQueued.compareAndSet(false,true))return;
        try{background.execute(()->{try{synchronized(this){if(vault!=owner||!deliveryEnabled())return;reconnectAt=0;reconnectAttempts=0;}transportTick();}finally{torRetryQueued.set(false);}});}
        catch(RejectedExecutionException closing){torRetryQueued.set(false);}
    }
    private void unregisterConnectivity(){
        if(connectivity!=null&&networkCallback!=null)try{connectivity.unregisterNetworkCallback(networkCallback);}catch(RuntimeException ignored){}
        networkCallback=null;
    }
    private void scheduleReconnect(){
        long base=Math.min(60000L,1000L<<Math.min(6,reconnectAttempts++));long delay=(long)(base*(0.75+Math.random()*0.5));reconnectAt=System.currentTimeMillis()+delay;
        if(reconnectTask!=null)reconnectTask.cancel(false);
        if(networkAvailable&&!backgroundSuspended&&!closed)reconnectTask=background.schedule(()->{synchronized(this){if(vault.isLocked()||quickLocked||closed)return;try{ensurePush();}catch(Exception unavailable){scheduleReconnect();}}},delay,TimeUnit.MILLISECONDS);
    }
    private void registerConnectivity(){
        connectivity=(android.net.ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(connectivity==null)return;
        final NetworkHandover handover=new NetworkHandover();
        networkCallback=new android.net.ConnectivityManager.NetworkCallback(){
            private void changed(boolean online){
                try{background.execute(()->{synchronized(NativeEngine.this){
                    if(networkCallback!=this||!deliveryEnabled()||!PigeonForegroundService.running())return;
                    networkAvailable=online;stopPush();if(reconnectTask!=null)reconnectTask.cancel(false);reconnectAt=0;reconnectAttempts=0;
                    if(online){try{ensureTor();if(tor!=null)tor.networkChanged();ensurePush();}catch(Exception unavailable){scheduleReconnect();}}
                }});}catch(RejectedExecutionException closing){}
            }
            @Override public void onAvailable(android.net.Network network){if(handover.available(network.toString()))changed(true);}
            @Override public void onLost(android.net.Network network){if(handover.lost(network.toString()))changed(false);}
            @Override public void onCapabilitiesChanged(android.net.Network network,android.net.NetworkCapabilities caps){if(handover.capabilities(network.toString(),caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)))changed(true);}
        };
        try{connectivity.registerDefaultNetworkCallback(networkCallback);}catch(RuntimeException unavailable){networkCallback=null;}
    }
    void foreground(boolean foreground){
        // Activity and screen callbacks must never wait for vault derivation or
        // serialized network/storage work while Android's service deadline runs.
        appForeground=foreground;backgroundSuspended=false;events.publish(foreground?"FOREGROUND":"BACKGROUND");
        try{background.execute(()->{synchronized(this){if(suspendTimer!=null)suspendTimer.cancel(false);if(!foreground||!appForeground||closed||vault.isLocked()||quickLocked||decoySession)return;try{ensurePush();sync(null);}catch(Exception offline){scheduleReconnect();}}});}
        catch(RejectedExecutionException closing){/* Activity teardown after engine close. */}
    }
    void wakeup(){
        if(directOnly()){transportTick();return;}
        if(vault.isLocked()||quickLocked){WakeupNotificationReceiver.notifyLocked(context);return;}
        long started=android.os.SystemClock.elapsedRealtime();background.execute(()->{synchronized(this){
            if(closed||vault.isLocked()||quickLocked)return;
            if(accessToken==null||accessExpires<System.currentTimeMillis()+10000){WakeupNotificationReceiver.notifyLocked(context);return;}
            try{
                Map<String,String> headers=new HashMap<>();headers.put("Authorization","Bearer "+accessToken);
                String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");if(instance!=null)headers.put("X-Vault-Instance",instance);
                RelayTransport.Response response=relay.request("GET","/api/messages/pending",null,headers,10000);
                if(response.ok()){JSONArray incoming=new JSONArray(new String(response.bytes,java.nio.charset.StandardCharsets.UTF_8));for(int i=0;i<incoming.length()&&pushedEnvelopes.size()<256;i++)pushedEnvelopes.add(incoming.getJSONObject(i));events.publish("NEW_ENVELOPE");}
                android.util.Log.i("CryptoPigeonPerf","backgroundWakeupArrivalMs="+(android.os.SystemClock.elapsedRealtime()-started));
            }catch(Exception ignored){}
        }});
    }
    private int reconnectAttempts;private ScheduledFuture<?> reconnectTask;
    private final ExecutorService signalIo=Executors.newSingleThreadExecutor(r->{Thread t=new Thread(r,"cp-signal-io");t.setDaemon(true);return t;});
    private EnvelopeTransportRouter router() throws Exception {
        ensureTor();
        if(transportRouter==null)transportRouter=new EnvelopeTransportRouter(new RelayEnvelopeTransport(packet->{
            String contact=db().text("SELECT contact_id FROM remote_contacts WHERE device_id=?",packet.recipientUid);
            byte[] secret=contact==null?null:db().blob("SELECT send_secret FROM contact_routing WHERE contact_id=?",contact);
            if(secret!=null&&packet.envelopeId.contains("-")&&!"TYPING".equals(packet.envelopeType)){
                JSONObject blind=new JSONObject().put("envelopeId",packet.envelopeId).put("blindDropboxId",routingTag(secret,System.currentTimeMillis()/3600000)).put("ciphertext",Crypto.b64(packet.serializedEncryptedPayload()));
                try{request("POST","/api/blind/send",blind);blindRoutingUsed=true;return;}catch(ApiError incompatible){if(incompatible.status!=404)throw incompatible;}
            }
            JSONObject wire=new JSONObject().put("version",1).put("envelopeId",packet.envelopeId).put("mailboxId",packet.recipientUid).put("ciphertext",Crypto.b64(packet.serializedEncryptedPayload()));
            if("TYPING".equals(packet.envelopeType))wire.put("envelopeType","TYPING").put("createdAtMs",packet.createdAtMs).put("ttlMs",Math.max(1,Math.min(10000,packet.expiresAtMs-packet.createdAtMs)));
            request("POST","/api/messages/send",wire);
        }),tor,uid->false);
        transportRouter.setMode(EnvelopeTransportRouter.TransportMode.valueOf(transportMode()));
        return transportRouter;
    }
    private void persistPacket(String id,String recipient,String type,byte[] encrypted,long created,long expires){
        exec("INSERT OR IGNORE INTO outbox_envelopes VALUES(?,?,?,?,?,?)",id,recipient,type,encrypted,created,expires);
    }
    private void sendPersisted(String id) throws Exception {
        JSONArray packets=rows("SELECT * FROM outbox_envelopes WHERE envelope_id=?",id);
        if(packets.length()!=1)throw new IllegalStateException("missing_encrypted_outbox");JSONObject p=packets.getJSONObject(0);
        EncryptedEnvelopePacket packet=new EncryptedEnvelopePacket(id,p.getString("recipient_uid"),p.getString("envelope_type"),Crypto.unhex(p.getString("serialized_encrypted_payload")),p.getLong("created_at"),p.getLong("expires_at"));
        if(!transportMode().equals("RELAY_ONLY")){
            ensureTor();final TorOnionTransport target=tor;final NativeVault owner=vault;
            final boolean hybrid=transportMode().equals("HYBRID_TOR_RELAY");
            if((target!=null&&target.live()||hybrid)&&torJobs.add(id)){
                final long epoch=transportEpoch;
                CompletableFuture<TransportSendResult> attempt=target!=null&&target.live()?target.sendEnvelope(packet,90000):CompletableFuture.completedFuture(new TransportSendResult(false,"DIRECT_TOR_P2P"));
                attempt.thenCompose(result->result.accepted||!hybrid?CompletableFuture.completedFuture(result):relayFallback(packet,owner,epoch)).whenComplete((result,error)->{synchronized(NativeEngine.this){
                    torJobs.remove(id);if(closed||vault!=owner||owner.isLocked()||quickLocked||tor!=target||error!=null||result==null||!result.accepted)return;
                    db().db().beginTransaction();try{exec("UPDATE messages SET status='sent' WHERE message_id IN (SELECT message_id FROM message_outbox WHERE envelope_id=?) AND status='queued'",id);exec("DELETE FROM message_outbox WHERE envelope_id=?",id);exec("DELETE FROM control_outbox WHERE envelope_id=?",id);exec("DELETE FROM outbox_envelopes WHERE envelope_id=?",id);db().db().setTransactionSuccessful();}finally{db().db().endTransaction();}try{scheduleBackup();events.publish("MESSAGES_CHANGED");}catch(Exception ignored){}
                }});
            }
            throw new IOException("TOR_DELIVERY_QUEUED");
        }
        long started=android.os.SystemClock.elapsedRealtime();TransportSendResult result=router().sendEnvelope(packet).get();
        if(!result.accepted)throw new IOException("TRANSPORT_NOT_ACKNOWLEDGED");
        if(result.transport.equals("RELAY_HTTPS")){android.util.Log.i("CryptoPigeonPerf","relayFallbackDeliveryMs="+(android.os.SystemClock.elapsedRealtime()-started));}
    }
    private CompletableFuture<TransportSendResult> relayFallback(EncryptedEnvelopePacket packet,NativeVault owner,long epoch){
        return CompletableFuture.supplyAsync(()->{try{
            final RelayTransport target;final Map<String,String> headers=new HashMap<>();final List<String> paths=new ArrayList<>();final List<JSONObject> bodies=new ArrayList<>();
            synchronized(NativeEngine.this){
                if(closed||vault!=owner||owner.isLocked()||quickLocked||transportEpoch!=epoch||!transportMode().equals("HYBRID_TOR_RELAY"))throw new IOException("VAULT_SESSION_CHANGED");
                target=relay;headers.put("Authorization","Bearer "+token());String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");if(instance!=null)headers.put("X-Vault-Instance",instance);
                JSONArray blobs=rows("SELECT b.* FROM tor_blobs b JOIN tor_attachment_links l ON l.blob_id=b.blob_id JOIN attachments a ON a.attachment_id=l.attachment_id JOIN message_outbox o ON o.message_id=a.message_id WHERE o.envelope_id=?",packet.envelopeId);
                for(int i=0;i<blobs.length();i++){JSONObject blob=blobs.getJSONObject(i);String id=blob.getString("blob_id");JSONArray chunks=rows("SELECT chunk_index,nonce,ciphertext FROM tor_chunks WHERE blob_id=? ORDER BY chunk_index",id);if(chunks.length()!=blob.getInt("chunk_count"))throw new IOException("CHUNKS_INCOMPLETE");paths.add("/api/attachments/upload");bodies.add(new JSONObject().put("blobId",id).put("chunkCount",blob.getInt("chunk_count")).put("totalSize",blob.getInt("total_size")));for(int j=0;j<chunks.length();j++){JSONObject part=chunks.getJSONObject(j);paths.add("/api/attachments/"+id+"/chunks");bodies.add(new JSONObject().put("chunkIndex",part.getInt("chunk_index")).put("nonce",part.getString("nonce")).put("ciphertext",part.getString("ciphertext")));}}
            }
            paths.add("/api/messages/send");bodies.add(new JSONObject().put("version",1).put("envelopeId",packet.envelopeId).put("mailboxId",packet.recipientUid).put("ciphertext",Crypto.b64(packet.serializedEncryptedPayload())));
            for(int i=0;i<paths.size();i++){if(transportEpoch!=epoch||System.currentTimeMillis()>=packet.expiresAtMs)throw new IOException("VAULT_SESSION_CHANGED");RelayTransport.Response response=target.request("POST",paths.get(i),bodies.get(i),headers);if(!response.ok()){if(response.status==401)synchronized(NativeEngine.this){if(vault==owner&&epoch==transportEpoch){accessToken=null;accessExpires=0;}}return new TransportSendResult(false,"RELAY_HTTPS");}}
            return new TransportSendResult(true,"RELAY_HTTPS");
        }catch(Exception unavailable){return new TransportSendResult(false,"RELAY_HTTPS");}},signalIo);
    }
    private final Map<String,Long> typingUntil=new HashMap<>();
    private volatile boolean blindRoutingUsed;
    private boolean decoySession;
    private android.content.SharedPreferences duressPrefs(){return context.getSharedPreferences(vaultRoot.getName().equals("vault")?"duress":"duress-"+vaultRoot.getName(),0);}
    private String duressTag(String id){return Crypto.hex(Crypto.sha256(Crypto.utf8("cp-duress-v1:"+duressPrefs().getString("salt","")+":"+id)));}
    private static char[] decoyPassword(String id){return (Crypto.hex(Crypto.sha256(Crypto.utf8("cp-decoy-password-v1:"+id)))+"Aa1!").toCharArray();}
    private NativeVault decoyVault(String tag) throws Exception{return new NativeVault(context,new File(vaultRoot.getParentFile(),"decoy-"+tag.substring(0,24)),relay);}
    private JSONObject configureDuress(String id) throws Exception {
        if(decoySession)throw new ApiError(403,"PRIMARY_VAULT_REQUIRED");if(id.length()<16||id.length()>256)throw new ApiError(400,"DURESS_ID_MINIMUM_16_CHARACTERS");
        android.content.SharedPreferences prefs=duressPrefs();
        if(!prefs.contains("salt"))prefs.edit().putString("salt",Crypto.hex(Crypto.random(32))).commit();String tag=duressTag(id);
        char[] password=decoyPassword(id);String browser;
        try(NativeVault decoy=decoyVault(tag)){
            if(decoy.exists())throw new ApiError(409,"DURESS_ID_ALREADY_CONFIGURED");browser=decoy.create(id,password);
            NativeDatabase db=decoy.database();String contact=UUID.randomUUID().toString(),conversation=UUID.randomUUID().toString();long now=System.currentTimeMillis();
            db.db().beginTransaction();try{
                db.db().execSQL("INSERT INTO contacts(contact_id,username,identity_public_key,verified,identity_changed,created_at) VALUES(?,?,?,0,0,?)",new Object[]{contact,"Daily notes",org.signal.libsignal.protocol.IdentityKeyPair.generate().getPublicKey().serialize(),now});
                db.db().execSQL("INSERT INTO remote_contacts(contact_id,user_id,device_id,signal_device_id) VALUES(?,?,?,1)",new Object[]{contact,UUID.randomUUID().toString(),UUID.randomUUID().toString()});
                db.db().execSQL("INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)",new Object[]{conversation,contact,now});
                for(String note:new String[]{"Pick up groceries after work.","Walk in the park this weekend.","Remember to water the plants."})db.db().execSQL("INSERT INTO messages(message_id,conversation_id,direction,plaintext,received_at,status) VALUES(?,?,'received',?,?,'received')",new Object[]{UUID.randomUUID().toString(),conversation,note,now++});
                db.db().setTransactionSuccessful();
            }finally{db.db().endTransaction();}decoy.syncBackup();
        }finally{Arrays.fill(password,'\0');}
        if(!prefs.edit().putString("tag",tag).commit())throw new IOException("LOCAL_SETTINGS_FAILED");return ok().put("decoyClientShard",browser);
    }
    private static String routingTag(byte[] secret,long hour) throws Exception {javax.crypto.Mac mac=javax.crypto.Mac.getInstance("HmacSHA256");mac.init(new javax.crypto.spec.SecretKeySpec(secret,"HmacSHA256"));return Crypto.hex(mac.doFinal(Crypto.utf8("cp-blind-dropbox-v1:"+hour)));}
    private JSONObject routedProfile(String contact) throws Exception {
        byte[] secret=db().blob("SELECT receive_secret FROM contact_routing WHERE contact_id=?",contact);
        if(secret==null){secret=Crypto.random(32);exec("INSERT INTO contact_routing(contact_id,receive_secret) VALUES(?,?)",contact,secret);}
        return profile().put("routingSecret",Crypto.b64(secret));
    }
    private Map<String,String> routingTags() throws Exception {
        Map<String,String> tags=new HashMap<>();JSONArray contacts=rows("SELECT r.device_id,c.receive_secret FROM contact_routing c JOIN remote_contacts r ON r.contact_id=c.contact_id");
        long hour=System.currentTimeMillis()/3600000;
        for(int i=0;i<contacts.length();i++){JSONObject row=contacts.getJSONObject(i);byte[] secret=Crypto.unhex(row.getString("receive_secret"));for(int age=-1;age<=720;age++)tags.put(routingTag(secret,hour-age),row.getString("device_id"));}return tags;
    }
    private String discoveredOrigin;private long lastDiscovery;
    private int authRefreshes,backupRuns,backupFailures;
    private boolean trustedRoute(String url){return url.equals(BuildConfig.RELAY_URL)||url.equals(discoveredOrigin)||url.equals(context.getSharedPreferences("relay",0).getString("previousInternetOrigin",""))||Arrays.asList("http://192.168.1.5:8443","http://127.0.0.1:8443","https://musical-medal-cleared-tube.trycloudflare.com").contains(url);}
    private boolean scheduleBackup(){
        vault.markDirty();
        if(localStorageTimer!=null)localStorageTimer.cancel(false);
        localStorageTimer=background.schedule(()->{synchronized(this){if(closed||vault.isLocked())return;try{vault.persistStorage();events.publish("STORAGE_SAVED");}catch(Exception failed){events.publish("STORAGE_SAVE_FAILED");}}},2,TimeUnit.SECONDS);
        if(!vault.cloudBackupEnabled())return false;
        backupDirty=true;if(backupTimer!=null)backupTimer.cancel(false);
        backupTimer=background.schedule(this::runBackup,60,TimeUnit.SECONDS);return true;
    }
    private void runBackup(){
        NativeVault owner;NativeVault.PreparedBackup prepared;CompletableFuture<Void> active=new CompletableFuture<>();
        synchronized(this){
            if(closed||vault.isLocked()||!backupDirty)return;
            try{owner=vault;prepared=owner.prepareBackgroundBackup();backupDirty=false;backupInFlight=active;backupRuns++;}
            catch(Exception failed){backupFailures++;events.publish("BACKUP_FAILED");scheduleBackup();return;}
        }
        boolean failed=false;
        try{owner.uploadPreparedBackup(prepared);events.publish("BACKUP_SYNCED");}
        catch(Exception unavailable){failed=true;events.publish("BACKUP_FAILED");}
        finally{active.complete(null);}
        synchronized(this){if(vault!=owner)return;backupInFlight=null;if(failed){backupFailures++;if(!closed&&!vault.isLocked())scheduleBackup();}}
    }
    private void cancelBackup(){if(backupTimer!=null)backupTimer.cancel(false);backupTimer=null;backupDirty=false;}
    private void drainBackup(){CompletableFuture<Void> active=backupInFlight;if(active!=null)try{active.get();}catch(Exception ignored){}}
    private void stopPush(){pushedEnvelopes.clear();WebSocket old=pushSocket;pushSocket=null;pushConnected=false;if(old!=null)old.cancel();}
    private void clearAuth(){accessToken=null;accessExpires=0;stopPush();}
    private void ensurePush() throws Exception {
        if(directOnly()){ensureTor();return;}
        if(!networkAvailable||!appForeground&&backgroundSuspended)return;
        String token=token();if(pushSocket!=null||System.currentTimeMillis()<reconnectAt)return;
        String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");
        pushSocket=relay.events(token,instance,new WebSocketListener(){
            @Override public void onOpen(WebSocket socket,okhttp3.Response response){if(socket==pushSocket){pushConnected=true;reconnectAttempts=0;events.publish("CONNECTED");}}
            @Override public void onMessage(WebSocket socket,String text){try{if(socket!=pushSocket)return;JSONObject packet=new JSONObject(text);String type=packet.optString("type");if(type.equals("ENCRYPTED_ENVELOPE")){JSONObject envelope=packet.optJSONObject("envelope");if(envelope!=null&&pushedEnvelopes.size()<256){pushedEnvelopes.add(envelope);events.publish("NEW_ENVELOPE");}return;}if(type.equals("NEW_ENVELOPE")||type.equals("envelope"))events.publish("NEW_ENVELOPE");}catch(Exception ignored){}}
            @Override public void onFailure(WebSocket socket,Throwable error,okhttp3.Response response){if(socket==pushSocket){pushConnected=false;pushSocket=null;scheduleReconnect();}}
            @Override public void onClosed(WebSocket socket,int code,String reason){if(socket==pushSocket){pushConnected=false;pushSocket=null;scheduleReconnect();}}
        });
    }
    private String token() throws Exception {if(accessToken!=null&&System.currentTimeMillis()<accessExpires-5000)return accessToken;return authenticate();}
    NativeEngine(Context context) throws Exception {
        this.context=context.getApplicationContext();vaultCatalog=new NativeVaultCatalog(this.context,new File(context.getNoBackupFilesDir(),"vault"));vaultHandle=vaultCatalog.active();vaultRoot=vaultCatalog.root(vaultHandle);
        discoveredOrigin=context.getSharedPreferences("relay",0).getString("discoveredOrigin",null);
        configure(context.getSharedPreferences("relay",0).getString("origin",BuildConfig.RELAY_URL));
        startBackgroundDelivery();
    }
    private boolean deliveryScheduled;
    synchronized void startBackgroundDelivery(){if(deliveryScheduled)return;deliveryScheduled=true;background.scheduleWithFixedDelay(this::transportTick,2,5,TimeUnit.SECONDS);if(!BuildConfig.RELAY_DISCOVERY_URL.isEmpty())background.scheduleWithFixedDelay(this::discoverRelay,0,60,TimeUnit.SECONDS);}
    NativeEngine(Context context,File root,String url) throws Exception {this.context=context.getApplicationContext();vaultCatalog=new NativeVaultCatalog(this.context,root);vaultHandle=vaultCatalog.active();vaultRoot=vaultCatalog.root(vaultHandle);relay=new RelayTransport(url,true);vault=new NativeVault(context,vaultRoot,relay);}
    private void discoverRelay(){
        if(directOnly())return;
        String previous;
        synchronized(this){
            if(closed||quickLocked||BuildConfig.RELAY_DISCOVERY_URL.isEmpty()||System.currentTimeMillis()-lastDiscovery<15000)return;
            // LAN and manually selected custom relay origins stay user-controlled.
            if(!relay.origin.equals(BuildConfig.RELAY_URL)&&!relay.origin.equals(discoveredOrigin)&&!relay.origin.endsWith(".trycloudflare.com"))return;
            lastDiscovery=System.currentTimeMillis();previous=relay.origin;
        }
        try{
            String next=RelayDiscovery.lookup(BuildConfig.RELAY_DISCOVERY_URL);
            // Validate readiness without vault credentials before replacing the cached working route.
            if(!RelayDiscovery.ready(next))return;
            synchronized(this){
                if(closed||quickLocked||!relay.origin.equals(previous))return;
                discoveredOrigin=next;
                if(!context.getSharedPreferences("relay",0).edit().putString("discoveredOrigin",next).commit())throw new IOException("LOCAL_SETTINGS_FAILED");
                if(!next.equals(previous)){configure(next);events.publish("ROUTE_CHANGED");}
            }
        }catch(Exception retryNextMinute){/* Keep the last working route on any discovery failure. */}
    }
    private void configure(String url) throws Exception {
        RelayTransport next=new RelayTransport(url,true);
        if(relay!=null&&relay.origin.endsWith(".trycloudflare.com"))context.getSharedPreferences("relay",0).edit().putString("previousInternetOrigin",relay.origin).apply();
        if(vault!=null&&!vault.isLocked()){
            if(!trustedRoute(relay.origin)||!trustedRoute(next.origin))throw new IllegalStateException("LOCK_BEFORE_RELAY_CHANGE");
            boolean pending=backupDirty;cancelBackup();drainBackup();clearAuth();vault.setRelay(next);
            if(pending)scheduleBackup();
        }else {if(vault!=null)vault.close();vault=new NativeVault(context,vaultRoot,next);clearAuth();}
        RelayTransport old=relay;relay=next;if(old!=null)old.close();events.publish("ROUTE_CHANGED");
        if(!context.getSharedPreferences("relay",0).edit().putString("origin",relay.origin).commit())throw new IOException("LOCAL_SETTINGS_FAILED");
    }
    String state(){return !vault.exists()?"unconfigured":vault.isLocked()?"locked":quickLocked?"quick_locked":"unlocked";}
    private NativeDatabase db(){return vault.database();}
    private void exec(String sql,Object...args){db().db().execSQL(sql,args);}
    private NativeSignalStore store(){return new NativeSignalStore(db());}
    private JSONObject ok() throws Exception{return new JSONObject().put("ok",true);}
    static final class ApiError extends Exception {final int status;ApiError(int status,String code){super(code);this.status=status;}}
    private RelayTransport.Response checked(RelayTransport.Response response) throws Exception {
        if(!response.ok())throw new ApiError(response.status,response.object().optString("error","RELAY_UNAVAILABLE"));return response;
    }
    private String authenticate() throws Exception {
        NativeSignalStore active=store();if(active.userId()==null)throw new ApiError(409,"DEVICE_NOT_REGISTERED");
        String id=active.deviceId();authRefreshes++;
        JSONObject challenge=checked(relay.request("POST","/api/auth/challenge",new JSONObject().put("deviceId",id),null)).object();
        String hostname=new URI(relay.origin).getRawAuthority(),value=challenge.getString("challenge");
        JSONObject result=checked(relay.request("POST","/api/auth/respond",new JSONObject().put("deviceId",id).put("challenge",value).put("relayHostname",hostname)
            .put("signature",Crypto.hex(active.signDeviceMessage(Crypto.utf8(id+value+hostname)))),null)).object();
        String token=result.getString("sessionToken");accessToken=token;accessExpires=result.getLong("expiresAt");stopPush();exec("INSERT OR REPLACE INTO relay_auth(singleton,access_token) VALUES(1,?)",token);return token;
    }
    private RelayTransport.Response request(String method,String path,JSONObject body) throws Exception {
        if(store().userId()==null)throw new ApiError(409,"DEVICE_NOT_REGISTERED");
        if(!transportMode().equals("RELAY_ONLY")){RelayTransport.Response direct=directRequest(method,path,body);if(direct!=null)return direct;}
        if(directOnly())throw new IOException("RELAY_DISABLED_IN_DIRECT_MODE");
        String token=token();
        Map<String,String> headers=new HashMap<>();headers.put("Authorization","Bearer "+token);
        String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");if(instance!=null)headers.put("X-Vault-Instance",instance);
        RelayTransport.Response response;
        try{response=relay.request(method,path,body,headers);}catch(Exception unavailable){if(!BuildConfig.RELAY_DISCOVERY_URL.isEmpty())background.execute(this::discoverRelay);throw unavailable;}
        if(response.status>=500&&!BuildConfig.RELAY_DISCOVERY_URL.isEmpty())background.execute(this::discoverRelay);
        if(response.status==401){headers.put("Authorization","Bearer "+authenticate());response=relay.request(method,path,body,headers);}
        return checked(response);
    }
    private RelayTransport.Response directResponse(Object value) throws Exception {return new RelayTransport.Response(200,Crypto.utf8(value.toString()));}
    private RelayTransport.Response directRequest(String method,String path,JSONObject body) throws Exception {
        if(path.equals("/api/messages/pending")){
            JSONArray waiting=rows("SELECT envelope FROM tor_inbox LIMIT 256"),packets=new JSONArray();for(int i=0;i<waiting.length();i++)packets.put(new JSONObject(waiting.getJSONObject(i).getString("envelope")));
            return packets.length()>0||directOnly()?directResponse(packets):null;
        }
        if(path.equals("/api/messages/ack")){
            JSONArray remaining=removeDirectAcks(body.getJSONArray("envelopeIds"));body.put("envelopeIds",remaining);return directOnly()||remaining.length()==0?directResponse(ok()):null;
        }
        if(path.equals("/api/attachments/upload")&&method.equals("POST")){
            int size=body.getInt("totalSize"),count=body.getInt("chunkCount");String blob=body.getString("blobId");if(size<0||size>25*1024*1024||count!=Math.max(1,(size+65535)/65536)||!blob.matches("[a-f0-9-]{36}"))throw new ApiError(400,"INVALID_BLOB");
            exec("INSERT INTO tor_blobs VALUES(?,?,?,?)",blob,count,size,System.currentTimeMillis());return directResponse(ok());
        }
        java.util.regex.Matcher upload=java.util.regex.Pattern.compile("/api/attachments/([a-f0-9-]{36})/chunks").matcher(path);
        if(method.equals("POST")&&upload.matches()){
            String count=db().text("SELECT chunk_count FROM tor_blobs WHERE blob_id=?",upload.group(1));int index=body.getInt("chunkIndex");if(count==null||index<0||index>=Integer.parseInt(count)||Crypto.unb64(body.getString("nonce")).length!=12||Crypto.unb64(body.getString("ciphertext")).length>65552)throw new ApiError(400,"INVALID_CHUNK");
            exec("INSERT INTO tor_chunks VALUES(?,?,?,?)",upload.group(1),index,body.getString("nonce"),body.getString("ciphertext"));return directResponse(ok());
        }
        java.util.regex.Matcher download=java.util.regex.Pattern.compile("/api/attachments/([a-f0-9-]{36})/chunks/(\\d{1,3})").matcher(path);
        if(method.equals("GET")&&download.matches()){
            JSONArray cached=rows("SELECT nonce,ciphertext FROM tor_download_chunks WHERE blob_id=? AND chunk_index=?",download.group(1),download.group(2));if(cached.length()==1)return directResponse(cached.getJSONObject(0));
            JSONArray pending=rows("SELECT d.manifest,p.onion FROM attachment_downloads d JOIN attachments a ON a.attachment_id=d.attachment_id JOIN messages m ON m.message_id=a.message_id JOIN conversations c ON c.conversation_id=m.conversation_id JOIN peer_onions p ON p.contact_id=c.contact_id");
            for(int i=0;i<pending.length();i++){JSONObject row=pending.getJSONObject(i);JSONObject manifest=new JSONObject(row.getString("manifest"));if(manifest.getString("blobId").equals(download.group(1))){prefetchChunks(row.getString("onion"),manifest);throw new IOException("TOR_ATTACHMENT_QUEUED");}}
        }
        if(method.equals("DELETE")&&path.matches("/api/attachments/[a-f0-9-]{36}"))return directResponse(ok());
        return null;
    }
    private void prefetchChunks(String onion,JSONObject manifest) throws Exception {
        final TorOnionTransport target=tor;final NativeVault owner=vault;String blob=manifest.getString("blobId"),job="blob:"+blob;
        if(target==null||!target.live()||!torJobs.add(job))return;
        signalIo.execute(()->{try{for(int index=0;index<manifest.getInt("chunkCount");index++){
            JSONObject part;
            try{part=target.request(onion,"GET","/p2p/v1/attachments/"+blob+"/chunks/"+index,"",90000);}catch(Exception unavailable){final RelayTransport fallback;final Map<String,String> headers=new HashMap<>();synchronized(NativeEngine.this){if(closed||vault!=owner||owner.isLocked()||quickLocked||tor!=target||!transportMode().equals("HYBRID_TOR_RELAY"))throw unavailable;fallback=relay;headers.put("Authorization","Bearer "+token());String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");if(instance!=null)headers.put("X-Vault-Instance",instance);}part=checked(fallback.request("GET","/api/attachments/"+blob+"/chunks/"+index,null,headers)).object();}
            if(!part.getString("nonce").equals(manifest.getJSONArray("chunkNonces").getString(index))||Crypto.unb64(part.getString("ciphertext")).length>65552)throw new SecurityException("INVALID_CHUNK");
            synchronized(NativeEngine.this){if(closed||vault!=owner||owner.isLocked()||quickLocked||tor!=target)throw new IOException("VAULT_SESSION_CHANGED");exec("INSERT OR REPLACE INTO tor_download_chunks VALUES(?,?,?,?)",blob,index,part.getString("nonce"),part.getString("ciphertext"));}
        }}catch(Exception retry){}finally{synchronized(NativeEngine.this){torJobs.remove(job);events.publish("ATTACHMENT_CHANGED");}}});
    }

    private JSONArray rows(String sql,String...args) throws Exception {
        JSONArray out=new JSONArray();try(Cursor cursor=db().query(sql,args)){while(cursor.moveToNext()){JSONObject row=new JSONObject();for(int i=0;i<cursor.getColumnCount();i++){
            Object value;switch(cursor.getType(i)){case Cursor.FIELD_TYPE_NULL:value=JSONObject.NULL;break;case Cursor.FIELD_TYPE_INTEGER:value=cursor.getLong(i);break;case Cursor.FIELD_TYPE_FLOAT:value=cursor.getDouble(i);break;case Cursor.FIELD_TYPE_BLOB:value=Crypto.hex(cursor.getBlob(i));break;default:value=cursor.getString(i);}
            row.put(cursor.getColumnName(i),value);
        }out.put(row);}}return out;
    }
    synchronized Object handle(String method,String path,JSONObject body,Map<String,String> query) throws Exception {
        if(quickLocked&&!Arrays.asList("/api/session/unlock","/api/vault/lock","/api/vault/status").contains(path))throw new ApiError(423,"SESSION_PIN_REQUIRED");
        if(path.equals("/api/session/unlock")&&method.equals("POST")){
            if(System.currentTimeMillis()<pinRetryAt)throw new ApiError(429,"PIN_RETRY_LATER");
            String pin=body.optString("pin");byte[] salt=db().blob("SELECT salt FROM session_pin WHERE singleton=1"),digest=db().blob("SELECT digest FROM session_pin WHERE singleton=1");
            byte[] submitted=salt==null?null:Crypto.sha256(Crypto.concat(salt,Crypto.utf8(pin)));
            boolean matches=pin.matches("[0-9]{4}")&&digest!=null&&MessageDigest.isEqual(digest,submitted);
            Crypto.wipe(salt,digest,submitted);
            if(!matches){if(++pinFailures>=5){pinRetryAt=System.currentTimeMillis()+30000;pinFailures=0;}throw new ApiError(401,"INVALID_SESSION_PIN");}
            quickLocked=false;pinFailures=0;return ok();
        }
        if(path.equals("/api/relay/config")){
            if(method.equals("POST"))configure(body.getString("relayUrl"));return new JSONObject().put("relayUrl",relay.origin).put("defaultRelayUrl",discoveredOrigin==null?BuildConfig.RELAY_URL:discoveredOrigin).put("discoveryConfigured",!BuildConfig.RELAY_DISCOVERY_URL.isEmpty());
        }
        if(path.equals("/api/transport/privacy"))return transportStatus().put("relayOnly",transportMode().equals("RELAY_ONLY")).put("sealedSender",blindRoutingUsed).put("blindRouting",blindRoutingUsed).put("liveRelayAnonymity",false).put("duressArmed",duressPrefs().contains("tag"));
        if(path.equals("/api/transport/chat"))return ok();
        if(path.equals("/api/transport/status"))return transportStatus().put("pushConnected",pushConnected).put("authRefreshes",authRefreshes).put("backupPending",backupDirty||backupInFlight!=null).put("backupRuns",backupRuns).put("backupFailures",backupFailures);
        if(path.equals("/api/transport/config")&&method.equals("POST")){
            String mode=body.getString("mode");if(!Arrays.asList("DIRECT_TOR_P2P","HYBRID_TOR_RELAY","RELAY_ONLY").contains(mode))throw new ApiError(400,"INVALID_TRANSPORT_MODE");stopDirect();context.getSharedPreferences("transport-"+vaultRoot.getName(),0).edit().putString("mode",mode).commit();ensureTor();return transportStatus();
        }
        if(path.equals("/api/vault/status"))return new JSONObject().put("requiresVaultId",true).put("vaultState",state()).put("multipleVaults",true).put("vaultHandle",vaultHandle);
        if(path.equals("/api/power/status"))return powerStatus();
        if(path.equals("/api/power/request")&&method.equals("POST")){
            context.getSharedPreferences("background-delivery",0).edit().putBoolean("batteryPrompted",true).commit();
            android.content.Intent settings=new android.content.Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,android.net.Uri.parse("package:"+context.getPackageName())).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            try{context.startActivity(settings);}catch(android.content.ActivityNotFoundException unsupported){context.startActivity(new android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,android.net.Uri.parse("package:"+context.getPackageName())).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));}return powerStatus();
        }
        if(path.equals("/api/power/dismiss")&&method.equals("POST")){context.getSharedPreferences("background-delivery",0).edit().putBoolean("batteryPrompted",true).commit();return powerStatus();}
        if(path.equals("/api/vault/storage")&&method.equals("GET"))return vault.storageStatus();
        if(path.equals("/api/vault/storage/import")&&method.equals("POST")){
            if(!vault.isLocked())throw new ApiError(409,"LOCK_BEFORE_STORAGE_SWITCH");
            byte[] selected=Crypto.unb64(body.getString("storagePayload"));
            try{byte[] metadata=SovereignFiles.envelope(selected,SovereignFiles.STORAGE_HEADER,SovereignFiles.MAX_STORAGE);Crypto.wipe(metadata);pendingStorageUri=null;String uri=body.optString("storageDocumentUri",null);if(uri!=null)for(android.content.UriPermission grant:context.getContentResolver().getPersistedUriPermissions())if(grant.isReadPermission()&&grant.isWritePermission()&&grant.getUri().toString().equals(uri))pendingStorageUri=grant.getUri();Crypto.wipe(pendingStorage);pendingStorage=selected;return ok().put("storageSelected",true);}catch(Exception invalid){Crypto.wipe(selected);throw invalid;}
        }
        if(path.equals("/api/vault/horcrux-status"))return vault.status("true".equals(query.get("clientPresent"))).put("configured",vault.exists()).put("locked",vault.isLocked());
        if(path.matches("/api/vault/(create|open|restore)")&&method.equals("POST")){
            if(!vault.isLocked())throw new ApiError(409,"LOCK_BEFORE_VAULT_SWITCH");
            String id=body.getString("vaultId");char[] password=body.getString("password").toCharArray();
            try{
                if(path.endsWith("open")&&duressTag(id).equals(duressPrefs().getString("tag",null))){
                    stopDirect();cancelBackup();clearAuth();vault.destroyRam();vault=decoyVault(duressTag(id));decoySession=true;
                    char[] decoyKey=decoyPassword(id);try{vault.open(id,decoyKey,body.optString("decoyClientShard",null));}finally{Arrays.fill(decoyKey,'\0');}return ok().put("decoySession",true);
                }
                if(decoySession){vault.close();vault=new NativeVault(context,vaultRoot,relay);decoySession=false;}
                if(path.endsWith("create")){
                    if(vaultCatalog.known(id))throw new ApiError(409,"VAULT_ID_ALREADY_ON_DEVICE");
                    String handle=vaultCatalog.allocate();NativeVault candidate=new NativeVault(context,vaultCatalog.root(handle),relay);
                    try{
                        String shard=candidate.createExternal(id,password);byte[] capsule=candidate.shard7File();
                        try{adoptVault(candidate,handle);pendingVaultId=id;return ok().put("clientShard",shard).put("shard7FileBytes",Crypto.b64(capsule)).put("vaultHandle",handle).put("onboardingPending",true);}finally{Crypto.wipe(capsule);}
                    }catch(Exception failed){if(vault!=candidate)candidate.close();throw failed;}
                }
                if(path.endsWith("restore")){
                    if(!body.optBoolean("transferConfirmed"))throw new ApiError(400,"TRANSFER_CONFIRMATION_REQUIRED");
                    String handle=vaultCatalog.allocate();NativeVault candidate=new NativeVault(context,vaultCatalog.root(handle),relay);
                    try{String browser=candidate.restore(id,password);byte[] capsule=candidate.shard7File();try{adoptVault(candidate,handle);pendingVaultId=id;return ok().put("clientShard",browser).put("shard7FileBytes",Crypto.b64(capsule)).put("vaultHandle",handle);}finally{Crypto.wipe(capsule);}}catch(Exception failed){if(vault!=candidate)candidate.close();throw failed;}
                }
                byte[] capsule=body.has("shard7Payload")?Crypto.unb64(body.getString("shard7Payload")):null;
                try{
                    if(pendingStorage!=null){
                        String handle=vaultCatalog.allocate();NativeVault candidate=new NativeVault(context,vaultCatalog.root(handle),relay);
                        try{String browser=candidate.importStorage(pendingStorage,id,password,capsule);if(pendingStorageUri!=null)candidate.bindStorage(pendingStorageUri);vaultCatalog.select(id,handle);adoptVault(candidate,handle);pendingStorageUri=null;Crypto.wipe(pendingStorage);pendingStorage=null;return ok().put("clientShard",browser).put("vaultHandle",handle);}catch(Exception failed){if(vault!=candidate)candidate.close();throw failed;}
                    }
                    return openVault(id,password,body,capsule);
                }finally{Crypto.wipe(capsule);}
            }finally{Arrays.fill(password,'\0');}
        }
        if(vault.isLocked())throw new ApiError(400,"vault_locked");
        if(path.equals("/api/vault/storage")&&method.equals("POST")){cancelBackup();drainBackup();vault.setCloudBackup(body.getBoolean("cloudBackupEnabled"));if(vault.cloudBackupEnabled())scheduleBackup();return vault.storageStatus();}
        if(path.equals("/api/vault/shard7/saved")&&method.equals("POST")){confirmVaultCreation();return ok();}
        if(path.equals("/api/duress/config")&&method.equals("POST"))return configureDuress(body.getString("duressId"));
        if(decoySession&&path.equals("/api/access/state"))return ok().put("status","activated");
        if(decoySession&&path.equals("/api/fetch-messages")){JSONObject response=ok().put("received",0).put("sent",0).put("typing",false);String conv=body==null?null:body.optString("conversationId",null);if(conv!=null)response.put("conversationId",conv).put("messages",messageRows(conv));return response;}
        if(decoySession&&path.equals("/api/send")){String id=UUID.randomUUID().toString();exec("INSERT INTO messages(message_id,conversation_id,direction,plaintext,sent_at,status) VALUES(?,?,'sent',?,?,'queued')",id,body.getString("conversationId"),body.getString("plaintext"),System.currentTimeMillis());scheduleBackup();return ok().put("messageId",id).put("status","queued");}
        expire();
        if(path.equals("/api/vault/lock")&&method.equals("POST")){fileEpoch++;stopDirect();quickLocked=false;typingUntil.clear();cancelBackup();clearAuth();Crypto.wipe(pendingStorage);pendingStorage=null;if(localStorageTimer!=null)localStorageTimer.cancel(false);events.publish("LOCKED");return vault.syncAndLock(backupInFlight);}
        if(path.equals("/api/vault/sync-backup")&&method.equals("POST")){cancelBackup();drainBackup();return vault.syncBackup();}
        if(path.equals("/api/vault/change-password")&&method.equals("POST")){
            stopDirect();
            cancelBackup();drainBackup();
            char[] old=body.getString("oldPassword").toCharArray(),next=body.getString("newPassword").toCharArray();
            try{String browser=vault.changePassword(body.getString("vaultId"),old,next);vaultCatalog.select(body.getString("vaultId"),vaultHandle);byte[] capsule=vault.shard7File();try{return ok().put("clientShard",browser).put("shard7FileBytes",Crypto.b64(capsule)).put("vaultHandle",vaultHandle);}finally{Crypto.wipe(capsule);}}finally{Arrays.fill(old,'\0');Arrays.fill(next,'\0');}
        }
        if(path.equals("/api/session/pin")&&method.equals("POST")){
            String pin=body.optString("pin");if(!pin.matches("[0-9]{4}"))throw new ApiError(400,"FOUR_DIGIT_PIN_REQUIRED");
            byte[] salt=Crypto.random(32),digest=Crypto.sha256(Crypto.concat(salt,Crypto.utf8(pin)));
            try{exec("INSERT OR REPLACE INTO session_pin(singleton,salt,digest) VALUES(1,?,?)",salt,digest);}finally{Crypto.wipe(salt,digest);}scheduleBackup();return ok();
        }
        if(path.equals("/api/session/lock")&&method.equals("POST")){
            if(!db().exists("SELECT 1 FROM session_pin WHERE singleton=1"))throw new ApiError(409,"SET_SESSION_PIN_FIRST");
            stopDirect();quickLocked=true;typingUntil.clear();events.publish("QUICK_LOCKED");return ok();
        }
        if(path.equals("/api/profile")){
            if(method.equals("POST")){
                String name=body.optString("displayName").trim(),status=body.optString("statusLine").trim();
                if(name.length()>64||status.length()>140)throw new ApiError(400,"PROFILE_TOO_LONG");
                exec("INSERT OR REPLACE INTO consumer_profile(singleton,display_name,status_line) VALUES(1,?,?)",name,status);scheduleBackup();
                JSONArray peers=rows("SELECT conversation_id FROM conversations");for(int i=0;i<peers.length();i++)queueControl(peers.getJSONObject(i).getString("conversation_id"),new JSONObject().put("type","profile"));
                flushControlsLater();
            }
            return profile();
        }
        if(path.equals("/api/contacts/invite")&&method.equals("GET")){
            ensureTor();if(tor==null||!tor.live())throw new ApiError(503,"TOR_NOT_READY");JSONObject own=store().ensureIdentity();
            own.put("publicUid",db().text("SELECT public_uid FROM account_public WHERE singleton=1")).put("username",db().text("SELECT username FROM activation_state WHERE singleton=1")).put("onion",tor.address()).put("userId",store().userId());
            return ok().put("uri",ServerlessInvite.create(own,store()));
        }
        if(path.equals("/api/contacts/import")&&method.equals("POST"))return importServerlessContact(body.getString("uri"));
        if(path.equals("/api/control")&&method.equals("POST")){
            String kind=body.optString("type"),conv=body.getString("conversationId");
            if(!Arrays.asList("typing","read_receipt").contains(kind))throw new ApiError(400,"INVALID_CONTROL");
            if(kind.equals("read_receipt")){
                String remote=db().text("SELECT l.remote_id FROM message_links l JOIN messages m ON m.message_id=l.message_id WHERE m.conversation_id=? AND m.direction='received' ORDER BY m.rowid DESC LIMIT 1",conv);
                if(remote==null)return ok();body.put("upToMessageId",remote);
            }else body.put("expiresAt",System.currentTimeMillis()+5000);
            queueControl(conv,body);flushControlsLater();return ok();
        }
        if(path.equals("/api/access/state")){
            JSONArray states=rows("SELECT request_id AS requestId,username,status FROM activation_state WHERE singleton=1");
            JSONObject state=states.length()==0?new JSONObject().put("status",store().userId()==null?"idle":"activated"):states.getJSONObject(0);
            return state.put("publicUid",db().text("SELECT public_uid FROM account_public WHERE singleton=1"));
        }
        if(path.equals("/api/access/apply")&&method.equals("POST")){
            return selfActivate(body.getString("username"));
        }

        if(path.equals("/api/access/activate")&&method.equals("POST")){
            return activate(body.getString("requestId"),body.getString("activationCode"));
        }

        if(path.equals("/api/contacts"))return rows("SELECT p.display_name AS displayName,p.status_line AS statusLine,c.contact_id,c.username,c.public_uid AS publicUid,c.verified,c.identity_changed,c.safety_number_hash,r.user_id,v.conversation_id,v.disappearing_seconds FROM contacts c LEFT JOIN peer_profiles p ON p.contact_id=c.contact_id JOIN conversations v ON c.contact_id=v.contact_id LEFT JOIN remote_contacts r ON r.contact_id=c.contact_id ORDER BY c.username");
        if(path.equals("/api/contacts/add")&&method.equals("POST")){
            JSONObject bundle=request("POST","/api/prekeys/bundle",new JSONObject().put("recipientUsername",body.getString("username"))).object();
            return ok().put("conversationId",addContact(bundle)).put("backupPending",scheduleBackup());
        }
        if(path.matches("/api/contacts/[^/]+/verify")&&method.equals("POST")){
            String id=java.net.URLDecoder.decode(path.split("/")[3],"UTF-8"),number=body.getString("safetyNumber");
            if(!number.matches("[0-9]{60}")||!db().exists("SELECT 1 FROM contacts WHERE contact_id=? AND safety_number_hash=? AND identity_changed=0",id,number))throw new ApiError(409,"SAFETY_NUMBER_CHANGED");
            exec("UPDATE contacts SET verified=1 WHERE contact_id=?",id);return ok().put("backupPending",scheduleBackup());
        }
        if(path.startsWith("/api/conversations/requests")){
            if(method.equals("GET")&&directOnly())return new JSONArray();
            if(!path.matches("/api/conversations/requests(?:/[a-f0-9-]{36}/(?:accept|reject))?"))throw new ApiError(400,"INVALID_REQUEST");
            RelayTransport.Response response=request(method,path,body);return new JSONTokener(new String(response.bytes,java.nio.charset.StandardCharsets.UTF_8)).nextValue();
        }
        if(path.matches("/api/conversations/[a-f0-9-]{36}/timer")&&method.equals("POST")){
            int seconds=body.getInt("seconds");if(!Arrays.asList(0,3600,86400,604800).contains(seconds))throw new ApiError(400,"INVALID_TIMER");
            exec("UPDATE conversations SET disappearing_seconds=? WHERE conversation_id=?",seconds,path.split("/")[3]);return ok().put("backupPending",scheduleBackup());
        }
        if(path.matches("/api/messages/[a-f0-9-]{36}"))return messageRows(path.split("/")[3]);
        if(path.equals("/api/send")&&method.equals("POST"))return send(body);
        if(path.equals("/api/fetch-messages")&&method.equals("POST")){ensurePush();return sync(body==null?null:body.optString("conversationId",null));}
        if(path.equals("/api/attachments/encrypt")&&method.equals("POST"))return upload(body);
        if(path.matches("/api/attachments/[a-f0-9]{32}/decrypt")){
            String id=path.split("/")[3];byte[] data=NativeAttachmentCache.read(vault,id);
            try{return new JSONObject().put("filename",filename(id)).put("filedataB64",Crypto.b64(data));}finally{Crypto.wipe(data);}
        }
        throw new ApiError(404,"NOT_FOUND");
    }
    private JSONObject selfActivate(String username) throws Exception {
        if(store().userId()!=null)throw new ApiError(409,"ALREADY_REGISTERED");
        if(directOnly()){
            if(!username.matches("[a-z0-9_]{3,32}"))throw new ApiError(400,"INVALID_USERNAME");JSONObject identity=store().ensureIdentity();
            String hash=Crypto.hex(Crypto.sha256(Crypto.utf8("cp-public-uid-v1\0"+identity.getString("identityPublicKey")))).substring(0,8).toUpperCase(Locale.ROOT);String uid="CP-"+hash.substring(0,4)+"-"+hash.substring(4);
            db().db().beginTransaction();try{store().setAccount(identity.getString("deviceId"));exec("INSERT OR REPLACE INTO activation_state(singleton,request_id,username,status,updated_at) VALUES(1,?,?,'activated',?)",UUID.randomUUID().toString(),username,System.currentTimeMillis());exec("INSERT OR REPLACE INTO account_public VALUES(1,?)",uid);db().db().setTransactionSuccessful();}finally{db().db().endTransaction();}scheduleBackup();ensureTor();return ok().put("activated",true).put("publicUid",uid);
        }
        JSONArray claims=rows("SELECT request_id,token FROM access_claim WHERE singleton=1 AND username=?",username);
        if(claims.length()>0)return activate(claims.getJSONObject(0).getString("request_id"),claims.getJSONObject(0).getString("token"));
        JSONObject result=checked(relay.request("POST","/api/access/apply",new JSONObject().put("username",username),null)).object();
        exec("INSERT OR REPLACE INTO access_claim(singleton,request_id,username,token) VALUES(1,?,?,?)",result.getString("requestId"),username,result.getString("activationCode"));
        exec("INSERT OR REPLACE INTO activation_state(singleton,request_id,username,status,updated_at) VALUES(1,?,?,'pending',?)",result.getString("requestId"),username,System.currentTimeMillis());
        return activate(result.getString("requestId"),result.getString("activationCode"));
    }
    private JSONObject activate(String requestId,String code) throws Exception {
            if(store().userId()!=null)throw new ApiError(409,"ALREADY_REGISTERED");
            JSONObject bundle=store().ensureIdentity();bundle.put("requestId",requestId).put("activationCode",code);
            bundle.put("signalIdentityPublicKey",bundle.getString("identityPublicKey"));bundle.remove("identityPublicKey");
            JSONObject result=checked(relay.request("POST","/api/access/activate",bundle,null)).object();
            if(!store().deviceId().equals(result.getString("deviceId")))throw new SecurityException("DEVICE_ID_MISMATCH");
            db().db().beginTransaction();try{
                store().setAccount(result.getString("userId"));exec("INSERT OR REPLACE INTO relay_auth(singleton,access_token) VALUES(1,?)",result.getString("sessionToken"));
                exec("UPDATE activation_state SET status='activated',updated_at=? WHERE singleton=1",System.currentTimeMillis());exec("DELETE FROM access_claim WHERE singleton=1");
                exec("INSERT OR REPLACE INTO account_public(singleton,public_uid) VALUES(1,?)",result.getString("publicUid"));db().db().setTransactionSuccessful();
            }finally{db().db().endTransaction();}accessToken=result.getString("sessionToken");accessExpires=result.getLong("expiresAt");return ok().put("activated",true).put("publicUid",result.getString("publicUid")).put("backupPending",scheduleBackup());
    }
    private JSONObject profile() throws Exception {
        JSONArray list=rows("SELECT display_name AS displayName,status_line AS statusLine FROM consumer_profile WHERE singleton=1");
        return list.length()==0?new JSONObject().put("displayName","").put("statusLine",""):list.getJSONObject(0);
    }
    private void queueControl(String conv,JSONObject payload) throws Exception {
        JSONArray peers=rows("SELECT r.*,c.identity_changed FROM conversations v JOIN remote_contacts r ON r.contact_id=v.contact_id JOIN contacts c ON c.contact_id=v.contact_id WHERE v.conversation_id=?",conv);
        if(peers.length()!=1||peers.getJSONObject(0).optInt("identity_changed")!=0)throw new ApiError(409,"IDENTITY_NOT_READY");
        JSONObject peer=peers.getJSONObject(0);payload.put("profile",routedProfile(peer.getString("contact_id"))).put("senderUid",db().text("SELECT public_uid FROM account_public WHERE singleton=1"));
        db().db().beginTransaction();byte[] plain=Crypto.utf8(payload.toString());try{
            byte[] encrypted=store().encrypt(new SignalProtocolAddress(peer.getString("user_id"),peer.getInt("signal_device_id")),plain);
            exec("INSERT INTO control_outbox(envelope_id,contact_id,mailbox_id,ciphertext,created_at,expires_at) VALUES(?,?,?,?,?,?)",UUID.randomUUID().toString(),peer.getString("contact_id"),peer.getString("device_id"),Crypto.b64(encrypted),System.currentTimeMillis(),"typing".equals(payload.optString("type"))?payload.getLong("expiresAt"):null);
            // Mirror control packets inside this same ratchet transaction; legacy rows remain update-compatible.
            String latest=db().text("SELECT envelope_id FROM control_outbox ORDER BY rowid DESC LIMIT 1");
            persistPacket(latest,peer.getString("device_id"),"typing".equals(payload.optString("type"))?"TYPING":"read_receipt".equals(payload.optString("type"))?"RECEIPT_READ":"RECEIPT_DELIVERED",encrypted,System.currentTimeMillis(),"typing".equals(payload.optString("type"))?payload.getLong("expiresAt"):System.currentTimeMillis()+30L*86400000);
            db().db().setTransactionSuccessful();
        }finally{Crypto.wipe(plain);db().db().endTransaction();}scheduleBackup();
    }
    private void flushControls() throws Exception {
        JSONArray list=rows("SELECT o.* FROM control_outbox o JOIN contacts c ON c.contact_id=o.contact_id WHERE c.identity_changed=0 ORDER BY o.created_at,o.rowid");
        for(int i=0;i<list.length();i++){JSONObject row=list.getJSONObject(i);
            if(!row.isNull("expires_at")&&row.getLong("expires_at")<=System.currentTimeMillis()){exec("DELETE FROM control_outbox WHERE envelope_id=?",row.getString("envelope_id"));exec("DELETE FROM outbox_envelopes WHERE envelope_id=?",row.getString("envelope_id"));continue;}
            JSONObject packet=new JSONObject().put("version",1).put("envelopeId",row.getString("envelope_id")).put("mailboxId",row.getString("mailbox_id")).put("ciphertext",row.getString("ciphertext"));
            if(!row.isNull("expires_at"))packet.put("envelopeType","TYPING").put("createdAtMs",row.getLong("created_at")).put("ttlMs",Math.max(1,Math.min(10000,row.getLong("expires_at")-row.getLong("created_at"))));
            persistPacket(row.getString("envelope_id"),row.getString("mailbox_id"),row.isNull("expires_at")?"RECEIPT_DELIVERED":"TYPING",Crypto.unb64(row.getString("ciphertext")),row.getLong("created_at"),row.isNull("expires_at")?row.getLong("created_at")+30L*86400000:row.getLong("expires_at"));
            try{sendPersisted(row.getString("envelope_id"));}
            catch(Exception unavailable){return;}
            exec("DELETE FROM control_outbox WHERE envelope_id=?",row.getString("envelope_id"));
            exec("DELETE FROM outbox_envelopes WHERE envelope_id=?",row.getString("envelope_id"));
        }
    }
    private void flushControlsLater(){background.execute(()->{synchronized(NativeEngine.this){if(closed||vault.isLocked()||quickLocked||decoySession)return;try{flushControls();}catch(Exception retryOnNextFetch){}}});}
    private JSONArray messageRows(String conversation) throws Exception {return rows("SELECT m.message_id,m.direction,m.plaintext,m.sent_at,m.received_at,m.status,a.attachment_id,a.file_size,a.encrypted_local_path IS NOT NULL AS attachment_ready FROM messages m LEFT JOIN attachments a ON a.message_id=m.message_id WHERE m.conversation_id=? AND (m.disappear_at IS NULL OR m.disappear_at>?) ORDER BY COALESCE(m.sent_at,m.received_at),m.rowid",conversation,String.valueOf(System.currentTimeMillis()));}
    private String conversation(String contact) {
        String id=db().text("SELECT conversation_id FROM conversations WHERE contact_id=?",contact);
        if(id==null){id=UUID.randomUUID().toString();exec("INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)",id,contact,System.currentTimeMillis());}return id;
    }
    private String addContact(JSONObject bundle) throws Exception {
        NativeSignalStore active=store();SignalProtocolAddress address=active.establish(bundle);String contact=address.getName()+"."+address.getDeviceId();
        String number=new NumericFingerprintGenerator(5200).createFor(1,Crypto.utf8(active.userId()),active.getIdentityKeyPair().getPublicKey(),Crypto.utf8(address.getName()),active.getIdentity(address)).getDisplayableFingerprint().getDisplayText();
        exec("INSERT OR REPLACE INTO remote_contacts(contact_id,user_id,device_id,signal_device_id) VALUES(?,?,?,?)",contact,bundle.getString("recipientUserId"),bundle.getString("recipientDeviceId"),bundle.getInt("signalDeviceId"));
        exec("UPDATE contacts SET username=?,public_uid=?,safety_number_hash=? WHERE contact_id=?",bundle.optString("recipientUsername",address.getName()),bundle.optString("publicUid",null),number,contact);
        final String peerDevice=bundle.getString("recipientDeviceId");
        if(!directOnly())background.execute(()->{synchronized(this){if(closed||vault.isLocked()||decoySession)return;try{request("POST","/api/contacts/exchange-ack",new JSONObject().put("peerDeviceId",peerDevice));}catch(Exception oldRelay){}}});
        return conversation(contact);
    }
    private JSONObject importServerlessContact(String uri) throws Exception {
        JSONObject invite=ServerlessInvite.parse(uri);String device=invite.getString("deviceId"),contact=invite.getString("userId")+"."+invite.getInt("signalDeviceId");if(device.equals(store().deviceId()))throw new ApiError(400,"SELF_INVITE");
        JSONArray previous=rows("SELECT * FROM peer_onions WHERE device_id=? OR contact_id=?",device,contact);
        for(int i=0;i<previous.length();i++){JSONObject row=previous.getJSONObject(i);if(!row.getString("contact_id").equals(contact)||!row.getString("onion").equals(invite.getString("onion"))||!row.getString("auth_key").equals(invite.getString("deviceAuthPublicKey")))throw new SecurityException("PINNED_INVITE_CHANGED");}
        JSONArray remotes=rows("SELECT * FROM remote_contacts WHERE device_id=? OR contact_id=?",device,contact);for(int i=0;i<remotes.length();i++){JSONObject row=remotes.getJSONObject(i);if(!row.getString("contact_id").equals(contact)||!row.getString("device_id").equals(device)||!row.getString("user_id").equals(invite.getString("userId"))||row.getInt("signal_device_id")!=invite.getInt("signalDeviceId"))throw new SecurityException("PINNED_DEVICE_CHANGED");}
        if(db().exists("SELECT 1 FROM contacts WHERE contact_id=? AND identity_changed=1",contact))throw new SecurityException("IDENTITY_CHANGED_REQUIRES_REVIEW");
        invite.put("recipientUserId",invite.getString("userId")).put("recipientDeviceId",device).put("recipientUsername",invite.getString("username"));
        db().db().beginTransaction();String conversation;
        try{
            if(!db().exists("SELECT 1 FROM signal_sessions WHERE contact_id=?",contact))conversation=addContact(invite);
            else{byte[] pinned=db().blob("SELECT identity_public_key FROM contacts WHERE contact_id=?",contact);if(pinned==null||!MessageDigest.isEqual(pinned,Crypto.unb64(invite.getString("identityPublicKey"))))throw new SecurityException("PINNED_IDENTITY_CHANGED");conversation=conversation(contact);}
            exec("INSERT OR REPLACE INTO peer_onions VALUES(?,?,?,?,?)",device,contact,invite.getString("onion"),invite.getString("deviceAuthPublicKey"),uri);exec("UPDATE contacts SET username=?,public_uid=?,verified=1,identity_changed=0 WHERE contact_id=?",invite.getString("username"),invite.getString("publicUid"),contact);
            db().db().setTransactionSuccessful();
        }finally{db().db().endTransaction();}if(tor!=null)tor.peer(device,invite.getString("onion"));events.publish("CONTACTS_CHANGED");return ok().put("conversationId",conversation).put("verified",true).put("backupPending",scheduleBackup());
    }
    private JSONObject send(JSONObject body) throws Exception {
        String conversation=body.getString("conversationId"),text=body.getString("plaintext");if(text.length()>65536)throw new ApiError(400,"MESSAGE_TOO_LONG");
        JSONArray destinations=rows("SELECT c.contact_id,c.disappearing_seconds,r.user_id,r.device_id,r.signal_device_id,p.identity_changed FROM conversations c JOIN remote_contacts r ON r.contact_id=c.contact_id JOIN contacts p ON p.contact_id=c.contact_id WHERE c.conversation_id=?",conversation);
        if(destinations.length()!=1)throw new ApiError(404,"conversation_not_found");JSONObject dest=destinations.getJSONObject(0);if(dest.getInt("identity_changed")==1)throw new ApiError(409,"identity_changed_blocked");
        JSONObject attachment=body.optJSONObject("attachmentManifest");if(attachment!=null){validateManifest(attachment);if(!vault.attachmentPath(attachment.getString("attachmentId")).isFile())throw new ApiError(400,"ATTACHMENT_NOT_UPLOADED");}
        String message=UUID.randomUUID().toString();long now=System.currentTimeMillis();int timer=dest.optInt("disappearing_seconds",0);
        db().db().beginTransaction();try{
            JSONObject payload=new JSONObject().put("type","text").put("text",text).put("messageId",message).put("senderUid",db().text("SELECT public_uid FROM account_public WHERE singleton=1")).put("profile",routedProfile(dest.getString("contact_id"))).put("disappearingSeconds",timer);if(attachment!=null)payload.put("attachment",attachment);
            byte[] plain=Crypto.utf8(payload.toString()),encrypted;
            try{encrypted=store().encrypt(new SignalProtocolAddress(dest.getString("user_id"),dest.getInt("signal_device_id")),plain);}finally{Crypto.wipe(plain);}
            exec("INSERT INTO messages(message_id,conversation_id,direction,plaintext,sent_at,status,disappear_at) VALUES(?,?,'sent',?,?,'queued',?)",message,conversation,text,now,timer==0?null:now+timer*1000L);
            String envelopeId=UUID.randomUUID().toString();
            exec("INSERT INTO message_outbox(envelope_id,message_id,mailbox_id,ciphertext,created_at) VALUES(?,?,?,?,?)",envelopeId,message,dest.getString("device_id"),Crypto.b64(encrypted),now);
            persistPacket(envelopeId,dest.getString("device_id"),"MESSAGE",encrypted,now,now+30L*86400000);
            if(attachment!=null){attachmentMetadata(attachment,message,true);if(!transportMode().equals("RELAY_ONLY"))exec("INSERT OR REPLACE INTO tor_attachment_links VALUES(?,?)",attachment.getString("attachmentId"),attachment.getString("blobId"));}db().db().setTransactionSuccessful();
        }finally{db().db().endTransaction();}
        flush();return ok().put("messageId",message).put("status",db().text("SELECT status FROM messages WHERE message_id=?",message)).put("backupPending",scheduleBackup());
    }
    private int flush() throws Exception {
        JSONArray queued=rows("SELECT o.* FROM message_outbox o JOIN messages m ON m.message_id=o.message_id JOIN conversations v ON v.conversation_id=m.conversation_id JOIN contacts c ON c.contact_id=v.contact_id WHERE c.identity_changed=0 AND (m.disappear_at IS NULL OR m.disappear_at>?) ORDER BY o.created_at,o.rowid",String.valueOf(System.currentTimeMillis()));int sent=0;
        for(int i=0;i<queued.length();i++){JSONObject row=queued.getJSONObject(i);
            // Import legacy pending bytes without re-encrypting or advancing Signal.
            persistPacket(row.getString("envelope_id"),row.getString("mailbox_id"),"MESSAGE",Crypto.unb64(row.getString("ciphertext")),row.getLong("created_at"),row.getLong("created_at")+30L*86400000);
            try{sendPersisted(row.getString("envelope_id"));}
            catch(Exception unavailable){break;}
            db().db().beginTransaction();try{exec("UPDATE messages SET status='sent' WHERE message_id=?",row.getString("message_id"));exec("DELETE FROM message_outbox WHERE envelope_id=?",row.getString("envelope_id"));exec("DELETE FROM outbox_envelopes WHERE envelope_id=?",row.getString("envelope_id"));db().db().setTransactionSuccessful();}finally{db().db().endTransaction();}sent++;
        }return sent;
    }
    private JSONObject sync(String conversation) throws Exception {
        int sent=flush(),received=0;JSONArray pending=new JSONArray(),acks=new JSONArray();
        JSONObject pushed;while((pushed=pushedEnvelopes.poll())!=null)pending.put(pushed);
        if(pending.length()==0)pending=new JSONArray(new String(request("GET","/api/messages/pending",null).bytes,java.nio.charset.StandardCharsets.UTF_8));
        Map<String,String> tags=directOnly()||db().exists("SELECT 1 FROM tor_inbox LIMIT 1")?new HashMap<>():routingTags(),blindIds=new HashMap<>();
        List<String> tagList=new ArrayList<>(tags.keySet());
        for(int offset=0;offset<tagList.size();offset+=2000){
            JSONArray selected=new JSONArray(tagList.subList(offset,Math.min(offset+2000,tagList.size())));
            try{JSONArray blind=new JSONArray(new String(request("POST","/api/blind/fetch",new JSONObject().put("dropboxIds",selected)).bytes,java.nio.charset.StandardCharsets.UTF_8));
                for(int i=0;i<blind.length();i++){JSONObject envelope=blind.getJSONObject(i);String tag=envelope.getString("blindDropboxId");if(!tags.containsKey(tag))continue;envelope.put("senderId",tags.get(tag));blindIds.put(envelope.getString("envelopeId").replace("-",""),tag);pending.put(envelope);}
            }catch(ApiError incompatible){if(incompatible.status!=404)throw incompatible;break;}
        }
        received=consumeIncoming(pending,acks);
        JSONArray legacyAcks=new JSONArray(),blindAcks=new JSONArray(),ackTags=new JSONArray();
        for(int i=0;i<acks.length();i++){String id=acks.getString(i);if(blindIds.containsKey(id)){blindAcks.put(id.substring(0,8)+"-"+id.substring(8,12)+"-"+id.substring(12,16)+"-"+id.substring(16,20)+"-"+id.substring(20));ackTags.put(blindIds.get(id));}else legacyAcks.put(id);}
        if(blindAcks.length()>0){try{request("POST","/api/blind/ack",new JSONObject().put("dropboxIds",ackTags).put("envelopeIds",blindAcks));}catch(Exception retryOnNextFetch){}}
        acks=removeDirectAcks(legacyAcks);
        if(!directOnly()&&acks.length()>0){
            // Decryption and durable seen-ID commit already succeeded. A lost or
            // failed ACK is safe: the next fetch deduplicates and acknowledges it.
            final RelayTransport target=relay;final JSONObject acknowledgement=new JSONObject().put("envelopeIds",acks);
            final Map<String,String> headers=new HashMap<>();headers.put("Authorization","Bearer "+token());
            String instance=db().text("SELECT token FROM vault_instance WHERE singleton=1");if(instance!=null)headers.put("X-Vault-Instance",instance);
            background.execute(()->{try{target.request("POST","/api/messages/ack",acknowledgement,headers);}catch(Exception retryOnNextFetch){}});
        }
        if(received+sent>0)scheduleBackup();flushControlsLater();
        JSONObject result=new JSONObject().put("typing",conversation!=null&&!quickLocked&&typingUntil.getOrDefault(conversation,0L)>System.currentTimeMillis()).put("received",received).put("sent",sent).put("backupPending",backupDirty||backupInFlight!=null);
        if(conversation!=null&&conversation.matches("[a-f0-9-]{36}"))result.put("conversationId",conversation).put("messages",messageRows(conversation));
        // Keep attachment transfer off the text-message response path.
        if(db().exists("SELECT 1 FROM attachment_downloads LIMIT 1"))background.execute(()->{synchronized(NativeEngine.this){if(closed||vault.isLocked())return;try{if(downloadPending()>0){scheduleBackup();events.publish("MESSAGES_CHANGED");}}catch(Exception retryOnNextFetch){}}});
        return result;
    }
    private JSONArray removeDirectAcks(JSONArray ids) throws Exception {
        JSONArray remaining=new JSONArray();for(int i=0;i<ids.length();i++){String id=ids.getString(i),normalized=id.replace("-","");if(db().exists("SELECT 1 FROM tor_inbox WHERE replace(envelope_id,'-','')=?",normalized))exec("DELETE FROM tor_inbox WHERE replace(envelope_id,'-','')=?",normalized);else remaining.put(id);}return remaining;
    }
    private JSONObject powerStatus() throws Exception {android.os.PowerManager power=context.getSystemService(android.os.PowerManager.class);return ok().put("native",true).put("ignoringBatteryOptimizations",power.isIgnoringBatteryOptimizations(context.getPackageName())).put("prompted",context.getSharedPreferences("background-delivery",0).getBoolean("batteryPrompted",false)).put("foregroundService",PigeonForegroundService.running()).put("notificationsEnabled",context.getSystemService(android.app.NotificationManager.class).areNotificationsEnabled());}
    private int consumeIncoming(JSONArray pending,JSONArray acks) throws Exception {
        int received=0,visible=0;
        for(int i=0;i<pending.length();i++){
            JSONObject envelope=pending.getJSONObject(i);String id=envelope.getString("envelopeId"),sender=envelope.getString("senderId");
            id=id.replace("-","").toLowerCase(java.util.Locale.ROOT);
            if(envelope.getInt("version")!=1||!id.matches("[a-f0-9]{32}"))continue;
            if(db().exists("SELECT 1 FROM processed_envelope_ids WHERE envelope_id=?",id)){acks.put(id);continue;}
            String contact=db().text("SELECT contact_id FROM remote_contacts WHERE device_id=?",sender);
            if(contact==null){JSONObject bundle=request("POST","/api/prekeys/bundle",new JSONObject().put("recipientDeviceId",sender)).object();addContact(bundle);contact=bundle.getString("recipientUserId")+"."+bundle.getInt("signalDeviceId");}
            if(db().exists("SELECT 1 FROM contacts WHERE contact_id=? AND identity_changed=1",contact))continue;
            JSONArray remotes=rows("SELECT user_id,signal_device_id FROM remote_contacts WHERE contact_id=?",contact);JSONObject remote=remotes.getJSONObject(0);
            db().db().beginTransaction();try{
                byte[] plain=store().decrypt(new SignalProtocolAddress(remote.getString("user_id"),remote.getInt("signal_device_id")),Crypto.unb64(envelope.getString("ciphertext")));JSONObject payload;
                try{payload=new JSONObject(new String(plain,java.nio.charset.StandardCharsets.UTF_8));}finally{Crypto.wipe(plain);}
                String claimedUid=payload.optString("senderUid","");String knownUid=db().text("SELECT public_uid FROM contacts WHERE contact_id=?",contact);
                if(!claimedUid.isEmpty()&&knownUid!=null&&!claimedUid.equals(knownUid))throw new SecurityException("SENDER_IDENTITY_MISMATCH");
                String conv=conversation(contact),kind=payload.optString("type","text");
                JSONObject metadata=payload.optJSONObject("profile");
                if(metadata!=null&&metadata.optString("routingSecret").matches("[A-Za-z0-9+/]{43}=")){
                    byte[] secret=Crypto.unb64(metadata.getString("routingSecret"));if(secret.length==32){routedProfile(contact);exec("UPDATE contact_routing SET send_secret=? WHERE contact_id=?",secret,contact);}
                }
                if(metadata!=null&&metadata.optString("displayName").length()<=64&&metadata.optString("statusLine").length()<=140)
                    exec("INSERT OR REPLACE INTO peer_profiles(contact_id,display_name,status_line) VALUES(?,?,?)",contact,metadata.optString("displayName"),metadata.optString("statusLine"));
                if(!kind.equals("text")){
                    String upTo=payload.optString("upToMessageId");
                    if(kind.equals("typing")){long expiry=payload.optLong("expiresAt");if(!quickLocked&&expiry>System.currentTimeMillis()&&expiry<System.currentTimeMillis()+10000)typingUntil.put(conv,System.currentTimeMillis()+5000);}
                    else if(kind.equals("delivered"))exec("UPDATE messages SET status='delivered' WHERE message_id=? AND conversation_id=? AND direction='sent' AND status IN ('queued','sent')",upTo,conv);
                    else if(kind.equals("read_receipt"))exec("UPDATE messages SET status='read' WHERE conversation_id=? AND direction='sent' AND rowid<=(SELECT rowid FROM messages WHERE message_id=? AND conversation_id=? AND direction='sent')",conv,upTo,conv);
                    exec("INSERT INTO seen_envelope_ids(envelope_id,received_at) VALUES(?,?)",id,System.currentTimeMillis());exec("INSERT INTO processed_envelope_ids VALUES(?,?)",id,System.currentTimeMillis());db().db().setTransactionSuccessful();acks.put(id);received++;continue;
                }
                JSONObject attachment=payload.optJSONObject("attachment");if(attachment!=null)validateManifest(attachment);
                String message=UUID.randomUUID().toString();long now=System.currentTimeMillis();int timer=payload.optInt("disappearingSeconds");if(!Arrays.asList(0,3600,86400,604800).contains(timer))timer=0;
                exec("INSERT INTO messages(message_id,conversation_id,direction,plaintext,received_at,status,disappear_at,remote_blob_id) VALUES(?,?,'received',?,?,'received',?,?)",message,conversation(contact),payload.optString("text"),now,timer==0?null:now+timer*1000L,id);
                String remoteId=payload.optString("messageId");if(remoteId.matches("[a-f0-9-]{36}")){
                    exec("INSERT INTO message_links(message_id,remote_id) VALUES(?,?)",message,remoteId);
                    queueControl(conv,new JSONObject().put("type","delivered").put("upToMessageId",remoteId));
                }
                typingUntil.remove(conv);
                if(attachment!=null){attachmentMetadata(attachment,message,false);exec("INSERT INTO attachment_downloads(attachment_id,manifest) VALUES(?,?)",attachment.getString("attachmentId"),attachment.toString());}
                exec("INSERT INTO seen_envelope_ids(envelope_id,received_at) VALUES(?,?)",id,now);exec("INSERT INTO processed_envelope_ids VALUES(?,?)",id,now);db().db().setTransactionSuccessful();received++;visible++;acks.put(id);
            }catch(Exception invalid){/* Keep the envelope pending; never acknowledge failed decryption. */}finally{db().db().endTransaction();}
        }
        if(received>0)events.publish("MESSAGES_CHANGED");if(visible>0&&!appForeground){backgroundReceiveSequence+=visible;lastBackgroundReceiveElapsedMs=android.os.SystemClock.elapsedRealtime();lastBackgroundReceiveInteractive=context.getSystemService(android.os.PowerManager.class).isInteractive();PigeonForegroundService.message(context);}return received;
    }
    static byte[] chunkAad(String id,int index,int count){return ByteBuffer.allocate(28).put(Crypto.unhex(id)).putInt(index).putInt(count).putInt(1).array();}
    private static byte[] chunk(byte[] data,byte[] key,byte[] nonce,byte[] aad,boolean encrypt) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));cipher.updateAAD(aad);return cipher.doFinal(data);
    }
    private JSONObject upload(JSONObject body) throws Exception {
        byte[] data=Crypto.unb64(body.getString("filedataB64")),key=Crypto.random(32);String id=Crypto.hex(Crypto.random(16)),blob=UUID.randomUUID().toString();
        try{
            if(data.length>25*1024*1024)throw new ApiError(413,"attachment_too_large");int count=Math.max(1,(data.length+65535)/65536);JSONArray nonces=new JSONArray();
            request("POST","/api/attachments/upload",new JSONObject().put("blobId",blob).put("chunkCount",count).put("totalSize",data.length));
            for(int i=0;i<count;i++){byte[] nonce=Crypto.random(12),part=Arrays.copyOfRange(data,i*65536,Math.min((i+1)*65536,data.length)),encrypted=null;
                try{encrypted=chunk(part,key,nonce,chunkAad(id,i,count),true);request("POST","/api/attachments/"+blob+"/chunks",new JSONObject().put("chunkIndex",i).put("nonce",Crypto.b64(nonce)).put("ciphertext",Crypto.b64(encrypted)));nonces.put(Crypto.b64(nonce));}finally{Crypto.wipe(part,encrypted);}}
            String filename=sanitize(body.getString("filename"));if(filename.isEmpty())filename="attachment.bin";
            JSONObject manifest=new JSONObject().put("attachmentId",id).put("blobId",blob).put("originalFilename",filename).put("claimedMimeType",body.optString("mimeType","application/octet-stream"))
                .put("totalPlaintextSize",data.length).put("chunkCount",count).put("chunkSize",65536).put("chunkNonces",nonces).put("fullFileDigest",Crypto.hex(Crypto.sha256(data))).put("attachmentKey",Crypto.b64(key)).put("encryptionVersion",1);
            // Keep the upload unlinked until send() commits its message and
            // attachment metadata. Cleanup may run between these two API calls.
            cache(id,data);return manifest;
        }finally{Crypto.wipe(data,key);}
    }
    private void validateManifest(JSONObject m) throws Exception {
        int size=m.getInt("totalPlaintextSize"),count=m.getInt("chunkCount");
        if(!m.getString("attachmentId").matches("[a-f0-9]{32}")||!m.getString("blobId").matches("[a-f0-9-]{36}")||size<0||size>25*1024*1024||count!=Math.max(1,(size+65535)/65536)||m.getInt("chunkSize")!=65536||m.getInt("encryptionVersion")!=1||m.getJSONArray("chunkNonces").length()!=count||Crypto.unb64(m.getString("attachmentKey")).length!=32||!m.getString("fullFileDigest").matches("[a-f0-9]{64}")||m.getString("originalFilename").length()>255)throw new ApiError(400,"INVALID_ATTACHMENT_MANIFEST");
        for(int i=0;i<count;i++)if(Crypto.unb64(m.getJSONArray("chunkNonces").getString(i)).length!=12)throw new ApiError(400,"INVALID_ATTACHMENT_NONCE");
    }
    private void cache(String id,byte[] bytes) throws Exception {
        byte[] key=vault.attachmentKey();try{Crypto.Sealed sealed=Crypto.seal(bytes,key,"cp-local-attachment-v1:"+id);int n=sealed.ciphertext.length;
            JSONObject json=new JSONObject().put("version",1).put("nonce",Crypto.b64(sealed.nonce)).put("tag",Crypto.b64(Arrays.copyOfRange(sealed.ciphertext,n-16,n))).put("ciphertext",Crypto.b64(Arrays.copyOf(sealed.ciphertext,n-16)));
            NativeIo.atomic(vault.attachmentPath(id),Crypto.concat(Crypto.utf8("CPAGCM1:"),Crypto.utf8(json.toString())));Crypto.wipe(sealed.ciphertext);
        }finally{Crypto.wipe(key);}
    }
    private void attachmentMetadata(JSONObject manifest,String message,boolean ready) throws Exception {
        String id=manifest.getString("attachmentId");byte[] key=vault.attachmentKey(),iv=Crypto.random(16);
        try{Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));
            exec("INSERT INTO attachments(attachment_id,message_id,encrypted_local_path,file_name_encrypted,file_size,file_hash,file_key) VALUES(?,?,?,?,?,?,?)",id,message,ready?vault.attachmentPath(id).getAbsolutePath():null,Crypto.concat(iv,cipher.doFinal(Crypto.utf8(manifest.getString("originalFilename")))),manifest.getLong("totalPlaintextSize"),Crypto.unhex(manifest.getString("fullFileDigest")),Crypto.unb64(manifest.getString("attachmentKey")));
        }finally{Crypto.wipe(key,iv);}
    }
    private int downloadPending() throws Exception {
        JSONArray waiting=rows("SELECT attachment_id,manifest FROM attachment_downloads LIMIT 8");int completed=0;
        for(int row=0;row<waiting.length();row++)try{
            JSONObject manifest=new JSONObject(waiting.getJSONObject(row).getString("manifest"));validateManifest(manifest);String id=manifest.getString("attachmentId"),blob=manifest.getString("blobId");byte[] key=Crypto.unb64(manifest.getString("attachmentKey"));
            try(ByteArrayOutputStream output=new ByteArrayOutputStream()){
                for(int i=0;i<manifest.getInt("chunkCount");i++){
                    JSONObject part=request("GET","/api/attachments/"+blob+"/chunks/"+i,null).object();String nonce=manifest.getJSONArray("chunkNonces").getString(i);
                    if(!nonce.equals(part.getString("nonce")))throw new SecurityException("attachment_nonce_mismatch");
                    byte[] plain=chunk(Crypto.unb64(part.getString("ciphertext")),key,Crypto.unb64(nonce),chunkAad(id,i,manifest.getInt("chunkCount")),false);
                    try{if(output.size()+plain.length>manifest.getInt("totalPlaintextSize"))throw new SecurityException("attachment_size_mismatch");output.write(plain);}finally{Crypto.wipe(plain);}
                }
                byte[] bytes=output.toByteArray();try{if(bytes.length!=manifest.getInt("totalPlaintextSize")||!MessageDigest.isEqual(Crypto.sha256(bytes),Crypto.unhex(manifest.getString("fullFileDigest"))))throw new SecurityException("attachment_integrity_failed");cache(id,bytes);}finally{Crypto.wipe(bytes);}
                exec("UPDATE attachments SET encrypted_local_path=? WHERE attachment_id=?",vault.attachmentPath(id).getAbsolutePath(),id);exec("DELETE FROM attachment_downloads WHERE attachment_id=?",id);completed++;
            }finally{Crypto.wipe(key);}
        }catch(Exception pending){/* Durable manifest retries after reconnection. */}return completed;
    }
    private String filename(String id) throws Exception {
        byte[] key=vault.attachmentKey(),encrypted=db().blob("SELECT file_name_encrypted FROM attachments WHERE attachment_id=?",id);
        try{if(encrypted==null||encrypted.length<32)throw new ApiError(404,"attachment_not_found");Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(Arrays.copyOf(encrypted,16)));return sanitize(new String(cipher.doFinal(encrypted,16,encrypted.length-16),java.nio.charset.StandardCharsets.UTF_8));}finally{Crypto.wipe(key,encrypted);}
    }
    static String sanitize(String name){String cleaned=name.replaceAll("[\\x00-\\x1f\\x7f]","").replaceAll("[\\\\/:*?\"<>|]","_");return cleaned.substring(0,Math.min(255,cleaned.length()));}
    private void expire() throws Exception {
        String now=String.valueOf(System.currentTimeMillis());JSONArray expired=rows("SELECT a.attachment_id FROM attachments a JOIN messages m ON a.message_id=m.message_id WHERE m.disappear_at IS NOT NULL AND m.disappear_at<=?",now);
        for(int i=0;i<expired.length();i++)vault.attachmentPath(expired.getJSONObject(i).getString("attachment_id")).delete();exec("DELETE FROM messages WHERE disappear_at IS NOT NULL AND disappear_at<=?",now);
        exec("DELETE FROM outbox_envelopes WHERE envelope_id NOT IN (SELECT envelope_id FROM message_outbox UNION SELECT envelope_id FROM control_outbox)");
        exec("DELETE FROM tor_blobs WHERE blob_id IN (SELECT l.blob_id FROM tor_attachment_links l LEFT JOIN attachments a ON a.attachment_id=l.attachment_id WHERE a.attachment_id IS NULL) OR (created_at<? AND blob_id NOT IN (SELECT blob_id FROM tor_attachment_links))",System.currentTimeMillis()-86400000);
        exec("DELETE FROM tor_attachment_links WHERE attachment_id NOT IN (SELECT attachment_id FROM attachments)");
        exec("DELETE FROM tor_download_chunks WHERE blob_id NOT IN (SELECT json_extract(manifest,'$.blobId') FROM attachment_downloads)");
    }
    synchronized byte[] attachment(String id) throws Exception {if(quickLocked)throw new ApiError(423,"SESSION_PIN_REQUIRED");if(vault.isLocked())throw new ApiError(400,"vault_locked");expire();return NativeAttachmentCache.read(vault,id);}
    synchronized String attachmentName(String id) throws Exception{if(quickLocked)throw new ApiError(423,"SESSION_PIN_REQUIRED");return filename(id);}
    @Override public synchronized void close(){closed=true;stopDirect();fileEpoch++;Crypto.wipe(pendingStorage);pendingStorage=null;pendingStorageUri=null;cancelBackup();clearAuth();events.publish("CLOSED");if(transportRouter!=null)transportRouter.close();if(connectivity!=null&&networkCallback!=null)try{connectivity.unregisterNetworkCallback(networkCallback);}catch(Exception ignored){}signalIo.shutdownNow();background.shutdownNow();if(relay!=null)relay.close();if(vault!=null){try{if(!vault.isLocked())vault.persistStorage();}catch(Exception ignored){}vault.close();}}
}
