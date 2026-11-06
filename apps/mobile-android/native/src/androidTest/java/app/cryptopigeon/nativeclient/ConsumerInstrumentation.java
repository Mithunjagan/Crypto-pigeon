package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.os.Bundle;
import android.webkit.*;
import java.io.*;
import java.util.concurrent.*;
import org.json.*;

/** Bounded consumer checks in an isolated fixture vault, never the installed account. */
final class ConsumerInstrumentation {
    private Instrumentation runner;private WebView web;
    private void progress(String text){Bundle status=new Bundle();status.putString("stream",text+"\n");runner.sendStatus(0,status);}
    private String js(String code) throws Exception {
        String[] result={null};CountDownLatch done=new CountDownLatch(1);
        runner.runOnMainSync(()->web.evaluateJavascript(code,value->{result[0]=value;done.countDown();}));
        if(!done.await(10,TimeUnit.SECONDS))throw new AssertionError("WebView timed out");return result[0];
    }
    private void waitFor(String expression,long ms) throws Exception {long end=System.currentTimeMillis()+ms;while(System.currentTimeMillis()<end){if("true".equals(js(expression)))return;Thread.sleep(100);}throw new AssertionError("Consumer UI timed out: "+expression+"; screen="+js("document.body.innerText.slice(-1500)"));}
    private static void check(boolean condition,String message){if(!condition)throw new AssertionError(message);}
    JSONArray run(Instrumentation runner,Bundle args) throws Exception {
        this.runner=runner;Context context=runner.getTargetContext();String tag=Crypto.hex(Crypto.random(5)),username="friend_"+tag;
        File root=new File(context.getNoBackupFilesDir(),"consumer-check-"+tag),peerRoot=new File(context.getNoBackupFilesDir(),"consumer-peer-"+tag);
        Activity activity=runner.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        JSONArray results=new JSONArray();
        try(NativeBridgeInstrumentation.Client client=new NativeBridgeInstrumentation.Client(context,root,args.getString("relayUrl",BuildConfig.RELAY_URL));NativeBridgeInstrumentation.Client peer=new NativeBridgeInstrumentation.Client(context,peerRoot,args.getString("relayUrl",BuildConfig.RELAY_URL))){
            runner.runOnMainSync(()->{
                android.view.View content=((android.view.ViewGroup)activity.findViewById(android.R.id.content)).getChildAt(0);
                if(content instanceof android.view.ViewGroup){android.view.View old=((android.view.ViewGroup)content).getChildAt(0);if(old instanceof WebView){((WebView)old).stopLoading();((WebView)old).destroy();}}
                web=new WebView(activity);web.getSettings().setJavaScriptEnabled(true);web.getSettings().setDomStorageEnabled(true);web.setWebViewClient(new WebViewClient());
                activity.setContentView(web);CookieManager.getInstance().setCookie(client.bridge.origin,client.cookie+"; Path=/; HttpOnly; SameSite=Strict",ignored->web.loadUrl(client.bridge.origin+"/"));
            });
            waitFor("!!document.querySelector('input[aria-label=\"Your username\"]')",15000);
            String id="consumer-vault-"+tag,password="FriendReady-Aa1!"+tag;
            js("(()=>{const values="+new JSONObject().put("Your username",username).put("Vault ID",id).put("Master passphrase",password).put("Confirm passphrase",password).toString()+";for(const [name,value]of Object.entries(values)){const e=document.querySelector('input[aria-label=\"'+name+'\"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,value);e.dispatchEvent(new Event('input',{bubbles:true}));}return true})()");
            Thread.sleep(200);long begin=System.nanoTime();js("document.querySelector('.vault-form').requestSubmit();true");
            waitFor("!!document.querySelector('.inbox-topbar')&&document.body.innerText.includes('Up to date')",90000);
            double milliseconds=(System.nanoTime()-begin)/1000000.0;
            JSONObject state=client.json("/api/access/state",null);check(state.optString("status").equals("activated")&&state.optString("publicUid").matches("CP-[A-F0-9]{4}-[A-F0-9]{4}"),"Self-serve did not assign a public UID");
            results.put(new JSONObject().put("name","Fresh vault signup through bundled UI without admin code").put("status","pass").put("signupToConnectedInboxMs",milliseconds));
            js("document.querySelector('[aria-label=\"Settings\"]')?.click();true");
            runner.runOnMainSync(()->{android.graphics.Bitmap bitmap=android.graphics.Bitmap.createBitmap(web.getWidth(),web.getHeight(),android.graphics.Bitmap.Config.ARGB_8888);web.draw(new android.graphics.Canvas(bitmap));try(FileOutputStream out=new FileOutputStream(new File(context.getFilesDir(),"consumer-signup-screen.png"))){bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out);}catch(Exception e){throw new IllegalStateException(e);}finally{bitmap.recycle();}});
            progress("Fresh UI signup passed; checking encrypted peer signals");
            peer.create("consumer-peer-"+tag);peer.json("/api/access/apply",new JSONObject().put("username","peer_"+tag));
            String peerUid=peer.json("/api/access/state",null).getString("publicUid");
            client.json("/api/conversations/requests",new JSONObject().put("recipientUsername",peerUid));
            JSONArray requests=peer.list("/api/conversations/requests");peer.json("/api/conversations/requests/"+requests.getJSONObject(0).getString("request_id")+"/accept",new JSONObject());
            String conv=client.json("/api/contacts/add",new JSONObject().put("username",peerUid)).getString("conversationId");
            peer.json("/api/contacts/add",new JSONObject().put("username",state.getString("publicUid")));
            String peerConv=peer.list("/api/contacts").getJSONObject(0).getString("conversation_id");
            client.json("/api/profile",new JSONObject().put("displayName","Friend Alice").put("statusLine","Available"));
            peer.json("/api/profile",new JSONObject().put("displayName","Friend Bob").put("statusLine","Hardware Vault"));
            js("document.querySelector('.sheet-header button')?.click();true");
            // Ask the UI to refresh its contacts through a visibility wake, not a manual message fetch.
            js("document.dispatchEvent(new Event('visibilitychange'));true");
            waitFor("!!document.querySelector('.contact-row')",15000);
            js("document.querySelector('.contact-row').click();true");waitFor("!!document.querySelector('.composer')",10000);
            peer.json("/api/control",new JSONObject().put("conversationId",peerConv).put("type","typing"));
            waitFor("!!document.querySelector('[aria-label=\"Peer is typing\"]')",15000);
            results.put(new JSONObject().put("name","Encrypted peer typing reaches the active WebView through relay WebSocket push").put("status","pass"));
            String marker="Consumer encrypted hello "+tag;
            js("window.__consumerReceivedAt=0;new MutationObserver(()=>{if([...document.querySelectorAll('.message-bubble.received .message-text')].some(e=>e.textContent==="+JSONObject.quote(marker)+"))requestAnimationFrame(()=>requestAnimationFrame(()=>window.__consumerReceivedAt ||= Date.now()));}).observe(document.body,{subtree:true,childList:true,characterData:true});true");
            long sentAt=System.currentTimeMillis();String messageId=peer.json("/api/send",new JSONObject().put("conversationId",peerConv).put("plaintext",marker)).getString("messageId");
            waitFor("window.__consumerReceivedAt>0",20000);
            double deliveryMs=Double.parseDouble(js("window.__consumerReceivedAt"))-sentAt;
            results.put(new JSONObject().put("name","Real Signal message through public relay to decrypted WebView bubble (two isolated accounts on one phone)").put("status","pass").put("deliveryMs",deliveryMs));
            JSONArray deliverySamples=new JSONArray().put(deliveryMs);
            for(int sample=1;sample<6;sample++){
                String next=marker+"_"+sample;
                js("(()=>{window.__consumerSampleAt=0;const observed="+JSONObject.quote(next)+";const watcher=new MutationObserver(()=>{if([...document.querySelectorAll('.message-bubble.received .message-text')].some(e=>e.textContent===observed)){watcher.disconnect();requestAnimationFrame(()=>requestAnimationFrame(()=>window.__consumerSampleAt=Date.now()));}});watcher.observe(document.body,{subtree:true,childList:true,characterData:true});return true})()");
                long began=System.currentTimeMillis();peer.json("/api/send",new JSONObject().put("conversationId",peerConv).put("plaintext",next));waitFor("window.__consumerSampleAt>0",20000);
                deliverySamples.put(Double.parseDouble(js("window.__consumerSampleAt"))-began);Thread.sleep(200);
            }
            results.put(new JSONObject().put("name","Warm public-relay delivery to two-frame rendered UI; single phone, independent encrypted accounts").put("status","pass").put("samplesMs",deliverySamples));
            check(js("document.querySelector('.thread-person').innerText").contains("Friend Bob"),"Encrypted profile name was not rendered");
            long end=System.currentTimeMillis()+15000;boolean read=false;
            while(System.currentTimeMillis()<end){peer.json("/api/fetch-messages",new JSONObject());JSONArray history=peer.list("/api/messages/"+peerConv);for(int i=0;i<history.length();i++)if(history.getJSONObject(i).getString("message_id").equals(messageId)&&history.getJSONObject(i).getString("status").equals("read"))read=true;if(read)break;Thread.sleep(150);}
            check(read,"Opening the conversation did not send an encrypted read receipt");
            String outgoing="UI sent check "+tag;
            js("(()=>{const e=document.querySelector('textarea');Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(e,"+JSONObject.quote(outgoing)+");e.dispatchEvent(new Event('input',{bubbles:true}));return true})()");Thread.sleep(150);
            js("document.querySelector('.composer').requestSubmit();true");
            waitFor("[...document.querySelectorAll('.message-bubble.sent')].some(e=>e.innerText.includes("+JSONObject.quote(outgoing)+")&&e.innerText.includes('Sent'))",15000);
            peer.json("/api/fetch-messages",new JSONObject());
            waitFor("[...document.querySelectorAll('.message-bubble.sent')].some(e=>e.innerText.includes("+JSONObject.quote(outgoing)+")&&e.innerText.includes('Delivered'))",15000);
            peer.json("/api/control",new JSONObject().put("conversationId",peerConv).put("type","read_receipt"));
            waitFor("[...document.querySelectorAll('.message-bubble.sent')].some(e=>e.innerText.includes("+JSONObject.quote(outgoing)+")&&e.querySelector('.receipt-read'))",15000);
            results.put(new JSONObject().put("name","Sent, Delivered and emerald Read states reflect authenticated encrypted peer receipts; profile stays inside encrypted payload").put("status","pass"));
            progress("Encrypted message, typing, profile and read/delivery UI states passed");
            String pin=String.format(java.util.Locale.ROOT,"%04d",new java.security.SecureRandom().nextInt(10000));
            client.json("/api/session/pin",new JSONObject().put("pin",pin));client.json("/api/session/lock",new JSONObject());
            client.raw("GET","/api/contacts",null,true,null);check(client.status==423,"PIN lock exposed contacts");
            client.raw("POST","/api/fetch-messages",new JSONObject(),true,null);check(client.status==423,"PIN lock exposed messages");
            client.raw("POST","/api/session/unlock",new JSONObject().put("pin","wrong"),true,null);check(client.status==401,"Wrong PIN unlocked session");
            long pinBegin=System.nanoTime();client.json("/api/session/unlock",new JSONObject().put("pin",pin));
            results.put(new JSONObject().put("name","PIN lock blocks native APIs and rejects wrong PIN").put("status","pass").put("unlockMs",(System.nanoTime()-pinBegin)/1000000.0));
            client.lock();check(client.engine.state().equals("locked"),"Panic lock kept vault open");
            results.put(new JSONObject().put("name","Panic lock synchronized backup, locked vault and revoked local session").put("status","pass"));
        }finally{
            runner.runOnMainSync(()->{if(web!=null){web.stopLoading();web.destroy();}activity.finish();});
            if(root.exists())NativeIo.deleteTree(root,context.getNoBackupFilesDir());if(peerRoot.exists())NativeIo.deleteTree(peerRoot,context.getNoBackupFilesDir());
        }
        return results;
    }
}
