package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.graphics.Rect;
import android.os.*;
import android.view.*;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.inputmethod.*;
import android.webkit.*;
import java.io.*;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import org.json.*;

/** Slow live demo on separate vault roots, using real UI, SAF and public relay. */
final class VisualDemoInstrumentation {
    private Instrumentation runner;private MainActivity activity;private WebView web;private String tag;
    private String js(String code) throws Exception {String[] value={null};CountDownLatch ready=new CountDownLatch(1);runner.runOnMainSync(()->web.evaluateJavascript(code,result->{value[0]=result;ready.countDown();}));if(!ready.await(10,TimeUnit.SECONDS))throw new AssertionError("WebView timeout");return value[0];}
    private void waitFor(String expression,long timeout) throws Exception {long end=System.currentTimeMillis()+timeout;while(System.currentTimeMillis()<end){if("true".equals(js(expression)))return;Thread.sleep(150);}throw new AssertionError("Demo stopped: "+expression+"; screen="+js("document.body.innerText.slice(-1000)"));}
    private Object field(Object object,String name) throws Exception {Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);}
    private void step(String text) throws Exception {Bundle event=new Bundle();event.putString("stream","DEMO: "+text+"\n");runner.sendStatus(0,event);boolean[] focus={false};runner.runOnMainSync(()->focus[0]=activity.hasWindowFocus());Thread.sleep(focus[0]?6000:600);}
    private void pointer(float x,float y) throws Exception {long now=SystemClock.uptimeMillis();MotionEvent down=MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,x,y,0),up=MotionEvent.obtain(now,now+60,MotionEvent.ACTION_UP,x,y,0);down.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);up.setSource(android.view.InputDevice.SOURCE_TOUCHSCREEN);try{if(!runner.getUiAutomation().injectInputEvent(down,true)||!runner.getUiAutomation().injectInputEvent(up,true))throw new AssertionError("System touch injection failed");}finally{down.recycle();up.recycle();}}
    private void tap(String selector) throws Exception {
        tap(selector,1);
    }
    private void tap(String selector,int count) throws Exception {
        boolean[] focus={false};runner.runOnMainSync(()->focus[0]=activity.hasWindowFocus());if(!focus[0])throw new AssertionError("Phone is in another app; demo taps stopped");
        waitFor("!!document.querySelector("+JSONObject.quote(selector)+")",10000);js("document.querySelector("+JSONObject.quote(selector)+").scrollIntoView({block:'center'});true");Thread.sleep(300);
        JSONObject r=new JSONObject(js("(()=>{const r=document.querySelector("+JSONObject.quote(selector)+").getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2-(visualViewport?.offsetTop||0),w:innerWidth}})()"));int[] origin=new int[2];runner.runOnMainSync(()->web.getLocationOnScreen(origin));float scale=web.getWidth()/(float)r.getDouble("w");for(int i=0;i<count;i++){pointer(origin[0]+(float)r.getDouble("x")*scale,origin[1]+(float)r.getDouble("y")*scale);Thread.sleep(130);}
    }
    private void type(String selector,String text) throws Exception {
        tap(selector);Thread.sleep(500);InputConnection[] connection={null};runner.runOnMainSync(()->connection[0]=web.onCreateInputConnection(new EditorInfo()));if(connection[0]==null)throw new AssertionError("Keyboard connection missing");
        for(char c:text.toCharArray()){runner.runOnMainSync(()->connection[0].commitText(String.valueOf(c),1));Thread.sleep(85);}
        Thread.sleep(500);runner.runOnMainSync(()->((InputMethodManager)activity.getSystemService(Context.INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(web.getWindowToken(),0));Thread.sleep(350);
    }
    private AccessibilityNodeInfo node(String text,boolean editable){AccessibilityNodeInfo root=runner.getUiAutomation().getRootInActiveWindow();return find(root,text,editable);}
    private AccessibilityNodeInfo find(AccessibilityNodeInfo n,String text,boolean editable){if(n==null)return null;String value=n.getText()==null?"":n.getText().toString();boolean file=text.startsWith("demo-")&&text.endsWith(".cp7"),matches=value.equalsIgnoreCase(text)||file&&value.startsWith(text.substring(0,12));if(n.isVisibleToUser()&&(editable?n.isEditable():!n.isEditable()&&matches))return n;for(int i=0;i<n.getChildCount();i++){AccessibilityNodeInfo found=find(n.getChild(i),text,editable);if(found!=null)return found;}return null;}
    private void systemTap(String text) throws Exception {
        long end=System.currentTimeMillis()+10000;AccessibilityNodeInfo target;
        while((target=node(text,false))==null&&System.currentTimeMillis()<end)Thread.sleep(200);
        if(target==null)throw new AssertionError("System file dialog item not found: "+text);
        Rect rect=new Rect();target.getBoundsInScreen(rect);pointer(rect.centerX(),rect.centerY());
    }
    private AccessibilityNodeInfo searchButton(AccessibilityNodeInfo node){if(node==null)return null;String description=String.valueOf(node.getContentDescription()).toLowerCase(java.util.Locale.ROOT);if(node.isVisibleToUser()&&description.contains("search"))return node;for(int i=0;i<node.getChildCount();i++){AccessibilityNodeInfo found=searchButton(node.getChild(i));if(found!=null)return found;}return null;}
    private void chooseSegment(String filename) throws Exception {
        Thread.sleep(500);AccessibilityNodeInfo root=runner.getUiAutomation().getRootInActiveWindow();
        if(root==null||!String.valueOf(root.getPackageName()).contains("documentsui"))throw new AssertionError("File Explorer is not foreground; no system taps sent");
        if(node(filename,false)==null){
            AccessibilityNodeInfo search=searchButton(root);if(search==null)throw new AssertionError("File Explorer search control unavailable");Rect bounds=new Rect();search.getBoundsInScreen(bounds);pointer(bounds.centerX(),bounds.centerY());Thread.sleep(350);
            AccessibilityNodeInfo editor=node("",true);if(editor==null)throw new AssertionError("File Explorer search field unavailable");Bundle query=new Bundle();query.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,filename);editor.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,query);Thread.sleep(700);
        }
        systemTap(filename);
        long until=SystemClock.uptimeMillis()+15000;boolean[] focus={false};while(SystemClock.uptimeMillis()<until){runner.runOnMainSync(()->focus[0]=activity.hasWindowFocus());if(focus[0])return;Thread.sleep(100);}throw new AssertionError("File selection did not return to Crypto Pigeon");
    }
    private void saveDialog(String filename) throws Exception {
        long end=System.currentTimeMillis()+10000;AccessibilityNodeInfo editor;
        while((editor=node("",true))==null&&System.currentTimeMillis()<end)Thread.sleep(200);
        if(editor==null)throw new AssertionError("Native filename field unavailable");Bundle text=new Bundle();text.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,filename);if(!editor.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT,text))throw new AssertionError("Could not name demo file");
        step("Android file saver: saving "+filename+" in the displayed folder.");systemTap("Save");
    }
    private void snapshot(String name) throws Exception {runner.runOnMainSync(()->{android.graphics.Bitmap bitmap=android.graphics.Bitmap.createBitmap(web.getWidth(),web.getHeight(),android.graphics.Bitmap.Config.ARGB_8888);web.draw(new android.graphics.Canvas(bitmap));try(FileOutputStream out=new FileOutputStream(new File(activity.getFilesDir(),"visual-demo-"+name+".png"))){bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,out);}catch(Exception error){throw new IllegalStateException(error);}finally{bitmap.recycle();}});}
    private JSONObject pass(String name) throws Exception {return new JSONObject().put("name",name).put("status","pass");}
    JSONArray run(Instrumentation runner,Bundle args) throws Exception {
        this.runner=runner;Context context=runner.getTargetContext();tag=Crypto.hex(Crypto.random(3));String relay=args.getString("relayUrl",BuildConfig.RELAY_URL),id="DemoVault-"+tag,password="Demo-Only-Aa123456!",username="demo_you_"+tag,peerName="demo_friend_"+tag,segment="demo-"+tag+"-segment.cp7";
        File root=new File(context.getNoBackupFilesDir(),"visual-demo-"+tag),peerRoot=new File(context.getNoBackupFilesDir(),"visual-peer-"+tag);JSONArray results=new JSONArray();
        Bundle launching=new Bundle();launching.putString("stream","DEMO: Opening a clean app screen; existing vault data is preserved.\n");runner.sendStatus(0,launching);
        activity=(MainActivity)runner.startActivitySync(new Intent(context,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK));web=(WebView)field(activity,"view");
        NativeEngine engine=new NativeEngine(context,root,relay);LocalBridge bridge=new LocalBridge(context,engine,false),previous=(LocalBridge)field(activity,"bridge");
        Field bridgeField=MainActivity.class.getDeclaredField("bridge");bridgeField.setAccessible(true);runner.runOnMainSync(()->{try{bridgeField.set(activity,bridge);activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);web.loadUrl(bridge.entry());}catch(Exception error){throw new IllegalStateException(error);}});previous.close();
        try(NativeBridgeInstrumentation.Client peer=new NativeBridgeInstrumentation.Client(context,peerRoot,relay)){
            waitFor("!!document.querySelector('input[aria-label=\"Your username\"]')",15000);
            step("1/9 — Create vault. This is a fresh DEMO account; your original vault is untouched.");
            type("input[aria-label='Your username']",username);Thread.sleep(1500);type("input[aria-label='Vault ID']",id);Thread.sleep(1500);type("input[aria-label='Master passphrase']",password);type("input[aria-label='Confirm passphrase']",password);
            snapshot("create");step("2/9 — Username and private vault credentials entered. Pressing Create vault.");tap(".gate-submit");
            waitFor("document.querySelector('.vault-form')?.hidden===true",45000);step("3/9 — The separate seventh segment must be saved before proceeding.");tap(".vault-card > .stack .btn-primary");saveDialog(segment);
            waitFor("!!document.querySelector('.registration-section form')",45000);results.put(pass("Created a new external-file vault through the bundled UI and saved Shard 7 through the real Android document dialog"));
            step("4/9 — Choose your public username, then Create identity. This needs the live relay.");tap(".registration-section button[type='submit'],.registration-section form .btn-primary");waitFor("!!document.querySelector('.inbox-topbar')&&!document.querySelector('.registration-section')",60000);
            NativeVault vault=(NativeVault)field(engine,"vault");String uid=vault.database().text("SELECT public_uid FROM account_public WHERE singleton=1");if(uid==null)throw new AssertionError("Signup did not assign a UID");snapshot("registered");results.put(pass("Live public-relay signup assigned a real public UID"));
            // Independent native peer uses the same public relay and Signal engine.
            peer.create("demo-peer-"+tag);peer.json("/api/vault/shard7/saved",new JSONObject());peer.json("/api/access/apply",new JSONObject().put("username",peerName));String peerUid=peer.json("/api/access/state",null).getString("publicUid");
            peer.json("/api/profile",new JSONObject().put("displayName","Demo Friend").put("statusLine","Live encrypted demo"));
            step("5/9 — Fully locking the new vault. Next we will load its file and reopen it.");tap("button[aria-label='Fully lock vault']");waitFor("!!document.querySelector('.vault-gate')",15000);Thread.sleep(1500);
            step("6/9 — Five taps on the top-right of Segment 07 open File Explorer.");tap(".segment-hit-zone",5);step("File Explorer is open. Selecting the segment file we just saved.");
            chooseSegment(segment);
            waitFor("document.body.innerText.includes('07 LOADED')",15000);type("input[aria-label='Vault ID']",id);type("input[aria-label='Master passphrase']",password);snapshot("unlock");step("The segment is loaded. Unlocking with the same Vault ID and passphrase.");tap(".gate-submit");waitFor("!!document.querySelector('.inbox-topbar')",45000);results.put(pass("Cold-locked then reopened through the real five-tap file picker and credential fields"));
            step("7/9 — Opening a new connection and inviting the independent Demo Friend account.");tap("button[aria-label='New connection']");type("input[placeholder='CP-XXXX-XXXX or username']",peerUid);tap("[aria-label='New connection'] form button[type='button']");
            long end=System.currentTimeMillis()+15000;JSONArray requests;while((requests=peer.list("/api/conversations/requests")).length()==0&&System.currentTimeMillis()<end)Thread.sleep(300);if(requests.length()==0)throw new AssertionError("Invitation not received");
            step("Demo Friend received the invitation and is accepting it on the relay.");peer.json("/api/conversations/requests/"+requests.getJSONObject(0).getString("request_id")+"/accept",new JSONObject());peer.json("/api/contacts/add",new JSONObject().put("username",uid));String peerConv=peer.list("/api/contacts").getJSONObject(0).getString("conversation_id");
            waitFor("!!document.querySelector('.contact-row')",40000);step("The request is accepted. Opening Demo Friend from the Chats list.");tap(".contact-row");waitFor("!!document.querySelector('.composer textarea')",15000);snapshot("connected");results.put(pass("Live invitation, acceptance and independent Signal sessions established"));
            step("8/9 — Typing and sending a message from your phone through the real composer.");String outgoing="Hello Demo Friend! Sent from this phone.";type(".composer textarea",outgoing);Thread.sleep(2500);tap("button[aria-label='Send message']");
            end=System.currentTimeMillis()+20000;boolean received=false;while(System.currentTimeMillis()<end){peer.json("/api/fetch-messages",new JSONObject());JSONArray history=peer.list("/api/messages/"+peerConv);for(int i=0;i<history.length();i++)if(outgoing.equals(history.getJSONObject(i).optString("plaintext")))received=true;if(received)break;Thread.sleep(400);}if(!received)throw new AssertionError("Peer did not decrypt the phone's message");
            step("9/9 — Demo Friend decrypted your message. Sending a live encrypted reply now.");peer.json("/api/control",new JSONObject().put("conversationId",peerConv).put("type","typing"));Thread.sleep(4000);peer.json("/api/send",new JSONObject().put("conversationId",peerConv).put("plaintext","Hi! I received your message. This reply travelled through the live relay."));
            waitFor("document.body.innerText.includes('This reply travelled through the live relay.')",25000);peer.json("/api/control",new JSONObject().put("conversationId",peerConv).put("type","read_receipt"));snapshot("chat");results.put(pass("Phone composer message decrypted by independent account; live encrypted reply rendered in the phone chat"));
            step("Demo complete. Both directions worked. Leaving this conversation visible for one minute.");Thread.sleep(45000);
            try(FileOutputStream out=new FileOutputStream(new File(context.getFilesDir(),"visual-demo-session.json"))){out.write(Crypto.utf8(new JSONObject().put("tag",tag).put("vaultId",id).put("password",password).put("username",username).put("publicUid",uid).put("peerUsername",peerName).put("segmentFilename",segment).put("vaultRoot",root.getName()).toString()));}
            return results;
        }catch(Exception error){step("Demo stopped so we can inspect the real failure: "+error.getMessage());snapshot("failure");throw error;}
        finally{bridge.close();}
    }
}
