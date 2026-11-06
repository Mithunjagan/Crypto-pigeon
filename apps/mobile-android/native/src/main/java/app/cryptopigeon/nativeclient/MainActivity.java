package app.cryptopigeon.nativeclient;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.*;
import android.graphics.Color;
import android.webkit.*;
import android.view.WindowManager;
import android.widget.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executors;

/** Standalone launcher: WebView and the native engine share this app's lifecycle. */
public final class MainActivity extends Activity {
    private WebView view;private LocalBridge bridge;private ValueCallback<Uri[]> fileSelection;private PermissionRequest microphone;
    private String exportUrl;
    private String sovereignKind,sovereignRequest;private long sovereignEpoch;
    private boolean pickingStorage;private volatile String selectedStorageUri;
    private void fileResult(String request,boolean success,String error){runOnUiThread(()->{if(view!=null)view.evaluateJavascript("window.dispatchEvent(new CustomEvent('cp-file-saved',{detail:{id:"+org.json.JSONObject.quote(request)+",ok:"+success+",error:"+org.json.JSONObject.quote(error==null?"":error)+"}}))",null);});}
    public final class FileBridge {
        @JavascriptInterface public String storageSelection(){return selectedStorageUri;}
        @JavascriptInterface public void save(String kind,String request){runOnUiThread(()->{
            if(view==null||!local(Uri.parse(view.getUrl()))||!java.util.Arrays.asList("shard7","storage").contains(kind)||request==null||!request.matches("[a-zA-Z0-9-]{1,64}"))return;
            if(sovereignRequest!=null){fileResult(request,false,"FILE_PICKER_BUSY");return;}
            sovereignKind=kind;sovereignRequest=request;sovereignEpoch=bridge.fileEpoch();
            Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
            save.putExtra(Intent.EXTRA_TITLE,kind.equals("shard7")?"segment-07.cp7":"pigeon.cpvault");
            try{startActivityForResult(save,4);}catch(Exception unavailable){sovereignRequest=null;fileResult(request,false,"FILE_PICKER_UNAVAILABLE");}
        });}
    }
    private android.content.BroadcastReceiver screenReceiver;
    private android.window.OnBackInvokedCallback backCallback;
    private boolean backPending;
    private void navigateBack(){
        if(backPending||isFinishing()||isDestroyed())return;
        if(view==null||!local(Uri.parse(view.getUrl()==null?"":view.getUrl()))){moveTaskToBack(true);return;}
        if(Build.VERSION.SDK_INT>=30){android.view.WindowInsets insets=view.getRootWindowInsets();if(insets!=null&&insets.isVisible(android.view.WindowInsets.Type.ime())){android.view.WindowInsetsController controller=view.getWindowInsetsController();if(controller!=null)controller.hide(android.view.WindowInsets.Type.ime());return;}}
        backPending=true;
        view.evaluateJavascript("Boolean(window.CryptoPigeonNavigation && window.CryptoPigeonNavigation.back())",result->{
            backPending=false;if(isFinishing()||isDestroyed())return;
            // At the root, behave like Home. Keep the activity, draft and vault
            // service alive instead of destroying them on a navigation gesture.
            if(!"true".equals(result))moveTaskToBack(true);
        });
    }
    @Override @SuppressWarnings("deprecation") public void onBackPressed(){navigateBack();}
    @Override protected void onResume(){super.onResume();if(bridge!=null)bridge.foreground(true);}
    @Override protected void onPause(){if(bridge!=null)bridge.foreground(false);super.onPause();}
    private boolean local(Uri uri){return bridge!=null&&"http".equals(uri.getScheme())&&"127.0.0.1".equals(uri.getHost())&&uri.getPort()==bridge.port&&uri.getUserInfo()==null;}
    @Override public void onCreate(Bundle state){
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        if(Build.VERSION.SDK_INT>=33){backCallback=this::navigateBack;getOnBackInvokedDispatcher().registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT,backCallback);}
        getWindow().setStatusBarColor(Color.rgb(4,7,17));getWindow().setNavigationBarColor(Color.rgb(4,7,17));
        try{bridge=PigeonRuntime.bridge(this);}catch(Exception failure){TextView message=new TextView(this);message.setText("Crypto Pigeon could not open its local vault service. Close and reopen the app.");message.setTextColor(Color.WHITE);message.setPadding(32,64,32,32);message.setBackgroundColor(Color.rgb(4,7,17));setContentView(message);return;}
        if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED&&!getPreferences(0).getBoolean("notificationsAsked",false)){getPreferences(0).edit().putBoolean("notificationsAsked",true).apply();requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},5);}
        view=new WebView(this){
            // Android 14+ can ignore autofill importance. Do not publish HTML
            // credential fields to the password manager's virtual structure.
            @Override public void onProvideAutofillVirtualStructure(android.view.ViewStructure structure,int flags){}
        };view.setBackgroundColor(Color.rgb(4,7,17));view.getSettings().setJavaScriptEnabled(true);view.getSettings().setDomStorageEnabled(true);view.getSettings().setAllowFileAccess(false);view.getSettings().setAllowContentAccess(true);view.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);view.getSettings().setMediaPlaybackRequiresUserGesture(true);
        // Avoid password-generation popups interrupting manual vault entry.
        view.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        view.addJavascriptInterface(new FileBridge(),"CryptoPigeonFiles");
        CookieManager.getInstance().setAcceptThirdPartyCookies(view,false);WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG);
        view.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView webView,WebResourceRequest request){return !local(request.getUrl());}
            @Override public WebResourceResponse shouldInterceptRequest(WebView webView,WebResourceRequest request){if(!local(request.getUrl()))return new WebResourceResponse("text/plain","UTF-8",403,"Forbidden",java.util.Collections.emptyMap(),new ByteArrayInputStream(new byte[0]));return null;}
            @Override public void onReceivedSslError(WebView webView,SslErrorHandler handler,android.net.http.SslError error){handler.cancel();}
            @Override public void onPageFinished(WebView v,String url){CookieManager.getInstance().flush();}
        });
        view.setWebChromeClient(new WebChromeClient(){
            @Override public boolean onShowFileChooser(WebView v,ValueCallback<Uri[]> callback,FileChooserParams params){if(fileSelection!=null)fileSelection.onReceiveValue(null);fileSelection=callback;pickingStorage=java.util.Arrays.asList(params.getAcceptTypes()).contains(".cpvault");Intent picker=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(Intent.CATEGORY_OPENABLE).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION|Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);try{startActivityForResult(picker,2);}catch(Exception unavailable){fileSelection=null;callback.onReceiveValue(null);}return true;}
            @Override public void onPermissionRequest(PermissionRequest request){
                if(!local(request.getOrigin())){request.deny();return;}
                java.util.ArrayList<String> needed=new java.util.ArrayList<>();
                for(String resource:request.getResources()){
                    if(PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource))needed.add(Manifest.permission.RECORD_AUDIO);
                    else if(PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource))needed.add(Manifest.permission.CAMERA);
                    else{request.deny();return;}
                }
                boolean granted=true;for(String permission:needed)if(checkSelfPermission(permission)!=PackageManager.PERMISSION_GRANTED)granted=false;
                if(granted)request.grant(request.getResources());
                else{if(microphone!=null)microphone.deny();microphone=request;requestPermissions(needed.toArray(new String[0]),1);}
            }
            @Override public void onPermissionRequestCanceled(PermissionRequest request){if(microphone==request)microphone=null;}
        });
        view.setDownloadListener((url,agent,disposition,mime,length)->{
            Uri uri=Uri.parse(url);if(!local(uri)||!uri.getPath().matches("/api/attachments/[a-f0-9]{32}/decrypt"))return;
            exportUrl=url;Intent save=new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/octet-stream").addCategory(Intent.CATEGORY_OPENABLE);
            String filename=URLUtil.guessFileName(url,disposition,mime);if(disposition!=null){java.util.regex.Matcher match=java.util.regex.Pattern.compile("filename\\*=UTF-8''([^;]+)").matcher(disposition);if(match.find())filename=Uri.decode(match.group(1));}
            save.putExtra(Intent.EXTRA_TITLE,filename);startActivityForResult(save,3);
        });
        FrameLayout frame=new FrameLayout(this);frame.addView(view);setContentView(frame);
        // adjustResize owns IME sizing. Applying IME padding as well repeatedly
        // resizes the focused WebView during keyboard animation and restarts input.
        if(Build.VERSION.SDK_INT>=35)frame.setOnApplyWindowInsetsListener((v,insets)->{android.graphics.Insets bars=insets.getInsets(android.view.WindowInsets.Type.systemBars()|android.view.WindowInsets.Type.displayCutout());if(v.getPaddingLeft()!=bars.left||v.getPaddingTop()!=bars.top||v.getPaddingRight()!=bars.right||v.getPaddingBottom()!=bars.bottom)v.setPadding(bars.left,bars.top,bars.right,bars.bottom);return new android.view.WindowInsets.Builder(insets).setInsets(android.view.WindowInsets.Type.systemBars()|android.view.WindowInsets.Type.displayCutout(),android.graphics.Insets.NONE).build();});
        view.loadUrl(bridge.entry());
        screenReceiver=new android.content.BroadcastReceiver(){public void onReceive(android.content.Context c,Intent i){if(bridge!=null)bridge.foreground(!Intent.ACTION_SCREEN_OFF.equals(i.getAction())&&hasWindowFocus());}};
        android.content.IntentFilter screenFilter=new android.content.IntentFilter();screenFilter.addAction(Intent.ACTION_SCREEN_OFF);screenFilter.addAction(Intent.ACTION_SCREEN_ON);registerReceiver(screenReceiver,screenFilter,android.content.Context.RECEIVER_NOT_EXPORTED);
    }
    @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] grants){super.onRequestPermissionsResult(code,permissions,grants);if(code==1&&microphone!=null){boolean allowed=grants.length>0;for(int grant:grants)allowed&=grant==PackageManager.PERMISSION_GRANTED;if(allowed)microphone.grant(microphone.getResources());else microphone.deny();microphone=null;}}
    @Override protected void onActivityResult(int code,int result,Intent data){
        super.onActivityResult(code,result,data);
        if(code==4&&sovereignRequest!=null){
            String request=sovereignRequest,kind=sovereignKind;long epoch=sovereignEpoch;sovereignRequest=null;sovereignKind=null;
            if(result!=RESULT_OK||data==null||data.getData()==null){fileResult(request,false,"SAVE_CANCELLED");return;}
            Uri destination=data.getData();if(!"content".equals(destination.getScheme())){fileResult(request,false,"INVALID_DOCUMENT_URI");return;}
            final int grants=data.getFlags()&(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            java.util.concurrent.ExecutorService worker=Executors.newSingleThreadExecutor();worker.execute(()->{
                byte[] bytes=null;try{
                    bytes=bridge.exportFile(kind,epoch);
                    try(OutputStream output=getContentResolver().openOutputStream(destination,"wt")){if(output==null)throw new IOException("STORAGE_FILE_UNAVAILABLE");output.write(bytes);output.flush();}
                    if(kind.equals("storage")){getContentResolver().takePersistableUriPermission(destination,grants);}
                    bridge.fileSaved(kind,epoch,destination);fileResult(request,true,null);
                }catch(Exception failure){fileResult(request,false,"FILE_SAVE_FAILED");}finally{Crypto.wipe(bytes);worker.shutdown();}
            });return;
        }
        if(code==2&&fileSelection!=null){Uri selected=result==RESULT_OK&&data!=null?data.getData():null;if(selected!=null&&!"content".equals(selected.getScheme()))selected=null;if(pickingStorage){selectedStorageUri=null;if(selected!=null)try{int grants=data.getFlags()&(Intent.FLAG_GRANT_READ_URI_PERMISSION|Intent.FLAG_GRANT_WRITE_URI_PERMISSION);getContentResolver().takePersistableUriPermission(selected,grants);if((grants&Intent.FLAG_GRANT_WRITE_URI_PERMISSION)!=0)selectedStorageUri=selected.toString();}catch(Exception readOnly){/* Import remains available for read-only providers. */}}fileSelection.onReceiveValue(selected==null?null:new Uri[]{selected});fileSelection=null;pickingStorage=false;}
        if(code==3&&result==RESULT_OK&&data!=null&&exportUrl!=null){Uri destination=data.getData();String url=exportUrl,cookie=CookieManager.getInstance().getCookie(url);exportUrl=null;
            java.util.concurrent.ExecutorService worker=Executors.newSingleThreadExecutor();worker.execute(()->{HttpURLConnection connection=null;try{
                connection=(HttpURLConnection)new URL(url).openConnection();connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(5000);connection.setReadTimeout(30000);if(cookie!=null)connection.setRequestProperty("Cookie",cookie);
                if(connection.getResponseCode()!=200)throw new IOException("download_failed");
                try(InputStream input=connection.getInputStream();OutputStream output=getContentResolver().openOutputStream(destination,"w")){byte[] buffer=new byte[65536];try{int n;while((n=input.read(buffer))!=-1)output.write(buffer,0,n);}finally{Crypto.wipe(buffer);}}
                runOnUiThread(()->Toast.makeText(this,"Verified attachment saved",Toast.LENGTH_SHORT).show());
            }catch(Exception failed){runOnUiThread(()->Toast.makeText(this,"Could not save attachment. Unlock the vault and retry.",Toast.LENGTH_LONG).show());}finally{if(connection!=null)connection.disconnect();worker.shutdown();}});
        }
    }
    @Override protected void onDestroy(){if(Build.VERSION.SDK_INT>=33&&backCallback!=null)getOnBackInvokedDispatcher().unregisterOnBackInvokedCallback(backCallback);if(screenReceiver!=null)unregisterReceiver(screenReceiver);if(fileSelection!=null)fileSelection.onReceiveValue(null);if(microphone!=null)microphone.deny();if(view!=null){view.stopLoading();view.destroy();}super.onDestroy();}
}
