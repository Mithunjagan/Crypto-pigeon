package app.cryptopigeon.mobile;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.*;
import android.graphics.Color;
import android.app.DownloadManager;
import android.os.Environment;
import android.webkit.ValueCallback;
import android.widget.FrameLayout;
import android.view.WindowInsets;
import android.os.Build;
import android.graphics.Insets;

/** USB development client. Cryptographic keys remain in the paired host daemon. */
public class MainActivity extends Activity {
    private WebView view;
    private ValueCallback<Uri[]> fileSelection;
    private PermissionRequest pendingMicrophone;
    private int pairedPort=17420;
    private boolean local(Uri uri) {
        return "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost()) && uri.getPort() == pairedPort && uri.getUserInfo()==null;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        pairedPort=getPreferences(MODE_PRIVATE).getInt("pairedPort",17420);
        getWindow().setStatusBarColor(Color.rgb(11,15,25));
        getWindow().setNavigationBarColor(Color.rgb(11,15,25));
        view = new WebView(this) {
            // Match the standalone app: never expose vault fields to autofill.
            @Override public void onProvideAutofillVirtualStructure(android.view.ViewStructure structure, int flags) {}
        };
        view.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        view.setBackgroundColor(Color.rgb(11,15,25));
        view.getSettings().setJavaScriptEnabled(true);
        view.getSettings().setDomStorageEnabled(true);
        view.getSettings().setAllowFileAccess(false);
        // File uploads use Android's explicit document picker; no raw file URLs.
        view.getSettings().setAllowContentAccess(true);
        view.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        CookieManager.getInstance().setAcceptThirdPartyCookies(view,false);
        view.setWebViewClient(new WebViewClient() {
            @Override public void onPageFinished(WebView webView, String url) {
                CookieManager.getInstance().flush();
            }
            @Override public void onReceivedError(WebView webView, WebResourceRequest request, WebResourceError error) {
                if(!request.isForMainFrame() || !local(request.getUrl()))return;
                String home="http://127.0.0.1:"+pairedPort+"/";
                webView.loadDataWithBaseURL(home,"<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'></head>"
                    +"<body style='margin:0;background:#0b0f19;color:#e2e8f0;font-family:system-ui;display:grid;place-items:center;min-height:100vh'>"
                    +"<main style='max-width:340px;padding:28px'><p style='color:#a5b4fc;letter-spacing:2px;font-size:12px'>CRYPTO PIGEON</p>"
                    +"<h1>Let's reconnect.</h1><p style='color:#94a3b8;line-height:1.7'>Keep this phone connected by USB and open Crypto Pigeon on your paired computer. Your saved conversations are still in your vault.</p>"
                    +"<a style='display:block;text-align:center;background:#4f46e5;color:white;border-radius:12px;padding:16px;text-decoration:none;margin-top:24px' href='"+home+"'>Try again</a></main></body></html>","text/html","UTF-8",null);
            }
            @Override public boolean shouldOverrideUrlLoading(WebView webView, WebResourceRequest request) {
                return !local(request.getUrl());
            }
            @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, android.net.http.SslError error) { handler.cancel(); }
        });
        view.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if(fileSelection!=null)fileSelection.onReceiveValue(null);
                fileSelection=callback;
                Intent chooser=new Intent(Intent.ACTION_OPEN_DOCUMENT);
                chooser.setType("*/*");chooser.addCategory(Intent.CATEGORY_OPENABLE);
                startActivityForResult(chooser,2);return true;
            }
            @Override public void onPermissionRequest(PermissionRequest request) {
                if(local(request.getOrigin())) {
                    for(String resource:request.getResources()) if(PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource)) {
                        if(checkSelfPermission(Manifest.permission.RECORD_AUDIO)==PackageManager.PERMISSION_GRANTED) {
                            request.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
                        } else {
                            if(pendingMicrophone!=null)pendingMicrophone.deny();
                            pendingMicrophone=request;
                            requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO},1);
                        }
                        return;
                    }
                }
                request.deny();
            }
            @Override public void onPermissionRequestCanceled(PermissionRequest request) {
                if(pendingMicrophone==request)pendingMicrophone=null;
            }
        });
        view.setDownloadListener((url,userAgent,disposition,mime,length)->{
            Uri uri=Uri.parse(url);
            if(!local(uri) || !uri.getPath().startsWith("/api/attachments/"))return;
            DownloadManager.Request download=new DownloadManager.Request(uri);
            String cookie=CookieManager.getInstance().getCookie(url);
            if(cookie!=null)download.addRequestHeader("Cookie",cookie);
            download.setMimeType("application/octet-stream");
            download.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            String filename=URLUtil.guessFileName(url,disposition,mime);
            if(disposition!=null) {
                java.util.regex.Matcher match=java.util.regex.Pattern.compile("(?i)filename\\*=UTF-8''([^;]+)").matcher(disposition);
                if(match.find())filename=Uri.decode(match.group(1));
            }
            filename=filename.replace('/','_').replace('\\','_').replaceAll("[\\x00-\\x1F\\x7F]", "_");
            if(filename.isEmpty())filename="attachment.bin";
            download.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS,filename);
            ((DownloadManager)getSystemService(DOWNLOAD_SERVICE)).enqueue(download);
        });
        // Android 15+ enforces edge-to-edge for target SDK 35. Keep the WebView
        // clear of system bars, display cutouts, and the on-screen keyboard.
        FrameLayout content = new FrameLayout(this);
        content.setBackgroundColor(Color.rgb(11,15,25));
        content.addView(view, new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        if (Build.VERSION.SDK_INT >= 30) {
            content.setOnApplyWindowInsetsListener((v, insets) -> {
                Insets safe = insets.getInsets(WindowInsets.Type.systemBars()
                    | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                v.setPadding(safe.left, safe.top, safe.right, safe.bottom);
                return insets;
            });
        }
        setContentView(content);
        content.requestApplyInsets();
        open(getIntent());
    }
    private void open(Intent intent) {
        Uri uri=intent.getData();
        String bootstrapExtra=intent.getStringExtra("bootstrapUrl");
        if(bootstrapExtra!=null)uri=Uri.parse(bootstrapExtra);
        boolean bootstrap=uri!=null && "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost())
            && uri.getUserInfo()==null && uri.getPort()>=1024 && uri.getPort()<=65535
            && "/bootstrap".equals(uri.getPath()) && uri.getQuery()==null
            && uri.getFragment()!=null && uri.getFragment().matches("[a-f0-9]{64}");
        if(bootstrap) {
            pairedPort=uri.getPort();
            getPreferences(MODE_PRIVATE).edit().putInt("pairedPort",pairedPort).apply();
            view.loadUrl(uri.toString());
        } else view.loadUrl("http://127.0.0.1:"+pairedPort+"/");
        // Avoid retaining the fragment in Activity state or a subsequent launch.
        intent.setData(null);
        intent.removeExtra("bootstrapUrl");
    }
    @Override public void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); open(intent); }
    @Override public void onPause() { CookieManager.getInstance().flush(); super.onPause(); }
    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request,permissions,results);
        if(request==1 && pendingMicrophone!=null) {
            if(results.length>0 && results[0]==PackageManager.PERMISSION_GRANTED)
                pendingMicrophone.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
            else pendingMicrophone.deny();
            pendingMicrophone=null;
        }
    }
    @Override public void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==2 && fileSelection!=null){
            Uri uri=data!=null?data.getData():null;
            fileSelection.onReceiveValue(result==RESULT_OK && uri!=null && "content".equals(uri.getScheme())?new Uri[]{uri}:null);
            fileSelection=null;
        }
    }
    @Override public void onDestroy() { if(view!=null){view.clearHistory();view.destroy();}super.onDestroy(); }
}
