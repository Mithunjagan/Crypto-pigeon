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

/** USB development client. Cryptographic keys remain in the paired host daemon. */
public class MainActivity extends Activity {
    private WebView view;
    private ValueCallback<Uri[]> fileSelection;
    private boolean local(Uri uri) {
        return "http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost()) && uri.getPort() == 17420;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(11,15,25));
        getWindow().setNavigationBarColor(Color.rgb(11,15,25));
        view = new WebView(this);
        view.setBackgroundColor(Color.rgb(11,15,25));
        view.getSettings().setJavaScriptEnabled(true);
        view.getSettings().setDomStorageEnabled(true);
        view.getSettings().setAllowFileAccess(false);
        // File uploads use Android's explicit document picker; no raw file URLs.
        view.getSettings().setAllowContentAccess(true);
        view.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        CookieManager.getInstance().setAcceptThirdPartyCookies(view,false);
        view.setWebViewClient(new WebViewClient() {
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
                if(local(request.getOrigin()) && checkSelfPermission(Manifest.permission.RECORD_AUDIO)==PackageManager.PERMISSION_GRANTED) {
                    for(String resource:request.getResources()) if(PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource)) {
                        request.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});return;
                    }
                }
                request.deny();
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
            download.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS,URLUtil.guessFileName(url,disposition,mime));
            ((DownloadManager)getSystemService(DOWNLOAD_SERVICE)).enqueue(download);
        });
        setContentView(view);
        if(checkSelfPermission(Manifest.permission.RECORD_AUDIO)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO},1);
        open(getIntent());
    }
    private void open(Intent intent) {
        Uri uri=intent.getData();
        if(uri!=null && local(uri) && "/bootstrap".equals(uri.getPath())) view.loadUrl(uri.toString());
        else view.loadUrl("http://127.0.0.1:17420/");
        // Avoid retaining the fragment in Activity state or a subsequent launch.
        intent.setData(null);
    }
    @Override public void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); open(intent); }
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
