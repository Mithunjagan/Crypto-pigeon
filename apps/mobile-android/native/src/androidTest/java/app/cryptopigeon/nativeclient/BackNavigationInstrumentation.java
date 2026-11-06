package app.cryptopigeon.nativeclient;

import android.app.Instrumentation;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.WindowInsets;
import android.webkit.WebView;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real system Back/IME regression. Does not create, open or reset user vaults. */
final class BackNavigationInstrumentation {
    private Instrumentation runner;private MainActivity activity;private WebView web;
    private String js(String expression) throws Exception {
        String[] value={null};CountDownLatch done=new CountDownLatch(1);
        runner.runOnMainSync(()->web.evaluateJavascript(expression,result->{value[0]=result;done.countDown();}));
        if(!done.await(8,TimeUnit.SECONDS))throw new AssertionError("WebView response timeout");return value[0];
    }
    private void waitFor(String expression) throws Exception {long end=SystemClock.uptimeMillis()+10000;while(SystemClock.uptimeMillis()<end){if("true".equals(js(expression)))return;Thread.sleep(80);}throw new AssertionError("Navigation check failed: "+expression);}
    private boolean ime() {boolean[] visible={false};runner.runOnMainSync(()->{if(Build.VERSION.SDK_INT>=30){WindowInsets insets=web.getRootWindowInsets();visible[0]=insets!=null&&insets.isVisible(WindowInsets.Type.ime());}});return visible[0];}
    private void checkAlive(){if(activity.isFinishing()||activity.isDestroyed())throw new AssertionError("Back destroyed the app activity");}
    private void back(){runner.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK);}
    private JSONObject pass(String name) throws Exception {return new JSONObject().put("name",name).put("status","pass");}
    JSONArray run(Instrumentation runner) throws Exception {
        this.runner=runner;JSONArray results=new JSONArray();
        activity=(MainActivity)runner.startActivitySync(new Intent(runner.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        Field field=MainActivity.class.getDeclaredField("view");field.setAccessible(true);web=(WebView)field.get(activity);
        waitFor("!!window.CryptoPigeonNavigation&&!!document.querySelector('.vault-form')");
        String baseline=js("document.querySelector('[role=tab][aria-selected=true]').textContent");
        js("document.querySelector('.network-chip').click();true");waitFor("!!document.querySelector('[role=dialog]')");
        back();waitFor("!document.querySelector('[role=dialog]')");checkAlive();results.put(pass("Physical Back closes a sheet without finishing the activity"));
        js("(()=>{const selected=document.querySelector('[role=tab][aria-selected=true]');const other=[...document.querySelectorAll('[role=tab]')].find(e=>e!==selected&&e.textContent!=='Restore');other.click();return true})()");
        back();waitFor("JSON.stringify(document.querySelector('[role=tab][aria-selected=true]').textContent)==="+JSONObject.quote(baseline));checkAlive();results.put(pass("Physical Back returns from another vault tab to the initial vault screen"));
        js("document.querySelector('input[aria-label=\"Vault ID\"]').scrollIntoView({block:'center'});true");Thread.sleep(150);
        JSONObject rect=new JSONObject(js("(()=>{const r=document.querySelector('input[aria-label=\"Vault ID\"]').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2,w:innerWidth}})()"));
        int[] origin=new int[2];runner.runOnMainSync(()->web.getLocationOnScreen(origin));float scale=web.getWidth()/(float)rect.getDouble("w"),x=origin[0]+(float)rect.getDouble("x")*scale,y=origin[1]+(float)rect.getDouble("y")*scale;
        long now=SystemClock.uptimeMillis();MotionEvent down=MotionEvent.obtain(now,now,MotionEvent.ACTION_DOWN,x,y,0),up=MotionEvent.obtain(now,now+60,MotionEvent.ACTION_UP,x,y,0);
        try{runner.sendPointerSync(down);runner.sendPointerSync(up);}finally{down.recycle();up.recycle();}
        if(Build.VERSION.SDK_INT>=30){long end=SystemClock.uptimeMillis()+5000;while(!ime()&&SystemClock.uptimeMillis()<end)Thread.sleep(80);if(!ime())throw new AssertionError("Keyboard did not open for IME Back check");back();end=SystemClock.uptimeMillis()+5000;while(ime()&&SystemClock.uptimeMillis()<end)Thread.sleep(80);if(ime())throw new AssertionError("Back did not dismiss the keyboard");checkAlive();results.put(pass("First physical Back dismisses the keyboard and keeps the current screen"));}
        js("(()=>{const e=document.querySelector('input[aria-label=\"Vault ID\"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'NavigationDraft123');e.dispatchEvent(new Event('input',{bubbles:true}));e.blur();return true})()");
        back();Thread.sleep(250);checkAlive();
        runner.runOnMainSync(()->activity.startActivity(new Intent(activity,MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT|Intent.FLAG_ACTIVITY_SINGLE_TOP)));
        waitFor("document.querySelector('input[aria-label=\"Vault ID\"]')?.value==='NavigationDraft123'");checkAlive();
        if(field.get(activity)!=web)throw new AssertionError("Returning to app recreated the WebView");
        results.put(pass("Root Back backgrounds the task; returning preserves the same activity, WebView and draft"));
        js("(()=>{const e=document.querySelector('input[aria-label=\"Vault ID\"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'');e.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
        return results;
    }
}
