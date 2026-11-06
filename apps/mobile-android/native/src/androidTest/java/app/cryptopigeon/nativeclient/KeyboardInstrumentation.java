package app.cryptopigeon.nativeclient;

import android.app.*;
import android.content.*;
import android.view.*;
import android.view.inputmethod.*;
import android.webkit.*;
import java.lang.reflect.Field;
import java.util.concurrent.*;
import org.json.*;

/** Real WebView/IME regression test. Only dummy credentials are typed; never submits. */
final class KeyboardInstrumentation {
    private Instrumentation runner;private WebView web;
    private String js(String expression) throws Exception {
        String[] value={null};CountDownLatch ready=new CountDownLatch(1);
        runner.runOnMainSync(()->web.evaluateJavascript(expression,result->{value[0]=result;ready.countDown();}));
        if(!ready.await(8,TimeUnit.SECONDS))throw new AssertionError("WebView evaluation timeout");return value[0];
    }
    JSONArray run(Instrumentation runner) throws Exception {
        this.runner=runner;Activity activity=runner.startActivitySync(new Intent(runner.getTargetContext(),MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        Field field=MainActivity.class.getDeclaredField("view");field.setAccessible(true);web=(WebView)field.get(activity);
        long until=System.currentTimeMillis()+15000;while(!"true".equals(js("!!document.querySelector('input[aria-label=\"Vault ID\"]')"))&&System.currentTimeMillis()<until)Thread.sleep(100);
        JSONArray results=new JSONArray();
        try{
            if(!"true".equals(js("(()=>{const tab=Array.from(document.querySelectorAll('[role=tab]')).find(e=>e.textContent==='Create vault');if(!tab)return false;tab.click();return true})()")))throw new AssertionError("Create vault tab unavailable");
            until=System.currentTimeMillis()+5000;while(!"true".equals(js("!!document.querySelector('input[aria-label=\"Confirm passphrase\"]')"))&&System.currentTimeMillis()<until)Thread.sleep(100);
            if(!"true".equals(js("!!document.querySelector('input[aria-label=\"Confirm passphrase\"]')")))throw new AssertionError("Create vault fields unavailable");
            for(String label:new String[]{"Your username","Vault ID","Master passphrase","Confirm passphrase"}){
                js("(()=>{window.__keyboardTarget=document.querySelector('input[aria-label=\""+label+"\"]');if(!window.__keyboardTarget)return false;const counter={value:0};window.__keyboardCounter=counter;window.__keyboardTarget.addEventListener('blur',()=>counter.value++);window.__keyboardTarget.scrollIntoView({block:'center'});return true})()");
                Thread.sleep(500);JSONObject rect=new JSONObject(js("(()=>{const r=window.__keyboardTarget.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2-(visualViewport?.offsetTop||0),width:innerWidth}})()"));
                int[] origin=new int[2];runner.runOnMainSync(()->web.getLocationOnScreen(origin));float scale=web.getWidth()/(float)rect.getDouble("width");float x=origin[0]+(float)rect.getDouble("x")*scale,y=origin[1]+(float)rect.getDouble("y")*scale;
                long down=android.os.SystemClock.uptimeMillis();MotionEvent press=MotionEvent.obtain(down,down,MotionEvent.ACTION_DOWN,x,y,0),release=MotionEvent.obtain(down,down+70,MotionEvent.ACTION_UP,x,y,0);
                runner.sendPointerSync(press);runner.sendPointerSync(release);press.recycle();release.recycle();Thread.sleep(700);
                if(!"true".equals(js("document.activeElement===window.__keyboardTarget")))throw new AssertionError(label+" tap missed target; active="+js("document.activeElement?.getAttribute('aria-label')"));
                final InputConnection[] connection={null};runner.runOnMainSync(()->connection[0]=web.onCreateInputConnection(new EditorInfo()));
                if(connection[0]==null)throw new AssertionError("No active input connection");
                for(char c:"DummyOnly-Aa123456".toCharArray()){
                    runner.runOnMainSync(()->connection[0].commitText(String.valueOf(c),1));Thread.sleep(90);
                    if(!"true".equals(js("document.activeElement===window.__keyboardTarget&&window.__keyboardTarget.isConnected")))throw new AssertionError(label+" lost input focus while typing; active="+js("document.activeElement?.getAttribute('aria-label')"));
                    boolean[] typingIme={false};runner.runOnMainSync(()->{WindowInsets insets=web.getRootWindowInsets();typingIme[0]=insets!=null&&insets.isVisible(WindowInsets.Type.ime());});
                    if(!typingIme[0])throw new AssertionError(label+" keyboard dismissed after character entry");
                }
                if(!"true".equals(js("window.__keyboardTarget.value==='DummyOnly-Aa123456'")))throw new AssertionError(label+" did not retain typed characters");
                boolean[] shown={false};runner.runOnMainSync(()->{WindowInsets insets=web.getRootWindowInsets();shown[0]=insets!=null&&insets.isVisible(WindowInsets.Type.ime());});
                if(!shown[0])throw new AssertionError(label+" keyboard dismissed while typing");
                if(!"0".equals(js("window.__keyboardCounter.value")))throw new AssertionError(label+" blurred while typing");
                results.put(new JSONObject().put("name",label+": continuous IME typing retains focus and keyboard").put("status","pass"));
                js("(()=>{const e=window.__keyboardTarget;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,'');e.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
            }
        }finally{js("document.activeElement?.blur();delete window.__keyboardTarget;delete window.__keyboardCounter;true");}
        return results;
    }
}
