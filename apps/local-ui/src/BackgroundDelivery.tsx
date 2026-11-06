import {useEffect,useState} from 'react';
export function BackgroundDelivery({api,open}:{api:(path:string,options?:RequestInit)=>Promise<Response>;open:boolean}){
  const [state,setState]=useState<{native:boolean;ignoringBatteryOptimizations:boolean;prompted:boolean;foregroundService:boolean;notificationsEnabled:boolean}|null>(null),[error,setError]=useState('');
  useEffect(()=>{if(!open)return;let live=true;const load=async()=>{try{const r=await api('/api/power/status');if(r.ok){const value=await r.json();if(live)setState(value);}}catch{/* Desktop has no Android power manager. */}};void load();const timer=setInterval(()=>void load(),5000);return()=>{live=false;clearInterval(timer);};},[open]);
  if(!state?.native)return null;
  const act=async(action:'request'|'dismiss')=>{try{const response=await api('/api/power/'+action,{method:'POST'});if(!response.ok)throw Error('Could not open battery settings.');setState(await response.json());setError('');}catch(e){setError(e instanceof Error?e.message:'Could not update battery settings.');}};
  return <section className="sheet-group" aria-label="Background delivery">
    <h3 className="group-title">Background delivery</h3><p className="field-help">{state.foregroundService?'Listening while your vault is unlocked.':'Unlock your vault to start listening.'} {state.notificationsEnabled?'Message notifications are enabled.':'Allow notifications in Android settings to see new-message alerts.'}</p>
    {state.ignoringBatteryOptimizations?<p className="field-help">Unrestricted battery usage is enabled.</p>:!state.prompted?<div role="status" className="inline-warning"><p>Allow unrestricted battery usage to keep Tor connected when your screen is off.</p><button className="btn-primary" onClick={()=>void act('request')}>Allow background delivery</button><button className="btn-secondary" onClick={()=>void act('dismiss')}>Later</button></div>:<button className="btn-secondary" onClick={()=>void act('request')}>Open battery settings</button>}
    {error&&<p role="alert">{error}</p>}
  </section>;
}
