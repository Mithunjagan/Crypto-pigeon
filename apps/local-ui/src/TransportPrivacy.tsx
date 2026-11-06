import {useEffect,useState} from "react";
import {EyeOff,Route,UserX,Info} from "lucide-react";
export function TransportPrivacy({api,open}:{api:(path:string,options?:RequestInit)=>Promise<Response>;open:boolean}){
  const [state,setState]=useState<{blindRouting:boolean;duressArmed:boolean;mode:string;serverless:boolean;bootstrapPercent:number;activeTransport:string}|null>(null),[duressId,setDuressId]=useState(""),[saving,setSaving]=useState(false),[error,setError]=useState("");
  useEffect(()=>{if(!open)return;let cancelled=false;const load=()=>void api("/api/transport/privacy").then(r=>r.ok?r.json():null).then(value=>{if(!cancelled)setState(value);}).catch(()=>{});load();const timer=setInterval(load,5000);return()=>{cancelled=true;clearInterval(timer);};},[open]);
  if(!state)return null;
  // Each row reports what is actually active; partial protection is labelled as partial.
  const rows:[typeof EyeOff,string,string,"on"|"partial"|"off"][]=[
    [EyeOff,"IP address hidden from contacts",state.mode!=="RELAY_ONLY"?"Peer connections use Tor onion services.":"Messages go through the configured relay.",state.serverless||state.mode==='RELAY_ONLY'?"on":"partial"],
    [Route,"Message delivery",state.mode==='DIRECT_TOR_P2P'?(state.serverless?"Direct Tor Onion P2P. No application relay or FCM.":`Tor bootstrap ${state.bootstrapPercent}%. Messages stay queued.`):state.mode==='HYBRID_TOR_RELAY'?"Tor preferred, with an optional relay fallback.":"Encrypted relay delivery.",state.serverless?"on":"partial"],
    [UserX,"Duress vault",state.duressArmed?"A separate decoy vault is configured.":"Not configured.",state.duressArmed?"on":"off"],
  ];
  return <section className="privacy-shield" aria-label="Privacy protections">
    <ul className="shield-rows">{rows.map(([Icon,title,detail,level])=><li key={title}><span className={`shield-icon ${level}`}><Icon size={17}/></span><span><strong>{title}</strong><small>{detail}</small></span><span className={`shield-level ${level}`}>{level==="on"?"Active":level==="partial"?"Partial":"Off"}</span></li>)}</ul>
    <label className="field-label">Delivery route<select className="glass-input" value={state.mode} onChange={async e=>{try{const r=await api('/api/transport/config',{method:'POST',body:JSON.stringify({mode:e.target.value})});if(!r.ok)throw Error('Could not change delivery route');setState({...state,...await r.json()});setError('');}catch(e){setError(e instanceof Error?e.message:'Could not change route');}}}><option value="DIRECT_TOR_P2P">Direct Tor P2P</option><option value="HYBRID_TOR_RELAY">Tor with relay fallback</option><option value="RELAY_ONLY">Relay only</option></select></label>
    <p className="shield-caveat"><Info size={14}/>{state.mode==='DIRECT_TOR_P2P'?"Both devices need Tor connectivity. Offline messages stay on the sender's device.":"A configured relay can observe connection timing and routing metadata."}</p>
    <details className="settings-subsection"><summary>Set up a duress vault <span className="tag">Experimental</span></summary>
      <p>Unlocking with this second ID opens an isolated decoy vault instead of your real one. It has not been fully verified on Android yet.</p>
      <form className="stack" onSubmit={async e=>{e.preventDefault();setSaving(true);setError("");try{const r=await api("/api/duress/config",{method:"POST",body:JSON.stringify({duressId})});const body=await r.json();if(!r.ok)throw Error(body.error||"Could not configure decoy");localStorage.setItem("cp-decoy-shard-v1",body.decoyClientShard);setDuressId("");setState({...state,duressArmed:true});}catch(e){setError(e instanceof Error?e.message:"Could not configure decoy");}finally{setSaving(false);}}}><label className="field-label">Decoy Vault ID<input aria-label="Duress Decoy Vault ID" type="password" className="glass-input" minLength={16} maxLength={256} required value={duressId} onChange={e=>setDuressId(e.target.value)} autoComplete="off"/></label><button className="btn-secondary" disabled={saving}>{saving?"Creating encrypted decoy…":"Create decoy vault"}</button></form>{error&&<p role="alert" className="inline-warning">{error}</p>}
    </details>
  </section>;
}
