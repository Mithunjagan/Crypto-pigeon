import { useState, type FormEvent } from 'react';
import { Shield, KeyRound } from 'lucide-react';
export const shardStorageKey = 'cp-browser-shard-v1';
export function FragmentShield({status}: {status: any}) {
  const names=['Hardware shard','SQLite shard','Preferences shard','Binary shard','WebView shard','RAM session shard','Relay shard'];
  return <section className="fragment-shield" aria-label="Seven fragment status">
    <div className="flex justify-between text-xs mb-3"><span>7-FRAGMENT SHIELD</span><span>{status?.sharesPresent ?? 0}/7 present</span></div>
    <div className="grid grid-cols-7 gap-2">{names.map((n,i)=><div key={n} title={n} aria-label={`${n}: ${status?.locations?.[n]?'present':'absent or locked'}`} className={`fragment ${status?.locations?.[n]?'present':''}`}>{i+1}</div>)}</div>
    <p className="text-xs text-slate-400 mt-3">All seven fragments are needed for local unlock. Lost a fragment? Restore your encrypted backup.</p>
  </section>;
}
export function VaultGate({state, status, requiresVaultId, busy, submit}: {
  state:string; status:any; requiresVaultId:boolean; busy:boolean;
  submit:(mode:string,vaultId:string,password:string,confirm:string)=>Promise<void>
}) {
  const [mode,setMode]=useState(state==='unconfigured'?'create':'open');
  const [id,setId]=useState('');const [password,setPassword]=useState('');const [confirm,setConfirm]=useState('');
  const [transfer,setTransfer]=useState(false);
  async function onSubmit(e:FormEvent){e.preventDefault();await submit(mode,id,password,confirm);setPassword('');setConfirm('');}
  return <main className="vault-gate"><section className="vault-card glass-panel">
    <div className="eyebrow"><Shield size={18}/> CRYPTO PIGEON</div>
    <h1>Your conversations.<br/><span className="text-indigo-300">Your keys.</span></h1>
    <p className="text-slate-400 text-sm">An encrypted space that travels with you. Keep your secret Vault ID separate from your public UID.</p>
    <div className="gate-tabs" role="tablist" aria-label="Vault action">{[['open','Unlock local'],['create','Create new'],['restore','Restore']].map(([v,label])=><button key={v} role="tab" aria-selected={mode===v} disabled={busy} onClick={()=>setMode(v)} className={mode===v?'active':''}>{label}</button>)}</div>
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      <label className="field-label">Secret Vault ID<input autoComplete="off" type="password" required={mode!=='open'||requiresVaultId} minLength={8} maxLength={256} value={id} onChange={e=>setId(e.target.value)} className="glass-input w-full" placeholder="At least 8 characters" /></label>
      <label className="field-label">Vault password<input autoComplete={mode==='create'?'new-password':'current-password'} type="password" required minLength={12} maxLength={1024} value={password} onChange={e=>setPassword(e.target.value)} className="glass-input w-full" placeholder="12+ characters, uppercase, lowercase, number" /></label>
      {mode==='create'&&<><label className="field-label">Confirm password<input type="password" required autoComplete="new-password" value={confirm} onChange={e=>setConfirm(e.target.value)} className="glass-input w-full" /></label><p className="text-xs text-amber-200">Neither secret can be recovered for you. Use a long, unique Vault ID. Creating a vault requires the relay to be reachable.</p></>}
      {mode==='restore'&&<label className="flex items-start gap-3 text-xs text-amber-200"><input type="checkbox" required checked={transfer} onChange={e=>setTransfer(e.target.checked)}/>I have stopped messaging on my previous device. Restore transfers the active vault to this device and preserves existing local files in a recovery folder.</label>}
      {mode==='open'&&!requiresVaultId&&state!=='unconfigured'&&<p className="text-xs text-amber-200">Legacy local vault: unlock with its existing password. Cloud restore is available for new dual-key vaults.</p>}
      <button disabled={busy || (mode==='restore'&&!transfer)} className="btn-primary flex gap-2 justify-center items-center"><KeyRound size={18}/>{busy?'Working securely…':mode==='restore'?'Restore from relay':mode==='create'?'Create encrypted vault':'Unlock vault'}</button>
    </form>
    <FragmentShield status={status}/>
    <p className="text-xs text-slate-500">Protected files are used for the hardware shard on this platform. Seven locations on one device do not equal seven independent security boundaries.</p>
  </section></main>;
}
