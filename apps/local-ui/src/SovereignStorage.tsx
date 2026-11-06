import {useEffect,useRef,useState} from 'react';
import {Sheet} from './ui';

export function useTapGesture(count:number,windowMs:number,action:()=>void){
  const taps=useRef({count:0,start:0});
  return ()=>{const now=performance.now();if(taps.current.count===0||now-taps.current.start>windowMs)taps.current={count:0,start:now};if(++taps.current.count===count){taps.current={count:0,start:0};navigator.vibrate?.(12);action();}};
}
export function base64Bytes(bytes:Uint8Array){let result='';for(let i=0;i<bytes.length;i+=8192)result+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(result);}
export async function readSovereignFile(file:File,kind:'shard7'|'storage'){
  const header=kind==='shard7'?'CPSHR701\n':'CPVAULT1\n',limit=kind==='shard7'?2048:18*1024*1024;
  if(file.size>limit||file.size<=header.length)throw new Error('Invalid or oversized vault file.');
  const bytes=new Uint8Array(await file.arrayBuffer());
  try{
    if(new TextDecoder().decode(bytes.subarray(0,header.length))!==header)throw new Error('This is not the selected type of vault file.');
    const envelope=JSON.parse(new TextDecoder().decode(bytes.subarray(header.length)));
    if(typeof envelope.nonce!=='string'||typeof envelope.ciphertext!=='string'||envelope.nonce.length!==16||!/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.ciphertext))throw new Error('Invalid vault file format.');
    return bytes;
  }catch(error){bytes.fill(0);throw error;}
}
export async function saveSovereignFile(kind:'shard7'|'storage'){
  const native=(window as any).CryptoPigeonFiles;
  if(native){
    return new Promise<void>((resolve,reject)=>{
      const id=crypto.randomUUID();
      const cleanup=()=>{window.removeEventListener('cp-file-saved',saved);window.removeEventListener('cp-vault-locked',locked);};
      const saved=(event:Event)=>{const detail=(event as CustomEvent).detail;if(detail?.id!==id)return;cleanup();detail.ok?resolve():reject(new Error(detail.error==='SAVE_CANCELLED'?'File save cancelled.':'The file could not be saved. Choose a writable folder and retry.'));};
      const locked=()=>{cleanup();reject(new Error('Vault locked. Unlock before saving.'));};
      window.addEventListener('cp-file-saved',saved);window.addEventListener('cp-vault-locked',locked);
      try{native.save(kind,id);}catch(error){cleanup();reject(error);}
    });
  }
  const picker=(window as any).showSaveFilePicker;
  if(!picker)throw new Error('Use the Android app or a browser with a system file-save picker to choose the vault file location.');
  const handle=await picker({suggestedName:kind==='shard7'?'segment-07.cp7':'pigeon.cpvault'});
  const response=await fetch('/api/vault/files/'+kind);if(!response.ok)throw new Error('Unlock the vault before exporting.');
  const bytes=new Uint8Array(await response.arrayBuffer());
  try{const output=await handle.createWritable();try{await output.write(bytes);await output.close();}catch(error){await output.abort();throw error;}}finally{bytes.fill(0);}
}

export function SovereignStorageSheet({open,onClose,api,onImport,onError}:{open:boolean;onClose:()=>void;api:(path:string,options?:RequestInit)=>Promise<Response>;onImport:(file:File)=>Promise<void>;onError:(message:string)=>void}){
  const picker=useRef<HTMLInputElement>(null),[cloud,setCloud]=useState(false),[bound,setBound]=useState(false),[busy,setBusy]=useState(false),[notice,setNotice]=useState('');
  useEffect(()=>{if(!open)return;setNotice('');void api('/api/vault/storage').then(async r=>{if(!r.ok)throw new Error('Storage settings unavailable.');const data=await r.json();setCloud(!!data.cloudBackupEnabled);setBound(!!data.storageBound);}).catch(e=>onError(e.message));},[open]);
  const save=async(kind:'shard7'|'storage')=>{setBusy(true);setNotice('');try{await saveSovereignFile(kind);if(kind==='shard7'){const r=await api('/api/vault/shard7/saved',{method:'POST'});if(!r.ok)throw new Error('File saved, but vault settings could not be updated.');setCloud(false);}else setBound(true);setNotice(kind==='shard7'?'Segment file saved. Use it on your next cold unlock.':'Encrypted storage file saved.');}catch(e:any){onError(e.message);}finally{setBusy(false);}};
  return <Sheet open={open} onClose={onClose} title="Sovereign App Storage" eyebrow="Your files. Your choice.">
    <div className="stack">
      <p>Your encrypted storage bundle contains your identity, contacts, Signal sessions and messages. Keep its separate segment file safe.</p>
      <button type="button" className="btn-primary" disabled={busy} onClick={()=>void save('storage')}>Select / Export App Storage File</button>
      <p className="field-help">{bound?'Android updates your chosen file after changes and when you lock.':'Choose a storage file to keep a separate encrypted copy.'} An encrypted working database remains inside the app.</p>
      <button type="button" className="btn-secondary" disabled={busy} onClick={()=>picker.current?.click()}>Load / Switch App Storage File</button>
      <input ref={picker} type="file" accept=".cpvault" className="visually-hidden" tabIndex={-1} aria-label="Select app storage file" onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';if(file)void onImport(file).catch(error=>onError(error.message));}} />
      <p className="field-help">Switching locks this session first. Enter the selected vault’s credentials and load its segment file to open it.</p>
      <button type="button" className="btn-secondary" disabled={busy} onClick={()=>void save('shard7')}>Save separate segment file</button>
      <label className="transfer-check"><input type="checkbox" role="switch" aria-label="Automatic Cloud Backup" checked={cloud} disabled={busy} onChange={async e=>{const enabled=e.currentTarget.checked;setBusy(true);try{const r=await api('/api/vault/storage',{method:'POST',body:JSON.stringify({cloudBackupEnabled:enabled})});if(!r.ok)throw new Error('Could not update cloud backup.');setCloud(enabled);}catch(error:any){onError(error.message);}finally{setBusy(false);}}}/><span>Automatic Cloud Backup <strong>{cloud?'ON':'OFF'}</strong></span></label>
      <p className="field-help">Off by default. When off, database backups are never uploaded to the relay. Encrypted message delivery still uses your relay.</p>
      {notice&&<p role="status" className="field-help">{notice}</p>}
    </div>
  </Sheet>;
}
