import { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";
import { ScanLine, ImageUp } from "lucide-react";
export function PeerScanner({onPeer}:{onPeer:(uid:string)=>Promise<void>}){
  const [active,setActive]=useState(false),[error,setError]=useState(""),[busy,setBusy]=useState(false);
  const video=useRef<HTMLVideoElement>(null),stream=useRef<MediaStream|null>(null),locked=useRef(false);
  const accept=async(raw:string)=>{
    const text=raw.trim(),uid=text.startsWith('pigeon://invite?')?text:text.toUpperCase();
    if(!uid.startsWith('pigeon://invite?')&&!/^CP-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(uid))throw new Error("This QR is not a Crypto Pigeon signed invite.");
    if(locked.current)return;locked.current=true;setBusy(true);
    try{navigator.vibrate?.(8);stream.current?.getTracks().forEach(t=>t.stop());await onPeer(uid);setActive(false);}finally{locked.current=false;setBusy(false);}
  };
  const decode=(source:CanvasImageSource,w:number,h:number)=>{
    const canvas=document.createElement("canvas"),scale=Math.min(1,900/Math.max(w,h));canvas.width=Math.round(w*scale);canvas.height=Math.round(h*scale);
    const ctx=canvas.getContext("2d",{willReadFrequently:true})!;ctx.drawImage(source,0,0,canvas.width,canvas.height);
    const pixels=ctx.getImageData(0,0,canvas.width,canvas.height);
    return jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:"attemptBoth"})?.data;
  };
  useEffect(()=>{
    if(!active)return;let stopped=false,timer:ReturnType<typeof setTimeout>;
    const stop=()=>{stream.current?.getTracks().forEach(t=>t.stop());stream.current=null;};
    void navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"},audio:false}).then(async media=>{
      if(stopped){media.getTracks().forEach(t=>t.stop());return;}stream.current=media;
      if(video.current){video.current.srcObject=media;await video.current.play();}
      const scan=async()=>{
        if(stopped)return;
        try{const v=video.current;if(v&&v.readyState>=2){const value=decode(v,v.videoWidth,v.videoHeight);if(value){await accept(value);if(!stopped){setActive(false);return;}}}}catch(e:any){setError(e.message);}
        if(!stopped)timer=setTimeout(()=>void scan(),200);
      };void scan();
    }).catch(()=>{setError("Camera unavailable. Choose a QR image below, or enter the UID.");setActive(false);});
    return()=>{stopped=true;clearTimeout(timer);stop();};
  },[active]);
  return <section aria-label="Scan Peer QR" className="peer-scanner"><div className="scanner-actions"><button type="button" className="btn-secondary" disabled={busy} onClick={()=>{setError("");setActive(!active);}}><ScanLine size={17}/>{active?"Stop camera":"Scan QR code"}</button><label className="btn-secondary"><ImageUp size={17}/>Choose QR image<input aria-label="Choose QR image" type="file" accept="image/*" className="visually-hidden" disabled={busy} onChange={async e=>{const file=e.target.files?.[0];e.target.value="";if(!file)return;let bitmap:ImageBitmap|undefined;try{setError("");bitmap=await createImageBitmap(file);const value=decode(bitmap,bitmap.width,bitmap.height);if(!value)throw new Error("No QR found. Try a clearer image.");await accept(value);}catch(err:any){setError(err.message);}finally{bitmap?.close();}}}/></label></div>{active&&<video ref={video} className="scanner-preview" autoPlay muted playsInline/>}{busy&&<p role="status" className="field-help">Sending invitation…</p>}{error&&<p role="alert" className="inline-warning">{error}</p>}</section>;
}
