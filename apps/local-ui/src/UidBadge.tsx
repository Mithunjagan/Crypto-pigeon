import { useRef, useState, useEffect } from 'react';
import QRCode from 'qrcode';
export function UidBadge({uid}:{uid:string}) {
  const canvas=useRef<HTMLCanvasElement>(null);const [show,setShow]=useState(false);const [copied,setCopied]=useState(false);
  useEffect(()=>{if(show&&canvas.current)void QRCode.toCanvas(canvas.current,uid,{width:176,margin:2});},[uid,show]);
  return <section className="uid-badge"><span className="text-xs text-slate-400">YOUR PUBLIC UID</span><div className="flex items-center justify-between gap-2"><strong>{uid}</strong><button className="text-xs p-2" onClick={async()=>{try{await navigator.clipboard.writeText(uid);setCopied(true);}catch{setCopied(false);}}}>{copied?'Copied':'Copy'}</button><button className="text-xs p-2" onClick={()=>setShow(!show)}>QR</button></div>{show&&<canvas className="mt-3 rounded-lg" ref={canvas} aria-label={`QR code for ${uid}`}/>}</section>;
}
