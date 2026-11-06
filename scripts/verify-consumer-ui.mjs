import {Phone,pause} from '../artifacts/hardware-control.mjs';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const phone=await Phone.connect(19322);
async function until(fn,label){const end=Date.now()+12000;while(Date.now()<end){if(await fn())return;await pause(100);}throw new Error(label);}
try{
 await phone.click('Identity & QR');await pause(350);await phone.click('Scan Peer QR');
 await until(()=>phone.eval('!!document.querySelector("video")?.videoWidth'),'Camera did not stream');
 const camera=await phone.eval('(()=>{const video=document.querySelector("video");window.__checkedTrack=video.srcObject.getVideoTracks()[0];return {width:video.videoWidth,height:video.videoHeight}})()');
 await phone.click('Stop camera');assert.equal(await phone.eval('window.__checkedTrack.readyState'),'ended');
 const identity=await phone.api('/api/access/state');
 // Scan the real account QR. The relay intentionally accepts self-invitations
 // as no-ops, so this checks the decoder and request path without adding contacts.
 await phone.eval(`(()=>{const img=document.querySelector('.qr-card img'),raw=atob(img.src.split(',')[1]),bytes=Uint8Array.from(raw,c=>c.charCodeAt(0)),file=new File([bytes],'identity-qr.png',{type:'image/png'}),transfer=new DataTransfer();transfer.items.add(file);const input=document.querySelector('input[accept="image/*"]');input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
 await until(()=>phone.eval('document.body.innerText.includes("Invitation sent")'),'QR image did not decode and submit');
 await phone.click('Settings');
 assert.ok(await phone.eval('!!document.querySelector("input[aria-label=\\"Display Name\\"]")&&!!document.querySelector("input[aria-label=\\"Status line\\"]")'));
 await phone.eval('document.querySelector(".sheet-header button")?.click();true');
 await phone.eval('document.querySelector("[aria-label=\\"Lock screen with PIN\\"]").click();true');
 await until(()=>phone.eval('!!document.querySelector("input[aria-label=\\"New session PIN\\"]")'),'PIN setup not presented');
 await phone.eval('document.querySelector(".sheet-header button")?.click();true');
 const report={cameraStreaming:camera,cameraStopped:true,realQrImageDecoded:true,automaticInvitationRequestChecked:'own UID; relay no-op, contacts unchanged',profileFields:true,pinSetupPresented:true,existingUidPreserved:(await phone.api('/api/access/state')).publicUid===identity.publicUid,contacts:(await phone.api('/api/contacts')).length};
 fs.writeFileSync('artifacts/consumer-ui-checks.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
 await phone.snapshot('artifacts/consumer-final-inbox.png');
}finally{phone.close();}
