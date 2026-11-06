import {Phone,pause} from './lib/phone-ui.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root=path.resolve(import.meta.dirname,'..'),out=path.join(root,'artifacts/three-phone-live-20261103');
const {credentials}=JSON.parse(fs.readFileSync(path.join(out,'credentials.private.json')));
const adb=path.join(root,'artifacts/android-device-tools/platform-tools/adb.exe');
const phones=[],checks=[],report={startedAt:new Date().toISOString(),scope:'Physical phones, phone-owned native Signal and public HTTPS relay. No USB networking or host vault. Recipient delivery observed from UI without manual fetch.',checks};
const save=()=>fs.writeFileSync(path.join(out,'recovery-results.json'),JSON.stringify(report,null,2));
const pass=(name,details={})=>{checks.push({name,status:'pass',...details});save();console.log('PASS '+name);};
function command(i,args){const r=spawnSync(adb,['-s',credentials[i].serial,...args],{encoding:'utf8',timeout:30000,windowsHide:true,maxBuffer:2*1024*1024});assert.equal(r.status,0,'ADB '+args.join(' ')+': '+r.stderr);return r.stdout.trim();}
async function until(check,label,ms=60000){const end=Date.now()+ms;while(Date.now()<end){if(await check())return;await pause(250);}throw Error('Timeout: '+label);}
async function chat(i,j){const p=phones[i];await p.eval(`document.querySelector('[aria-label="Back to conversations"]')?.click();true`);await pause(150);assert.ok(await p.eval(`(()=>{const e=[...document.querySelectorAll('.contact-row')].find(e=>e.textContent.includes(${JSON.stringify(credentials[j].username)}));e?.click();return !!e})()`));await until(()=>p.eval(`!!document.querySelector('.composer textarea')`),'composer');}
async function type(i,text){await phones[i].fill('textarea[aria-label="Message"]',text);await phones[i].eval(`document.querySelector('.composer').requestSubmit();true`);}
async function received(i,text,ms){const attachment=text.startsWith('Sent an attachment: '),label=attachment?text.slice('Sent an attachment: '.length):text;await until(()=>phones[i].eval(`Array.from(document.querySelectorAll(${JSON.stringify(attachment?'.message-bubble.received .attachment-card strong':'.message-bubble.received .message-text')})).filter(e=>e.textContent===${JSON.stringify(label)}).length===1`),'recipient UI message',ms);}
let wifiChanged=false,dataChanged=false;
try{
 for(let i=0;i<3;i++){assert.equal(command(i,['reverse','--list']),'');phones.push(await Phone.connect(19430+i));assert.equal((await phones[i].api('/api/vault/status')).vaultState,'unlocked');}
 for(const [a,b]of [[0,1],[1,2],[2,0]]){
  await chat(a,b);await chat(b,a);
  const bytes=crypto.randomBytes(150123),filename='live-'+a+'-to-'+b+'-'+crypto.randomBytes(4).toString('hex')+'.bin';
  await phones[a].eval(`(()=>{const data=Uint8Array.from(atob(${JSON.stringify(bytes.toString('base64'))}),c=>c.charCodeAt(0));const files=new DataTransfer();files.items.add(new File([data],${JSON.stringify(filename)},{type:'application/octet-stream'}));const input=document.querySelector('input[type="file"]');input.files=files.files;input.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
  await received(b,'Sent an attachment: '+filename,90000);
  let message;
  const contact=(await phones[b].api('/api/contacts')).find(c=>c.publicUid===credentials[a].uid);
  await until(async()=>{message=(await phones[b].api('/api/messages/'+contact.conversation_id)).find(m=>m.plaintext==='Sent an attachment: '+filename);return !!message?.attachment_ready;},'native attachment download',90000);
  const downloaded=await phones[b].api('/api/attachments/'+message.attachment_id+'/decrypt');
  assert.deepEqual(Buffer.from(downloaded.filedataB64,'base64'),bytes);
  pass('Phone '+a+' -> '+b+': UI attachment decrypted byte-for-byte on receiving phone',{bytes:bytes.length,sha256:crypto.createHash('sha256').update(bytes).digest('hex')});
 }
 // Deliberately leave Wi-Fi: the sender must reach the relay over cellular.
 assert.equal(command(0,['shell','settings','get','global','wifi_on']),'1');
 assert.equal(command(0,['shell','settings','get','global','mobile_data']),'1');
 wifiChanged=true;command(0,['shell','svc','wifi','disable']);
 await until(async()=>{const routes=command(0,['shell','ip','route']);return !routes.includes('dev wlan')&&routes.includes('dev rmnet');},'cellular-only route');
 report.cellularRoute=command(0,['shell','ip','route']);
 await chat(0,1);await chat(1,0);
 let marker='Cellular -> WiFi '+crypto.randomBytes(6).toString('hex');await type(0,marker);await received(1,marker,90000);
 marker='WiFi -> Cellular '+crypto.randomBytes(6).toString('hex');await type(1,marker);await received(0,marker,90000);
 pass('Phone 0 on cellular, Phone 1 on Wi-Fi: real bidirectional internet delivery');
 // Both physical network transports go down; USB remains observation only.
 dataChanged=true;command(0,['shell','svc','data','disable']);
 await until(async()=>!command(0,['shell','ip','route']).includes('dev rmnet'),'cellular disconnected');
 const queued='Offline durable queue '+crypto.randomBytes(8).toString('hex');report.queuedMarker=queued;
 await type(0,queued);
 const ownContact=(await phones[0].api('/api/contacts')).find(c=>c.publicUid===credentials[1].uid);
 await until(async()=>{const m=(await phones[0].api('/api/messages/'+ownContact.conversation_id)).find(m=>m.plaintext===queued);return m?.status==='queued';},'offline message queued',90000);
 assert.equal(await phones[1].eval(`document.body.innerText.includes(${JSON.stringify(queued)})`),false);
 pass('Phone 0 offline: message durably queued and absent from receiver');
 command(0,['shell','svc','data','enable']);dataChanged=false;
 await received(1,queued,120000);
 await until(async()=>{const m=(await phones[0].api('/api/messages/'+ownContact.conversation_id)).find(m=>m.plaintext===queued);return m&&m.status!=='queued';},'sender queued status clears',45000);
 pass('Cellular restored: queued message automatically delivered once and sender status updated');
 command(0,['shell','svc','wifi','enable']);wifiChanged=false;
 for(let i=0;i<3;i++){
  const contacts=await phones[i].api('/api/contacts');
  for(const c of contacts){const peer=credentials.findIndex(x=>x.uid===c.publicUid);if(peer<0)continue;const reverse=(await phones[peer].api('/api/contacts')).find(x=>x.publicUid===credentials[i].uid);assert.equal(c.safety_number_hash,reverse.safety_number_hash);}
  await phones[i].snapshot(path.join(out,'phone-'+i+'-final.png'));
 }
 pass('All three pairs have matching safety numbers after live traffic');
}catch(e){checks.push({name:e.message,status:'fail'});console.error(e.stack);process.exitCode=1;
 for(const [i,p]of phones.entries())try{fs.writeFileSync(path.join(out,'recovery-phone-'+i+'-failure.txt'),await p.text());await p.snapshot(path.join(out,'recovery-phone-'+i+'-failure.png'));}catch{}
}finally{
 if(dataChanged)try{command(0,['shell','svc','data','enable']);}catch{}
 if(wifiChanged)try{command(0,['shell','svc','wifi','enable']);}catch{}
 report.finishedAt=new Date().toISOString();save();for(const p of phones)p.close();console.log('Evidence: '+out);
}
