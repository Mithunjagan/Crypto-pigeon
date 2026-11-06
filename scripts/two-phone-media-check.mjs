import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {writeFileSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
const root=resolve(import.meta.dirname,'..'),results=[],out=resolve(root,'artifacts','two-phone-media');
mkdirSync(out,{recursive:true});
const serials=process.env.ANDROID_SERIALS?.split(',');assert.equal(serials?.length,2);
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function adb(serial,args,binary=false){const r=spawnSync(resolve(root,'artifacts/android-device-tools/platform-tools/adb.exe'),['-s',serial,...args],{encoding:binary?undefined:'utf8',timeout:15000,maxBuffer:4*1024*1024});if(r.error)throw r.error;return r;}
class Page{
  constructor(ws){this.ws=ws;this.id=0;this.pending=new Map();ws.addEventListener('message',event=>{const m=JSON.parse(event.data);const p=this.pending.get(m.id);if(p){this.pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});}
  call(method,params={}){const id=++this.id;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('CDP timeout: '+method));},15000);this.pending.set(id,{resolve,reject,timer});this.ws.send(JSON.stringify({id,method,params}));});}
  async eval(expression){const r=await this.call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true,userGesture:true});if(r.exceptionDetails)throw new Error(r.exceptionDetails.exception?.description??r.exceptionDetails.text);return r.result.value;}
}
async function connect(port){const entries=await fetch(`http://127.0.0.1:${port}/json/list`).then(r=>r.json());const entry=entries.find(p=>p.url.startsWith('http://127.0.0.1:184'));assert.ok(entry,'Phone page missing');const ws=new WebSocket(entry.webSocketDebuggerUrl.replace('localhost:','127.0.0.1:'));await new Promise((res,rej)=>{ws.addEventListener('open',res,{once:true});ws.addEventListener('error',rej,{once:true});});return new Page(ws);}
function pass(name){console.log('PASS: '+name);results.push({name,status:'pass'});}
const pages=[];
try{
  pages.push(await connect(19322),await connect(19323));
  for(let i=0;i<2;i++){
    const page=pages[i];
    await page.eval(`(async()=>{const contacts=await fetch('/api/contacts').then(r=>r.json());const e=[...document.querySelectorAll('.contact-sidebar button')].find(b=>b.textContent.includes(contacts[0].username));if(!e)throw new Error('Contact button missing');e.click();return true;})()`);
    await pause(1000);
    const attachment=await page.eval(`(async()=>{const c=await fetch('/api/contacts').then(r=>r.json());const messages=await fetch('/api/messages/'+c[0].conversation_id).then(r=>r.json());const m=messages.find(m=>m.direction==='received'&&m.attachment_ready);if(!m)return null;return {id:m.attachment_id,...await fetch('/api/attachments/'+m.attachment_id+'/decrypt').then(r=>r.json())}})()`);
    assert.ok(attachment);assert.match(attachment.filename,/^phone-(first|second)-[a-z0-9]+\.bin$/);
    await page.eval(`(()=>{const e=document.querySelector('a[href="/api/attachments/${attachment.id}/decrypt?download=1"]');if(!e)throw new Error('Download link missing');e.click();return true})()`);
    const path='/sdcard/Download/'+attachment.filename;
    const deadline=Date.now()+30000;let downloaded;
    while(Date.now()<deadline){const exists=adb(serials[i],['shell','test','-f',path]);if(exists.status===0){const r=adb(serials[i],['exec-out','cat',path],true);downloaded=r.stdout;break;}await pause(500);}
    assert.ok(downloaded,'DownloadManager did not save '+attachment.filename);
    assert.equal(sha(downloaded),sha(Buffer.from(attachment.filedataB64,'base64')));
    pass('Phone '+(i+1)+': native Android download saved the exact decrypted file');
  }
  // Generate a tone in the WebView: no room audio or hardware microphone is captured.
  await pages[0].eval(`(async()=>{
    document.querySelector('[aria-label="Dismiss notification"]')?.click();
    const ctx=new AudioContext(),osc=ctx.createOscillator(),dest=ctx.createMediaStreamDestination();osc.connect(dest);osc.frequency.value=440;osc.start();await ctx.resume();
    const original=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);navigator.mediaDevices.getUserMedia=async()=>dest.stream;
    document.querySelector('[aria-label="Record voice note"]').click();
    await new Promise(r=>setTimeout(r,1200));document.querySelector('[aria-label="Stop and send voice note"]').click();
    navigator.mediaDevices.getUserMedia=original;osc.stop();setTimeout(()=>ctx.close(),1000);return true;
  })()`);
  let received;const deadline=Date.now()+45000;
  while(Date.now()<deadline){received=await pages[1].eval(`(async()=>{const c=await fetch('/api/contacts').then(r=>r.json());const m=(await fetch('/api/messages/'+c[0].conversation_id).then(r=>r.json())).find(m=>m.plaintext==='Voice note'&&m.attachment_ready);return m?{id:m.attachment_id,...await fetch('/api/attachments/'+m.attachment_id+'/decrypt').then(r=>r.json())}:null})()`);if(received)break;await pause(500);}
  assert.ok(received,'Synthetic voice note not received');
  const bytes=Buffer.from(received.filedataB64,'base64');assert.equal(bytes.subarray(0,4).toString('hex'),'1a45dfa3');
  const playable=await pages[1].eval(`new Promise(resolve=>{const a=new Audio('/api/attachments/${received.id}/decrypt?play=1');a.onloadedmetadata=()=>resolve({ok:true,duration:a.duration});a.onerror=()=>resolve({ok:false});a.load();setTimeout(()=>resolve({ok:false,timeout:true}),10000);})`);
  assert.equal(playable.ok,true);
  pass('Synthetic voice note recorded, encrypted, delivered, decrypted and decoded as playable audio');
  for(let i=0;i<2;i++){const shot=await pages[i].call('Page.captureScreenshot',{format:'png'});writeFileSync(resolve(out,'phone-'+(i+1)+'.png'),Buffer.from(shot.data,'base64'));}
}catch(error){results.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;}
finally{for(const page of pages)page.ws.close();writeFileSync(resolve(out,'results.json'),JSON.stringify({results,notes:['Voice note uses a generated tone, not the physical microphone.']},null,2));}
