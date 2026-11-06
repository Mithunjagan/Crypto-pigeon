// Real UI sends and real native Signal decryption on the two named phones.
// Device performance clocks are calibrated to the host monotonic clock over USB.
import { Phone, pause } from '../artifacts/hardware-control.mjs';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const adb=path.join(root,'artifacts/android-device-tools/platform-tools/adb.exe');
const output=path.join(root,'artifacts/phone-latency-results.json');
const credentials=JSON.parse(fs.readFileSync(path.join(root,'artifacts/hardware-active-phone-credentials.private.json')));
const serials=['10BEAN0MX8001J4','1396271662000T1'];
const urls={global:JSON.parse(fs.readFileSync(path.join(root,'apps/mobile-android/relay-defaults.json'),'utf8')).relayUrl,lan:'http://192.168.1.5:8443',usb:'http://127.0.0.1:8443'};
const routes=process.argv.includes('--routes')?process.argv[process.argv.indexOf('--routes')+1].split(','):['global','usb','lan'];
const prefix='CP_LATENCY_'+Date.now()+'_';
const phones=[],samples=[],phases=[],clocks=[];
const report=()=>fs.writeFileSync(output,JSON.stringify({method:'Warm active chats. Real composer submit to recipient decrypted bubble, observed after two animation frames. USB-calibrated device performance clocks; no manual fetch during samples.',prefix,samples,phases,clocks},null,2));
const command=(serial,args)=>{const r=spawnSync(adb,['-s',serial,...args],{encoding:'utf8',timeout:60000,windowsHide:true,maxBuffer:1024*1024});assert.equal(r.status,0,'ADB '+args.join(' ')+' failed');return r.stdout.trim();};
async function until(fn,label,timeout=30000){const deadline=Date.now()+timeout;while(Date.now()<deadline){if(await fn())return;await pause(100);}throw new Error('Timeout: '+label);}
async function calibrate(phone){let best={rtt:Infinity,offset:0};for(let i=0;i<9;i++){const start=performance.now(),stamp=await phone.eval('performance.now()'),end=performance.now();if(end-start<best.rtt)best={rtt:end-start,offset:(start+end)/2-stamp};}return best;}
const events=new Map();
async function instrument(phone,index){
  await phone.call('Runtime.addBinding',{name:'cpLatencyRecord'});
  phone.ws.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.method!=='Runtime.bindingCalled'||message.params.name!=='cpLatencyRecord')return;const value=JSON.parse(message.params.payload);const row=events.get(value.marker)||{};row[value.kind]={hostStamp:value.stamp+clocks[index].offset,deviceStamp:value.stamp,index,...value};events.set(value.marker,row);});
  await phone.eval(`(()=>{
    const prefix=${JSON.stringify(prefix)},seen=new Set();
    const observer=new MutationObserver(()=>{
      for(const bubble of document.querySelectorAll('.message-bubble')){
        const marker=bubble.querySelector('.message-text')?.textContent;if(!marker?.startsWith(prefix))continue;
        const kind=bubble.classList.contains('received')?'decrypted':'optimistic';
        if(seen.has(kind+marker))continue;seen.add(kind+marker);
        if(kind==='decrypted')requestAnimationFrame(()=>requestAnimationFrame(()=>cpLatencyRecord(JSON.stringify({kind,marker,stamp:performance.now()}))));
        else cpLatencyRecord(JSON.stringify({kind,marker,stamp:performance.now()}));
      }
    });observer.observe(document.body,{subtree:true,childList:true,characterData:true});
    const fetchOriginal=window.fetch.bind(window);
    window.fetch=async(...args)=>{const began=performance.now(),response=await fetchOriginal(...args);const stamp=performance.now(),url=String(args[0]);
      if(url==='/api/send'){const body=await response.clone().json();cpLatencyRecord(JSON.stringify({kind:'api',marker:window.__cpLatencyMarker,stamp,status:response.status,sendStatus:body.status,backupPending:body.backupPending}));}
      else if(url.startsWith('/api/events')){const body=await response.clone().json();if(body.type==='NEW_ENVELOPE'&&window.__cpActiveMarker)cpLatencyRecord(JSON.stringify({kind:'push',marker:window.__cpActiveMarker,stamp}));}
      else if(url==='/api/fetch-messages'){const body=await response.clone().json();if(body.received>0&&window.__cpActiveMarker)cpLatencyRecord(JSON.stringify({kind:'fetch',marker:window.__cpActiveMarker,stamp,duration:stamp-began}));}
      else if(url.startsWith('/api/messages/')&&window.__cpActiveMarker)cpLatencyRecord(JSON.stringify({kind:'history',marker:window.__cpActiveMarker,stamp}));
      return response;};
    return true;
  })()`);
}
async function openChat(phone,uid){
  await phone.eval(`(()=>{const close=[...document.querySelectorAll('.sheet-header button')];for(const e of close)e.click();const row=[...document.querySelectorAll('.contact-row')].find(e=>e.textContent.includes(${JSON.stringify(uid)}));if(row)row.click();return !!row})()`);
  await until(()=>phone.eval(`!!document.querySelector('.composer')&&document.querySelector('.thread-person')?.textContent.includes(${JSON.stringify(uid)})`),'expected peer chat');await pause(150);
}
async function route(phone,serial,url){
  const current=(await phone.api('/api/relay/config')).relayUrl;if(current===url)return;
  if(url===urls.usb||current===urls.usb){if(url===urls.usb)command(serial,['reverse','tcp:8443','tcp:8443']);await phone.api('/api/relay/config',{relayUrl:url});return;}
  await phone.eval(`document.querySelector('[aria-label="Back to conversations"]')?.click();true`);await pause(600);
  await phone.click('Settings');await pause(400);
  await phone.eval(`(()=>{const summary=[...document.querySelectorAll('summary')].find(e=>e.textContent.includes('Relay connection'));summary.click();return true})()`);
  const name=url===urls.lan?'Same network':'Internet';
  assert.ok(await phone.eval(`(()=>{const button=[...document.querySelectorAll('.relay-routes button')].find(e=>e.textContent.includes(${JSON.stringify(name)}));if(button)button.click();return !!button})()`),'Routing preset missing');
  await until(async()=>((await phone.api('/api/relay/config')).relayUrl===url),'live routing switch');
  await phone.eval(`document.querySelector('[aria-label="Close Settings"]')?.click();true`);await pause(500);
}
try {
  for(const [i,serial] of serials.entries()){
    command(serial,['shell','input','keyevent','KEYCODE_WAKEUP']);
    command(serial,['shell','am','start','-W','-n','app.cryptopigeon.nativeclient.debug/app.cryptopigeon.nativeclient.MainActivity']);
    const pid=command(serial,['shell','pidof','app.cryptopigeon.nativeclient.debug']);assert.ok(pid,'App did not start');
    command(serial,['forward','tcp:'+(19322+i),'localabstract:webview_devtools_remote_'+pid]);
    const phone=await Phone.connect(19322+i);phones.push(phone);
    const credential=credentials.find(c=>c.currentSerial===serial)||credentials.find(c=>c.serial===serial);assert.ok(credential);
    if((await phone.api('/api/vault/status')).vaultState!=='unlocked'){
      await phone.click('Unlock');await pause(300);await phone.fill('input[aria-label="Vault ID"]',credential.vaultId);await phone.fill('input[aria-label="Master passphrase"]',credential.password);await phone.click('Unlock vault');await phone.wait('Conversations',90000);
    }
    assert.equal((await phone.api('/api/access/state')).publicUid,credential.uid,'Vault identity changed');
    clocks.push({...await calibrate(phone),serial});await instrument(phone,i);
  }
  const own=serials.map(serial=>credentials.find(c=>c.currentSerial===serial)||credentials.find(c=>c.serial===serial));
  for(let i=0;i<2;i++)await openChat(phones[i],own[1-i].uid);
  for(const phase of routes){
    for(let i=0;i<2;i++){await route(phones[i],serials[i],urls[phase]);await openChat(phones[i],own[1-i].uid);}
    await until(async()=>{const status=await Promise.all(phones.map(p=>p.api('/api/transport/status')));return status.every(s=>s.pushConnected);},phase+' WebSocket connection',45000);
    for(const phone of phones){const point=await phone.eval(`(()=>{const r=document.querySelector('.thread-header .avatar').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);await phone.call('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});await phone.call('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});}
    const before=await Promise.all(phones.map(p=>p.api('/api/transport/status')));
    for(let n=0;n<6;n++){
      const sender=n<5?0:1,marker=prefix+phase+'_'+n;
      await Promise.all(phones.map(p=>p.eval(`window.__cpActiveMarker=${JSON.stringify(marker)};true`)));
      await phones[sender].fill('textarea[aria-label="Message"]',marker);
      await until(()=>phones[sender].eval(`!!document.querySelector('[aria-label="Send message"]:not(:disabled)')`),'send action ready');
      await phones[sender].eval(`(()=>{window.__cpLatencyMarker=${JSON.stringify(marker)};cpLatencyRecord(JSON.stringify({kind:'start',marker:window.__cpLatencyMarker,stamp:performance.now()}));document.querySelector('.composer').requestSubmit();return true})()`);
      await until(()=>{const row=events.get(marker);return !!row?.start&&!!row.api&&!!row.decrypted;},'decrypted recipient UI '+phase,30000);
      const row=events.get(marker);assert.equal(row.api.sendStatus,'sent','Message queued instead of delivered to relay');assert.equal(row.api.backupPending,true);
      const sample={route:phase,direction:sender===0?'V2422 → V2152':'V2152 → V2422',deliveryMs:+(row.decrypted.hostStamp-row.start.hostStamp).toFixed(2),sendApiMs:+(row.api.hostStamp-row.start.hostStamp).toFixed(2),optimisticMs:row.optimistic?+(row.optimistic.hostStamp-row.start.hostStamp).toFixed(2):null,clockUncertaintyMs:+((clocks[0].rtt+clocks[1].rtt)/2).toFixed(2)};
      sample.pushMs=row.push?+(row.push.hostStamp-row.start.hostStamp).toFixed(2):null;sample.fetchMs=row.fetch?+row.fetch.duration.toFixed(2):null;sample.renderAfterHistoryMs=row.history?+(row.decrypted.hostStamp-row.history.hostStamp).toFixed(2):null;
      samples.push(sample);report();console.log(JSON.stringify(sample));await pause(250);
    }
    const after=await Promise.all(phones.map(p=>p.api('/api/transport/status')));
    assert.ok(after.every((s,i)=>s.authRefreshes===before[i].authRefreshes),'Redundant challenge/response during active messaging');
    phases.push({route:phase,before,after});report();
    const times=samples.filter(s=>s.route===phase&&s.direction.startsWith('V2422')).map(s=>s.deliveryMs).sort((a,b)=>a-b);
    console.log(phase.toUpperCase()+' V2422 → V2152: min '+times[0]+' ms; median '+times[2]+' ms; max '+times.at(-1)+' ms');
  }
  // Restore the public route for cellular use and verify a quiet-period backup.
  for(let i=0;i<2;i++){await route(phones[i],serials[i],urls.global);await openChat(phones[i],own[1-i].uid);}
  const beforeQuiet=await Promise.all(phones.map(p=>p.api('/api/transport/status')));
  await pause(18000);
  const afterQuiet=await Promise.all(phones.map(p=>p.api('/api/transport/status')));
  phases.push({route:'restored-global',beforeQuiet,afterQuiet});report();
  assert.ok(afterQuiet.every(s=>!s.backupPending&&s.backupFailures===0&&s.backupRuns>=1),'Background backup did not settle cleanly');
  for(let i=0;i<2;i++)await phones[i].snapshot(path.join(root,'artifacts/latency-'+serials[i]+'-final.png'));
} finally {
  for(const phone of phones)try{await phone.api('/api/relay/config',{relayUrl:urls.global});}catch{}
  for(const phone of phones)phone.close();report();
}
