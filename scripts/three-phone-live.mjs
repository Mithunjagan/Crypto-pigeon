// Real standalone phones, public internet relay, no adb reverse or host vault.
import {spawn,spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {Phone,pause} from './lib/phone-ui.mjs';

const root=path.resolve(import.meta.dirname,'..');
const out=path.join(root,'artifacts/three-phone-live-20261103');
fs.mkdirSync(out,{recursive:true});
const adb=path.join(root,'artifacts/android-device-tools/platform-tools/adb.exe');
const pkg='app.cryptopigeon.nativeclient.debug';
const serials=['10BE7802KH0012D','10BEAN0MX8001J4','1396271662000T1'];
const relay=JSON.parse(fs.readFileSync(path.join(root,'apps/mobile-android/relay-defaults.json'))).relayUrl;
assert.equal(new URL(relay).protocol,'https:');
const privatePath=path.join(out,'credentials.private.json');
const saved=process.argv.includes('--attach')&&fs.existsSync(privatePath)?JSON.parse(fs.readFileSync(privatePath)):null;
const tag=saved?.tag??'live-'+Date.now().toString(36);
const credentials=saved?.credentials??serials.map((serial,i)=>({serial,username:'live_'+i+'_'+crypto.randomBytes(4).toString('hex'),vaultId:'LivePhone-'+crypto.randomBytes(12).toString('hex'),password:'LivePhone-Aa1!'+crypto.randomBytes(16).toString('hex')}));
fs.writeFileSync(privatePath,JSON.stringify({tag,credentials},null,2));
const phones=[],runners=[],checks=[],messages=[];
const report={tag,relay,startedAt:new Date().toISOString(),scope:'Three physical phones. Native per-phone vaults and Signal. Public HTTPS relay. USB only for UI control and observations. No host daemon or adb reverse. Direct WebRTC P2P is not implemented in the app.',devices:[],checks,messages};
const save=()=>fs.writeFileSync(path.join(out,'results.json'),JSON.stringify(report,null,2));
const pass=(name,details={})=>{checks.push({name,status:'pass',...details});save();console.log('PASS '+name);};
function command(serial,args,binary=false){const r=spawnSync(adb,['-s',serial,...args],{encoding:binary?undefined:'utf8',windowsHide:true,timeout:60000,maxBuffer:16*1024*1024});if(r.error)throw r.error;assert.equal(r.status,0,'ADB '+args[0]+': '+(binary?'':r.stderr));return binary?r.stdout:r.stdout.trim();}
async function until(check,label,timeout=45000){const end=Date.now()+timeout;while(Date.now()<end){if(await check())return;await pause(200);}throw Error('Timeout: '+label);}
async function openChat(p,uid){
 const name=credentials.find(c=>c.uid===uid)?.username??uid;
 await p.eval(`(()=>{document.querySelector('[aria-label="Close Settings"]')?.click();document.querySelector('[aria-label="Back to conversations"]')?.click();return true})()`);await pause(250);
 await until(()=>p.eval(`(()=>{const row=[...document.querySelectorAll('.contact-row')].find(e=>e.textContent.includes(${JSON.stringify(name)}));row?.click();return !!row})()`),'contact '+uid);
 await until(()=>p.eval(`!!document.querySelector('.composer textarea')`),'composer');
}
async function saveSegment(serial,index){
 let xml='';await until(async()=>{command(serial,['shell','uiautomator','dump','/sdcard/cp-live-window.xml']);xml=command(serial,['shell','cat','/sdcard/cp-live-window.xml']);return xml.includes('documentsui');},'Android file saver',20000);
 const nodes=[...xml.matchAll(/<node\s+([^>]+)>/g)].map(m=>Object.fromEntries([...m[1].matchAll(/([\w-]+)="([^"]*)"/g)].map(a=>[a[1],a[2]])));
 const edit=nodes.find(n=>n['class']==='android.widget.EditText');
 const tap=n=>{assert.ok(n,'Native document control missing');const b=n.bounds.match(/\d+/g).map(Number);command(serial,['shell','input','tap',String(Math.round((b[0]+b[2])/2)),String(Math.round((b[1]+b[3])/2))]);};
 if(edit){tap(edit);command(serial,['shell','input','keyevent','123']);command(serial,['shell','input','keyevent',...Array(45).fill('67')]);command(serial,['shell','input','text',tag+'-phone'+index+'.cp7']);command(serial,['shell','input','keyevent','4']);}
 command(serial,['shell','uiautomator','dump','/sdcard/cp-live-window.xml']);xml=command(serial,['shell','cat','/sdcard/cp-live-window.xml']);
 const buttons=[...xml.matchAll(/<node\s+([^>]+)>/g)].map(m=>Object.fromEntries([...m[1].matchAll(/([\w-]+)="([^"]*)"/g)].map(a=>[a[1],a[2]])));
 tap(buttons.find(n=>/^save$/i.test(n.text)&&n.enabled==='true'));
}
async function setup(p,i){
 const c=credentials[i];const state=await p.api('/api/vault/status');
 if(state.vaultState==='unconfigured'){
  await p.fill('input[aria-label="Your username"]',c.username);
  await p.fill('input[aria-label="Vault ID"]',c.vaultId);
  await p.fill('input[aria-label="Master passphrase"]',c.password);
  await p.fill('input[aria-label="Confirm passphrase"]',c.password);
  await p.eval(`document.querySelector('.vault-form').requestSubmit();true`);
  await until(()=>p.eval(`document.querySelector('.vault-form')?.hidden===true`),'seventh segment prompt',90000);
  assert.ok(await p.eval(`(()=>{const b=document.querySelector('.vault-card > .stack .btn-primary');b?.click();return !!b})()`));
  await saveSegment(c.serial,i);
  await until(()=>p.eval(`!!document.querySelector('.registration-section')`),'identity registration',45000);
  await p.click('Create identity');await p.wait('Chats',90000);
  pass('Phone '+i+': created isolated vault, saved seventh segment through Android, registered over HTTPS');
 }else if(state.vaultState!=='unlocked')throw Error('Test vault is locked; reopen using its saved seventh segment before resuming');
 c.uid=(await p.api('/api/access/state')).publicUid;assert.match(c.uid,/^CP-[A-F0-9]{4}-[A-F0-9]{4}$/);
 fs.writeFileSync(privatePath,JSON.stringify({tag,credentials},null,2));
 assert.equal((await p.api('/api/relay/config')).relayUrl,relay);
 report.devices[i]={serial:c.serial,uid:c.uid,network:command(c.serial,['shell','ip','route']),transport:await p.api('/api/transport/status')};save();
}
async function connectPair(a,b){
 const pa=phones[a],pb=phones[b],ca=credentials[a],cb=credentials[b];
 if(!(await pa.api('/api/contacts')).some(c=>c.publicUid===cb.uid)){
  await pa.eval(`document.querySelector('[aria-label="Close Settings"]')?.click();document.querySelector('[aria-label="Back to conversations"]')?.click();true`);
  await pa.eval(`document.querySelector('button[aria-label="New connection"]').click();true`);
  await pa.fill('input[placeholder="CP-XXXX-XXXX or username"]',cb.uid);
  await pa.eval(`document.querySelector('[aria-label="New connection"] form button[type="button"]').click();true`);
  let requests;await until(async()=>{requests=await pb.api('/api/conversations/requests');return requests.some(r=>r.requester_public_uid===ca.uid);},'real incoming invitation');
  await pb.wait('Approve',25000);await pb.click('Approve');
  await until(()=>pa.eval(`Array.from(document.querySelectorAll('.contact-row')).some(e=>e.textContent.includes(${JSON.stringify(cb.username)}))`),'invitation opens conversation automatically');
 }
 pass('Phones '+a+' and '+b+': live invitation approved and native Signal session established');
}
async function send(a,b,text){
 const sender=phones[a],recipient=phones[b];
 await openChat(sender,credentials[b].uid);
 const c=(await recipient.api('/api/contacts')).find(c=>c.publicUid===credentials[a].uid);
 if(c)await openChat(recipient,credentials[a].uid);
 await sender.fill('textarea[aria-label="Message"]',text);
 const start=Date.now();await sender.eval(`document.querySelector('.composer').requestSubmit();true`);
 let count=0;
 await until(async()=>{count=await recipient.eval(`Array.from(document.querySelectorAll('.message-bubble.received .message-text')).filter(e=>e.textContent===${JSON.stringify(text)}).length`);if(count===1)return true;
  // Select a newly created incoming conversation, without fetching messages manually.
  await recipient.eval(`(()=>{const row=[...document.querySelectorAll('.contact-row')].find(e=>e.textContent.includes(${JSON.stringify(credentials[a].username)}));row?.click();return !!row})()`);return false;
 },'recipient UI decrypts '+a+' -> '+b,60000);
 assert.equal(count,1);messages.push({from:a,to:b,text,observedMs:Date.now()-start});
 pass('Phone '+a+' -> '+b+': message decrypted once in recipient UI',{observedMs:Date.now()-start});
}
try{
 for(const [i,serial]of serials.entries()){
  assert.equal(command(serial,['reverse','--list']),'','Remove existing USB network routes before testing');
  if(process.argv.includes('--attach')){const p=await Phone.connect(19430+i);phones.push(p);await setup(p,i);continue;}
  if(!process.argv.includes('--no-install')){
   command(serial,['install','-r',path.join(root,'artifacts/crypto-pigeon-standalone.apk')]);
   command(serial,['install','-r','-t',path.join(root,'artifacts/native-android/crypto-pigeon-native-tests.apk')]);
  }
  command(serial,['shell','input','keyevent','KEYCODE_WAKEUP']);
  const log=fs.openSync(path.join(out,'instrumentation-'+i+'.log'),'w');
  const child=spawn(adb,['-s',serial,'shell','am','instrument','-w','-r','-e','phase','live-phones','-e','runTag',tag,'-e','relayUrl',relay,pkg+'.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation'],{windowsHide:true,stdio:['ignore',log,log]});fs.closeSync(log);runners.push(child);
  let pid;await until(async()=>{pid=spawnSync(adb,['-s',serial,'shell','pidof',pkg],{encoding:'utf8',windowsHide:true,timeout:10000}).stdout?.trim();if(!pid)return false;command(serial,['forward','tcp:'+(19430+i),'localabstract:webview_devtools_remote_'+pid]);return fetch('http://127.0.0.1:'+(19430+i)+'/json/list',{signal:AbortSignal.timeout(1500)}).then(r=>r.json()).then(l=>l.some(x=>x.type==='page')).catch(()=>false);},'phone WebView '+i,45000);
  const p=await Phone.connect(19430+i);phones.push(p);await p.wait('Create vault',30000);await setup(p,i);
 }
 for(const [a,b]of [[0,1],[1,2],[2,0]])await connectPair(a,b);
 for(const [a,b]of [[0,1],[1,2],[2,0],[1,0],[2,1],[0,2]])await send(a,b,'Live internet '+a+' → '+b+' தமிழ் नमस्ते 🕊️ '+crypto.randomBytes(4).toString('hex'));
 for(const [i,p]of phones.entries()){await p.snapshot(path.join(out,'phone-'+i+'-chat.png'));report.devices[i].transportAfter=await p.api('/api/transport/status');}
 pass('All six directions delivered between three real phones over public HTTPS');
}catch(error){checks.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;
 for(const [i,p]of phones.entries())try{fs.writeFileSync(path.join(out,'phone-'+i+'-failure.txt'),await p.text());await p.snapshot(path.join(out,'phone-'+i+'-failure.png'));}catch{}
}finally{report.finishedAt=new Date().toISOString();save();for(const p of phones)p.close();for(const c of runners)c.unref();console.log('Evidence: '+out);}
