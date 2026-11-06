import {Phone,pause} from './lib/phone-ui.mjs';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root=path.resolve(import.meta.dirname,'..'),out=path.join(root,'artifacts/multi-vault-20261105');
const adb=path.join(root,'artifacts/android-device-tools/platform-tools/adb.exe'),serial='10BEAN0MX8001J4',pkg='app.cryptopigeon.nativeclient.debug',port=19431;
const credentials={username:'pigeon_test05',vaultId:'Pigeon123',password:'Pigeon123456!'};
let p;const checks=[],report={serial,checks,scope:'Actual installed app, existing default vault preserved; a separate easy-credential vault is created and reopened after process death.'};
const save=()=>fs.writeFileSync(path.join(out,'ui-results.json'),JSON.stringify(report,null,2));
const pass=name=>{checks.push({name,status:'pass'});save();console.log('PASS '+name);};
function cmd(args,binary=false){const r=spawnSync(adb,['-s',serial,...args],{encoding:binary?undefined:'utf8',timeout:60000,windowsHide:true,maxBuffer:16*1024*1024});assert.equal(r.status,0,'ADB '+args[0]+': '+r.stderr);return binary?r.stdout:r.stdout.trim();}
async function until(check,label,timeout=45000){const end=Date.now()+timeout;while(Date.now()<end){if(await check())return;await pause(250);}throw Error('Timeout: '+label);}
async function connect(){cmd(['shell','am','start','-W','-n',pkg+'/app.cryptopigeon.nativeclient.MainActivity']);const pid=cmd(['shell','pidof',pkg]);cmd(['forward','tcp:'+port,'localabstract:webview_devtools_remote_'+pid]);await until(()=>fetch('http://127.0.0.1:'+port+'/json/list',{signal:AbortSignal.timeout(1500)}).then(r=>r.json()).then(l=>l.some(x=>x.type==='page')).catch(()=>false),'WebView');return Phone.connect(port);}
function originalHashes(){return Object.fromEntries(['config.json','data/chat.db'].map(name=>[name,crypto.createHash('sha256').update(cmd(['exec-out','run-as',pkg,'cat','no_backup/vault/'+name],true)).digest('hex')]));}
function nodes(xml){return [...xml.matchAll(/<node\s+([^>]+)>/g)].map(m=>Object.fromEntries([...m[1].matchAll(/([\w-]+)="([^"]*)"/g)].map(a=>[a[1],a[2]])));}
function tap(n){assert.ok(n,'Android document control missing');const b=n.bounds.match(/\d+/g).map(Number);cmd(['shell','input','tap',String(Math.round((b[0]+b[2])/2)),String(Math.round((b[1]+b[3])/2))]);}
function xml(){cmd(['shell','uiautomator','dump','/sdcard/cp-multi-window.xml']);return cmd(['shell','cat','/sdcard/cp-multi-window.xml']);}
async function saveSegment(){let tree;await until(async()=>{tree=xml();return tree.includes('documentsui');},'Android document saver');const edit=nodes(tree).find(n=>n.class==='android.widget.EditText');assert.ok(edit);tap(edit);cmd(['shell','input','keyevent','123']);cmd(['shell','input','keyevent',...Array(50).fill('67')]);cmd(['shell','input','text','pigeon123-segment.cp7']);cmd(['shell','input','keyevent','4']);tap(nodes(xml()).find(n=>/^save$/i.test(n.text)&&n.enabled==='true'));}
async function loadSegment(capsule){await p.eval(`(()=>{const bytes=Uint8Array.from(atob(${JSON.stringify(capsule)}),c=>c.charCodeAt(0));const files=new DataTransfer();files.items.add(new File([bytes],'pigeon123-segment.cp7'));const input=document.querySelector('input[aria-label="Select segment 07 file"]');input.files=files.files;input.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);await p.wait('07 LOADED',10000);}
async function enter(password){await p.fill('input[aria-label="Vault ID"]',credentials.vaultId);await p.fill('input[aria-label="Master passphrase"]',password);await p.eval(`document.querySelector('.vault-form').requestSubmit();true`);}
try{
 p=await connect();await until(()=>p.eval(`!!document.querySelector('.vault-form')`),'vault gate');
 const before=originalHashes(),initialShard=await p.eval(`localStorage.getItem('cp-browser-shard-v1')`);
 assert.equal((await p.api('/api/vault/status')).multipleVaults,true);
 await p.click('Create vault');
 await p.fill('input[aria-label="Your username"]',credentials.username);await p.fill('input[aria-label="Vault ID"]',credentials.vaultId);await p.fill('input[aria-label="Master passphrase"]',credentials.password);await p.fill('input[aria-label="Confirm passphrase"]',credentials.password);
 await p.eval(`document.querySelector('.vault-form').requestSubmit();true`);await p.wait('Choose 7th Segment File Location',60000);
 await p.click('Choose 7th Segment File Location');await saveSegment();await p.wait('Create identity',45000);
 const status=await p.api('/api/vault/status');assert.notEqual(status.vaultHandle,'legacy');report.vaultHandle=status.vaultHandle;
 const shards=await p.eval(`JSON.parse(localStorage.getItem('cp-browser-shards-v2'))`);assert.equal(shards.legacy,initialShard);assert.ok(shards[status.vaultHandle]);
 assert.deepEqual(originalHashes(),before);pass('Created a second vault through the real UI and Android file saver; original vault files and browser fragment preserved');
 const capsule=await p.eval(`fetch('/api/vault/files/shard7').then(r=>r.arrayBuffer()).then(b=>btoa(String.fromCharCode(...new Uint8Array(b))))`);
 fs.writeFileSync(path.join(out,'easy-vault.private.json'),JSON.stringify({...credentials,vaultHandle:status.vaultHandle,segmentFilename:'pigeon123-segment.cp7'},null,2));
 await p.fill('input[aria-label="Display Name"]','Pigeon test');await p.click('Save profile');await pause(600);
 // Register only if the configured public internet relay is ready.
 const relay=(await p.api('/api/relay/config')).relayUrl;
 const ready=await fetch(relay+'/readyz',{headers:{'ngrok-skip-browser-warning':'1'},signal:AbortSignal.timeout(5000)}).then(r=>r.ok).catch(()=>false);
 if(ready){await p.click('Create identity');await until(async()=>{const access=await p.api('/api/access/state');if(access.publicUid){report.publicUid=access.publicUid;return true;}return false;},'real public identity',45000);pass('Registered the easy vault as a separate identity through the public HTTPS relay');}
 await p.eval(`document.querySelector('[aria-label="Close Settings"]')?.click();true`);await p.snapshot(path.join(out,'easy-vault-created.png'));
 await pause(1500);p.close();p=null;cmd(['shell','am','force-stop',pkg]);p=await connect();await p.wait('Unlock vault',30000);
 assert.equal((await p.api('/api/vault/status')).vaultState,'locked');await loadSegment(capsule);await enter('Pigeon123456?');
 await p.wait('Vault ID or master passphrase is incorrect.',30000);assert.equal((await p.api('/api/vault/status')).vaultState,'locked');pass('After force-stop/relaunch, wrong master passphrase is rejected and the vault stays locked');
 await enter(credentials.password);await until(()=>p.eval(`!!document.querySelector('.inbox-topbar')`),'correct password unlock',60000);
 assert.equal((await p.api('/api/profile')).displayName,'Pigeon test');assert.equal((await p.api('/api/vault/status')).vaultHandle,status.vaultHandle);assert.deepEqual(originalHashes(),before);
 const afterShards=await p.eval(`JSON.parse(localStorage.getItem('cp-browser-shards-v2'))`);assert.equal(afterShards.legacy,initialShard);
 pass('Correct master passphrase and matching segment reopen the new vault after process death; original vault still preserved');
 await p.snapshot(path.join(out,'easy-vault-unlocked.png'));report.originalHashes=before;
}catch(e){checks.push({name:e.message,status:'fail'});console.error(e.stack);process.exitCode=1;if(p)try{fs.writeFileSync(path.join(out,'ui-failure.txt'),await p.text());await p.snapshot(path.join(out,'ui-failure.png'));}catch{}
}finally{report.finishedAt=new Date().toISOString();save();p?.close();console.log('Evidence: '+out);}
