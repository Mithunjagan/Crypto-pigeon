import {fork,spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root=resolve(import.meta.dirname,'..'),out=resolve(root,'artifacts','two-phones-'+Date.now());
mkdirSync(out,{recursive:true});
const require=createRequire(resolve(root,'apps/relay-server/package.json'));
const {Pool}=require('pg');
const pg=JSON.parse(readFileSync(resolve(root,'artifacts/android-chat-postgres/connection.json'),'utf8'));
const pgUrl=new URL(`postgresql://${pg.user}@127.0.0.1:${pg.port}/postgres`);pgUrl.password=pg.password;
const adminPool=new Pool({connectionString:pgUrl.href});
const database='cp_chat_'+Date.now();
const relayEnv={...process.env,PORT:'18443',HOST:'127.0.0.1',RELAY_HOSTNAME:'127.0.0.1:18443',ADMIN_USERNAME:'android_chat_test',ADMIN_TOKEN:crypto.randomBytes(32).toString('hex'),ACTIVATION_PEPPER:crypto.randomBytes(32).toString('hex'),LOG_LEVEL:'error'};
const serials=process.env.ANDROID_SERIALS?.split(',')??[];
assert.equal(serials.length,2,'Set ANDROID_SERIALS to two comma-separated authorized devices');
let activeSerial=serials[0];
const children=[],sockets=[],results=[],testMessages=[],testCredentials=[];
let relay,pool,phonePage,desktopPage;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
function save(){writeFileSync(resolve(out,'results.json'),JSON.stringify({database,results,testMessages,limitations:['Both physical phones use isolated host daemons over USB. Standalone on-phone cryptography is not implemented.']},null,2));}
function pass(name){results.push({name,status:'pass'});console.log('PASS: '+name);save();}
function adb(args,binary=false){const r=spawnSync(resolve(root,'artifacts/android-device-tools/platform-tools/adb.exe'),['-s',activeSerial,...args],{encoding:binary?undefined:'utf8',maxBuffer:32*1024*1024,timeout:60000});if(r.error)throw r.error;assert.equal(r.status,0,'ADB '+args[0]+': '+r.stderr);return r.stdout;}
function nodeChild(file,env){const child=fork(resolve(root,file),[],{cwd:root,silent:true,env:{...process.env,...env}});children.push(child);let errors='';const record=b=>{errors=(errors+b.toString()).slice(-24000);};child.stderr.on('data',record);child.stdout.on('data',record);child.diagnostic=()=>errors.replace(/postgres(?:ql)?:\/\/\S+/g,'[database URL redacted]');return child;}
async function waitUntil(check,label,ms=45000){const end=Date.now()+ms;while(Date.now()<end){if(await check())return;await pause(500);}throw new Error('Timed out: '+label);}
async function startRelay(){relay=nodeChild('apps/relay-server/dist/server.js',relayEnv);await waitUntil(async()=>{if(relay.exitCode!==null)throw new Error('Relay startup failed: '+relay.diagnostic());return fetch('http://127.0.0.1:18443/readyz',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok).catch(()=>false);},'relay readiness');}
async function stop(child){if(child.exitCode!==null)return;await new Promise(res=>{child.once('exit',res);child.kill();});}
async function daemon(name,port){const child=nodeChild('apps/local-daemon/dist/server.js',{PORT:String(port),CRYPTO_PIGEON_HOME:resolve(out,name+'-vault'),RELAY_URL:'http://127.0.0.1:18443'});const url=await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error(name+' daemon timeout: '+child.diagnostic())),30000);child.on('message',m=>{if(m?.type==='desktop-ready'){clearTimeout(t);res(m.url);}});child.on('exit',c=>{clearTimeout(t);rej(new Error(name+' daemon exited '+c+': '+child.diagnostic()));});});return {child,url,port,name};}
class Page{
  constructor(ws){this.ws=ws;this.id=0;this.pending=new Map();ws.addEventListener('message',e=>{const m=JSON.parse(e.data);if(m.id){const p=this.pending.get(m.id);this.pending.delete(m.id);if(p)m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});}
  async call(method,params={}){const id=++this.id;return await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>{this.pending.delete(id);reject(new Error('CDP timeout: '+method));},15000);this.pending.set(id,{resolve:v=>{clearTimeout(timeout);resolve(v);},reject:e=>{clearTimeout(timeout);reject(e);}});this.ws.send(JSON.stringify({id,method,params}));});}
  async eval(expression){const r=await this.call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error('WebView script exception: '+(r.exceptionDetails.exception?.description??r.exceptionDetails.text));return r.result.value;}
  async fill(selector,value){assert.equal(await this.eval(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)return false;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));return true})()`),true,'Input missing: '+selector);await pause(100);}
  async clickText(text){assert.equal(await this.eval(`(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)});if(!b)return false;b.click();return true})()`),true,'Button missing: '+text);await pause(200);}
  async waitText(text,ms){await waitUntil(()=>this.eval(`document.body.innerText.includes(${JSON.stringify(text)})`),'UI text '+text,ms);}
  async text(){return this.eval('document.body.innerText');}
  async screenshot(name){const r=await this.call('Page.captureScreenshot',{format:'png'});writeFileSync(resolve(out,name+'.png'),Buffer.from(r.data,'base64'));}
}
async function devicePid(){let pid;await waitUntil(async()=>{try{pid=adb(['shell','pidof','app.cryptopigeon.mobile.debug']).trim();return !!pid;}catch{adb(['shell','am','start','-W','-n','app.cryptopigeon.mobile.debug/app.cryptopigeon.mobile.MainActivity']);return false;}},'Android app process',30000);return pid;}
async function connect(port,origin){let entry;await waitUntil(async()=>{const pages=await fetch(`http://127.0.0.1:${port}/json/list`).then(r=>r.json()).catch(()=>[]);entry=pages.find(p=>p.url.startsWith(origin));return !!entry;},'WebView debugger');const ws=new WebSocket(entry.webSocketDebuggerUrl.replace('localhost:','127.0.0.1:'));await new Promise((res,rej)=>{ws.addEventListener('open',res,{once:true});ws.addEventListener('error',rej,{once:true});});sockets.push(ws);return new Page(ws);}
async function createVault(page,label){
  await page.waitText('Create encrypted vault');
  const id=label+'-'+crypto.randomBytes(16).toString('hex'),password='ChatTest-Aa1!'+crypto.randomBytes(16).toString('hex');
  testCredentials.push({label,vaultId:id,password});writeFileSync(resolve(out,'test-credentials.private.json'),JSON.stringify(testCredentials,null,2),{mode:0o600});
  await page.fill('.vault-gate form input:nth-of-type(1)',id);
  // Inputs live inside separate labels, so select by label order.
  for(const [i,value]of [[0,id],[1,password],[2,password]]){assert.equal(await page.eval(`(()=>{const e=document.querySelectorAll('.vault-gate form input')[${i}];if(!e)return false;Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));return true})()`),true);await pause(100);}
  await page.clickText('Create encrypted vault');
  await page.waitText('New Conversation',90000);
  pass(label+': created encrypted vault through UI');
}
async function register(page,name){
  assert.equal(await page.eval(`(()=>{const b=document.querySelector('button:has(svg.lucide-settings)');if(!b)return false;b.click();return true})()`),true,'Settings toolbar button missing');
  await page.waitText('Request Activation');
  await page.fill('input[placeholder="Register Username"]',name);await page.clickText('Request Activation');
  await page.waitText('Submit Activation Code');
  const request=await pool.query('SELECT request_id FROM access_requests WHERE username=$1 AND status=$2',[name,'pending']);assert.equal(request.rowCount,1);
  const code=crypto.randomBytes(16).toString('base64url');
  const hash=crypto.createHmac('sha256',relayEnv.ACTIVATION_PEPPER).update(code).digest('hex');
  await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$2,activation_expires_at=NOW()+INTERVAL '10 minutes',attempt_count=0,decided_at=NOW() WHERE request_id=$1 AND status='pending'",[request.rows[0].request_id,hash]);
  await page.fill('input[placeholder="Enter Activation Code"]',code);await page.clickText('Submit Activation Code');
  await page.waitText('Device Activated & Keys Synchronized!',90000);await page.clickText('Close');
  pass(name+': registered with real relay and Signal keys');
}
async function newConversation(page,username,action){await page.clickText('New Conversation');await page.fill('input[placeholder="CP-XXXX-XXXX or username"]',username);await page.clickText(action);}
async function selectContact(page,username){assert.equal(await page.eval(`(()=>{const b=[...document.querySelectorAll('.contact-sidebar button')].find(b=>b.textContent.includes(${JSON.stringify(username)}));if(!b)return false;b.click();return true})()`),true,'Contact missing: '+username);await page.waitText('Disappearing messages');}
async function send(page,text){await page.fill('input[placeholder="Type E2EE message..."]',text);assert.equal(await page.eval(`(()=>{document.querySelector('.chat-thread form').requestSubmit();return true})()`),true);await page.waitText(text,60000);}
async function waitReceived(page,text){await page.waitText(text,90000);assert.equal(await page.eval(`Array.from(document.querySelectorAll('.chat-thread .self-start span')).filter(e=>e.textContent===${JSON.stringify(text)}).length`),1,'Received message should appear once');}
try{
  activeSerial=serials[0];
  if(!process.argv.includes('--skip-install'))adb(['install','-r',resolve(root,'artifacts/crypto-pigeon-debug.apk')]);pass(process.argv.includes('--skip-install')?'Using the preinstalled debug APK on the first phone':'Installed the debug APK on the first phone');
  await adminPool.query('CREATE DATABASE '+database);await adminPool.end();pgUrl.pathname='/'+database;relayEnv.DATABASE_URL=pgUrl.href;pool=new Pool({connectionString:pgUrl.href});
  await startRelay();pass('Real PostgreSQL-backed relay is healthy');
  // Capture the actual opaque envelope before normal recipient ACK deletes it.
  await pool.query('CREATE TABLE chat_test_envelopes (id uuid, encrypted_payload bytea); CREATE FUNCTION chat_test_capture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO chat_test_envelopes VALUES (NEW.id,NEW.encrypted_payload); RETURN NEW; END $$; CREATE TRIGGER chat_test_capture AFTER INSERT ON messages FOR EACH ROW EXECUTE FUNCTION chat_test_capture()');
  const phone=await daemon('phone',18420),desktop=await daemon('desktop',18421);
  adb(['reverse','tcp:18420','tcp:18420']);adb(['shell','am','force-stop','app.cryptopigeon.mobile.debug']);adb(['shell','am','start','-W','-n','app.cryptopigeon.mobile.debug/app.cryptopigeon.mobile.MainActivity','--es','bootstrapUrl',phone.url]);
  await pause(2000);const pid=await devicePid();adb(['forward','tcp:19322','localabstract:webview_devtools_remote_'+pid]);
  phonePage=await connect(19322,'http://127.0.0.1:18420/');console.log('First phone debugger connected');
  console.log('Connecting second phone');activeSerial=serials[1];
  if(!process.argv.includes('--skip-install'))adb(['install','-r',resolve(root,'artifacts/crypto-pigeon-debug.apk')]);
  adb(['reverse','tcp:18421','tcp:18421']);adb(['shell','am','force-stop','app.cryptopigeon.mobile.debug']);
  adb(['shell','am','start','-W','-n','app.cryptopigeon.mobile.debug/app.cryptopigeon.mobile.MainActivity','--es','bootstrapUrl',desktop.url]);
  await pause(2000);const secondPid=await devicePid();
  adb(['forward','tcp:19323','localabstract:webview_devtools_remote_'+secondPid]);
  desktopPage=await connect(19323,'http://127.0.0.1:18421/');console.log('Second phone debugger connected');
  activeSerial=serials[0];
  await createVault(phonePage,'Phone');await createVault(desktopPage,'Second phone');
  const suffix=Date.now().toString(36),alice='phone_'+suffix,bob='second_'+suffix;
  await register(phonePage,alice);await register(desktopPage,bob);
  await newConversation(phonePage,bob,'Send Conversation Request');
  await desktopPage.waitText('Accept',45000);await desktopPage.clickText('Accept');
  await waitUntil(async()=>(await pool.query('SELECT 1 FROM conversation_permissions WHERE revoked_at IS NULL')).rowCount===1,'conversation approval');pass('Recipient accepted conversation request through UI');
  await newConversation(phonePage,bob,'Establish Session');
  await waitUntil(()=>phonePage.eval(`Array.from(document.querySelectorAll('.contact-sidebar button')).some(b=>b.textContent.includes(${JSON.stringify(bob)}))`),'phone contact');
  await selectContact(phonePage,bob);
  const first='Hello from the Android phone — live E2EE test '+suffix;testMessages.push(first);await send(phonePage,first);
  // The incoming prekey message must refresh the conversation list without reload.
  await waitUntil(async()=>{const body=await desktopPage.eval('fetch("/api/contacts").then(r=>r.json())');return body.some(c=>c.username===alice);},'computer receives first message',90000);
  await waitUntil(()=>desktopPage.eval(`Array.from(document.querySelectorAll('.contact-sidebar button')).some(b=>b.textContent.includes(${JSON.stringify(alice)}))`),'incoming conversation appears without reload');
  await selectContact(desktopPage,alice);await waitReceived(desktopPage,first);pass('First phone message delivered and decrypted on second phone without page reload');
  const reply='Second phone reply received on first phone ✅ '+suffix;testMessages.push(reply);await send(desktopPage,reply);await waitReceived(phonePage,reply);pass('Second phone reply delivered and decrypted on first phone');
  for(const [sender,receiver,text]of [[phonePage,desktopPage,'தமிழ் नमस्ते 🕊️ from phone '+suffix],[desktopPage,phonePage,'Another phone reply: punctuation & <text> '+suffix]]){testMessages.push(text);await send(sender,text);await waitReceived(receiver,text);}pass('Unicode and repeated bidirectional messages delivered exactly once');
  await phonePage.screenshot('phone-chat');await desktopPage.screenshot('computer-chat');
  // Exercise the UI upload path with a multi-chunk binary file on each phone.
  for (const [sender,receiver,label] of [[phonePage,desktopPage,'first'],[desktopPage,phonePage,'second']]) {
    const file=crypto.randomBytes(150000),filename='phone-'+label+'-'+suffix+'.bin';
    await sender.eval(`(()=>{const bytes=Uint8Array.from(atob(${JSON.stringify(file.toString('base64'))}),c=>c.charCodeAt(0));const dt=new DataTransfer();dt.items.add(new File([bytes],${JSON.stringify(filename)},{type:'application/octet-stream'}));const e=document.querySelector('input[type=file]');e.files=dt.files;e.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
    await receiver.waitText('Sent an attachment: '+filename,90000);
    const fetchFile=async page=>{let data;await waitUntil(async()=>{data=await page.eval(`(async()=>{const messages=await fetch('/api/messages/'+(await fetch('/api/contacts').then(r=>r.json()))[0].conversation_id).then(r=>r.json());const m=messages.find(m=>m.plaintext===${JSON.stringify('Sent an attachment: '+filename)});if(!m?.attachment_ready)return null;const r=await fetch('/api/attachments/'+m.attachment_id+'/decrypt');return r.ok?(await r.json()).filedataB64:null})()`);return !!data;},'attachment ready',90000);return Buffer.from(data,'base64');};
    assert.deepEqual(await fetchFile(receiver),file);assert.deepEqual(await fetchFile(sender),file);
    testMessages.push('Sent an attachment: '+filename);
    pass(label+': multi-chunk attachment uploaded through phone UI; sender and recipient hashes match');
  }
  // Kill and reopen each WebView process with no new secret.
  for (const [index,debugPort,port] of [[0,19322,18420],[1,19323,18421]]) {
    activeSerial=serials[index];
    adb(['shell','am','force-stop','app.cryptopigeon.mobile.debug']);
    adb(['shell','am','start','-W','-n','app.cryptopigeon.mobile.debug/app.cryptopigeon.mobile.MainActivity']);
    await pause(1500);const pid=await devicePid();
    adb(['forward','tcp:'+debugPort,'localabstract:webview_devtools_remote_'+pid]);
    const page=await connect(debugPort,'http://127.0.0.1:'+port+'/');
    await page.waitText('New Conversation',45000);
    if(index===0){phonePage=page;await selectContact(page,bob);}else{desktopPage=page;await selectContact(page,alice);}
    pass('Phone '+(index+1)+': force-stop/relaunch preserves authenticated pairing and conversation history');
  }
  activeSerial=serials[0];
  await stop(relay);const offline='Queued while relay offline '+suffix;testMessages.push(offline);await send(phonePage,offline);await phonePage.waitText('Queued · waiting for relay',45000);pass('Phone UI queues outgoing message during relay outage');
  await startRelay();await waitReceived(desktopPage,offline);pass('Queued message delivered after relay restart');
  for(const page of [phonePage,desktopPage]){
    const texts=await page.eval("Array.from(document.querySelectorAll('.chat-thread span.whitespace-pre-wrap')).map(e=>e.textContent)");
    assert.deepEqual(texts,testMessages,'Chat messages must remain in chronological conversation order');
  }
  pass('Both UIs show sent and received messages in chronological order');
  await waitUntil(async()=>!(await phonePage.text()).includes('Message queued. It will retry'),'queued notice clears after delivery');
  pass('Queued notice clears after successful retry');
  const envelopes=await pool.query('SELECT encrypted_payload FROM chat_test_envelopes');assert.ok(envelopes.rowCount>=testMessages.length);
  for(const {encrypted_payload:bytes}of envelopes.rows)for(const text of testMessages)assert.ok(!Buffer.from(bytes).includes(Buffer.from(text,'utf8')),'Relay envelope contains plaintext');
  pass('Actual relay envelopes contain ciphertext, with no test message plaintext');
  await phonePage.eval("document.querySelector('button:has(svg.lucide-settings)').click();true");
  await phonePage.waitText('Sync encrypted backup');await phonePage.clickText('Sync encrypted backup');
  await phonePage.waitText('Encrypted backup synchronized');await phonePage.clickText('Close');
  // The intentional outage left a backup warning; acknowledge it after a verified retry.
  await phonePage.eval("(()=>{const b=[...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='×');if(b)b.click();return true})()");
  pass('Manual encrypted backup succeeds after relay recovery');
  await phonePage.screenshot('phone-chat-final');await desktopPage.screenshot('computer-chat-final');
  writeFileSync(resolve(out,'phone-screen.png'),adb(['exec-out','screencap','-p'],true));
  pass('Chat test completed on both physical Android phones');
  console.log('Evidence: '+out);console.log('Relay and both phone daemons remain running for review.');
}catch(e){results.push({name:e.message,status:'fail'});console.error('FAIL: '+e.message);for(const [name,page]of [['phone',phonePage],['computer',desktopPage]])if(page){try{writeFileSync(resolve(out,name+'-failure.txt'),await page.text());await page.screenshot(name+'-failure');}catch{}}writeFileSync(resolve(out,'diagnostics.log'),children.map(c=>c.diagnostic?.()??'').join('\n'));save();process.exitCode=1;for(const child of children)if(child.exitCode===null)child.kill();}
finally{for(const ws of sockets)ws.close();await pool?.end();save();}
