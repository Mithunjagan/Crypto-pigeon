import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {createReadStream,createWriteStream} from 'node:fs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {seedPublicTorCache,delay} from './tor-live-support.mjs';

const root=resolve(import.meta.dirname,'..');
const runId=crypto.randomBytes(8).toString('hex'),started=Date.now();
const out=join(root,'artifacts/serverless-p2p','two-phone-'+runId);
await mkdir(out,{recursive:true});
const adbPath=resolve(root,'artifacts/android-device-tools/platform-tools/adb.exe');
const apk=resolve(root,'artifacts/crypto-pigeon-standalone.apk');
const testApk=resolve(root,'artifacts/native-android/crypto-pigeon-native-tests.apk');
const events=[],phones=[];
let pkg,apkSha256,failure;
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const record=(name,data={})=>{const event={name,elapsedMs:Date.now()-started,...data};events.push(event);console.log(`[${Math.round(event.elapsedMs/1000)}s] ${name}`);};

function adb(phone,args,{input,timeout=30000,allowFailure=false}={}){
  if(args.some(value=>value==='reverse'||value==='forward'))throw Error('USB_PEER_TRANSPORT_FORBIDDEN');
  const result=spawnSync(adbPath,[...(phone?['-s',phone.serial]:[]),...args],{input,encoding:'utf8',timeout,maxBuffer:16*1024*1024,windowsHide:true});
  if((result.error||result.status!==0)&&!allowFailure)throw Error('ADB_'+(phone?.label??'HOST')+'_'+args[0].toUpperCase()+'_FAILED');
  return result.stdout??'';
}
function deviceFile(phone,name){
  const raw=adb(phone,['exec-out','run-as',pkg,'cat',`files/one-phone-tor-${runId}/${name}`],{allowFailure:true});
  try{return JSON.parse(raw);}catch{return null;}
}
async function wait(label,condition,timeout=480000,interval=1000,watch=phones){
  const deadline=Date.now()+timeout;
  while(Date.now()<deadline){
    const result=await condition();if(result)return result;
    for(const phone of watch)if(phone.instrument?.exitCode!=null&&!phone.finished)throw Error('PHONE_'+phone.label+'_INSTRUMENTATION_EXITED');
    await delay(interval);
  }
  throw Error('DEADLINE_'+label.toUpperCase().replace(/[^A-Z0-9]/g,'_'));
}
async function command(phone,action,extra={},cleanup=false){
  const id=String(++phone.counter);
  // Only local action selectors, a sample index and public signed invites cross ADB.
  // Text, file bytes and microphone audio are created on-device and use Tor only.
  adb(phone,['shell','run-as',pkg,'tee',`files/one-phone-tor-${runId}/command.json`],{input:JSON.stringify({id,action,...extra})});
  const response=await wait('PHONE_'+phone.label+'_'+action,()=>{const value=deviceFile(phone,'response.json');return value?.id===id?value:null;},180000,400,cleanup?[phone]:phones);
  if(!response.ok)throw Error('PHONE_'+phone.label+'_'+action+'_FAILED');
  return response.result;
}
const text=(phone,label)=>`Phone ${phone.label} ${label} தமிழ் 🌍🕊️ ${runId}`;
const fixture=(size,seed)=>Buffer.from(Array.from({length:size},(_,i)=>(i*31+seed)&255));
function maximumText(){const unit='வணக்கம் 🌍🕊️ ';let value=unit.repeat(Math.ceil(65536/unit.length)).slice(0,65536);const last=value.charCodeAt(value.length-1);if(last>=0xd800&&last<=0xdbff)value=value.slice(0,-1)+'A';return value;}
async function hasReceived(phone,expected,{attachmentSha,attachmentBytes}={}){
  const state=await command(phone,'SNAPSHOT');
  const row=state.messages?.find(message=>message.direction==='received'&&message.textSha256===hash(Buffer.from(expected))&&(!attachmentSha||message.attachmentSha256===attachmentSha)&&(attachmentBytes===undefined||message.attachmentBytes===attachmentBytes));
  return row?state:null;
}
async function delivered(phone,expected){
  const state=await command(phone,'SNAPSHOT');
  return state.outbox===0&&state.messages?.some(message=>message.direction==='sent'&&message.textSha256===hash(Buffer.from(expected))&&['delivered','read'].includes(message.status));
}
async function finish(phone){
  await command(phone,'FINISH',{},true);phone.finished=true;
  await wait('PHONE_'+phone.label+'_FINISHED',()=>phone.logClosed,30000,300,[]);
  assert.match(await readFile(join(out,phone.label+'-instrumentation.log'),'utf8'),/INSTRUMENTATION_CODE: -1/,'PHONE_'+phone.label+'_DID_NOT_PASS');
}
async function prepare(phone){
  const installedPath=adb(phone,['shell','pm','path',pkg],{allowFailure:true}).trim().replace(/^package:/,'');
  const validPath=/^\/data\/app\/[A-Za-z0-9_/.=+~\-]+\.apk$/.test(installedPath);
  const installedHash=validPath?adb(phone,['shell','sha256sum',installedPath],{allowFailure:true}).match(/^[a-f0-9]{64}/)?.[0]:null;
  if(installedHash!==apkSha256)adb(phone,['install','-r',apk],{timeout:180000});
  adb(phone,['install','-r','-t',testApk],{timeout:120000});
  for(const permission of ['POST_NOTIFICATIONS','RECORD_AUDIO'])adb(phone,['shell','pm','grant','--user','0',pkg,'android.permission.'+permission]);
  adb(phone,['shell','dumpsys','deviceidle','whitelist','+'+pkg]);
  adb(phone,['shell','input','keyevent','KEYCODE_WAKEUP']);adb(phone,['shell','wm','dismiss-keyguard'],{allowFailure:true});
  const policy=adb(phone,['shell','dumpsys','window','policy']);
  if(/(?:showing|inputRestricted)=true/.test(policy))throw Error('UNLOCK_PHONE_'+phone.label);
  record('Phone '+phone.label+' APK, permissions and unlocked display ready',{phone:phone.label,androidApi:phone.androidApi,reusedInstalledApk:installedHash===apkSha256});
}
function launch(phone){
  const stream=createWriteStream(join(out,phone.label+'-instrumentation.log'));
  phone.instrument=spawn(adbPath,['-s',phone.serial,'shell','am','instrument','-w','-r','-e','phase','one-phone-tor','-e','runId',runId,'-e','peerLabel',phone.label,pkg+'.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation'],{stdio:['ignore','pipe','pipe'],windowsHide:true});
  phone.instrument.stdout.pipe(stream,{end:false});phone.instrument.stderr.pipe(stream,{end:false});
  phone.instrument.once('close',()=>stream.end(()=>{phone.logClosed=true;}));
}
async function publication(phone,restart=false){
  let previous='';
  return wait('PHONE_'+phone.label+'_PUBLICATION',async()=>{
    const status=restart?(await command(phone,'SNAPSHOT')).transport:deviceFile(phone,'progress.json');
    const stage=restart?'republication':deviceFile(phone,'stage.json')?.stage;
    const state=JSON.stringify({stage,percent:status?.bootstrapPercent??0,published:!!status?.descriptorPublished});
    if(previous!==state){record('Phone '+phone.label+' '+(restart?'republication':'startup')+' progress',JSON.parse(state));previous=state;}
    if(stage==='vault_create'){
      const sample=deviceFile(phone,'stage.json');
      if(sample&&Date.now()-phone.launchedAt-sample.elapsedMs>60000){const stacks=deviceFile(phone,'stacks.json');if(stacks?.threads?.some(thread=>thread.frames.some(frame=>frame.includes('KeyStoreSecurityLevel.interruptedPreservingSleep'))))throw Error('PHONE_'+phone.label+'_KEYSTORE_BACKEND_BUSY');}
    }
    const ready=restart?{ok:true,transport:status}:deviceFile(phone,'ready.json');
    if(status?.serverless&&status.descriptorPublished&&ready?.ok){phone.ready=true;return ready;}
    return null;
  },restart?8*60000:14*60000,2500);
}
async function screenOff(receiver,sender){
  const before=await command(receiver,'ARM_BACKGROUND');
  receiver.originalWake=adb(receiver,['shell','settings','get','global','stay_on_while_plugged_in']).trim();
  assert.match(receiver.originalWake,/^(?:\d+|null)$/,'INVALID_CHARGING_SETTING');
  adb(receiver,['shell','settings','put','global','stay_on_while_plugged_in','0']);
  adb(receiver,['shell','input','keyevent','KEYCODE_HOME']);record('Phone '+receiver.label+' background wait started');
  await delay(70000);adb(receiver,['shell','input','keyevent','KEYCODE_SLEEP']);
  const asleep=()=>/mWakefulness=Asleep|mWakefulness=Dozing/.test(adb(receiver,['shell','dumpsys','power']));
  await wait('PHONE_'+receiver.label+'_DISPLAY_ASLEEP',asleep,15000,500);
  await command(sender,'BACKGROUND_TEXT');
  const state=await wait('PHONE_'+receiver.label+'_SCREEN_OFF_PERSISTENCE',()=>hasReceived(receiver,text(sender,'screen-off delivery')),8*60000);
  const observation={receiver:receiver.label,sender:sender.label,serviceRunning:state.serviceRunning,receiveSequenceBefore:before.backgroundReceiveSequence,receiveSequenceAfter:state.backgroundReceiveSequence,interactiveAtNativePersistence:state.lastBackgroundReceiveInteractive,screenAsleepAtInspection:asleep()};
  await writeFile(join(out,receiver.label+'-background-observation.json'),JSON.stringify(observation,null,2));
  record('Phone '+receiver.label+' native background receive observed',observation);
  assert.equal(state.serviceRunning,true,'PHONE_'+receiver.label+'_FOREGROUND_SERVICE_MISSING');assert.equal(state.backgroundReceiveSequence,before.backgroundReceiveSequence+1,'PHONE_'+receiver.label+'_BACKGROUND_SEQUENCE_MISMATCH');assert.equal(state.lastBackgroundReceiveInteractive,false,'PHONE_'+receiver.label+'_INTERACTIVE_AT_PERSISTENCE');
  const notifications=adb(receiver,['shell','dumpsys','notification','--noredact']);
  assert.ok(notifications.split(/(?=NotificationRecord\()/).some(block=>block.includes(pkg)&&block.includes('New encrypted message')),'PHONE_'+receiver.label+'_GENERIC_NOTIFICATION_MISSING');
  const evidence={receiver:receiver.label,sender:sender.label,backgroundWaitMs:70000,asleepBeforeSend:true,interactiveAtNativePersistence:false,serviceRunning:true,genericNotification:true,receiveSequenceBefore:before.backgroundReceiveSequence,receiveSequenceAfter:state.backgroundReceiveSequence,screenInteractiveAfterNotification:!asleep()};
  await writeFile(join(out,receiver.label+'-background-evidence.json'),JSON.stringify(evidence,null,2));
  record('Phone '+receiver.label+' screen-off persistence and generic notification passed',evidence);
}
async function recovery(sender,receiver){
  const paused=await command(receiver,'PAUSE_PEER');assert.equal(paused.transport.serverless,false);assert.equal(paused.serviceRunning,false);
  const queued=await command(sender,'OFFLINE_SEND');assert.ok(queued.outbox>0);
  record('Phone '+sender.label+' encrypted outbox queued while '+receiver.label+' listener stopped',{sender:sender.label,receiver:receiver.label,outbox:queued.outbox});
  const begin=Date.now();await command(receiver,'RESUME_PEER');await publication(receiver,true);
  await wait('OFFLINE_'+sender.label+'_TO_'+receiver.label,()=>hasReceived(receiver,text(sender,'offline recovery')),10*60000);
  await wait('RECEIPT_'+receiver.label+'_TO_'+sender.label,()=>delivered(sender,text(sender,'offline recovery')),8*60000);
  record('Automatic outbox recovery and encrypted receipt '+sender.label+' to '+receiver.label+' passed',{sender:sender.label,receiver:receiver.label,recoveryMs:Date.now()-begin});
}

try{
  const serials=adb(null,['devices']).split(/\r?\n/).map(line=>line.match(/^(\S+)\s+device$/)?.[1]).filter(Boolean);
  assert.equal(serials.length,2,'TWO_AUTHORIZED_PHONES_REQUIRED');
  for(const [index,serial] of serials.entries())phones.push({label:index===0?'A':'B',serial,counter:0,androidApi:Number(adb({serial},['shell','getprop','ro.build.version.sdk']).trim())});
  record('Two authorized physical Android phones detected',{androidApis:phones.map(phone=>phone.androidApi)});
  await seedPublicTorCache(resolve(root,'artifacts/serverless-p2p/public-tor-cache'),resolve(root,'apps/mobile-android/native/src/androidTest/assets/tor-public-cache'));
  if(!process.argv.includes('--skip-build')){
    const stream=createWriteStream(join(out,'build.log'));
    const build=spawn(process.execPath,[join(root,'scripts/android-native-build.mjs'),'--offline','--tests','--jvm-tests'],{cwd:root,stdio:['ignore','pipe','pipe'],windowsHide:true});
    build.stdout.pipe(stream,{end:false});build.stderr.pipe(stream,{end:false});const exit=await new Promise(resolve=>build.once('close',resolve));stream.end();assert.equal(exit,0,'NATIVE_BUILD_FAILED');
  }
  const aapt=resolve(root,'artifacts/android-device-tools/build-tools/35.0.0/aapt.exe');
  pkg=spawnSync(aapt,['dump','badging',apk],{encoding:'utf8',windowsHide:true}).stdout?.match(/^package: name='([^']+)'/m)?.[1];
  assert.match(pkg??'',/^app\.cryptopigeon\.nativeclient(?:\.debug)?$/);
  const digest=crypto.createHash('sha256');for await(const chunk of createReadStream(apk))digest.update(chunk);apkSha256=digest.digest('hex');
  for(const phone of phones)await prepare(phone);
  for(const phone of phones){phone.launchedAt=Date.now();launch(phone);}
  const ready=await Promise.all(phones.map(phone=>publication(phone)));
  const [a,b]=phones;
  await Promise.all([command(a,'PAIR',{invite:ready[1].invite}),command(b,'PAIR',{invite:ready[0].invite})]);
  record('Both native Tor services published; mutual signed pinning and visible chats passed');await delay(20000);
  await Promise.all(phones.map(phone=>command(phone,'PHONE_TEXT')));
  for(const [sender,receiver] of [[a,b],[b,a]])await wait('TEXT_'+sender.label+'_TO_'+receiver.label,()=>hasReceived(receiver,text(sender,'to peer')));
  await Promise.all(phones.map(phone=>command(phone,'UI_RECEIVED')));await Promise.all(phones.map(phone=>command(phone,'READ')));
  for(const phone of phones)await wait('TEXT_RECEIPT_'+phone.label,()=>delivered(phone,text(phone,'to peer')));
  record('Simultaneous bidirectional Tamil/emoji, visible messages and encrypted receipts passed');
  for(const [sender,receiver] of [[a,b],[b,a]])for(let sample=1;sample<=2;sample++){
    const begin=Date.now();await command(sender,'PROBE_TEXT',{sample});await wait('LATENCY_'+sender.label+'_TO_'+receiver.label,()=>hasReceived(receiver,text(sender,'latency sample '+sample)),180000,500);
    record('Warm persistence latency '+sender.label+' to '+receiver.label,{sender:sender.label,receiver:receiver.label,sample,latencyMs:Date.now()-begin,includes:'ADB local control and persistence inspection overhead'});
  }
  const maximum=await command(a,'MAX_TEXT');assert.equal(maximum.codeUnits,65536);assert.equal(maximum.sha256,hash(Buffer.from(maximumText())));
  await wait('MAXIMUM_NATIVE_UNICODE',()=>hasReceived(b,maximumText()),10*60000);record('Maximum 65536-code-unit Tamil/emoji message passed native to native');
  for(const [sender,receiver,size,seed] of [[a,b,65537,17],[b,a,98321,7]]){
    const expected=await command(sender,'PHONE_FILE');assert.equal(expected.bytes,size);assert.equal(expected.sha256,hash(fixture(size,seed)));
    await wait('FILE_'+sender.label+'_TO_'+receiver.label,()=>hasReceived(receiver,text(sender,'encrypted file'),{attachmentSha:expected.sha256,attachmentBytes:size}),10*60000);
    record('Exact decrypted file integrity '+sender.label+' to '+receiver.label+' passed',{sender:sender.label,receiver:receiver.label,bytes:size,sha256:expected.sha256});
  }
  for(const [sender,receiver] of [[a,b],[b,a]]){
    const expected=await command(sender,'VOICE');await wait('MICROPHONE_'+sender.label+'_TO_'+receiver.label,()=>hasReceived(receiver,text(sender,'voice'),{attachmentSha:expected.sha256,attachmentBytes:expected.bytes}),10*60000);
    record('Physical microphone payload integrity '+sender.label+' to '+receiver.label+' passed',{sender:sender.label,receiver:receiver.label,bytes:expected.bytes,sha256:expected.sha256});
  }
  await screenOff(a,b);await screenOff(b,a);
  await recovery(a,b);await recovery(b,a);
  for(const phone of phones){const locked=await command(phone,'LOCK');assert.equal(locked.vaultState,'locked');assert.equal(locked.serviceRunning,false);assert.equal(locked.transport.serverless,false);record('Phone '+phone.label+' vault, foreground service, Tor process and monitor stopped');await finish(phone);}
  record('Full two-physical-phone public Tor suite passed');
}catch(error){failure=error;const first=String(error.message??'').split('\n')[0].trim();record('Two-phone verification failed',{code:/^[A-Za-z0-9_]+$/.test(first)?first:error.name,...(typeof error.actual==='number'||typeof error.actual==='boolean'?{actual:error.actual}:{}),...(typeof error.expected==='number'||typeof error.expected==='boolean'?{expected:error.expected}:{})});}
finally{
  for(const phone of phones){
    if(phone.originalWake!==undefined){try{adb(phone,['shell','settings',phone.originalWake==='null'?'delete':'put','global','stay_on_while_plugged_in',...(phone.originalWake==='null'?[]:[phone.originalWake])]);record('Phone '+phone.label+' original charging wake setting restored',{original:phone.originalWake});}catch{failure??=Error('PHONE_'+phone.label+'_CHARGING_SETTING_NOT_RESTORED');record('Phone '+phone.label+' charging setting requires restoration',{original:phone.originalWake});}}
    if(phone.instrument&&!phone.finished&&phone.instrument.exitCode==null){
      try{if(phone.ready){await command(phone,'LOCK',{},true);await finish(phone);}else{adb(phone,['shell','run-as',pkg,'touch',`files/one-phone-tor-${runId}/cancel`],{allowFailure:true});await delay(3500);}}
      catch{}
      if(phone.instrument.exitCode==null)adb(phone,['shell','am','force-stop',pkg],{allowFailure:true});
    }
    if(pkg&&phone.instrument){
      for(const name of ['checks.json','stage.json']){const value=deviceFile(phone,name);if(value)await writeFile(join(out,phone.label+'-'+name),JSON.stringify(value,null,2));}
      try{const processes=adb(phone,['shell','ps','-A','-o','ARGS']);phone.remainingTestTor=processes.split(/\r?\n/).filter(line=>line.includes('libtor.so')&&line.includes('one-phone-tor-'+runId)).length;}
      catch{phone.remainingTestTor=null;failure??=Error('PHONE_'+phone.label+'_CLEANUP_INSPECTION_FAILED');record('Phone '+phone.label+' cleanup inspection unavailable');}
      if(phone.remainingTestTor){failure??=Error('PHONE_'+phone.label+'_TEST_TOR_SURVIVED');record('Phone '+phone.label+' test Tor process remained after cleanup');}
    }
  }
  const report={runId,completedAtUtc:new Date().toISOString(),passed:!failure,elapsedMs:Date.now()-started,apkSha256,package:pkg,phones:phones.map(phone=>({label:phone.label,androidApi:phone.androidApi,nativeFinished:!!phone.finished,remainingTestTor:phone.remainingTestTor,originalChargingWakeSetting:phone.originalWake})),events,transport:'Two real native Android Tor v3 peers; no laptop messaging daemon; no adb reverse/forward or peer payload bytes over USB',limits:['Instrumented native API actions with explicit visible connection/chat checks','Actual microphone capture and byte/hash integrity; speaker playback not asserted','70 seconds app backgrounding, with display off verified before send and at native persistence; not extended Doze/OEM reliability']};
  await writeFile(join(out,'results.json'),JSON.stringify(report,null,2));await writeFile(join(root,'artifacts/serverless-p2p/two-phone-latest.json'),JSON.stringify({directory:out,passed:report.passed,apkSha256},null,2));
  console.log('Results: '+join(out,'results.json'));
}
if(failure)process.exitCode=1;
