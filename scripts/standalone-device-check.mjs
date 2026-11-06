import {spawn,spawnSync,fork} from 'node:child_process';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root=resolve(import.meta.dirname,'..'),out=join(root,'artifacts/standalone-device-results.json'),adb=join(root,'artifacts/android-device-tools/platform-tools/adb.exe');
await mkdir(join(root,'artifacts'),{recursive:true});const results=[];
function command(args,timeout=120000){const r=spawnSync(adb,args,{encoding:'utf8',timeout,windowsHide:true,maxBuffer:4*1024*1024});if(r.error)throw r.error;assert.equal(r.status,0,'ADB '+args[0]+' failed');return r.stdout;}
// This is the only discovery call. Missing phones never fail or postpone the host/JVM gate.
let devices;
if(process.argv.includes('--serial'))devices=[process.argv[process.argv.indexOf('--serial')+1]];
else if(process.argv.includes('--known-devices'))devices=JSON.parse(await readFile(out,'utf8')).devices;
else{const listing=command(['devices']);devices=listing.split(/\r?\n/).filter(line=>/^\S+\s+device$/.test(line.trim())).map(line=>line.trim().split(/\s+/)[0]);}
await writeFile(out,JSON.stringify({devices,results,scope:'Discovery complete; host/JVM verification is independent of connected devices'},null,2));
if(devices.length===0){console.log('No authorized Android devices connected. Standalone APK, host relay tests and native JVM tests are complete.');process.exit(0);}
for(const serial of devices){
  try{command(['-s',serial,'install','-r',join(root,'artifacts/crypto-pigeon-standalone.apk')]);results.push({serial,name:'Standalone APK installed',status:'pass'});console.log('Installed standalone APK on '+serial);}
  catch(error){results.push({serial,name:error.message,status:'fail'});process.exitCode=1;}
}
const require=createRequire(join(root,'apps/relay-server/package.json')),{Pool}=require('pg');
const pg=JSON.parse(await readFile(join(root,'artifacts/android-chat-postgres/connection.json'),'utf8')),url=new URL(`postgresql://${pg.user}@127.0.0.1:${pg.port}/postgres`);url.password=pg.password;
const admin=new Pool({connectionString:url.href});
try{for(const serial of devices){
  const database='cp_native_bridge_'+crypto.randomBytes(6).toString('hex'),port=18948,origin='http://127.0.0.1:'+port,pepper=crypto.randomBytes(32).toString('hex'),activation=crypto.randomBytes(24).toString('base64url');let pool,child,interval;
  try{
    await admin.query(`CREATE DATABASE ${database}`);url.pathname='/'+database;pool=new Pool({connectionString:url.href});
    child=fork(join(root,'apps/relay-server/dist/server.js'),[],{cwd:root,silent:true,env:{...process.env,DATABASE_URL:url.href,HOST:'127.0.0.1',PORT:String(port),RELAY_HOSTNAME:'127.0.0.1:'+port,ADMIN_USERNAME:'native_bridge_test',ADMIN_TOKEN:crypto.randomBytes(32).toString('hex'),ACTIVATION_PEPPER:pepper,LOG_LEVEL:'error'}});child.stdout.resume();child.stderr.resume();
    const end=Date.now()+30000;while(true){if(await fetch(origin+'/readyz').then(r=>r.ok).catch(()=>false))break;assert.ok(Date.now()<end,'Native relay startup timeout');await new Promise(r=>setTimeout(r,200));}
    command(['-s',serial,'install','-r','-t',join(root,'apps/mobile-android/native/build/outputs/apk/androidTest/debug/native-debug-androidTest.apk')]);command(['-s',serial,'reverse','tcp:'+port,'tcp:'+port]);
    let approving=false;interval=setInterval(async()=>{if(approving)return;approving=true;try{await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$1,activation_expires_at=NOW()+INTERVAL '10 minutes',attempt_count=0,decided_at=NOW() WHERE status='pending'",[crypto.createHmac('sha256',pepper).update(activation).digest('hex')]);}catch{}finally{approving=false;}},200);
    const args=['-s',serial,'shell','am','instrument','-w','-r','-e','phase','bridge','-e','relayUrl',origin,'-e','activationCode',activation,'app.cryptopigeon.nativeclient.debug.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation'];
    const test=spawn(adb,args,{windowsHide:true});let output='';test.stdout.on('data',b=>{output+=b.toString();});test.stderr.on('data',b=>{output+=b.toString();});
    const code=await new Promise((res,rej)=>{const timer=setTimeout(()=>{test.kill();rej(new Error('Native bridge instrumentation timeout'));},300000);test.once('exit',code=>{clearTimeout(timer);res(code);});test.once('error',rej);});
    clearInterval(interval);interval=null;await writeFile(join(root,'artifacts','native-bridge-'+serial.replace(/[^a-zA-Z0-9_-]/g,'_')+'.log'),output);
    assert.equal(code,0);assert.match(output,/INSTRUMENTATION_CODE: -1/,'Native bridge checks failed: '+output.slice(-2500));
    const report=JSON.parse(command(['-s',serial,'exec-out','run-as','app.cryptopigeon.nativeclient.debug','cat','files/native-test-bridge.json']));assert.ok(report.results.length);assert.ok(report.results.every(r=>r.status==='pass'));for(const row of report.results){results.push({serial,...row});console.log('PASS: '+serial+' '+row.name);}
    const screenshot=spawnSync(adb,['-s',serial,'exec-out','run-as','app.cryptopigeon.nativeclient.debug','cat','files/native-standalone-gate.png'],{windowsHide:true,maxBuffer:8*1024*1024,timeout:15000});if(screenshot.status===0)await writeFile(join(root,'artifacts','standalone-gate-'+serial.replace(/[^a-zA-Z0-9_-]/g,'_')+'.png'),screenshot.stdout);
  }catch(error){results.push({serial,name:error.message,status:'fail'});console.error(error.message);process.exitCode=1;}
  finally{if(interval)clearInterval(interval);try{command(['-s',serial,'reverse','--remove','tcp:'+port]);}catch{}if(child&&child.exitCode===null){const stopped=new Promise(r=>child.once('exit',r));child.kill();await stopped;}if(pool)await pool.end();await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);}
}}finally{await admin.end();await writeFile(out,JSON.stringify({devices,results,scope:'Standalone native bridge/engine with a real relay; no host vault daemon'},null,2));}
