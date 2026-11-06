import {fork,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {formatPublicUid} from '@crypto-pigeon/protocol';
import {SecureVault} from '../apps/local-daemon/dist/secure-vault.js';
import {readDecryptedAttachment} from '../apps/local-daemon/dist/attachments.js';
import {deriveVaultKeys} from '../apps/local-daemon/dist/vault-dual-key.js';
const root=resolve(import.meta.dirname,'..'),out=resolve(root,'artifacts/native-android','vault-run-'+Date.now());
const require=createRequire(resolve(root,'apps/relay-server/package.json')),{Pool}=require('pg');
const database='cp_native_vault_'+crypto.randomBytes(6).toString('hex'),port=18843,origin='http://127.0.0.1:'+port;
const pg=JSON.parse(await readFile(resolve(root,'artifacts/android-chat-postgres/connection.json'),'utf8'));
const url=new URL(`postgresql://${pg.user}@127.0.0.1:${pg.port}/postgres`);url.password=pg.password;
const admin=new Pool({connectionString:url.href});let pool,server;const results=[];
const serials=process.env.ANDROID_SERIALS?.split(',');assert.equal(serials?.length,2,'Set ANDROID_SERIALS');
const pkg='app.cryptopigeon.nativeclient.debug',adbPath=resolve(root,'artifacts/android-device-tools/platform-tools/adb.exe');
await mkdir(out,{recursive:true});
function adb(serial,args,binary=false,timeout=30000){const r=spawnSync(adbPath,['-s',serial,...args],{encoding:binary?undefined:'utf8',timeout,maxBuffer:4*1024*1024,windowsHide:true});if(r.error)throw r.error;if(r.status)throw new Error('ADB '+args[0]+' failed');return r.stdout;}
function pass(serial,name){results.push({serial,name,status:'pass'});console.log('PASS: '+serial+' '+name);}
async function instrument(serial,phase,name,directory,extras={}){
  const args=['shell','am','instrument','-w','-r','-e','phase',phase,'-e','case',name,'-e','relayUrl',origin];
  for(const [key,value]of Object.entries(extras))args.push('-e',key,value);
  args.push(pkg+'.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation');
  const text=adb(serial,args,false,300000);await writeFile(join(directory,phase+'.log'),text);
  assert.match(text,/INSTRUMENTATION_CODE: -1/,'Native '+phase+' failed: '+text.slice(-4000));
  const report=JSON.parse(adb(serial,['exec-out','run-as',pkg,'cat','files/native-test-'+phase+'.json']));
  assert.ok(report.results.length);assert.ok(report.results.every(r=>r.status==='pass'));await writeFile(join(directory,phase+'.json'),JSON.stringify(report,null,2));
  for(const row of report.results)pass(serial,row.name);
  return JSON.parse(adb(serial,['exec-out','run-as',pkg,'cat','files/native-vault-'+name+'.json']));
}
try{
  await admin.query('CREATE DATABASE '+database);url.pathname='/'+database;pool=new Pool({connectionString:url.href});
  server=fork(resolve(root,'apps/relay-server/dist/server.js'),[],{cwd:root,silent:true,env:{...process.env,DATABASE_URL:url.href,PORT:String(port),HOST:'127.0.0.1',RELAY_HOSTNAME:'127.0.0.1:'+port,ADMIN_USERNAME:'native_vault_test',ADMIN_TOKEN:crypto.randomBytes(32).toString('hex'),ACTIVATION_PEPPER:crypto.randomBytes(32).toString('hex'),LOG_LEVEL:'error'}});
  let diagnostics='';server.stdout.resume();server.stderr.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-4000);});
  const deadline=Date.now()+30000;let ready=false;
  while(Date.now()<deadline){if(server.exitCode!==null)throw new Error('Isolated relay exited');if(await fetch(origin+'/readyz',{signal:AbortSignal.timeout(1000)}).then(r=>r.ok).catch(()=>false)){ready=true;break;}await new Promise(r=>setTimeout(r,250));}
  assert.ok(ready,'Isolated relay readiness timeout');
  for(const serial of serials){
    assert.match(serial,/^[a-zA-Z0-9:_-]+$/);const directory=join(out,serial);await mkdir(directory);
    adb(serial,['install','-r',resolve(root,'artifacts/native-android/crypto-pigeon-native-alpha.apk')],false,90000);
    adb(serial,['install','-r','-t',resolve(root,'artifacts/native-android/crypto-pigeon-native-tests.apk')],false,90000);adb(serial,['reverse','tcp:'+port,'tcp:'+port]);
    const name='vault_'+crypto.randomBytes(6).toString('hex'),userId=crypto.randomUUID();
    const state=await instrument(serial,'vault-create',name,directory,{vaultId:'NativeVault-'+name,password:'NativeVaultTest123!',userId});
    const published=state.published,username='native_'+crypto.randomBytes(6).toString('hex');
    await pool.query('INSERT INTO users(user_id,username,password_hash,public_uid) VALUES($1,$2,$3,$4)',[userId,username,'device_auth_only',formatPublicUid(userId)]);
    await pool.query('INSERT INTO device_identity_keys(device_id,user_id,identity_public_key,auth_public_key,registration_id,signal_device_id) VALUES($1,$2,$3,$4,$5,1)',[published.deviceId,userId,Buffer.from(published.identityPublicKey,'base64'),Buffer.from(published.deviceAuthPublicKey,'base64'),published.registrationId]);
    const oldSession=crypto.randomBytes(24).toString('hex');await pool.query('INSERT INTO sessions(token,device_id,expires_at) VALUES($1,$2,$3)',[oldSession,published.deviceId,Date.now()+3600000]);
    const complete=await instrument(serial,'vault-lifecycle',name,directory);
    await writeFile(join(directory,'test-state.private.json'),JSON.stringify(complete));
    assert.equal((await fetch(origin+'/api/conversations/requests',{headers:{Authorization:'Bearer '+oldSession,'X-Vault-Instance':state.oldInstance}})).status,401);
    const reauth=crypto.randomBytes(24).toString('hex');await pool.query('INSERT INTO sessions(token,device_id,expires_at) VALUES($1,$2,$3)',[reauth,published.deviceId,Date.now()+3600000]);
    assert.equal((await fetch(origin+'/api/conversations/requests',{headers:{Authorization:'Bearer '+reauth,'X-Vault-Instance':state.oldInstance}})).status,409);
    assert.equal((await fetch(origin+'/api/conversations/requests',{headers:{Authorization:'Bearer '+reauth,'X-Vault-Instance':complete.newInstance}})).status,200);
    pass(serial,'Actual relay revokes old sessions and rejects the original instance even after reauthentication');
    const old=await deriveVaultKeys(complete.vaultId,complete.password);
    try{assert.equal((await fetch(origin+'/api/vault-backup/'+old.lookup.toString('hex'))).status,404);}finally{Object.values(old).forEach(k=>k.fill(0));}
    pass(serial,'Old credential lookup is removed after native password rotation');
    const restored=new SecureVault(join(directory,'restored-on-node'),origin);await restored.initialize();
    try{
      await restored.restoreSecure(complete.vaultId,complete.nextPassword);
      assert.equal(restored.database().prepare("SELECT plaintext FROM messages WHERE plaintext='Native encrypted recovery message'").get().plaintext,'Native encrypted recovery message');
      assert.equal(restored.database().prepare('SELECT device_id FROM signal_account WHERE singleton=1').get().device_id,published.deviceId);
      const file=await readDecryptedAttachment(restored,complete.attachmentId);
      assert.equal(crypto.createHash('sha256').update(file.filedata).digest('hex'),complete.attachmentHash);assert.equal(file.filename,'native-தமிழ்.bin');
      pass(serial,'Desktop restores the native signed/encrypted cloud backup with original Signal identity, history, filename and exact file bytes');
    }finally{restored.close?.();restored.lock();}
    assert.equal((await fetch(origin+'/api/conversations/requests',{headers:{Authorization:'Bearer '+reauth,'X-Vault-Instance':complete.newInstance}})).status,401);
    pass(serial,'Desktop transfer invalidates the native account session on the real relay');
  }
}catch(error){results.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;}
finally{
  if(server&&server.exitCode===null){const ended=new Promise(r=>server.once('exit',r));server.kill();await ended;}
  await pool?.end();await admin.query('DROP DATABASE IF EXISTS '+database+' WITH (FORCE)');await admin.end();
  await writeFile(join(out,'results.json'),JSON.stringify({results,database,scope:'Native on-device vault lifecycle against isolated real PostgreSQL relay; USB routes relay traffic only.'},null,2));console.log('Evidence: '+out);
}
