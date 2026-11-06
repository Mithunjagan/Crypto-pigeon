import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {resolve,join} from 'node:path';
import {mkdir,readFile,writeFile,cp} from 'node:fs/promises';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {Vault} from '../apps/local-daemon/dist/vault.js';
import {LocalSignalStore} from '../apps/local-daemon/dist/signal-store.js';
import {establishSession,encryptPayload,decryptPayload} from '../apps/local-daemon/dist/signal-adapter.js';
const root=resolve(import.meta.dirname,'..'),out=resolve(root,'artifacts/native-android','run-'+Date.now());
const require=createRequire(resolve(root,'apps/local-daemon/package.json'));
const signal=require('@signalapp/libsignal-client'),sqlcipher=require('@signalapp/sqlcipher');
const Database=sqlcipher.Database??sqlcipher.default??sqlcipher;
const config=JSON.parse(await readFile(resolve(root,'artifacts/native-android/interop-config.json'),'utf8'));
const fixture=JSON.parse(await readFile(resolve(root,'apps/mobile-android/native/src/androidTest/assets/native-fixture.json'),'utf8'));
const serials=process.env.ANDROID_SERIALS?.split(',');assert.equal(serials?.length,2,'Set ANDROID_SERIALS to both devices');
const pkg='app.cryptopigeon.nativeclient.debug',results=[];
await mkdir(out,{recursive:true});
const adbPath=resolve(root,process.env.ADB_PATH??'artifacts/android-device-tools/platform-tools/adb.exe');
function adb(serial,args,binary=false,timeout=30000){
  const r=spawnSync(adbPath,['-s',serial,...args],{encoding:binary?undefined:'utf8',timeout,maxBuffer:32*1024*1024,windowsHide:true});
  if(r.error)throw r.error;if(r.status!==0)throw new Error('ADB '+args[0]+' failed: '+(binary?'binary response omitted':r.stderr));return r.stdout;
}
function pass(serial,name){results.push({serial,name,status:'pass'});console.log('PASS: '+serial+' '+name);}
async function instrument(serial,phase,directory){
  const text=adb(serial,['shell','am','instrument','-w','-r','-e','phase',phase,pkg+'.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation'],false,180000);
  await writeFile(join(directory,phase+'.log'),text);
  assert.match(text,/INSTRUMENTATION_CODE: -1/,'On-device '+phase+' tests failed: '+text.slice(-3500));
  const report=JSON.parse(adb(serial,['exec-out','run-as',pkg,'cat','files/native-test-'+phase+'.json']));
  assert.ok(report.results.length>0);assert.ok(report.results.every(r=>r.status==='pass'));
  await writeFile(join(directory,phase+'.json'),JSON.stringify(report,null,2));
  for(const row of report.results)pass(serial,row.name);
}
try{
  for(const serial of serials){
    assert.match(serial,/^[a-zA-Z0-9:_-]+$/);
    const directory=join(out,serial);await mkdir(directory);
    adb(serial,['install','-r',resolve(root,'apps/mobile-android/native/build/outputs/apk/debug/native-debug.apk')],false,90000);
    adb(serial,['install','-r','-t',resolve(root,'apps/mobile-android/native/build/outputs/apk/androidTest/debug/native-debug-androidTest.apk')],false,90000);
    await instrument(serial,'foundation',directory);
    const exported=JSON.parse(adb(serial,['exec-out','run-as',pkg,'cat','files/native-interop-result.json']));
    await writeFile(join(directory,'native-result.json'),JSON.stringify(exported));
    const bobRoot=join(directory,'bob-node');await cp(config.bobRoot,bobRoot,{recursive:true});
    const bobVault=new Vault(bobRoot);await bobVault.initialize();await bobVault.unlock(config.password);
    let bob=new LocalSignalStore(bobVault.database());
    const aliceAddress=signal.ProtocolAddress.new(exported.aliceId,1),published=exported.aliceBundle;
    await establishSession(bob,aliceAddress,{...published,oneTimePrekey:published.oneTimePrekeys[0],pqOneTimePrekey:published.pqOneTimePrekeys[0]});
    const frame=Buffer.from(exported.ciphertext,'base64');
    assert.equal(await decryptPayload(bob,aliceAddress,frame.subarray(1).toString('base64'),frame[0]),JSON.stringify({type:'text',text:'Android to Node தமிழ் 🕊️'}));
    pass(serial,'Independent Node libsignal decrypts the on-device Java Signal envelope');
    const reply=await encryptPayload(bob,aliceAddress,JSON.stringify({type:'text',text:'Node to Android नमस्ते 🕊️'}));
    const replyPath=join(directory,'reply.json');
    await writeFile(replyPath,JSON.stringify({bobId:config.bobId,ciphertext:Buffer.concat([Buffer.from([reply.type]),Buffer.from(reply.ciphertext,'base64')]).toString('base64')}));
    bobVault.lock();
    const remote='/data/local/tmp/cp-native-'+serial+'.json';
    adb(serial,['push',replyPath,remote]);adb(serial,['shell','run-as',pkg,'cp',remote,'files/native-interop-reply.json']);
    await instrument(serial,'reply',directory);
    const sqlKey=Buffer.from(fixture.sqlKey,'base64');
    const importedPath=join(directory,'native-alice.db');
    await writeFile(importedPath,adb(serial,['exec-out','run-as',pkg,'cat','no_backup/native-interop-fixture/alice.db'],true));
    const db=new Database(importedPath);db.pragma(`key = "x'${sqlKey.toString('hex')}'"`);
    try{
      const account=db.prepare('SELECT identity_key_pair FROM signal_account WHERE singleton=1').get();
      const identity=signal.IdentityKeyPair.deserialize(new Uint8Array(account.identity_key_pair));
      assert.equal(Buffer.from(identity.publicKey.serialize()).toString('base64'),published.identityPublicKey);
      const nativeStore=new LocalSignalStore(db);
      const third=await encryptPayload(nativeStore,signal.ProtocolAddress.new(config.bobId,1),JSON.stringify({type:'text',text:'Imported native database reply'}));
      await bobVault.unlock(config.password);bob=new LocalSignalStore(bobVault.database());
      assert.equal(await decryptPayload(bob,aliceAddress,third.ciphertext,third.type),JSON.stringify({type:'text',text:'Imported native database reply'}));
      const auth=nativeStore.getDeviceAuthKeyPair(),challenge=Buffer.from('native-auth-interoperability');
      const signature=crypto.sign(null,challenge,crypto.createPrivateKey({key:auth.privateKey,format:'der',type:'pkcs8'}));
      assert.ok(crypto.verify(null,challenge,crypto.createPublicKey({key:auth.publicKey,format:'der',type:'spki'}),signature));
      pass(serial,'Node opens the Android SQLCipher vault and continues its Signal ratchet and separate auth identity');
    }finally{db.close();bobVault.lock();sqlKey.fill(0);}
    const importedNodeDb=join(directory,'node-database-after-android.db');
    await writeFile(importedNodeDb,adb(serial,['exec-out','run-as',pkg,'cat','no_backup/native-interop-fixture/node.db'],true));
    const verify=new Database(importedNodeDb);verify.pragma(`key = "x'${Buffer.from(fixture.sqlKey,'base64').toString('hex')}'"`);
    assert.equal(verify.prepare("SELECT value FROM native_interop WHERE value='android-persistent-value'").get().value,'android-persistent-value');verify.close();
    pass(serial,'Android-modified encrypted database reopens in Node with its original data intact');
  }
}catch(error){results.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;}
finally{await writeFile(join(out,'results.json'),JSON.stringify({results,scope:'Native JNI/SQLCipher/key derivation foundation and desktop interoperability. No native app UI or relay workflow acceptance yet.'},null,2));console.log('Evidence: '+out);}
