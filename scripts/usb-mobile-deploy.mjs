import { spawn, spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
const root=resolve(import.meta.dirname,'..');
const args=process.argv.slice(2);
const port=Number(process.env.CRYPTO_PIGEON_MOBILE_PORT??17420);
if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('Invalid mobile port');
function adb(command,{quiet=false}={}) {
  const sdk=process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT;
  const executable=sdk?resolve(sdk,'platform-tools',process.platform==='win32'?'adb.exe':'adb'):'adb';
  const result=spawnSync(executable,[...(process.env.ANDROID_SERIAL?['-s',process.env.ANDROID_SERIAL]:[]),...command],{encoding:'utf8'});
  if(result.error)throw new Error('adb unavailable. Install Android SDK platform-tools and connect an authorized USB-debugging device.');
  if(result.status)throw new Error(quiet?'ADB operation failed (sensitive arguments omitted)':result.stderr.trim());
  return result.stdout.trim();
}
try {
  const devices=adb(['devices']).split('\n').slice(1).map(v=>v.trim().split(/\s+/)).filter(v=>v[1]==='device');
  if(devices.length===0)throw new Error('No authorized Android phone detected. Connect USB, enable USB debugging, and approve the computer on the phone.');
  if(devices.length>1&&!process.env.ANDROID_SERIAL)throw new Error('Multiple phones detected. Set ANDROID_SERIAL to choose one.');
  if(args.includes('--check')){console.log('Authorized Android device detected.');process.exit(0);}
  const ready=await fetch('http://127.0.0.1:8443/readyz').then(r=>r.ok).catch(()=>false);
  if(!ready)throw new Error('Start the PostgreSQL-backed relay on loopback port 8443 first.');
  const occupied=await fetch(`http://127.0.0.1:${port}/api/vault/status`).then(r=>r.ok).catch(()=>false);
  if(occupied)throw new Error('Port 17420 already hosts a daemon. Stop your prior mobile daemon and rerun to obtain a fresh bootstrap.');
  adb(['reverse',`tcp:${port}`,`tcp:${port}`]);adb(['reverse','tcp:8443','tcp:8443']);
  const apk=resolve(root,'artifacts/crypto-pigeon-debug.apk');
  if(!existsSync(apk)){
    const build=spawnSync(process.execPath,['scripts/android-build.mjs'],{cwd:root,stdio:'inherit'});
    if(build.status)throw new Error('Android build failed');
  }
  adb(['install','-r',apk]);
  const child=spawn(process.execPath,['scripts/mobile-daemon.mjs'],{cwd:root,stdio:['ignore','pipe','pipe']});
  let output='',launched=false;
  const timeout=setTimeout(()=>{child.kill();console.error('Mobile daemon bootstrap timed out.');process.exitCode=1;},30000);
  child.stdout.on('data',chunk=>{
    output=(output+chunk.toString()).slice(-8192);
    const match=output.match(new RegExp(`http://127\\.0\\.0\\.1:${port}/bootstrap#[a-f0-9]+`));
    if(match&&!launched){
      launched=true;clearTimeout(timeout);
      try {adb(['shell','am','start','-n','app.cryptopigeon.mobile.debug/app.cryptopigeon.mobile.MainActivity','--es','bootstrapUrl',match[0]],{quiet:true});
        console.log('USB tunnels active; APK installed and launched. Keep this process and USB connection open. The vault and cryptography run in the isolated host daemon.');
      }catch(e){child.kill();console.error(e.message);process.exitCode=1;}
      output='';
    }
  });
  child.stderr.on('data',()=>{ /* Never echo daemon diagnostics containing local secrets. */ });
  for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{clearTimeout(timeout);child.kill(signal);});
  child.on('exit',code=>{clearTimeout(timeout);process.exitCode=code??1;});
}catch(error){console.error(error.message);process.exitCode=1;}
