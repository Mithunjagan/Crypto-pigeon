import {spawnSync} from 'node:child_process';
import {writeFile,readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
const root=resolve(import.meta.dirname,'..'),adb=resolve(root,'artifacts/android-device-tools/platform-tools/adb.exe'),pkg='app.cryptopigeon.nativeclient.debug';
function run(args){const r=spawnSync(adb,args,{encoding:'utf8',windowsHide:true});if(r.status)throw new Error(r.stderr||'ADB failed');return r.stdout.trim();}
const devices=run(['devices']).split(/\r?\n/).slice(1).map(row=>row.split(/\s+/)).filter(row=>row[1]==='device').map(row=>row[0]);assert.ok(devices.length,'No connected authorized phones');
const state=[];
for(const serial of devices){
  const paths=run(['-s',serial,'exec-out','run-as',pkg,'find','no_backup/vault','-type','f']).split(/\r?\n/).filter(Boolean).sort();
  const files={};for(const path of paths){assert.match(path,/^no_backup\/vault\/[A-Za-z0-9_./-]+$/);files[path]=run(['-s',serial,'exec-out','run-as',pkg,'sha256sum',path]).split(/\s+/)[0];}
  state.push({serial,files});
}
const path=resolve(root,'artifacts/external-storage-phone-before.private.json');
if(process.argv.includes('--capture')){await writeFile(path,JSON.stringify(state,null,2));console.log('Captured encrypted vault fingerprints: '+state.map(x=>x.serial+' ('+Object.keys(x.files).length+' files)').join(', '));}
else {assert.deepEqual(state,JSON.parse(await readFile(path,'utf8')),'Existing encrypted vault files changed');console.log('PASS: Every existing encrypted vault file is byte-for-byte unchanged on '+devices.join(', '));}
