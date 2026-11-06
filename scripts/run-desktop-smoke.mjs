import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, cpSync, readdirSync, lstatSync, realpathSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
const root=resolve(import.meta.dirname,'..');
const require=createRequire(join(root,'apps/desktop/package.json'));
const electron=require('electron');
const packagedResources=join(root,'artifacts/desktop/win-unpacked/resources');
const resourceRoot=realpathSync(packagedResources);
function validateLinks(directory) {
  for(const entry of readdirSync(directory)) {
    const file=join(directory,entry),stat=lstatSync(file);
    if(stat.isSymbolicLink()&&!realpathSync(file).startsWith(resourceRoot+sep))throw new Error('Packaged link escapes resources: '+file);
    if(stat.isDirectory()&&!stat.isSymbolicLink())validateLinks(file);
  }
}
validateLinks(packagedResources);
// Run outside the source checkout so missing dependencies cannot fall back to it.
const resources=join(mkdtempSync(join(tmpdir(),'cp-desktop-bundle-')),'resources');
cpSync(packagedResources,resources,{recursive:true,dereference:true});
const profile=mkdtempSync(join(tmpdir(),'cp-desktop-smoke-'));
const reports=join(root,'artifacts/desktop-smoke');mkdirSync(reports,{recursive:true});
for(const mode of ['setup','launch','restart']) {
  if(mode==='launch')writeFileSync(join(profile,'desktop.json'),JSON.stringify({relayUrl:'https://relay.invalid'}));
  const report=join(reports,mode+'.json');
  const child=spawnSync(electron,[join(root,'scripts/desktop-smoke.cjs'),resources,profile,mode,report],{cwd:root,windowsHide:true,encoding:'utf8',timeout:90000});
  if(child.status!==0)throw new Error(mode+' failed: '+child.stdout+'\n'+child.stderr);
  console.log(readFileSync(report,'utf8'));
  let alive=false;try{await fetch('http://127.0.0.1:17421/api/vault/status',{signal:AbortSignal.timeout(1000)});alive=true;}catch{}
  if(alive)throw new Error('Daemon remained running after desktop exit');
}
console.log('Desktop smoke screenshots and isolated profile: '+profile);
