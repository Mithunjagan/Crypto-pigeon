import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root=resolve(import.meta.dirname,'..'), project=resolve(root,'apps/mobile-android');
if(!existsSync(resolve(root,'apps/local-ui/dist/index.html')))throw new Error('Build the local UI first: npm run build');
for(const module of ['app','native']){
  const target=resolve(project,module,'src/main/assets/ui');
  if(!target.startsWith(project+ (process.platform==='win32'?'\\':'/')))throw new Error('Invalid asset target');
  rmSync(target,{recursive:true,force:true});mkdirSync(target,{recursive:true});
  cpSync(resolve(root,'apps/local-ui/dist'),target,{recursive:true});
}
if(!process.argv.includes('--assets-only')){
  const result=spawnSync(process.execPath,[resolve(root,'scripts/android-native-build.mjs'),...process.argv.slice(2)],{cwd:root,stdio:'inherit',env:process.env});
  if(result.error)throw result.error;if(result.status!==0)process.exit(result.status??1);
}
