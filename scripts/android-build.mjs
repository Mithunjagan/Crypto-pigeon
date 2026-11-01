import { cpSync, existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root=resolve(import.meta.dirname,'..'), project=resolve(root,'apps/mobile-android');
if(!existsSync(resolve(root,'apps/local-ui/dist/index.html')))throw new Error('Build the local UI first: npm run build');
mkdirSync(resolve(project,'app/src/main/assets/ui'),{recursive:true});
cpSync(resolve(root,'apps/local-ui/dist'),resolve(project,'app/src/main/assets/ui'),{recursive:true});
if(!process.argv.includes('--assets-only')){
  if(!(process.env.ANDROID_HOME||process.env.ANDROID_SDK_ROOT))throw new Error('Set ANDROID_HOME to an Android SDK with platform 35 and build-tools 35.0.0.');
  const result=spawnSync(process.platform==='win32'?(process.env.ComSpec??'cmd.exe'):'./gradlew',process.platform==='win32'?['/d','/s','/c','gradlew.bat --no-daemon assembleDebug']:['--no-daemon','assembleDebug'],{cwd:project,stdio:'inherit',env:process.env});
  if(result.error)throw result.error;if(result.status!==0)process.exit(result.status??1);
  mkdirSync(resolve(root,'artifacts'),{recursive:true});
  copyFileSync(resolve(project,'app/build/outputs/apk/debug/app-debug.apk'),resolve(root,'artifacts/crypto-pigeon-debug.apk'));
  console.log('Built artifacts/crypto-pigeon-debug.apk (USB development wrapper; host daemon required).');
}
