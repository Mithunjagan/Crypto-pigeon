import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {mkdirSync,openSync,closeSync,existsSync,copyFileSync,readFileSync} from 'node:fs';
const root=resolve(import.meta.dirname,'..'),project=resolve(root,'apps/mobile-android');
process.env.ANDROID_HOME??=process.env.ANDROID_SDK_ROOT??(existsSync(resolve(root,'artifacts/android-device-tools/platforms/android-36/android.jar'))?resolve(root,'artifacts/android-device-tools'):undefined);
const localJdk=resolve(process.env.LOCALAPPDATA??'', 'CryptoPigeon/android-tools/jdk-17.0.20.1+1');
if(!process.env.JAVA_HOME&&existsSync(resolve(localJdk,'bin/java.exe')))process.env.JAVA_HOME=localJdk;
if(!process.env.GRADLE_USER_HOME&&existsSync(resolve(root,'artifacts/android-gradle-cache')))process.env.GRADLE_USER_HOME=resolve(root,'artifacts/android-gradle-cache');
const assets=spawnSync(process.execPath,[resolve(root,'scripts/android-build.mjs'),'--assets-only'],{cwd:root,stdio:'inherit'});if(assets.status!==0)throw new Error('UI asset bundling failed');
const sdk=process.env.ANDROID_HOME??process.env.ANDROID_SDK_ROOT;
if(!sdk||!existsSync(resolve(sdk,'platforms/android-36/android.jar')))throw new Error('Native Android build requires Android SDK platform 36.');
const out=resolve(root,'artifacts/native-android');mkdirSync(out,{recursive:true});
const release=process.argv.includes('--release');
if(release&&!existsSync(resolve(root,'artifacts/keys/release-signing.properties')))throw new Error('Run node scripts/prepare-release-signing.mjs before building a release.');
const args=['--no-daemon','--console=plain',release?':native:assembleRelease':':native:assembleDebug'];
if(process.argv.includes('--friend-ready'))args.push('-PconsumerBuild=true');
if(process.argv.includes('--jvm-tests'))args.push(':native:testDebugUnitTest');
if(process.argv.includes('--tests'))args.push(':native:assembleDebugAndroidTest');
if(process.argv.includes('--offline'))args.push('--offline');
// Optional machine-local init script; the standard SDK needs no override.
const init=process.env.CRYPTO_PIGEON_GRADLE_INIT;
if(init){if(!existsSync(init))throw new Error('Gradle init script not found');args.push('-I',resolve(init));}
const log=resolve(out,'build.log'),fd=openSync(log,'w');let result;
try{
  if(process.platform==='win32'){
    for(const arg of args)if(/["&|<>^%!\r\n]/.test(arg))throw new Error('Unsupported shell character in Gradle argument');
    result=spawnSync(process.env.ComSpec??'cmd.exe',['/d','/s','/c','gradlew.bat '+args.map(arg=>/\s/.test(arg)?`"${arg}"`:arg).join(' ')],{cwd:project,stdio:['ignore',fd,fd],windowsHide:true,windowsVerbatimArguments:true});
  }else result=spawnSync('./gradlew',args,{cwd:project,stdio:['ignore',fd,fd]});
}finally{closeSync(fd);}
if(result.error)throw result.error;
if(result.status!==0){console.error(readFileSync(log,'utf8').slice(-10000));throw new Error('Native Android build failed; full log: '+log);}
if(release){
  copyFileSync(resolve(project,'native/build/outputs/apk/release/native-release.apk'),resolve(root,'artifacts/crypto-pigeon-release.apk'));
}else{
  copyFileSync(resolve(project,'native/build/outputs/apk/debug/native-debug.apk'),resolve(out,'crypto-pigeon-native-alpha.apk'));
  for(const name of ['crypto-pigeon-standalone.apk','crypto-pigeon-debug.apk'])copyFileSync(resolve(project,'native/build/outputs/apk/debug/native-debug.apk'),resolve(root,'artifacts',name));
}
if(process.argv.includes('--tests'))copyFileSync(resolve(project,'native/build/outputs/apk/androidTest/debug/native-debug-androidTest.apk'),resolve(out,'crypto-pigeon-native-tests.apk'));
console.log('Native Android build passed. APKs and bounded build log: '+out);
