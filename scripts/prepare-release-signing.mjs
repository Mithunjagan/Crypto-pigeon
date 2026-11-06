import {randomBytes} from 'node:crypto';
import {existsSync,mkdirSync,writeFileSync,readFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {spawnSync} from 'node:child_process';

const root=resolve(import.meta.dirname,'..'),directory=join(root,'artifacts/keys');
const key=join(directory,'crypto-pigeon-release.jks'),properties=join(directory,'release-signing.properties');
mkdirSync(directory,{recursive:true,mode:0o700});
if(process.platform==='win32'){
  const identity=spawnSync('powershell.exe',['-NoProfile','-Command','[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],{encoding:'utf8',windowsHide:true});
  const sid=identity.stdout?.trim();if(identity.status!==0||!/^S-1-[\d-]+$/.test(sid))throw Error('Cannot identify signing-file owner');
  const acl=spawnSync('icacls.exe',[directory,'/inheritance:r','/grant:r',`*${sid}:(OI)(CI)F`],{encoding:'utf8',windowsHide:true});
  if(acl.status!==0)throw Error('Cannot restrict signing directory permissions');
}
if(existsSync(key)&&!existsSync(properties))throw Error('Existing release key has no local signing properties; refusing to replace it');
if(!existsSync(properties)){
  writeFileSync(properties,`storeFile=crypto-pigeon-release.jks\nstorePassword=${randomBytes(32).toString('hex')}\nkeyAlias=crypto-pigeon-release\nkeyPassword=${randomBytes(32).toString('hex')}\n`,{mode:0o600,flag:'wx'});
}
const values=Object.fromEntries(readFileSync(properties,'utf8').split(/\r?\n/).filter(line=>line.includes('=')).map(line=>{const at=line.indexOf('=');return [line.slice(0,at),line.slice(at+1)];}));
if(!values.storePassword||!values.keyPassword||!values.keyAlias||values.storeFile!=='crypto-pigeon-release.jks')throw Error('Invalid local release signing configuration');
const jdk=process.env.JAVA_HOME??join(process.env.LOCALAPPDATA??'','CryptoPigeon/android-tools/jdk-17.0.20.1+1');
const keytool=join(jdk,'bin',process.platform==='win32'?'keytool.exe':'keytool');
const env={...process.env,CP_RELEASE_STORE_PASSWORD:values.storePassword,CP_RELEASE_KEY_PASSWORD:values.keyPassword};
const common=['-keystore',key,'-storetype','JKS','-storepass:env','CP_RELEASE_STORE_PASSWORD','-alias',values.keyAlias];
const creating=!existsSync(key);
const args=creating?['-genkeypair',...common,'-keypass:env','CP_RELEASE_KEY_PASSWORD','-keyalg','RSA','-keysize','4096','-validity','10000','-dname','CN=Crypto Pigeon Release, O=Crypto Pigeon','-noprompt']:['-list',...common];
const result=spawnSync(keytool,args,{env,encoding:'utf8',windowsHide:true});
if(result.status!==0)throw Error('Release keystore generation/validation failed; credentials were not logged');
console.log(creating?'Release RSA-4096 signing key generated; credentials restricted to the local owner.':'Existing release signing key validated and preserved.');
