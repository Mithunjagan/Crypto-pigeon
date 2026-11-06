import {spawnSync} from 'node:child_process';
import {readFileSync,existsSync,readdirSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve,basename} from 'node:path';

const root=resolve(import.meta.dirname,'..');
function git(args,encoding='utf8'){
  const result=spawnSync('git',args,{cwd:root,encoding,windowsHide:true,maxBuffer:32*1024*1024});
  if(result.status!==0)throw Error('Git audit read failed');return result.stdout;
}
const localSecrets=[];
for(const name of readdirSync(root).filter(name=>name.startsWith('.env')&&name!=='.env.example')){
  for(const line of readFileSync(resolve(root,name),'utf8').split(/\r?\n/)){
    const match=line.match(/^\s*([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if(match){const value=match[2].replace(/^['"]|['"]$/g,'');if(value.length>=16&&!/^(?:change|replace|example|your[_-])/i.test(value))localSecrets.push(value);}
  }
}
const findings=[];let files=0;
const entries=git(['ls-files','--stage','-z']).split('\0').filter(Boolean);
const allowedProperties=new Set(['apps/mobile-android/gradle.properties','apps/mobile-android/gradle/wrapper/gradle-wrapper.properties']);
for(const entry of entries){
  const match=entry.match(/^(\d+) ([a-f0-9]+) \d\t(.+)$/s);if(!match)throw Error('Unexpected Git index entry');
  const [,mode,hash,file]=match;files++;
  if(mode==='120000'||/(?:^|\/)(?:\.env[^/]*|node_modules|\.crypto_pigeon[^/]*)(?:\/|$)|\.(?:jks|keystore|p12|pfx|cp7|cpvault|apk|exe|key|pem)$/i.test(file)||file.startsWith('artifacts/')&&!/^artifacts\/serverless-p2p\/[^/]+\.md$/.test(file)||file.endsWith('.properties')&&!allowedProperties.has(file))findings.push({file,reason:'Forbidden local data, signing material or build output'});
  const bytes=git(['cat-file','blob',hash],null);
  if(bytes.length>5*1024*1024){findings.push({file,reason:'Unexpected large staged artifact'});continue;}
  if(bytes.includes(0))continue;
  const content=bytes.toString('utf8');
  const patterns=[
    /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
    /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})\b/,
    /["'](?:private_key|privateKey|storePassword|keyPassword|access_token|refresh_token)["']\s*:\s*["'][A-Za-z0-9+/=_-]{32,}["']/
  ];
  if(patterns.some(pattern=>pattern.test(content)))findings.push({file,reason:'Private key or credential literal pattern'});
  if(localSecrets.some(value=>content.includes(value)))findings.push({file,reason:'Local environment credential found in staged content'});
}
const report={passed:findings.length===0,files,findings,checks:['Forbidden paths/extensions','Private-key and credential literal patterns','Exact local environment secret matches','Unexpected large files and symlinks'],scope:'Staged Git blobs; credentials and matching content are never printed'};
mkdirSync(resolve(root,'artifacts/serverless-p2p'),{recursive:true});
writeFileSync(resolve(root,'artifacts/serverless-p2p/release-secret-audit.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify(report,null,2));
if(findings.length)process.exitCode=1;
