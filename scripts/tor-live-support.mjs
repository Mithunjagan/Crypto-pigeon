import { mkdir,copyFile,rename,stat } from 'node:fs/promises';
import { join } from 'node:path';
export const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
// Never copy state, guards, control cookies, locks, or onion/private service keys.
const publicCacheFiles=['cached-certs','cached-microdesc-consensus','cached-microdescs','cached-microdescs.new','cached-descriptors','cached-descriptors.new'];
export async function seedPublicTorCache(source,target){
  await mkdir(target,{recursive:true});let copied=0;
  for(const name of publicCacheFiles){try{if((await stat(join(source,name))).size===0)continue;const temporary=join(target,name+'.seed');await copyFile(join(source,name),temporary);await rename(temporary,join(target,name));copied++;}catch(error){if(error.code!=='ENOENT')throw error;}}
  return copied;
}
export async function waitForTorPublication(tor,{timeoutMs=480000,label='Tor',log=console.log}={}){
  const started=Date.now();let backoff=1000,last='';
  while(Date.now()-started<timeoutMs){const status=tor.status(),stage=`${status.bootstrapPercent}% / descriptor ${status.descriptorPublished?'published':'pending'}`;if(stage!==last){log(`${label}: ${stage} (${Math.round((Date.now()-started)/1000)}s)`);last=stage;}if(tor.isStopped())throw new Error(`${label}: ${status.errorCode??'TOR_STOPPED'}`);if(status.serverless&&status.descriptorPublished)return Date.now()-started;await delay(backoff);backoff=Math.min(5000,Math.round(backoff*1.4));}
  throw new Error(`${label}: bootstrap/publication deadline exceeded`);
}
