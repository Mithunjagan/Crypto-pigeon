import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {TorOnionTransport} from '../apps/local-daemon/dist/tor-transport.js';
import {seedPublicTorCache} from './tor-live-support.mjs';
test('Async descriptor events cannot consume or contaminate a pending Tor command reply',()=>{
  const tor=new TorOnionTransport(()=>{throw Error('DB must not be read');},()=>{throw Error('No key access');},fn=>fn());
  tor.onion='a'.repeat(56)+'.onion';let reply,error;
  tor.waiter={resolve:value=>reply=value,reject:value=>error=value};
  tor.onData('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100\r\n650 HS_DESC UPLOADED '+'a'.repeat(56)+' NO_AUTH directory\r\n650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100\r\n250 O');
  assert.equal(reply,undefined);assert.equal(error,undefined);assert.equal(tor.status().descriptorPublished,true);assert.equal(tor.status().bootstrapPercent,100);
  tor.onData('K\r\n');assert.deepEqual(reply,['250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100','250 OK']);assert.equal(error,undefined);tor.close();
});
test('Warm-cache seeding copies only public directory data and never identity or control state',async()=>{
  const root=await mkdtemp(join(tmpdir(),'cp-public-cache-')),source=join(root,'source'),target=join(root,'target');
  try{await mkdir(source);for(const name of ['cached-certs','cached-microdesc-consensus','cached-microdescs','state','control.cookie','lock','hs_ed25519_secret_key'])await writeFile(join(source,name),'isolated test data');
    assert.equal(await seedPublicTorCache(source,target),3);assert.deepEqual((await readdir(target)).sort(),['cached-certs','cached-microdesc-consensus','cached-microdescs']);
  }finally{await rm(root,{recursive:true,force:true});}
});
