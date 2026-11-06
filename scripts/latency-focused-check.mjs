// Targeted transport/debounce regression checks, independent of backend/emulator suites.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { DebouncedBackup } from '../apps/local-daemon/dist/debounced-backup.js';
import { ChangeFeed } from '../apps/local-daemon/dist/change-feed.js';
import { RelayClient } from '../apps/local-daemon/dist/relay-client.js';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let calls=0,release,failed=0,unlocked=true;
const backup=new DebouncedBackup(()=>{calls++;return new Promise(resolve=>release=resolve);},()=>unlocked,()=>failed++,25);
for(let i=0;i<8;i++){backup.schedule();await pause(3);}
assert.equal(calls,0,'A burst must not start a synchronous backup');
await pause(40);assert.equal(calls,1);
backup.schedule();await pause(40);assert.equal(calls,1,'Uploads must never overlap');
release();await pause(55);assert.equal(calls,2);release();backup.cancel();await pause(10);
backup.schedule();assert.equal(backup.pending(),true);backup.cancel();assert.equal(backup.pending(),false);await pause(40);assert.equal(calls,2,'Lock cancellation must remove the debounce');
let retries=0;
const retry=new DebouncedBackup(async()=>{retries++;if(retries===1)throw new Error('offline');},()=>unlocked,()=>failed++,15);
retry.schedule();await pause(55);retry.cancel();assert.ok(retries>=2);assert.equal(failed,1);
const feed=new ChangeFeed();const waiting=feed.after(0);feed.publish('NEW_ENVELOPE');assert.deepEqual(await waiting,{revision:1,type:'NEW_ENVELOPE'});
const abort=new AbortController();const cancelled=feed.after(1,abort.signal);abort.abort();await cancelled;
console.log('PASS debounce, burst coalescing, upload serialization, lock cancellation, offline retry and event wakeup');

let challenges=0,responses=0,cachedRequests=0,force401=false;
const tokens=new Set();
const server=createServer(async(req,res)=>{
  for await(const _ of req){} // Drain each request for keep-alive reuse.
  res.setHeader('Content-Type','application/json');
  if(req.url==='/api/auth/challenge'){challenges++;res.end(JSON.stringify({challenge:'test-challenge'}));return;}
  if(req.url==='/api/auth/respond'){responses++;const token='test-token-'+responses;tokens.add(token);res.end(JSON.stringify({sessionToken:token,expiresAt:Date.now()+86400000}));return;}
  if(force401){force401=false;res.statusCode=401;res.end('{"error":"expired"}');return;}
  if(!tokens.has(req.headers.authorization?.slice(7))){res.statusCode=401;res.end('{}');return;}
  cachedRequests++;res.end('{"ok":true}');
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const key=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'der'});
const vault={isLocked:()=>false,database:()=>({prepare:sql=>({get:()=>sql.includes('vault_instance')?{token:'test-instance'}:null,run:()=>({changes:1})})})};
const store={ensureIdentity:async()=>({deviceId:'device-test'}),getDeviceAuthKeyPair:()=>({privateKey:key})};
try {
  const client=new RelayClient('http://127.0.0.1:'+server.address().port);
  await Promise.all(Array.from({length:8},()=>client.request(vault,store,'/api/probe')));
  assert.equal(challenges,1);assert.equal(responses,1);assert.equal(cachedRequests,8);
  force401=true;assert.ok((await client.request(vault,store,'/api/probe')).ok);assert.equal(challenges,2);
  // The cached token is refreshed inside the five-second expiry window.
  client.expiresAt=Date.now()+4500;
  assert.ok((await client.request(vault,store,'/api/probe')).ok);assert.equal(challenges,3);
  assert.ok((await client.request(vault,store,'/api/probe')).ok);assert.equal(challenges,3);
  client.clearSession();assert.equal(client.cachedToken,null);
  console.log('PASS concurrent token caching, a single challenge/response refresh, 401 recovery, five-second expiry window and lock cache clearing');
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
