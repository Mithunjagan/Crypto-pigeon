import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join,resolve } from 'node:path';
import { Vault } from '../apps/local-daemon/dist/vault.js';
import { LocalSignalStore } from '../apps/local-daemon/dist/signal-store.js';
import { TorOnionTransport,initializeTorSchema } from '../apps/local-daemon/dist/tor-transport.js';
import { TorRouting } from '../apps/local-daemon/dist/tor-routing.js';
import { RelayClient } from '../apps/local-daemon/dist/relay-client.js';
import { importServerlessContact } from '../apps/local-daemon/dist/serverless-contacts.js';
import { sendMessage,syncMessages } from '../apps/local-daemon/dist/messages.js';
import { encryptAndUploadAttachment,readDecryptedAttachment } from '../apps/local-daemon/dist/attachments.js';
import { createServerlessInvite,formatPublicUid } from '../packages/protocol/dist/index.js';
import {seedPublicTorCache,waitForTorPublication} from './tor-live-support.mjs';
const root=await mkdtemp(join(tmpdir(),'cp-live-tor-')),peers=[],delay=ms=>new Promise(r=>setTimeout(r,ms));
try{
  for(let i=0;i<2;i++){
    const directory=join(root,String(i)),vault=new Vault(directory),password=crypto.randomBytes(32).toString('hex')+'Aa1!';await vault.create(password);const store=new LocalSignalStore(vault.database()),identity=await store.ensureIdentity();store.setAccount(identity.deviceId);initializeTorSchema(vault.database());
    let tail=Promise.resolve();const serialize=async fn=>{const prior=tail;let release;tail=new Promise(r=>release=r);await prior;try{return await fn();}finally{release();}};
    const tor=new TorOnionTransport(()=>vault.database(),()=>({deviceId:identity.deviceId,...store.getDeviceAuthKeyPair()}),serialize);
    const routing=new TorRouting(()=>vault.database(),serialize);routing.transport=tor;const client=new RelayClient();client.torRouting=routing;
    const peer={vault,store,identity,tor,serialize,client,password,directory};peers.push(peer);
    const cache=resolve('artifacts/serverless-p2p/public-tor-cache');
    if(i){await seedPublicTorCache(join(peers[0].directory,'tor'),cache);await delay(3000);}
    const copied=await seedPublicTorCache(cache,join(directory,'tor'));console.log(`Peer ${i+1}: seeded ${copied} public Tor cache files`);
    await tor.start(process.env.TOR_BINARY??resolve('artifacts/tor/tor.exe'),join(directory,'tor'));
    await waitForTorPublication(tor,{label:`Peer ${i+1}`});
  }
  const deadline=Date.now()+240000;let last='';
  while(peers.some(p=>!p.tor.status().serverless)&&Date.now()<deadline){
    const status=peers.map(p=>p.tor.status().bootstrapPercent+'%'+(p.tor.status().errorCode?' ('+p.tor.status().errorCode+')':'')).join(', ');if(status!==last){console.log('Tor bootstrap: '+status);last=status;}if(peers.some(p=>p.tor.isStopped()))throw new Error('Tor instance stopped during bootstrap');await delay(3000);
  }
  assert.ok(peers.every(p=>p.tor.status().serverless),'Tor circuits did not bootstrap within four minutes');
  const uris=peers.map(p=>{const b=p.identity;return createServerlessInvite({version:2,publicUid:formatPublicUid(b.identityPublicKey),username:'partner',onion:p.tor.address(),userId:b.deviceId,deviceId:b.deviceId,signalDeviceId:b.signalDeviceId,registrationId:b.registrationId,deviceAuthPublicKey:b.deviceAuthPublicKey,identityPublicKey:b.identityPublicKey,signedPrekey:b.signedPrekey,pqLastResortPrekey:b.pqLastResortPrekey},p.store.getDeviceAuthKeyPair().privateKey);});
  for(let i=0;i<2;i++)peers[i].contact=await peers[i].serialize(()=>importServerlessContact(peers[i].vault,peers[i].store,uris[1-i]));
  // Start both sends simultaneously to exercise reciprocal incoming/outgoing delivery.
  await Promise.all(peers.map((p,i)=>p.serialize(()=>sendMessage(p.vault,p.store,p.client,p.contact.conversationId,'Live Tor encrypted test '+i))));
  const delivered=Date.now()+300000;
  while(Date.now()<delivered){
    await Promise.all(peers.map(p=>p.serialize(async()=>{await syncMessages(p.vault,p.store,p.client);const {flushOutbox}=await import('../apps/local-daemon/dist/messages.js');await flushOutbox(p.vault,p.store,p.client);}))); 
    if(peers.every(p=>p.vault.database().prepare("SELECT count(*) AS n FROM messages WHERE direction='received'").get().n===1))break;
    await delay(5000);
  }
  for(const p of peers){assert.equal(p.vault.database().prepare("SELECT count(*) AS n FROM messages WHERE direction='received'").get().n,1);assert.equal(p.vault.database().prepare('SELECT count(*) AS n FROM message_outbox').get().n,0);}
  console.log('PASS: two app-owned Tor instances exchanged real Signal messages simultaneously without an application relay.');
  const plaintext=crypto.randomBytes(131073),unicode=('வணக்கம் தமிழில் பேசலாம் 😀🕊️').repeat(3000).slice(0,65536),sender=peers[0],receiver=peers[1];
  const manifest=await sender.serialize(()=>encryptAndUploadAttachment(sender.vault,sender.store,sender.client,plaintext,'tor-live.bin','application/octet-stream'));
  await Promise.all([sender.serialize(()=>sendMessage(sender.vault,sender.store,sender.client,sender.contact.conversationId,'Live Tor attachment',manifest)),receiver.serialize(()=>sendMessage(receiver.vault,receiver.store,receiver.client,receiver.contact.conversationId,unicode))]);
  const pump=async()=>Promise.all(peers.map(p=>p.serialize(async()=>{const {flushOutbox}=await import('../apps/local-daemon/dist/messages.js');await syncMessages(p.vault,p.store,p.client);await flushOutbox(p.vault,p.store,p.client);}))); 
  const mediaDeadline=Date.now()+480000;let lastTransfer='';
  while(Date.now()<mediaDeadline){await pump();const failure=receiver.client.torRouting.lastTransferError;if(failure&&failure!==lastTransfer){console.log('Attachment diagnostic: '+failure+'; sender '+JSON.stringify({peerChunks:sender.tor.status().peerChunks,peerError:sender.tor.status().peerError}));lastTransfer=failure;}if(receiver.vault.database().prepare('SELECT 1 FROM attachments WHERE attachment_id=? AND encrypted_local_path IS NOT NULL').get([manifest.attachmentId])&&sender.vault.database().prepare("SELECT 1 FROM messages WHERE direction='received' AND plaintext=?").get([unicode]))break;await delay(3000);}
  const attachment=await receiver.serialize(()=>readDecryptedAttachment(receiver.vault,manifest.attachmentId));assert.ok(attachment.filedata.equals(plaintext),'Direct attachment bytes differ');assert.ok(sender.vault.database().prepare("SELECT 1 FROM messages WHERE direction='received' AND plaintext=?").get([unicode]),'Maximum Unicode message was not received');
  console.log('PASS: chunked AES-GCM attachment bytes and a maximum-length Unicode message survived direct Tor delivery.');
  // Persist while the partner is offline, then reopen both encrypted databases and onion identities.
  const addresses=peers.map(p=>p.tor.address());receiver.tor.close();
  const queued=await sender.serialize(()=>sendMessage(sender.vault,sender.store,sender.client,sender.contact.conversationId,'Queued before cold vault reopen'));assert.equal(queued.status,'queued');
  for(const p of peers){p.tor.close();await p.serialize(async()=>p.vault.lock());}
  await delay(1500);
  for(const p of peers){
    await p.serialize(async()=>{await p.vault.unlock(p.password);p.store=new LocalSignalStore(p.vault.database());});
    p.tor=new TorOnionTransport(()=>p.vault.database(),()=>({deviceId:p.identity.deviceId,...p.store.getDeviceAuthKeyPair()}),p.serialize);
    const routing=new TorRouting(()=>p.vault.database(),p.serialize);routing.transport=p.tor;p.client=new RelayClient();p.client.torRouting=routing;
    await p.tor.start(process.env.TOR_BINARY??resolve('artifacts/tor/tor.exe'),join(p.directory,'tor'));
    await waitForTorPublication(p.tor,{label:'Reopened peer'});
  }
  const restartDeadline=Date.now()+240000;
  while(peers.some(p=>!p.tor.status().serverless)&&Date.now()<restartDeadline){if(peers.some(p=>p.tor.isStopped()))throw new Error('Tor restart stopped');await delay(3000);}
  for(let i=0;i<peers.length;i++)assert.equal(peers[i].tor.address(),addresses[i],'Onion identity changed after reopen');
  const retryDeadline=Date.now()+300000;
  while(Date.now()<retryDeadline){await pump();if(!sender.vault.database().prepare('SELECT 1 FROM message_outbox WHERE message_id=?').get([queued.messageId])&&receiver.vault.database().prepare("SELECT 1 FROM messages WHERE direction='received' AND plaintext=?").get(['Queued before cold vault reopen']))break;await delay(3000);}
  assert.equal(sender.vault.database().prepare('SELECT count(*) AS n FROM message_outbox WHERE message_id=?').get([queued.messageId]).n,0);assert.equal(receiver.vault.database().prepare("SELECT count(*) AS n FROM messages WHERE direction='received' AND plaintext=?").get(['Queued before cold vault reopen']).n,1);
  console.log('PASS: offline ciphertext retried once after both vaults reopened with their original onion identities.');
}finally{for(const p of peers)p.tor.close();await delay(1500);if(peers[0])await seedPublicTorCache(join(peers[0].directory,'tor'),resolve('artifacts/serverless-p2p/public-tor-cache'));for(const p of peers)p.vault.lock();await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:500});}
