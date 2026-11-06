import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {TorOnionTransport,initializeTorSchema} from '../apps/local-daemon/dist/tor-transport.js';
import {Vault} from '../apps/local-daemon/dist/vault.js';
import {generateDeviceKeyPair} from '../packages/protocol/dist/index.js';
import {TorRecoveryWakeup} from '../apps/local-daemon/dist/tor-recovery.js';

test('Publication and resumed circuit events immediately wake queued retry, coalescing bursts',async()=>{
  const drain=async()=>{await Promise.resolve();await new Promise(setImmediate);};
  let retries=0;
  const retry=new TorRecoveryWakeup(async()=>{retries++;});
  const tor=new TorOnionTransport(()=>{throw Error('No key or DB access for control events');},()=>{throw Error('No key access');},fn=>fn());
  tor.onReady=()=>retry.wake();
  tor.onData('650 HS_DESC UPLOADED '+'a'.repeat(56)+' NO_AUTH directory\r\n650 CIRC 42 BUILT path\r\n');
  await drain();assert.equal(retries,1);
  tor.onData('650 CIRC 43 BUILT path\r\n650 HS_DESC UPLOADED '+'a'.repeat(56)+' NO_AUTH directory\r\n');
  await drain();assert.equal(retries,1);
  tor.onData('650 NETWORK_LIVENESS DOWN\r\n650 NETWORK_LIVENESS UP\r\n650 CIRC 44 BUILT path\r\n');
  await drain();assert.equal(retries,2);
  retry.wake();retry.close();tor.close();await new Promise(setImmediate);assert.equal(retries,2);
});

test('SOCKS-backed HTTP supports a POST followed by a full encrypted GET chunk',async()=>{
  const part={nonce:crypto.randomBytes(12).toString('base64'),ciphertext:crypto.randomBytes(65552).toString('base64')},sockets=new Set();
  const root=await mkdtemp(join(tmpdir(),'cp-http-unit-')),vault=new Vault(root);await vault.create(crypto.randomBytes(24).toString('hex')+'Aa1!');const db=vault.database();initializeTorSchema(db);
  const keys=generateDeviceKeyPair(),own=generateDeviceKeyPair(),device=crypto.randomUUID(),ownDevice=crypto.randomUUID(),conversation=crypto.randomUUID(),message=crypto.randomUUID(),attachment=crypto.randomBytes(16).toString('hex'),blob=crypto.randomUUID(),contact=device+'.1';
  db.prepare('INSERT INTO contacts(contact_id,username,identity_public_key,verified,identity_changed,created_at) VALUES(?,?,?,1,0,?)').run([contact,'peer',Buffer.alloc(33),Date.now()]);
  db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,Date.now()]);db.prepare("INSERT INTO messages(message_id,conversation_id,direction,plaintext,status) VALUES(?,?,'sent','','sent')").run([message,conversation]);
  db.prepare('INSERT INTO attachments(attachment_id,message_id,encrypted_local_path,file_name_encrypted,file_size,file_hash,file_key) VALUES(?,?,?,?,?,?,?)').run([attachment,message,'unit-cache',Buffer.alloc(32),65536,Buffer.alloc(32),Buffer.alloc(32)]);
  db.prepare('INSERT INTO peer_onions VALUES(?,?,?,?,?)').run([device,contact,'a'.repeat(56)+'.onion',keys.publicKey.toString('base64'),'public fixture']);db.prepare('INSERT INTO tor_blobs VALUES(?,?,?,?)').run([blob,1,65536,Date.now()]);db.prepare('INSERT INTO tor_attachment_links VALUES(?,?)').run([attachment,blob]);db.prepare('INSERT INTO tor_chunks VALUES(?,?,?,?)').run([blob,0,part.nonce,part.ciphertext]);
  const recipient=new TorOnionTransport(()=>db,()=>({deviceId:ownDevice,privateKey:Buffer.from(own.privateKey)}),fn=>fn());recipient.deviceId=ownDevice;
  const endpoint=http.createServer((req,res)=>void recipient.receive(req,res));
  await new Promise(r=>endpoint.listen(0,'127.0.0.1',r));
  const proxy=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));let phase=0;
    const handshake=data=>{if(phase++===0){socket.write(Buffer.from([5,0]));return;}
      assert.equal(data[3],3);socket.off('data',handshake);const upstream=net.connect(endpoint.address().port,'127.0.0.1',()=>{socket.write(Buffer.from([5,0,0,1,127,0,0,1,0,80]));socket.pipe(upstream);upstream.pipe(socket);});socket.on('close',()=>upstream.destroy());upstream.on('error',()=>socket.destroy());
    };socket.on('data',handshake);
  });await new Promise(r=>proxy.listen(0,'127.0.0.1',r));
  const tor=new TorOnionTransport(()=>{throw Error('No DB needed');},()=>({deviceId:device,privateKey:Buffer.from(keys.privateKey)}),fn=>fn());
  tor.boot=100;tor.onion='a'.repeat(56)+'.onion';tor.socksPort=proxy.address().port;
  try{const first=await tor.request(tor.onion,'/p2p/v1/envelopes','POST',JSON.stringify({version:1,envelopeId:crypto.randomBytes(16).toString('hex'),mailboxId:ownDevice,ciphertext:'AQID'}));assert.equal(first.status,200);assert.equal((await first.json()).accepted,true);const response=await tor.request(tor.onion,`/p2p/v1/attachments/${blob}/chunks/0`,'GET');assert.equal(response.status,200);assert.deepEqual(await response.json(),part);assert.equal(db.prepare('SELECT count(*) AS n FROM tor_inbox').get().n,1);}
  finally{tor.close();recipient.close();for(const s of sockets)s.destroy();endpoint.closeAllConnections();await Promise.all([new Promise(r=>proxy.close(r)),new Promise(r=>endpoint.close(r))]);vault.lock();await rm(root,{recursive:true,force:true});}
});
