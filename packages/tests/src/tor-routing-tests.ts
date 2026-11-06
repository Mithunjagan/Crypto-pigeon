import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import { Vault } from '../../../apps/local-daemon/dist/vault.js';
import { TorRouting } from '../../../apps/local-daemon/dist/tor-routing.js';
import { initializeTorSchema,p2pSigningBytes,socksConnect,cleanupTorSpool } from '../../../apps/local-daemon/dist/tor-transport.js';
import { LocalSignalStore } from '../../../apps/local-daemon/dist/signal-store.js';
import { establishSession,decryptPayload } from '../../../apps/local-daemon/dist/signal-adapter.js';
import { sendMessage } from '../../../apps/local-daemon/dist/messages.js';
import { RelayClient } from '../../../apps/local-daemon/dist/relay-client.js';
import { generateDeviceKeyPair,signChallenge,verifyChallenge } from '@crypto-pigeon/protocol';

export function registerTorRoutingTests(test:(name:string,fn:()=>void|Promise<void>)=>void){
  test('Hybrid retries original Signal bytes over relay only after Tor failure and keeps direct ACKs local',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-hybrid-')),alice=new Vault(join(root,'a')),bob=new Vault(join(root,'b')),password=crypto.randomBytes(24).toString('hex')+'Aa1!';
    try{await alice.create(password);await bob.create(password);const db=alice.database(),a=new LocalSignalStore(db),b=new LocalSignalStore(bob.database()),identity=await a.ensureIdentity(),bundle=await b.ensureIdentity();a.setAccount(identity.deviceId);b.setAccount(bundle.deviceId);initializeTorSchema(db);
      await establishSession(a,b.localAddress(),{...bundle,oneTimePrekey:null,pqOneTimePrekey:null});const contact=b.localAddress().toString(),conversation=crypto.randomUUID();db.prepare('INSERT INTO remote_contacts VALUES(?,?,?,?)').run([contact,bundle.deviceId,bundle.deviceId,1]);db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,Date.now()]);db.prepare('INSERT INTO peer_onions VALUES(?,?,?,?,?)').run([bundle.deviceId,contact,'a'.repeat(56)+'.onion',bundle.deviceAuthPublicKey,'public-test-invite']);
      const attempts:any[]=[];const routing=new TorRouting(()=>alice.database());routing.mode='HYBRID_TOR_RELAY';routing.transport={status:()=>({serverless:true}),isStopped:()=>false,request:async(_peer:string,_path:string,_method:string,body:string)=>{attempts.push(JSON.parse(body));throw new Error('offline');}} as any;
      routing.prepareRelay=async body=>async()=>{attempts.push(body);return Response.json({accepted:true});};const client=new RelayClient();client.torRouting=routing;
      const message=await sendMessage(alice,a,client,conversation,'same ciphertext on fallback');assert.equal(message.status,'queued');
      for(let i=0;i<100&&db.prepare('SELECT 1 FROM message_outbox').get();i++)await new Promise(r=>setTimeout(r,10));
      assert.equal(db.prepare('SELECT count(*) AS n FROM message_outbox').get<any>().n,0);assert.deepEqual(attempts[0],attempts[1]);
      const bytes=Buffer.from(attempts[1].ciphertext,'base64');assert.equal(JSON.parse(await decryptPayload(b,a.localAddress(),bytes.subarray(1).toString('base64'),bytes[0])).text,'same ciphertext on fallback');
      db.prepare('INSERT INTO tor_inbox VALUES(?,?)').run(['direct-id','{}']);assert.equal((await routing.route('/api/messages/ack',{method:'POST',body:JSON.stringify({envelopeIds:['direct-id']})}))?.status,204);
      const mixed={method:'POST',body:JSON.stringify({envelopeIds:['relay-id']})};assert.equal(await routing.route('/api/messages/ack',mixed),undefined);assert.deepEqual(JSON.parse(mixed.body).envelopeIds,['relay-id']);
    }finally{alice.lock();bob.lock();await rm(root,{recursive:true,force:true});}
  });
  test('Orphaned outgoing and completed incoming encrypted chunk spools are removed',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-spool-')),vault=new Vault(root),password=crypto.randomBytes(24).toString('hex')+'Aa1!';
    try{await vault.create(password);const db=vault.database();initializeTorSchema(db);const blob=crypto.randomUUID();db.prepare('INSERT INTO tor_blobs VALUES(?,?,?,?)').run([blob,1,0,Date.now()]);db.prepare('INSERT INTO tor_chunks VALUES(?,?,?,?)').run([blob,0,'nonce','ciphertext']);db.prepare('INSERT INTO tor_attachment_links VALUES(?,?)').run(['a'.repeat(32),blob]);db.prepare('INSERT INTO tor_download_chunks VALUES(?,?,?,?)').run([blob,0,'nonce','ciphertext']);cleanupTorSpool(db);assert.equal(db.prepare('SELECT count(*) AS n FROM tor_blobs').get<any>().n,0);assert.equal(db.prepare('SELECT count(*) AS n FROM tor_chunks').get<any>().n,0);assert.equal(db.prepare('SELECT count(*) AS n FROM tor_download_chunks').get<any>().n,0);
    }finally{vault.lock();await rm(root,{recursive:true,force:true});}
  });
  test('Tor request authentication binds sender, path, method and exact encrypted body',()=>{
    const key=generateDeviceKeyPair(),sender=crypto.randomUUID(),time=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
    const payload=p2pSigningBytes(sender,time,nonce,'POST','/p2p/v1/envelopes','Ynl0ZXM=');const signature=signChallenge(key.privateKey,payload);
    assert.equal(verifyChallenge(key.publicKey,payload,signature),true);
    for(const changed of [p2pSigningBytes(sender,time,nonce,'GET','/p2p/v1/envelopes','Ynl0ZXM='),p2pSigningBytes(sender,time,nonce,'POST','/p2p/v1/envelopes','YWx0ZXJlZA==')])assert.equal(verifyChallenge(key.publicKey,changed,signature),false);
  });
  test('Tor routing persists encrypted inbox and offline attachment chunks without contacting a relay',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-tor-')),vault=new Vault(root);
    try{await vault.create('StrongPassword123!');const db=vault.database();initializeTorSchema(db);const routing=new TorRouting(()=>vault.database());
      const packet={version:1,envelopeId:crypto.randomBytes(16).toString('hex'),mailboxId:crypto.randomUUID(),ciphertext:'AQID'};
      assert.equal((await routing.route('/api/messages/send',{method:'POST',body:JSON.stringify(packet)}))?.status,503);
      db.prepare('INSERT INTO tor_inbox VALUES(?,?)').run([packet.envelopeId,JSON.stringify(packet)]);
      assert.deepEqual(await (await routing.route('/api/messages/pending'))!.json(),[packet]);
      const blobId=crypto.randomUUID();assert.equal((await routing.route('/api/attachments/upload',{method:'POST',body:JSON.stringify({blobId,chunkCount:1,totalSize:1})}))?.status,200);
      await routing.route(`/api/attachments/${blobId}/chunks`,{method:'POST',body:JSON.stringify({chunkIndex:0,nonce:crypto.randomBytes(12).toString('base64'),ciphertext:crypto.randomBytes(17).toString('base64')})});
      assert.equal(db.prepare('SELECT count(*) AS n FROM tor_chunks').get<{n:number}>()!.n,1);
      await assert.rejects(()=>routing.route('/api/prekeys/bundle',{method:'POST',body:'{}'}),/RELAY_DISABLED/);
      vault.lock();await vault.unlock('StrongPassword123!');
      assert.equal((await (await routing.route('/api/messages/pending'))!.json() as any[]).length,1);
      await routing.route('/api/messages/ack',{method:'POST',body:JSON.stringify({envelopeIds:[packet.envelopeId]})});
      assert.deepEqual(await (await routing.route('/api/messages/pending'))!.json(),[]);
    }finally{vault.lock();await rm(root,{recursive:true,force:true});}
  });
  test('SOCKS sends onion names as domain bytes and rejects clearnet destinations',async()=>{
    const host='a'.repeat(56)+'.onion';let sawDomain=false;
    const server=net.createServer(socket=>{let stage=0;socket.on('data',data=>{if(stage++===0){assert.deepEqual([...data],[5,1,0]);socket.write(Buffer.from([5,0]));}else{assert.equal(data[3],3);assert.equal(data.subarray(5,-2).toString(),host);sawDomain=true;socket.write(Buffer.from([5,0,0,1,127,0,0,1,0,80]));}});});
    await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
    try{const socket=await socksConnect((server.address() as net.AddressInfo).port,host,80);assert.equal(sawDomain,true);socket.destroy();await assert.rejects(()=>socksConnect(1,'example.com',80),/ONION_REQUIRED/);}finally{await new Promise<void>(r=>server.close(()=>r()));}
  });
}
