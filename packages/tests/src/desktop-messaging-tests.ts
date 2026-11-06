import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeRelayUrl } from '@crypto-pigeon/protocol';
import { Vault } from '../../../apps/local-daemon/dist/vault.js';
import { LocalSignalStore } from '../../../apps/local-daemon/dist/signal-store.js';
import { establishSession, decryptPayload, encryptPayload } from '../../../apps/local-daemon/dist/signal-adapter.js';
import { sendMessage, flushOutbox, syncMessages } from '../../../apps/local-daemon/dist/messages.js';

export function registerDesktopMessagingTests(test:(name:string,fn:()=>void|Promise<void>)=>void) {
  test('First incoming Signal message creates one named contact and decrypts exactly once', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cp-first-incoming-'));
    const aliceVault = new Vault(join(root, 'alice')), bobVault = new Vault(join(root, 'bob'));
    try {
      await aliceVault.create('StrongPassword123!'); await bobVault.create('StrongPassword123!');
      const alice = new LocalSignalStore(aliceVault.database()), bob = new LocalSignalStore(bobVault.database());
      const aliceBundle = await alice.ensureIdentity(), bobBundle = await bob.ensureIdentity();
      const aliceId = crypto.randomUUID(), bobId = crypto.randomUUID();
      alice.setAccount(aliceId); bob.setAccount(bobId);
      await establishSession(alice, bob.localAddress(), {...bobBundle, oneTimePrekey:bobBundle.oneTimePrekeys[0], pqOneTimePrekey:bobBundle.pqOneTimePrekeys[0]});
      const plaintext = 'The first message from a newly approved contact';
      const encrypted = await encryptPayload(alice, bob.localAddress(), JSON.stringify({type:'text', text:plaintext}));
      const envelope = {version:1, envelopeId:crypto.randomBytes(16).toString('hex'), senderId:aliceBundle.deviceId, mailboxId:bobBundle.deviceId,
        ciphertext:Buffer.concat([Buffer.from([encrypted.type]), Buffer.from(encrypted.ciphertext,'base64')]).toString('base64')};
      let acknowledged = false;
      const relay = {takePushedEnvelopes:()=>[],request:async (_v:any,_s:any,path:string) => {
        if(path==='/api/messages/pending')return Response.json(acknowledged?[]:[envelope]);
        if(path==='/api/prekeys/bundle')return Response.json({...aliceBundle, recipientUserId:aliceId, recipientDeviceId:aliceBundle.deviceId,
          recipientUsername:'alice', publicUid:'CP-TEST-ALICE', oneTimePrekey:aliceBundle.oneTimePrekeys[0], pqOneTimePrekey:aliceBundle.pqOneTimePrekeys[0]});
        assert.equal(path,'/api/messages/ack'); acknowledged=true; return new Response(null,{status:204});
      }} as any;
      bobVault.database().exec("CREATE TRIGGER fail_receive BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END");
      assert.equal(await syncMessages(bobVault,bob,relay),0);
      assert.equal(acknowledged,false,'Failed receive must not acknowledge the envelope');
      assert.equal(bobVault.database().prepare('SELECT count(*) AS n FROM seen_envelope_ids').get<{n:number}>()!.n,0);
      bobVault.database().exec('DROP TRIGGER fail_receive');
      assert.equal(await syncMessages(bobVault,bob,relay),1);
      assert.equal(acknowledged,true);
      const contacts=bobVault.database().prepare('SELECT username,public_uid FROM contacts').all();
      assert.equal(contacts.length,1); assert.equal(contacts[0].username,'alice'); assert.equal(contacts[0].public_uid,'CP-TEST-ALICE');
      const messages=bobVault.database().prepare('SELECT plaintext,direction FROM messages').all();
      assert.equal(messages.length,1);assert.equal(messages[0].plaintext,plaintext);assert.equal(messages[0].direction,'received');
      assert.equal(await syncMessages(bobVault,bob,relay),0);
      assert.equal(bobVault.database().prepare('SELECT count(*) AS n FROM messages').get<{n:number}>()!.n,1);
    } finally {aliceVault.lock();bobVault.lock();await rm(root,{recursive:true,force:true});}
  });
  test('Relay configuration blocks remote HTTP, URL credentials and HTTPS downgrade routes', () => {
    assert.equal(normalizeRelayUrl('https://relay.test/'), 'https://relay.test');
    assert.equal(normalizeRelayUrl('http://127.0.0.1:8443', true), 'http://127.0.0.1:8443');
    assert.equal(normalizeRelayUrl('http://192.168.1.20:8443'),'http://192.168.1.20:8443');
    assert.equal(normalizeRelayUrl('http://10.0.0.20:8443'),'http://10.0.0.20:8443');
    for (const url of ['http://relay.test','https://user:pass@relay.test','https://relay.test/api','https://relay.test/?token=secret','https://relay.test/#secret']) assert.throws(()=>normalizeRelayUrl(url));
    assert.throws(()=>normalizeRelayUrl('http://127.0.0.1:8443',false));
  });
  test('Outbox survives restart and retries identical Signal ciphertext after a lost relay response', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cp-outbox-'));
    const aliceVault = new Vault(join(root,'alice')), bobVault = new Vault(join(root,'bob'));
    try {
      await aliceVault.create('StrongPassword123!'); await bobVault.create('StrongPassword123!');
      let alice = new LocalSignalStore(aliceVault.database());
      const bob = new LocalSignalStore(bobVault.database());
      await alice.ensureIdentity(); const bundle = await bob.ensureIdentity();
      const aliceId = crypto.randomUUID(), bobId = crypto.randomUUID();
      alice.setAccount(aliceId); bob.setAccount(bobId);
      await establishSession(alice, bob.localAddress(), {...bundle,oneTimePrekey:bundle.oneTimePrekeys[0],pqOneTimePrekey:bundle.pqOneTimePrekeys[0]});
      const contact = bob.localAddress().toString(), conversation = crypto.randomUUID();
      aliceVault.database().prepare('INSERT INTO remote_contacts(contact_id,user_id,device_id,signal_device_id) VALUES(?,?,?,?)').run([contact,bobId,bundle.deviceId,1]);
      aliceVault.database().prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,Date.now()]);
      const attempts:any[]=[];
      const offline = {request:async (_v:any,_s:any,path:string,options:any) => {
        assert.equal(path,'/api/messages/send'); attempts.push(JSON.parse(options.body)); throw new Error('Response lost after server accepted');
      }} as any;
      const before = aliceVault.database().prepare('SELECT ratchet_state FROM signal_sessions WHERE contact_id=?').get<{ratchet_state:Uint8Array}>([contact])!.ratchet_state;
      aliceVault.database().exec("CREATE TRIGGER fail_message BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'test disk failure'); END");
      await assert.rejects(()=>sendMessage(aliceVault,alice,offline,conversation,'must roll back'));
      const after = aliceVault.database().prepare('SELECT ratchet_state FROM signal_sessions WHERE contact_id=?').get<{ratchet_state:Uint8Array}>([contact])!.ratchet_state;
      assert.deepEqual(before,after,'failed persistence must roll back the Signal ratchet');
      assert.equal(attempts.length,0,'failed persistence must never send');
      aliceVault.database().exec('DROP TRIGGER fail_message');
      const result = await sendMessage(aliceVault,alice,offline,conversation,'survives a disconnect');
      assert.equal(result.status,'queued');
      assert.equal(aliceVault.database().prepare('SELECT count(*) AS n FROM message_outbox').get<{n:number}>()!.n,1);
      aliceVault.lock(); await aliceVault.unlock('StrongPassword123!');
      alice = new LocalSignalStore(aliceVault.database());
      aliceVault.database().prepare('UPDATE messages SET disappear_at=? WHERE message_id=?').run([Date.now()-1000,result.messageId]);
      assert.equal(await flushOutbox(aliceVault,alice,offline),0,'Expired queued messages must not leave the device');
      assert.equal(attempts.length,1);
      aliceVault.database().prepare('UPDATE messages SET disappear_at=NULL WHERE message_id=?').run([result.messageId]);
      aliceVault.database().prepare('UPDATE contacts SET identity_changed=1 WHERE contact_id=?').run([contact]);
      assert.equal(await flushOutbox(aliceVault,alice,offline),0);
      assert.equal(attempts.length,1,'identity changes must block queued delivery');
      aliceVault.database().prepare('UPDATE contacts SET identity_changed=0 WHERE contact_id=?').run([contact]);
      const recovered = {request:async (_v:any,_s:any,_path:string,options:any) => { attempts.push(JSON.parse(options.body)); return new Response('{}',{status:202}); }} as any;
      assert.equal(await flushOutbox(aliceVault,alice,recovered),1);
      assert.deepEqual(attempts[0],attempts[1],'retry must use the original envelope id and encrypted bytes');
      assert.equal(aliceVault.database().prepare('SELECT status FROM messages WHERE message_id=?').get<{status:string}>([result.messageId])!.status,'sent');
      assert.equal(aliceVault.database().prepare('SELECT count(*) AS n FROM message_outbox').get<{n:number}>()!.n,0);
      const encrypted = Buffer.from(attempts[1].ciphertext,'base64');
      assert.deepEqual(JSON.parse(await decryptPayload(bob,alice.localAddress(),encrypted.subarray(1).toString('base64'),encrypted[0])),{
        type:'text',messageId:result.messageId,profile:{displayName:'',statusLine:''},text:'survives a disconnect',disappearingSeconds:0
      });
      assert.equal(await flushOutbox(aliceVault,alice,recovered),0);
      assert.equal(attempts.length,2);
    } finally { aliceVault.lock(); bobVault.lock(); await rm(root,{recursive:true,force:true}); }
  });
}
