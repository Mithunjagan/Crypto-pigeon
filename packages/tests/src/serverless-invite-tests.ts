import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp,rm,readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { deflateRawSync,inflateRawSync } from 'node:zlib';
import { createServerlessInvite,parseServerlessInvite,inviteSigningBytes,formatPublicUid } from '@crypto-pigeon/protocol';
import { Vault } from '../../../apps/local-daemon/dist/vault.js';
import { LocalSignalStore } from '../../../apps/local-daemon/dist/signal-store.js';
import { importServerlessContact } from '../../../apps/local-daemon/dist/serverless-contacts.js';
import { encryptPayload,decryptPayload } from '../../../apps/local-daemon/dist/signal-adapter.js';

export function registerServerlessInviteTests(test:(name:string,fn:()=>void|Promise<void>)=>void){
  test('Signed serverless invite fits QR, pins keys offline, preserves sessions and rejects tampering',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-invite-')),alice=new Vault(join(root,'alice')),bob=new Vault(join(root,'bob'));
    try{
      await alice.create('StrongPassword123!');await bob.create('StrongPassword123!');
      const a=new LocalSignalStore(alice.database()),b=new LocalSignalStore(bob.database());
      const own=await a.ensureIdentity(),partner=await b.ensureIdentity();a.setAccount(own.deviceId);b.setAccount(partner.deviceId);
      const invite={version:2 as const,publicUid:formatPublicUid(partner.identityPublicKey),username:'partner',onion:'a'.repeat(56)+'.onion',userId:partner.deviceId,deviceId:partner.deviceId,signalDeviceId:partner.signalDeviceId,registrationId:partner.registrationId,deviceAuthPublicKey:partner.deviceAuthPublicKey,identityPublicKey:partner.identityPublicKey,signedPrekey:partner.signedPrekey,pqLastResortPrekey:partner.pqLastResortPrekey};
      const key=b.getDeviceAuthKeyPair(),uri=createServerlessInvite(invite,key.privateKey);
      assert.ok(uri.length<=2953);assert.deepEqual(parseServerlessInvite(uri),invite);
      const imported=await importServerlessContact(alice,a,uri);assert.equal(imported.verified,true);
      const sent=await encryptPayload(a,b.localAddress(),'Serverless pinned Signal session');assert.equal(await decryptPayload(b,a.localAddress(),sent.ciphertext,sent.type),'Serverless pinned Signal session');
      const before=alice.database().prepare('SELECT ratchet_state FROM signal_sessions').get<any>().ratchet_state;
      assert.equal((await importServerlessContact(alice,a,uri)).conversationId,imported.conversationId);
      assert.deepEqual(alice.database().prepare('SELECT ratchet_state FROM signal_sessions').get<any>().ratchet_state,before);
      const altered=new URL(uri),bytes=JSON.parse(inflateRawSync(Buffer.from(altered.searchParams.get('data')!,'base64url')).toString());bytes[3]='b'.repeat(56)+'.onion';altered.searchParams.set('data',deflateRawSync(Buffer.from(JSON.stringify(bytes))).toString('base64url'));
      assert.throws(()=>parseServerlessInvite(altered.toString()),/SIGNATURE/);
      await assert.rejects(()=>importServerlessContact(alice,a,createServerlessInvite({...invite,onion:'b'.repeat(56)+'.onion'},key.privateKey)),/PINNED_INVITE_CHANGED/);
      const badPrekey={...invite,signedPrekey:{...invite.signedPrekey,signature:crypto.randomBytes(64).toString('base64')}};
      await assert.rejects(()=>importServerlessContact(alice,a,createServerlessInvite(badPrekey,key.privateKey)),/PREKEY_SIGNATURE/);
      assert.throws(()=>parseServerlessInvite(uri+'&v=2'),/INVALID_INVITE/);
      assert.throws(()=>parseServerlessInvite(uri.replace('v=2','v=1')),/INVALID_INVITE/);
      const bomb='pigeon://invite?v=2&data='+deflateRawSync(Buffer.alloc(9000)).toString('base64url')+'&sig='+'a'.repeat(86);assert.throws(()=>parseServerlessInvite(bomb));
      assert.equal(alice.database().prepare('SELECT count(*) AS n FROM contacts WHERE verified=1').get<any>().n,1);
      const fixture=JSON.parse(await readFile(new URL('../../../apps/mobile-android/native/src/test/resources/serverless-invite.json',import.meta.url),'utf8'));
      assert.equal(inviteSigningBytes(parseServerlessInvite(fixture.uri)).toString('base64'),fixture.canonical);
    }finally{alice.lock();bob.lock();await rm(root,{recursive:true,force:true});}
  });
}
