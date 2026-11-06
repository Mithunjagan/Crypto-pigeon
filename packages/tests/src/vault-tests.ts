import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, rm, unlink, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from '@signalapp/sqlcipher';
import {deriveSubkey} from '../../../apps/local-daemon/dist/vault-keys.js';
import { deriveVaultKeys, wipeKeys, seal, unseal, encryptBackup, decryptBackup } from '../../../apps/local-daemon/dist/vault-dual-key.js';
import { splitSeven, reconstructSeven, HorcruxStore } from '../../../apps/local-daemon/dist/horcrux.js';
import { formatPublicUid, publicUidSchema, contactIdentifierSchema, vaultRestoreSchema } from '@crypto-pigeon/protocol';
import { Vault } from '../../../apps/local-daemon/dist/vault.js';
import { LocalSignalStore } from '../../../apps/local-daemon/dist/signal-store.js';
import { establishSession, encryptPayload, decryptPayload } from '../../../apps/local-daemon/dist/signal-adapter.js';

export function registerVaultTests(test:(name:string,fn:()=>void|Promise<void>)=>void) {
  test('Pinned libsignal 0.96.4 establishes a session and decrypts a real message',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-signal-')),a=new Vault(join(root,'a')),b=new Vault(join(root,'b'));
    try{
      await a.create('StrongPassword123!');await b.create('StrongPassword123!');
      const alice=new LocalSignalStore(a.database()),bob=new LocalSignalStore(b.database());
      await alice.ensureIdentity();const bundle=await bob.ensureIdentity();
      alice.setAccount(crypto.randomUUID());bob.setAccount(crypto.randomUUID());
      await establishSession(alice,bob.localAddress(),{...bundle,oneTimePrekey:bundle.oneTimePrekeys[0],pqOneTimePrekey:bundle.pqOneTimePrekeys[0]});
      const encrypted=await encryptPayload(alice,bob.localAddress(),'real encrypted test');
      assert.equal(await decryptPayload(bob,alice.localAddress(),encrypted.ciphertext,encrypted.type),'real encrypted test');
      assert.ok(await alice.getSession(bob.localAddress()));
    }finally{a.lock();b.lock();await rm(root,{recursive:true,force:true});}
  });
  test('Dual-key derivation is deterministic, binds both secrets, and separates domains',async()=>{
    const a=await deriveVaultKeys('secret-vault-one','StrongPassword123!');
    const b=await deriveVaultKeys('secret-vault-one','StrongPassword123!');
    const c=await deriveVaultKeys('secret-vault-two','StrongPassword123!');
    const d=await deriveVaultKeys('secret-vault-one','DifferentPassword123!');
    try{
      for(const name of Object.keys(a) as Array<keyof typeof a>){assert.deepEqual(a[name],b[name]);assert.notDeepEqual(a[name],c[name]);assert.notDeepEqual(a[name],d[name]);}
      assert.equal(new Set(Object.values(a).map(v=>v.toString('hex'))).size,5);
      const vmk=crypto.randomBytes(32), wrapped=seal(vmk,a.kek,'vmk-wrap-v1');
      assert.deepEqual(unseal(wrapped,a.kek,'vmk-wrap-v1'),vmk);
      assert.throws(()=>unseal(wrapped,a.backup,'vmk-wrap-v1'));
      assert.throws(()=>unseal(wrapped,a.kek,'wrong-domain'));
    }finally{[a,b,c,d].forEach(wipeKeys);}
  });
  test('Seven-way split requires every share and authenticates the recovered wrapping',()=>{
    const key=crypto.randomBytes(32),vmk=crypto.randomBytes(32),encrypted=seal(vmk,key,'vmk-wrap-v1');
    const shares=splitSeven(Buffer.from(encrypted.ciphertext,'base64'));
    assert.deepEqual(unseal({...encrypted,ciphertext:reconstructSeven(shares).toString('base64')},key,'vmk-wrap-v1'),vmk);
    for(let i=0;i<7;i++){
      assert.throws(()=>reconstructSeven(shares.map((s,j)=>i===j?null:s)));
      const corrupted=shares.map(s=>Buffer.from(s));corrupted[i][0]^=1;
      assert.throws(()=>unseal({...encrypted,ciphertext:reconstructSeven(corrupted).toString('base64')},key,'vmk-wrap-v1'));
    }
  });
  test('Fragment storage detects missing and corrupted files; logout wipes the RAM share',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-fragments-')),store=new HorcruxStore(root);
    const mask=crypto.randomBytes(32),key=crypto.randomBytes(32);
    try{
      const wrapped=crypto.randomBytes(48),s=await store.scatter(wrapped,mask,key);
      const unkeyed=new Database(join(root,'shards/metadata.db'));try{assert.throws(()=>unkeyed.prepare('SELECT shard FROM vault_horcrux_shard').get());}finally{unkeyed.close();}
      const metadataFile=join(root,'shards/metadata.db'),metadataKey=deriveSubkey(key,Buffer.alloc(32),'cp-shard2-db-v1');
      const encryptedDb=new Database(metadataFile);encryptedDb.pragma(`key = "x'${metadataKey.toString('hex')}'"`);
      const oldShare=encryptedDb.prepare('SELECT shard FROM vault_horcrux_shard WHERE id=2').get<{shard:Uint8Array}>()!.shard;encryptedDb.close();metadataKey.fill(0);
      await rm(metadataFile);const legacyDb=new Database(metadataFile);legacyDb.exec('CREATE TABLE vault_horcrux_shard(id INTEGER PRIMARY KEY,shard BLOB NOT NULL)');legacyDb.prepare('INSERT INTO vault_horcrux_shard VALUES(2,?)').run([oldShare]);legacyDb.close();
      assert.deepEqual(await store.collect(s.clientShard,s.fragment7Shard,mask,key,s.hashes),wrapped);
      assert.deepEqual(await store.collect(s.clientShard,s.fragment7Shard,mask,key,s.hashes),wrapped);
      const memory=store.sessionShare!;store.lock();assert.ok(memory.every(v=>v===0));assert.equal(store.sessionShare,null);
      assert.equal((await store.status(true,true,s.hashes)).isReconstructable,false);
      await assert.rejects(()=>store.collect(undefined,s.fragment7Shard,mask,key,s.hashes));
      await assert.rejects(()=>store.collect(s.clientShard,undefined,mask,key,s.hashes));
      const file=join(root,'assets/f4.dat'),original=await readFile(file);
      await unlink(file);await assert.rejects(()=>store.collect(s.clientShard,s.fragment7Shard,mask,key,s.hashes));
      original[0]^=1;await writeFile(file,original);
      await assert.rejects(()=>store.collect(s.clientShard,s.fragment7Shard,mask,key,s.hashes));
    }finally{store.lock();await rm(root,{recursive:true,force:true});}
  });
  test('Compressed encrypted backup roundtrip rejects tampering, wrong keys and AAD',()=>{
    const key=crypto.randomBytes(32),plain=Buffer.from(JSON.stringify({messages:['private message'],signalSession:'opaque'}));
    const envelope=encryptBackup(plain,key);assert.deepEqual(decryptBackup(envelope,key),plain);
    const bytes=Buffer.from(envelope.ciphertext,'base64');bytes[0]^=1;
    assert.throws(()=>decryptBackup({...envelope,ciphertext:bytes.toString('base64')},key));
    assert.throws(()=>decryptBackup(envelope,crypto.randomBytes(32)));
    assert.throws(()=>unseal(envelope,key,'vmk-wrap-v1'));
  });
  test('Public UIDs are deterministic and credentials/restore confirmation are validated',()=>{
    const uid=formatPublicUid('account-fingerprint');assert.match(uid,/^CP-[A-F0-9]{4}-[A-F0-9]{4}$/);
    assert.equal(formatPublicUid('account-fingerprint'),uid);assert.notEqual(formatPublicUid('different'),uid);
    assert.equal(publicUidSchema.parse(uid.toLowerCase()),uid);
    assert.equal(contactIdentifierSchema.parse(uid),uid);assert.equal(contactIdentifierSchema.parse('Alice'),'alice');
    assert.equal(vaultRestoreSchema.safeParse({vaultId:'secret-id',password:'StrongPassword123!'}).success,false);
  });
}
