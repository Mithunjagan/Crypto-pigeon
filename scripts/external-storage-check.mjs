import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {SecureVault} from '../apps/local-daemon/dist/secure-vault.js';
import {LocalSignalStore} from '../apps/local-daemon/dist/signal-store.js';
const root=resolve(import.meta.dirname,'../artifacts/external-storage-tests',String(Date.now()));await mkdir(root,{recursive:true});
const vault=new SecureVault(join(root,'source'),'http://127.0.0.1:9'),imported=new SecureVault(join(root,'imported'),'http://127.0.0.1:9');
const savedFetch=globalThis.fetch;let calls=0;globalThis.fetch=async()=>{calls++;throw new Error('Unexpected network access');};
const results=[];const pass=name=>{results.push({name,status:'pass'});console.log('PASS: '+name);};
const id='FixtureStorage-'+crypto.randomUUID(),password='FixtureStorage-Aa123456!',contact=crypto.randomUUID(),conversation=crypto.randomUUID(),message=crypto.randomUUID();
let capsule,storage;
try{
  const created=await vault.createSecure(id,password);capsule=Buffer.from(created.shard7FileBytes,'base64');await vault.confirmShard7Saved();
  assert.equal(vault.cloudBackupEnabled(),false);assert.equal(calls,0);pass('Creation needs no relay and returns a separate segment file; cloud defaults OFF');
  const store=new LocalSignalStore(vault.database());await store.ensureIdentity();const user=crypto.randomUUID();store.setAccount(user);
  const db=vault.database();db.prepare("INSERT INTO account_public VALUES(1,'CP-ABCD-1234')").run();
  db.prepare('INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES(?,?,?,?)').run([contact,'fixture_contact',crypto.randomBytes(33),Date.now()]);
  db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,Date.now()]);
  db.prepare("INSERT INTO messages(message_id,conversation_id,direction,plaintext,received_at,status) VALUES(?,?,'received','keep message',?,'received')").run([message,conversation,Date.now()]);
  db.prepare('INSERT INTO signal_sessions(contact_id,ratchet_state,updated_at) VALUES(?,?,?)').run([contact,Buffer.from('fixture-ratchet'),Date.now()]);
  const identity=Buffer.from(db.prepare('SELECT identity_key_pair FROM signal_account').get().identity_key_pair);
  storage=vault.exportStorage();assert.ok(!storage.includes(Buffer.from('keep message')));
  const refs=[vault.vmk,vault.external7,vault.fragments.sessionShare];vault.lock();assert.ok(refs.every(ref=>ref.every(n=>n===0)));
  await assert.rejects(()=>vault.unlockSecure(id,password,created.clientShard),/SHARD7_FILE_REQUIRED/);
  await assert.rejects(()=>vault.unlockSecure(id,password+'wrong',created.clientShard,undefined,capsule.toString('base64')));
  await vault.unlockSecure(id,password,created.clientShard,undefined,capsule.toString('base64'));assert.equal((await vault.status()).sharesPresent,7);pass('Cold unlock requires file plus credentials and lock zeroes keys and Shards 6/7');
  const loaded=await imported.importStorage(storage,id,password,capsule),restored=imported.database();
  assert.equal(restored.prepare('SELECT public_uid FROM account_public').get().public_uid,'CP-ABCD-1234');
  assert.equal(restored.prepare('SELECT user_id FROM signal_account').get().user_id,user);
  assert.deepEqual(Buffer.from(restored.prepare('SELECT identity_key_pair FROM signal_account').get().identity_key_pair),identity);
  assert.equal(restored.prepare('SELECT username FROM contacts').get().username,'fixture_contact');assert.equal(restored.prepare('SELECT plaintext FROM messages').get().plaintext,'keep message');
  assert.equal(Buffer.from(restored.prepare('SELECT ratchet_state FROM signal_sessions').get().ratchet_state).toString(),'fixture-ratchet');
  imported.lock();await imported.unlockSecure(id,password,loaded.clientShard,undefined,capsule.toString('base64'));pass('Storage import preserves account, UID, identity, contacts, messages and ratchet bytes; original segment still opens it');
  imported.lock();const damaged=Buffer.from(storage);damaged[damaged.length-3]^=1;await assert.rejects(()=>imported.importStorage(damaged,id,password,capsule));
  await imported.unlockSecure(id,password,loaded.clientShard,undefined,capsule.toString('base64'));assert.equal(imported.database().prepare('SELECT count(*) AS n FROM messages').get().n,1);
  assert.equal((await imported.syncBackup()).skipped,true);assert.equal(calls,0);pass('Tampered imports preserve current data; OFF performs zero network calls');
  globalThis.fetch=async()=>{calls++;return new Response('{}',{status:200});};await imported.setCloudBackup(true);await imported.syncBackup();assert.equal(calls,1);await imported.setCloudBackup(false);await imported.syncBackup();assert.equal(calls,1);pass('Explicit opt-in permits backup; disabling it blocks later uploads');
  const rotated=await imported.changeSecurePassword(id,password,password+'Rotated');assert.ok(rotated.shard7FileBytes);const nextCapsule=Buffer.from(rotated.shard7FileBytes,'base64');await imported.confirmShard7Saved();imported.lock();
  await assert.rejects(()=>imported.unlockSecure(id,password,rotated.clientShard,undefined,capsule.toString('base64')));await imported.unlockSecure(id,password+'Rotated',rotated.clientShard,undefined,nextCapsule.toString('base64'));assert.equal(imported.database().prepare('SELECT count(*) AS n FROM messages').get().n,1);assert.equal(calls,1);pass('Offline password rotation returns a new segment and preserves history');
  // Public dummy fixtures support the matching focused Android interoperability test.
  await writeFile(join(root,'node-storage.cpvault'),storage);await writeFile(join(root,'node-segment.cp7'),capsule);await writeFile(join(root,'fixture.json'),JSON.stringify({id,password,contact,message}));
}catch(error){results.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;}
finally{globalThis.fetch=savedFetch;vault.lock();imported.lock();capsule?.fill(0);storage?.fill(0);await writeFile(join(root,'results.json'),JSON.stringify({results},null,2));console.log('Evidence: '+root);}
