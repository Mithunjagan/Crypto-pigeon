import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Vault} from '../apps/local-daemon/dist/vault.js';
import {flushControls} from '../apps/local-daemon/dist/consumer.js';
const root=await mkdtemp(join(tmpdir(),'cp-stage1-daemon-')),vault=new Vault(root);
try {
  await vault.create('Stage1FixturePassword123!');
  const db=vault.database(),contact=crypto.randomUUID();
  assert.ok(db.prepare('PRAGMA table_info(control_outbox)').all().some(c=>c.name==='expires_at'));
  db.prepare('INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES(?,?,?,?)').run([contact,'stage1-peer',crypto.randomBytes(33),Date.now()]);
  const samples=[{id:crypto.randomBytes(16).toString('hex'),expires:Date.now()-1000},{id:crypto.randomBytes(16).toString('hex'),expires:Date.now()+5000},{id:crypto.randomBytes(16).toString('hex'),expires:null}];
  for(const s of samples){s.ciphertext=crypto.randomBytes(96).toString('base64');db.prepare('INSERT INTO control_outbox(envelope_id,contact_id,mailbox_id,ciphertext,created_at,expires_at) VALUES(?,?,?,?,?,?)').run([s.id,contact,'opaque-mailbox',s.ciphertext,Date.now(),s.expires]);}
  const attempts=[];let fail=true;
  const relay={async request(_v,_s,path,options){assert.equal(path,'/api/messages/send');attempts.push(JSON.parse(options.body));return {ok:!fail};}};
  await flushControls(vault,{},relay);assert.equal(attempts.length,1);assert.equal(db.prepare('SELECT count(*) AS n FROM control_outbox').get().n,2);
  fail=false;await flushControls(vault,{},relay);assert.equal(attempts.length,3);assert.equal(attempts[0].envelopeId,attempts[1].envelopeId);assert.equal(attempts[0].ciphertext,attempts[1].ciphertext);
  assert.equal(attempts[1].envelopeType,'TYPING');assert.ok(attempts[1].ttlMs<=10000);assert.equal(attempts[2].envelopeType,undefined);
  assert.equal(attempts[2].ciphertext,samples[2].ciphertext);assert.equal(db.prepare('SELECT count(*) AS n FROM control_outbox').get().n,0);
  console.log('PASS daemon SQLCipher migration, expired typing removal, ephemeral TTL forwarding and exact retry ciphertext/ID preservation');
}finally{vault.lock();await rm(root,{recursive:true,force:true});}
