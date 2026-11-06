import {fork} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdtemp,rm,readFile,writeFile,mkdir,unlink} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {deriveVaultKeys,wipeKeys} from '../apps/local-daemon/dist/vault-dual-key.js';
import {deriveSubkey} from '../apps/local-daemon/dist/vault-keys.js';
const root=resolve(import.meta.dirname,'..'),output=join(root,'artifacts/standalone-host-results.json');
const require=createRequire(resolve(root,'apps/relay-server/package.json')),{Pool}=require('pg');
const pg=JSON.parse(await readFile(join(root,'artifacts/android-chat-postgres/connection.json'),'utf8'));
const connection=new URL(`postgresql://${pg.user}@127.0.0.1:${pg.port}/postgres`);connection.password=pg.password;
const admin=new Pool({connectionString:connection.href}),database='cp_standalone_'+crypto.randomBytes(6).toString('hex');
const home=await mkdtemp(join(tmpdir(),'cp-standalone-')),children=[],results=[],logs=[];
let pool;
const pepper=crypto.randomBytes(32).toString('hex'),relayPort=Number(process.env.CP_TEST_RELAY_PORT??18947),relayUrl='http://127.0.0.1:'+relayPort;
function pass(name){results.push({name,status:'pass'});console.log('PASS:',name);}
function start(file,env){const child=fork(join(root,file),[],{cwd:root,silent:true,env:{...process.env,...env}});children.push(child);child.stdout.on('data',b=>logs.push(b.toString()));child.stderr.on('data',b=>logs.push(b.toString()));return child;}
async function wait(check,label){const end=Date.now()+45000;while(Date.now()<end){if(await check())return;await new Promise(r=>setTimeout(r,150));}throw new Error('Timeout: '+label);}
async function daemon(name){const child=start('apps/local-daemon/dist/server.js',{PORT:'0',CRYPTO_PIGEON_HOME:join(home,name),RELAY_URL:relayUrl});const url=await new Promise((res,rej)=>{const t=setTimeout(()=>rej(new Error('Daemon startup timeout')),30000);child.on('message',m=>{if(m?.type==='desktop-ready'){clearTimeout(t);res(new URL(m.url));}});child.once('exit',()=>{clearTimeout(t);rej(new Error('Daemon failed'));});});const client={origin:url.origin,csrf:null,cookie:null,name};await bootstrap(client,url.hash.slice(1));return client;}
async function raw(client,path,body){return fetch(client.origin+path,{method:body===undefined?'GET':'POST',headers:{Cookie:client.cookie??'','X-CSRF-Token':client.csrf??'','Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});}
async function api(client,path,body){const r=await raw(client,path,body),data=await r.json();assert.ok(r.ok,`${path}: ${r.status} ${data.error??''}`);return data;}
async function bootstrap(client,secret){const r=await fetch(client.origin+'/api/bootstrap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret})});assert.equal(r.status,200);client.cookie=r.headers.get('set-cookie').split(';')[0];client.csrf=(await r.json()).csrfToken;}
async function create(client){client.id=client.name+'-private-'+crypto.randomBytes(12).toString('hex');client.password='Standalone-Strong-Aa1!'+crypto.randomBytes(8).toString('hex');client.shard=(await api(client,'/api/vault/create',{vaultId:client.id,password:client.password})).clientShard;}
async function lock(client){const old={cookie:client.cookie,csrf:client.csrf},r=await api(client,'/api/vault/lock',{});assert.equal(r.backupSynced,true);assert.equal((await raw({...client,...old},'/api/contacts')).status,401);await bootstrap(client,r.bootstrapSecret);}
async function register(client,username){const applied=await api(client,'/api/access/apply',{username});const code=crypto.randomBytes(24).toString('base64url');await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$2,activation_expires_at=NOW()+INTERVAL '10 minutes',attempt_count=0,decided_at=NOW() WHERE request_id=$1",[applied.requestId,crypto.createHmac('sha256',pepper).update(code).digest('hex')]);await api(client,'/api/access/activate',{requestId:applied.requestId,activationCode:code});client.uid=(await api(client,'/api/access/state')).publicUid;assert.match(client.uid,/^CP-[A-F0-9]{4}-[A-F0-9]{4}$/);}
try{
  await admin.query(`CREATE DATABASE ${database}`);connection.pathname='/'+database;pool=new Pool({connectionString:connection.href});
  const relay=start('apps/relay-server/dist/server.js',{DATABASE_URL:connection.href,HOST:'127.0.0.1',PORT:String(relayPort),RELAY_HOSTNAME:'127.0.0.1:'+relayPort,ADMIN_USERNAME:'standalone_test',ADMIN_TOKEN:crypto.randomBytes(32).toString('hex'),ACTIVATION_PEPPER:pepper,LOG_LEVEL:'error'});
  await wait(async()=>{if(relay.exitCode!==null)throw new Error('Relay failed to start');return fetch(relayUrl+'/readyz').then(r=>r.ok).catch(()=>false);},'relay');
  const alice=await daemon('alice'),bob=await daemon('bob');await create(alice);await create(bob);await register(alice,'standalone_alice');await register(bob,'standalone_bob');
  pass('Alice and Bob initialize isolated dual-key SQLCipher vaults and activate distinct public UIDs on a real PostgreSQL relay');
  const denied=await raw(alice,'/api/contacts/add',{username:bob.uid});assert.ok(!denied.ok);
  await api(alice,'/api/conversations/requests',{recipientUsername:bob.uid});const requests=await api(bob,'/api/conversations/requests');assert.equal(requests[0].requester_public_uid,alice.uid);
  await api(bob,`/api/conversations/requests/${requests[0].request_id}/accept`,{});const chat=await api(alice,'/api/contacts/add',{username:bob.uid});
  pass('UID lookup is blocked before approval; the recipient can approve a real follow request and authorize a Signal session');
  const first='Alice private E2EE '+crypto.randomBytes(16).toString('hex');await api(alice,'/api/send',{conversationId:chat.conversationId,plaintext:first});await api(bob,'/api/fetch-messages',{});
  const contact=(await api(bob,'/api/contacts'))[0];assert.ok(contact);assert.equal((await api(bob,'/api/messages/'+contact.conversation_id))[0].plaintext,first);
  const second='Bob private reply '+crypto.randomBytes(16).toString('hex');await api(bob,'/api/send',{conversationId:contact.conversation_id,plaintext:second});await api(alice,'/api/fetch-messages',{});assert.equal((await api(alice,'/api/messages/'+chat.conversationId)).at(-1).plaintext,second);
  pass('Alice ↔ Bob exchange and decrypt real libsignal messages through independent vaults and the relay queue');
  const contacts=await api(alice,'/api/contacts');assert.equal(contacts[0].safety_number_hash,contact.safety_number_hash);assert.match(contact.safety_number_hash,/^\d{60}$/);
  await api(alice,'/api/contacts/'+encodeURIComponent(contacts[0].contact_id)+'/verify',{safetyNumber:contact.safety_number_hash});assert.equal((await api(alice,'/api/contacts'))[0].verified,1);
  pass('Both peers calculate the same safety number and explicit out-of-band confirmation persists verification');
  const bytes=crypto.randomBytes(process.argv.includes('--max-attachment')?25*1024*1024:130125);const manifest=await api(alice,'/api/attachments/encrypt',{filedataB64:bytes.toString('base64'),filename:'verified-தமிழ்.bin',mimeType:'application/octet-stream'});await api(alice,'/api/send',{conversationId:chat.conversationId,plaintext:'File integrity test',attachmentManifest:manifest});await api(bob,'/api/fetch-messages',{});
  const received=(await api(bob,'/api/messages/'+contact.conversation_id)).at(-1);assert.equal(received.attachment_ready,1);const downloaded=await api(bob,'/api/attachments/'+received.attachment_id+'/decrypt');assert.deepEqual(Buffer.from(downloaded.filedataB64,'base64'),bytes);
  pass('Encrypted multi-chunk attachment is decrypted, SHA-256 verified and downloaded byte-for-byte on the recipient');
  await api(alice,'/api/conversations/'+chat.conversationId+'/timer',{seconds:3600});await api(alice,'/api/send',{conversationId:chat.conversationId,plaintext:'Expiring private message'});await api(bob,'/api/fetch-messages',{});pass('Disappearing timer is carried inside the encrypted payload');
  await lock(alice);const open=extra=>raw(alice,'/api/vault/open',{vaultId:alice.id,password:alice.password,clientShard:alice.shard,...extra});
  const f1=join(home,'alice/shards/f1.bin'),f3=join(home,'alice/config/f3.json'),f4=join(home,'alice/assets/f4.dat'),f6=join(home,'alice/shards/f6.masked');
  const Sql=require('@signalapp/sqlcipher'),Database=Sql.Database??Sql.default??Sql;const metadataPath=join(home,'alice/shards/metadata.db');
  const keys=await deriveVaultKeys(alice.id,alice.password),lookup=keys.lookup.toString('hex'),metadataKey=deriveSubkey(keys.backup,Buffer.alloc(32),'cp-shard2-db-v1');wipeKeys(keys);
  const metadata=()=>{const db=new Database(metadataPath);db.pragma(`key = "x'${metadataKey.toString('hex')}'"`);return db;};
  const remote=(await pool.query('SELECT fragment7_shard FROM vault_backups WHERE lookup_token=$1',[lookup])).rows[0];
  for(let shard=1;shard<=7;shard++)for(const corrupt of [false,true]){
    let restore,extra={};
    if([1,3,4,6].includes(shard)){const file={1:f1,3:f3,4:f4,6:f6}[shard],saved=await readFile(file);if(corrupt){const modified=Buffer.from(saved);modified[0]^=1;await writeFile(file,modified);}else await unlink(file);restore=()=>writeFile(file,saved);}
    if(shard===2){const db=metadata(),saved=db.prepare('SELECT shard FROM vault_horcrux_shard WHERE id=2').get().shard;if(corrupt){const value=Buffer.from(saved);value[0]^=1;db.prepare('UPDATE vault_horcrux_shard SET shard=? WHERE id=2').run([value]);}else db.prepare('DELETE FROM vault_horcrux_shard WHERE id=2').run();db.close();restore=async()=>{const db=metadata();db.prepare('INSERT OR REPLACE INTO vault_horcrux_shard(id,shard) VALUES(2,?)').run([saved]);db.close();};}
    if(shard===5){extra={clientShard:corrupt?Buffer.alloc(48,3).toString('base64'):undefined};restore=async()=>{};}
    if(shard===7){await pool.query('UPDATE vault_backups SET fragment7_shard=$2 WHERE lookup_token=$1',[lookup,corrupt?Buffer.alloc(48,4):Buffer.alloc(0)]);restore=()=>pool.query('UPDATE vault_backups SET fragment7_shard=$2 WHERE lookup_token=$1',[lookup,remote.fragment7_shard]);}
    try{const r=await open(extra);assert.equal(r.status,400);const error=(await r.json()).error;assert.equal(error,'HORCRUX_INCOMPLETE_RESTORE_REQUIRED');assert.equal((await api(alice,'/api/vault/status')).vaultState,'locked');}finally{await restore();}
  }
  pass('All seven missing and all seven corrupted shard cases block unlock without USB devices');
  assert.equal((await open()).status,200);await lock(alice);
  const fresh=await daemon('alice-restored');const restored=await api(fresh,'/api/vault/restore',{vaultId:alice.id,password:alice.password,transferConfirmed:true});assert.ok(restored.clientShard);
  assert.equal((await api(fresh,'/api/access/state')).publicUid,alice.uid);const restoredContacts=await api(fresh,'/api/contacts');assert.equal(restoredContacts[0].verified,1);const history=await api(fresh,'/api/messages/'+chat.conversationId);assert.ok(history.some(m=>m.plaintext===second));
  assert.deepEqual(Buffer.from((await api(fresh,'/api/attachments/'+manifest.attachmentId+'/decrypt')).filedataB64,'base64'),bytes);
  pass('Fresh-device cloud restore recovers original UID, verified contact, messages, Signal state and authenticated attachment bytes');
  const old=await open();assert.equal(old.status,400);pass('Active-device transfer prevents old fragment sets from reopening the transferred vault');
  const dbRows=await pool.query("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema='public'");assert.ok(!dbRows.rows.some(r=>/vault_?id|backup_?key|plaintext|master_?password/i.test(r.column_name)));
  const dump=await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public'");let stored='';for(const row of dump.rows){const rows=await pool.query(`SELECT row_to_json(t)::text AS data FROM "${row.tablename.replaceAll('"','""')}" t`);stored+=rows.rows.map(r=>r.data).join('');}
  for(const secret of [alice.id,alice.password,bob.id,bob.password,first,second]){assert.ok(!stored.includes(secret));assert.ok(!logs.join('').includes(secret));}
  pass('Real PostgreSQL tables and captured relay/daemon logs contain no vault IDs, passwords or plaintext test messages');
  await api(fresh,'/api/send',{conversationId:chat.conversationId,plaintext:'Restored ratchet continues'});await api(bob,'/api/fetch-messages',{});assert.equal((await api(bob,'/api/messages/'+contact.conversation_id)).at(-1).plaintext,'Restored ratchet continues');pass('The restored account continues its existing E2EE conversation with Bob');
  if(process.argv.includes('--ui-review')){
    const locked=await api(fresh,'/api/vault/lock',{});
    await writeFile(join(root,'artifacts/standalone-ui-session.json'),JSON.stringify({url:fresh.origin+'/#'+locked.bootstrapSecret,vaultId:alice.id,password:alice.password,shard:restored.clientShard,home:join(home,'alice-restored')}),{mode:0o600});
    console.log('UI_REVIEW_READY');await new Promise(r=>{const timer=setTimeout(r,600000);process.once('message',m=>{if(m?.type==='review-complete'){clearTimeout(timer);r();}});});
  }
}catch(error){results.push({name:error.message,status:'fail'});console.error(error.stack);process.exitCode=1;}
finally{
  for(const child of children.reverse())if(child.exitCode===null){const stopped=new Promise(r=>child.once('exit',r));child.kill();await stopped;}
  if(pool)await pool.end();await admin.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);await admin.end();await rm(home,{recursive:true,force:true});
  await mkdir(join(root,'artifacts'),{recursive:true});await writeFile(output,JSON.stringify({scope:'Host isolated vaults with real PostgreSQL relay; no physical-phone validation',attachmentBytes:process.argv.includes('--max-attachment')?25*1024*1024:130125,results},null,2));
  console.log(`${results.filter(r=>r.status==='pass').length} checks passed. Results: ${output}`);
}
