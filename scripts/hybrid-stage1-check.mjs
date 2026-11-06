// Focused Stage 1 checks against a temporary PostgreSQL database; no consumer accounts touched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {once} from 'node:events';
const require=createRequire(new URL('../apps/relay-server/package.json',import.meta.url));
const {Pool}=require('pg'), Fastify=require('fastify'), {WebSocket}=require('ws');
const protocol=await import('../packages/protocol/dist/index.js');
const local=process.env.STAGE1_DATABASE_URL ? null : JSON.parse(readFileSync(new URL('../artifacts/android-chat-postgres/connection.json',import.meta.url)));
const admin=new Pool(process.env.STAGE1_DATABASE_URL?{connectionString:process.env.STAGE1_DATABASE_URL}:{host:'127.0.0.1',port:local.port,user:local.user,password:local.password,database:'postgres'});
const name='cp_stage1_'+crypto.randomBytes(8).toString('hex');
const dbUrl=process.env.STAGE1_DATABASE_URL?new URL(process.env.STAGE1_DATABASE_URL):new URL('postgresql://127.0.0.1:'+local.port);
if(local){dbUrl.username=local.user;dbUrl.password=local.password;}dbUrl.pathname='/'+name;
Object.assign(process.env,{DATABASE_URL:dbUrl.href,ADMIN_USERNAME:'stage1-admin',ADMIN_TOKEN:crypto.randomBytes(32).toString('hex'),ACTIVATION_PEPPER:crypto.randomBytes(32).toString('hex'),RELAY_HOSTNAME:'stage1-relay',LOG_LEVEL:'error'});
let app,pool,wss,passed=0;const sockets=[];
const pass=name=>{passed++;console.log('PASS '+name);};
try {
  const legacy={version:1,envelopeId:crypto.randomBytes(16).toString('hex'),mailboxId:crypto.randomUUID(),ciphertext:'AQID'};
  assert.deepEqual(protocol.envelopeSchema.parse(legacy),legacy);
  assert.equal(protocol.envelopeSchema.parse({...legacy,clientCapabilities:{supportsWebRtcP2p:true,protocolVersion:1}}).clientCapabilities.supportsWebRtcP2p,true);
  const sample={type:'WEBRTC_SIGNAL',signalId:crypto.randomUUID(),fromUid:'CP-AAA1-0001',toUid:'CP-BBB2-0002',sessionId:crypto.randomUUID(),signalType:'OFFER',encryptedSignalPayload:'AQID'};
  assert.equal(protocol.webRtcSignalSchema.parse(sample).ttlMs,30000);
  for(const invalid of [{ttlMs:30001},{encryptedSignalPayload:'v=0 plaintext SDP'},{bearerToken:'private'},{fromUid:'other'}])assert.equal(protocol.webRtcSignalSchema.safeParse({...sample,...invalid}).success,false);
  pass('protocol accepts old envelopes and optional capabilities; signaling rejects plaintext, secrets and invalid TTL/UID');
  await admin.query(`CREATE DATABASE ${name}`);
  const db=await import('../apps/relay-server/dist/db.js');pool=db.pool;await db.initDb();await db.initDb();
  const {setupQueueRoutes}=await import('../apps/relay-server/dist/queue.js');
  const {setupVaultBackupRoutes}=await import('../apps/relay-server/dist/vault-backup.js');
  const {setupSignalRoutes,SignalBudget}=await import('../apps/relay-server/dist/signaling.js');
  const {setupWebSocket}=await import('../apps/relay-server/dist/ws-handler.js');
  const {setupAuthRoutes}=await import('../apps/relay-server/dist/auth.js');
  app=Fastify();app.setErrorHandler((e,_req,reply)=>reply.code(e.name==='ZodError'?400:500).send({error:'INVALID_REQUEST'}));
  setupQueueRoutes(app);setupVaultBackupRoutes(app);setupSignalRoutes(app);setupAuthRoutes(app);(await import('../apps/relay-server/dist/blind-dropbox.js')).setupBlindDropboxRoutes(app);wss=setupWebSocket(app.server);
  await app.listen({host:'127.0.0.1',port:0});const origin='http://127.0.0.1:'+app.server.address().port;
  const peers=[];
  for(const [index,uid] of ['CP-AAA1-0001','CP-BBB2-0002','CP-CCC3-0003'].entries()){
    const keys=protocol.generateDeviceKeyPair(),deviceId=crypto.randomUUID(),userId=crypto.randomUUID();
    await pool.query('INSERT INTO users(user_id,username,password_hash,public_uid) VALUES($1,$2,$3,$4)',[userId,'stage1_'+index,'fixture-not-a-password',uid]);
    await pool.query('INSERT INTO device_identity_keys(device_id,user_id,identity_public_key,auth_public_key,registration_id,signal_device_id) VALUES($1,$2,$3,$4,1,1)',[deviceId,userId,crypto.randomBytes(33),keys.publicKey]);
    const challenge=(await app.inject({method:'POST',url:'/api/auth/challenge',payload:{deviceId}})).json().challenge;
    const response=await app.inject({method:'POST',url:'/api/auth/respond',payload:{deviceId,challenge,relayHostname:'stage1-relay',signature:protocol.signChallenge(keys.privateKey,Buffer.from(deviceId+challenge+'stage1-relay')).toString('hex')}});
    assert.equal(response.statusCode,200);peers.push({uid,deviceId,userId,token:response.json().sessionToken});
  }
  const [alice,bob,mallory]=peers;
  await pool.query('INSERT INTO conversation_permissions(user_one,user_two) VALUES(LEAST($1::uuid,$2::uuid),GREATEST($1::uuid,$2::uuid))',[alice.userId,bob.userId]);
  const headers=peer=>({authorization:'Bearer '+peer.token});
  const request=(peer,method,url,payload,extra={})=>app.inject({method,url,payload,headers:{...headers(peer),...extra}});
  pass('idempotent database migrations and real signed challenge-to-bearer authentication');
  const envelope={...legacy,mailboxId:bob.deviceId};
  assert.equal((await request(alice,'POST','/api/messages/send',envelope)).statusCode,202);
  assert.equal((await request(alice,'POST','/api/messages/send',envelope)).statusCode,202);
  let pending=(await request(bob,'GET','/api/messages/pending')).json();assert.equal(pending.length,1);assert.equal(pending[0].ciphertext,envelope.ciphertext);
  await request(bob,'POST','/api/messages/ack',{envelopeIds:[envelope.envelopeId]});
  assert.equal((await request(bob,'GET','/api/messages/pending')).json().length,0);
  pass('legacy encrypted relay send/fetch/retry/recipient-ACK removes exactly one mailbox row');
  const typing={...envelope,envelopeId:crypto.randomBytes(16).toString('hex'),envelopeType:'TYPING',ttlMs:5000,createdAtMs:Date.now()-6000};
  assert.equal((await request(alice,'POST','/api/messages/send',typing)).json().delivered,false);
  assert.equal((await pool.query('SELECT count(*) FROM messages')).rows[0].count,'0');
  pass('expired typing never reaches the persistent offline queue');
  const sendSignal=(peer,changes={})=>request(peer,'POST','/api/signal',{...sample,signalId:crypto.randomUUID(),...changes});
  assert.equal((await sendSignal(alice)).json().reason,'PEER_OFFLINE');
  assert.equal((await sendSignal(mallory)).json().reason,'SENDER_MISMATCH');
  assert.equal((await sendSignal(alice,{toUid:mallory.uid})).json().reason,'CONTACT_NOT_APPROVED');
  assert.equal((await app.inject({method:'POST',url:'/api/signal',payload:sample})).statusCode,401);
  const connect=async peer=>{
    const socket=new WebSocket(origin.replace('http','ws')+'/ws',{headers:headers(peer)});sockets.push(socket);
    socket.frames=[];socket.on('message',raw=>socket.frames.push(JSON.parse(raw.toString())));await once(socket,'open');return socket;
  };
  const take=async(socket,predicate)=>{
    const until=Date.now()+3000;
    while(Date.now()<until){const i=socket.frames.findIndex(predicate);if(i>=0)return socket.frames.splice(i,1)[0];await new Promise(r=>setTimeout(r,5));}
    throw new Error('Timed out waiting for expected WebSocket frame');
  };
  const bobSocket=await connect(bob),aliceSocket=await connect(alice);
  const signal={...sample,signalId:crypto.randomUUID()};aliceSocket.send(JSON.stringify(signal));
  const routed=await take(bobSocket,p=>p.signalId===signal.signalId);assert.equal(routed.encryptedSignalPayload,signal.encryptedSignalPayload);assert.equal(routed.ttlMs,30000);
  assert.equal((await take(aliceSocket,p=>p.type==='WEBRTC_SIGNAL_RESULT')).delivered,true);
  assert.equal((await pool.query('SELECT count(*) FROM messages')).rows[0].count,'0');
  pass('authenticated WebSocket forwards opaque signaling only to an online approved peer; no persisted frames');
  const budget=new SignalBudget();for(let i=0;i<30;i++)assert.equal(budget.take('a','b',100000+i),true);
  assert.equal(budget.take('a','b',100031),false);assert.equal(budget.take('a','c',100032),true);assert.equal(budget.take('a','b',160031),true);
  let limited=false;for(let i=0;i<30;i++){const response=await sendSignal(alice);if(response.statusCode===429){limited=true;break;}}assert.equal(limited,true);
  pass('rolling 30/minute peer-pair signaling limit enforced by HTTP and shared WebSocket route');
  await pool.query('DELETE FROM sessions WHERE token=$1',[alice.token]);
  aliceSocket.send(JSON.stringify({...sample,signalId:crypto.randomUUID()}));
  assert.equal((await take(aliceSocket,p=>p.type==='WEBRTC_SIGNAL_RESULT')).reason,'UNAUTHORIZED');
  pass('an already-open WebSocket cannot signal after session revocation');
  const writer=protocol.generateDeviceKeyPair(),lookupToken=crypto.randomBytes(32).toString('hex');
  const unsigned={lookupToken,version:1,nonce:crypto.randomBytes(12).toString('base64'),ciphertext:crypto.randomBytes(64).toString('base64'),updatedAt:new Date().toISOString(),fragment7Shard:crypto.randomBytes(48).toString('base64'),writerPublicKey:writer.publicKey.toString('base64'),claim:false};
  const sign=body=>({...body,signature:protocol.signChallenge(writer.privateKey,protocol.backupSigningPayload(body)).toString('base64')});
  const digest=crypto.createHash('sha256').update(Buffer.from(unsigned.ciphertext,'base64')).digest('hex');
  const backupUrl='/api/vault-backup/'+lookupToken;
  const put=body=>app.inject({method:'PUT',url:backupUrl,payload:sign(body),headers:{'x-backup-sha256':crypto.createHash('sha256').update(Buffer.from(body.ciphertext,'base64')).digest('hex')}});
  assert.equal((await put(unsigned)).statusCode,200);
  const first=(await pool.query('SELECT updated_at FROM vault_backups WHERE lookup_token=$1',[lookupToken])).rows[0].updated_at.toISOString();
  assert.equal((await put(unsigned)).json().skipped,true);
  assert.equal((await put({...unsigned,version:2})).json().skipped,true);
  assert.equal((await pool.query('SELECT updated_at FROM vault_backups WHERE lookup_token=$1',[lookupToken])).rows[0].updated_at.toISOString(),first);
  const remote=(await app.inject({url:backupUrl})).json();assert.equal(remote.fragment7Shard,unsigned.fragment7Shard);assert.equal(remote.version,1);
  assert.equal(protocol.verifyChallenge(writer.publicKey,protocol.backupSigningPayload(remote),Buffer.from(remote.signature,'base64')),true);
  assert.equal((await app.inject({method:'PUT',url:backupUrl,payload:sign({...unsigned,version:2}),headers:{'x-backup-sha256':'0'.repeat(64)}})).statusCode,400);
  assert.equal((await app.inject({method:'PUT',url:backupUrl,payload:{...sign({...unsigned,version:2}),signature:crypto.randomBytes(64).toString('base64')}})).statusCode,403);
  for(let version=2;version<=4;version++)assert.equal((await put({...unsigned,version,ciphertext:crypto.randomBytes(64).toString('base64')})).statusCode,200);
  assert.equal((await pool.query('SELECT count(*) FROM vault_backups WHERE lookup_token=$1',[lookupToken])).rows[0].count,'1');
  pass('signed Shard 7 retrieval, SHA-256 verification, retry deduplication and bounded single-revision storage');
  const {ChangeFeed}=await import('../apps/local-daemon/dist/change-feed.js');const feed=new ChangeFeed(),change=feed.after(0);feed.publish('NEW_ENVELOPE');assert.deepEqual(await change,{revision:1,type:'NEW_ENVELOPE'});
  pass('local-daemon change-feed consumer remains compatible');
  const routeSecret=crypto.randomBytes(32),hour=Math.floor(Date.now()/3600000),tag=protocol.blindDropboxId(routeSecret,hour),blindId=crypto.randomUUID(),opaque=crypto.randomBytes(128).toString('base64');
  assert.notEqual(tag,protocol.blindDropboxId(routeSecret,hour+1));
  assert.equal((await request(bob,'POST','/api/blind/send',{envelopeId:blindId,blindDropboxId:tag,ciphertext:opaque})).statusCode,202);
  const stored=(await pool.query('SELECT * FROM blind_messages WHERE id=$1',[blindId])).rows[0];assert.equal(stored.sender_id,undefined);assert.equal(stored.recipient_id,undefined);assert.equal(stored.from_uid,undefined);assert.match(stored.sender_hash,/^[a-f0-9]{64}$/);assert.equal(stored.ciphertext.toString('base64'),opaque);
  assert.equal((await request(bob,'POST','/api/blind/fetch',{dropboxIds:[protocol.blindDropboxId(routeSecret,hour+1)]})).json().length,0);
  assert.equal((await request(bob,'POST','/api/blind/fetch',{dropboxIds:[tag]})).json().length,1);
  await request(bob,'POST','/api/blind/ack',{dropboxIds:[tag],envelopeIds:[blindId]});assert.equal((await pool.query('SELECT count(*) FROM blind_messages')).rows[0].count,'0');
  pass('blind routing rotates hourly, preserves ciphertext, omits plaintext sender/recipient columns and requires tag capability for fetch/ACK');
  const {mkdtemp,rm}=await import('node:fs/promises'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
  if(!process.argv.includes('--skip-desktop')){
  const root=await mkdtemp(join(tmpdir(),'cp-sovereign-'));const {SecureVault}=await import('../apps/local-daemon/dist/secure-vault.js');const vault=new SecureVault(root,origin);
  try{const primary=await vault.createSecure('fixture-primary-id','FixturePrimaryPassword123!');
    const master=vault.vmk,configured=await vault.configureDuress('fixture-duress-id-long');
    await vault.unlockSecure('fixture-duress-id-long','irrelevant',undefined,configured.decoyClientShard);
    assert.ok(vault.isDecoyActive());assert.ok(master.every(b=>b===0));assert.equal(vault.db,null);assert.equal(vault.database().prepare('SELECT count(*) AS n FROM messages').get().n,3);
    assert.equal((await vault.status(true)).sharesPresent,7);
    vault.lock();await vault.unlockSecure('fixture-primary-id','FixturePrimaryPassword123!',primary.clientShard);assert.equal(vault.isDecoyActive(),false);assert.equal(vault.database().prepare('SELECT count(*) AS n FROM messages').get().n,0);
    pass('desktop duress zeroes primary master key, opens three-note isolated SQLCipher decoy with real seven-fragment quorum and preserves primary');
  }finally{vault.lock();await rm(root,{recursive:true,force:true});}
  }
  if(process.argv.includes('--device')){
    const {spawnSync}=await import('node:child_process'),{fileURLToPath}=await import('node:url'),adb=fileURLToPath(new URL('../artifacts/android-device-tools/platform-tools/adb.exe',import.meta.url));
    const serial='10BEAN0MX8001J4';let result=spawnSync(adb,['-s',serial,'reverse','tcp:18443','tcp:'+app.server.address().port],{encoding:'utf8',windowsHide:true});assert.equal(result.status,0);
    result=await new Promise((resolve,reject)=>{import('node:child_process').then(({spawn})=>{const child=spawn(adb,['-s',serial,'shell','am','instrument','-w','-e','phase','sovereign','-e','relayUrl','http://127.0.0.1:18443','app.cryptopigeon.nativeclient.debug.test/app.cryptopigeon.nativeclient.NativeCryptoInstrumentation'],{windowsHide:true,timeout:180000});let stdout='',stderr='';child.stdout.on('data',data=>{stdout+=data;process.stdout.write(data);});child.stderr.on('data',data=>stderr+=data);child.on('error',reject);child.on('exit',status=>resolve({stdout,stderr,status}));}).catch(reject);});
    console.log(result.stdout);assert.match(result.stdout,/Native sovereign checks passed: 3/);spawnSync(adb,['-s',serial,'reverse','--remove','tcp:18443'],{windowsHide:true});pass('three targeted Android Signal/SQLCipher/duress checks on isolated vaults');
  }
  console.log(`Stage 1 targeted checks: ${passed} groups passed`);
} finally {
  for(const socket of sockets)socket.terminate();
  if(wss)await new Promise(resolve=>wss.close(resolve));
  await app?.close();await pool?.end();
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);await admin.end();
}
