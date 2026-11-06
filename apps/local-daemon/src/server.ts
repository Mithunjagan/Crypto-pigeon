import crypto from 'node:crypto';
import {profile,queueControl,flushControls,typingUntil} from './consumer.js';
import { fileURLToPath } from 'node:url';
import { join, dirname, basename, resolve } from 'node:path';
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import Fastify from 'fastify';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { env } from './config.js';
import { logger } from './logger.js';
import { SecureVault } from './secure-vault.js';
import {fileEnvelope,STORAGE_HEADER} from './sovereign-files.js';
import { vaultCredentialsSchema, vaultOpenSchema, vaultRestoreSchema, formatPublicUid, normalizeRelayUrl } from '@crypto-pigeon/protocol';
import { LocalSignalStore } from './signal-store.js';
import { RelayClient, RelayClientError } from './relay-client.js';
import { TorOnionTransport, initializeTorSchema,cleanupTorSpool } from './tor-transport.js';
import { TorRouting } from './tor-routing.js';
import { TorRecoveryWakeup } from './tor-recovery.js';
import { ownServerlessInvite,importServerlessContact } from './serverless-contacts.js';
import { setSecurityHeaders } from './security.js';
import {
  generateBootstrapSecret,
  invalidateSession,
  nextBootstrapSecret,
  verifyLocalSession,
  setupAuthRoutes
} from './auth.js';
import {
  addContactAndSession,
  sendMessage,
  flushOutbox,
  syncMessages
} from './messages.js';
import {
  encryptAndUploadAttachment,
  readDecryptedAttachment
} from './attachments.js';
import { ChangeFeed } from './change-feed.js';
import { DebouncedBackup } from './debounced-backup.js';
import { startDisappearingMessageJob } from './disappearing.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Relay settings survive atomic vault-directory replacement during restore.
const relayConfigPath=join(dirname(resolve(env.CRYPTO_PIGEON_HOME)),basename(resolve(env.CRYPTO_PIGEON_HOME))+'.relay.json');
let relayUrl=existsSync(relayConfigPath)?normalizeRelayUrl(JSON.parse(readFileSync(relayConfigPath,'utf8')).relayUrl):env.RELAY_URL;
const vault = new SecureVault(env.CRYPTO_PIGEON_HOME, relayUrl);
let quickLocked=false,pinFailures=0,pinRetryAt=0;
let pendingStorage:Buffer|null=null;
let store: LocalSignalStore | null = null;
let relayClient = new RelayClient(relayUrl);
const changes=new ChangeFeed();
const backups=new DebouncedBackup(()=>vault.syncBackup(),()=>!vault.isLocked()&&vault.cloudBackupEnabled(),()=>{changes.publish('BACKUP_FAILED');logger.warn('Background backup failed; will retry while unlocked');});
const trustedRoutes=new Set([env.RELAY_URL,'http://192.168.1.5:8443','http://127.0.0.1:8443','https://musical-medal-cleared-tube.trycloudflare.com']);

const app = Fastify({
  logger: false,
  bodyLimit: 25 * 1024 * 1024 // 25 MB limit for attachments
});

// Serialize lifecycle and database access so lock/restore cannot race a send or backup.
let requestTail=Promise.resolve();
async function serialized<T>(fn:()=>Promise<T>):Promise<T>{const previous=requestTail;let release!:()=>void;requestTail=new Promise<void>(r=>release=r);await previous;try{return await fn();}finally{release();}}
const torRouting=new TorRouting(()=>vault.database(),serialized);relayClient.torRouting=torRouting;
let torStarting=false,torRetryAt=0,torGeneration=0;
let torDatabase:unknown;
function stopTor(){torGeneration++;torRouting.transport?.close();torRouting.transport=undefined;torDatabase=undefined;torRetryAt=0;}
torRouting.prepareRelay=async body=>{
  if(vault.isLocked()||quickLocked||torRouting.mode!=='HYBRID_TOR_RELAY')return;
  const generation=torGeneration,db=vault.database(),active=getStore(),prepared:Array<()=>Promise<Response>>=[];
  const prepare=async(path:string,payload:any)=>prepared.push(await relayClient.prepareRequest(vault,active,path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}));
  const blobs=db.prepare(`SELECT b.* FROM tor_blobs b JOIN tor_attachment_links l ON l.blob_id=b.blob_id JOIN attachments a ON a.attachment_id=l.attachment_id JOIN message_outbox o ON o.message_id=a.message_id WHERE o.envelope_id=?`).all<any>([body.envelopeId]);
  for(const blob of blobs){const chunks=db.prepare('SELECT chunk_index,nonce,ciphertext FROM tor_chunks WHERE blob_id=? ORDER BY chunk_index').all<any>([blob.blob_id]);if(chunks.length!==blob.chunk_count)throw new Error('CHUNKS_INCOMPLETE');await prepare('/api/attachments/upload',{blobId:blob.blob_id,chunkCount:blob.chunk_count,totalSize:blob.total_size});for(const part of chunks)await prepare(`/api/attachments/${blob.blob_id}/chunks`,{chunkIndex:part.chunk_index,nonce:part.nonce,ciphertext:part.ciphertext});}
  await prepare('/api/messages/send',body);
  return async()=>{let response=new Response(null,{status:503});for(const request of prepared){if(generation!==torGeneration)throw new Error('VAULT_SESSION_CHANGED');response=await request();if(!response.ok)break;}return response;};
};
torRouting.prepareRelayDownload=async path=>{if(vault.isLocked()||quickLocked||torRouting.mode!=='HYBRID_TOR_RELAY')return;return relayClient.prepareRequest(vault,getStore(),path,{method:'GET'});};
async function ensureTor(){
  if(vault.isLocked()||quickLocked||vault.isDecoyActive())return;
  const db=vault.database();if(torDatabase!==db){initializeTorSchema(db);const saved=db.prepare('SELECT mode FROM tor_settings WHERE singleton=1').get<{mode:string}>();torRouting.mode=saved&&['DIRECT_TOR_P2P','HYBRID_TOR_RELAY','RELAY_ONLY'].includes(saved.mode)?saved.mode as typeof torRouting.mode:'DIRECT_TOR_P2P';torDatabase=db;}
  if(torRouting.transport?.isStopped())torRouting.transport=undefined;
  if(vault.isLocked()||quickLocked||vault.isDecoyActive()||torRouting.mode==='RELAY_ONLY'||torRouting.transport||torStarting||Date.now()<torRetryAt)return;
  torStarting=true;const generation=torGeneration;
  try{
    const activeStore=getStore(),identity=await activeStore.ensureIdentity();initializeTorSchema(vault.database());
    const transport=new TorOnionTransport(()=>vault.database(),()=>({deviceId:identity.deviceId,...activeStore.getDeviceAuthKeyPair()}),serialized);
    transport.onReady=()=>{if(generation===torGeneration&&torRouting.transport===transport)torRecovery.wake();};
    torRouting.transport=transport;
    void transport.start(process.env.TOR_BINARY??join(process.cwd(),'artifacts','tor','tor.exe'),join(env.CRYPTO_PIGEON_HOME,'tor')).then(()=>{if(generation!==torGeneration)transport.close();else changes.publish('TRANSPORT_CHANGED');}).catch(()=>{transport.close();if(torRouting.transport===transport)torRouting.transport=undefined;torRetryAt=Date.now()+30000;}).finally(()=>{torStarting=false;});
  }catch{torStarting=false;torRetryAt=Date.now()+30000;}
}
async function retryTorQueues(){await serialized(async()=>{
  if(vault.isLocked()||quickLocked||vault.isDecoyActive())return;await ensureTor();
  cleanupTorSpool(vault.database());
  if(!getStore().isRegistered())return;
  try{const received=await syncMessages(vault,getStore(),relayClient);await flushOutbox(vault,getStore(),relayClient);await flushControls(vault,getStore(),relayClient);if(received){changes.publish('MESSAGES_CHANGED');backups.schedule();}}catch{/* Durable queues survive network failure. */}
});}
const torRecovery=new TorRecoveryWakeup(retryTorQueues);
const torTimer=setInterval(()=>{torRecovery.wake();},5000);torTimer.unref();
app.addHook('onClose',async()=>{torRecovery.close();clearInterval(torTimer);stopTor();});
const releases=new WeakMap<object,()=>void>();
app.addHook('preHandler',async request=>{
  if(!request.url.startsWith('/api/')||request.url.split('?')[0]==='/api/events')return;
  const previous=requestTail;
  requestTail=new Promise<void>(resolve=>releases.set(request,resolve));
  await previous;
});
app.addHook('onResponse',async request=>{releases.get(request)?.();releases.delete(request);});

// Setup Host/Origin/CSRF validation hook
app.addHook('preHandler', (request: FastifyRequest, reply: FastifyReply, done) => {
  setSecurityHeaders(reply);
  const err = verifyLocalSession(request, reply, vault);
  if (err) return; // Hook already replied
  if(quickLocked&&request.url.startsWith('/api/')&&!['/api/bootstrap','/api/session','/api/vault/status','/api/session/unlock','/api/vault/lock'].includes(request.url.split('?')[0])){reply.code(423).send({error:'SESSION_PIN_REQUIRED'});return;}
  done();
});

// Setup auth endpoints (bootstrap, CSRF refresh)
await vault.initialize();
setupAuthRoutes(app, vault,()=>quickLocked);

// Helper to get active store
function getStore(): LocalSignalStore {
  if (vault.isLocked()) throw new Error('vault_locked');
  if (!store) {
    store = new LocalSignalStore(vault.database());
  }
  return store;
}

function errorCode(error: unknown): string {
  return error instanceof RelayClientError ? error.code : 'LOCAL_VAULT_PERSISTENCE_FAILED';
}

function logRouteError(error: unknown, request: FastifyRequest, message: string) {
  const cause = error instanceof Error ? error : new Error('unknown_error');
  logger.error({
    errorName: cause.name,
    safeMessage: cause.message,
    stack: process.env.NODE_ENV === 'development' ? cause.stack : undefined,
    method: request.method,
    route: request.routeOptions.url
  }, message);
}

function requireRegistered(reply: FastifyReply): LocalSignalStore | null {
  const activeStore = getStore();
  if (!activeStore.isRegistered()) {
    reply.code(409).send({ error: 'DEVICE_NOT_REGISTERED' });
    return null;
  }
  return activeStore;
}

// Local API Endpoints
app.get('/api/relay/config',async()=>({relayUrl,defaultRelayUrl:env.RELAY_URL}));
app.post('/api/relay/config',async(request,reply)=>{

  try {
    const next=normalizeRelayUrl(z.object({relayUrl:z.string()}).parse(request.body).relayUrl);
    const alias=trustedRoutes.has(relayUrl)&&trustedRoutes.has(next);
    if(!vault.isLocked()&&!alias)return reply.code(409).send({error:'LOCK_BEFORE_RELAY_CHANGE'});
    const pending=backups.pending();backups.cancel();await backups.drain();relayClient.clearSession();
    mkdirSync(dirname(relayConfigPath),{recursive:true});writeFileSync(relayConfigPath,JSON.stringify({relayUrl:next}),{mode:0o600});
    vault.setRelayUrl(next,alias);relayClient=new RelayClient(next);relayClient.torRouting=torRouting;relayUrl=next;if(pending&&!vault.isLocked())backups.schedule();changes.publish('ROUTE_CHANGED');return {relayUrl,defaultRelayUrl:env.RELAY_URL};
  }catch{return reply.code(400).send({error:'INVALID_RELAY_URL'});}
});

// GET /api/vault/status
app.get('/api/vault/status', async () => {
  return {
    requiresVaultId: vault.isSecure(),
    vaultState: vault.exists() ? (vault.isLocked() ? 'locked' : quickLocked?'quick_locked':'unlocked') : 'unconfigured'
  };
});

// POST /api/vault/create
app.post('/api/vault/create', async (request: FastifyRequest, reply: FastifyReply) => {
  const { vaultId, password } = vaultCredentialsSchema.parse(request.body);
  try {
    const result = await vault.createSecure(vaultId,password);
    store = new LocalSignalStore(vault.database());
    const username=(request.body as any).username;
    return { ok: true, ...result,onboardingPending:!!username };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'vault_creation_failed' });
  }
});

function torStatus(){return {...(torRouting.transport?.status()??{activeTransport:torRouting.mode==='RELAY_ONLY'?'Encrypted Relay':'Tor connecting',serverless:false,bootstrapPercent:0}),mode:torRouting.mode,transferError:torRouting.lastTransferError||undefined};}
app.get('/api/transport/status',async()=>torStatus());
app.get('/api/transport/privacy',async()=>({...torStatus(),relayOnly:torRouting.mode==='RELAY_ONLY',blindRouting:false,duressArmed:vault.duressArmed(),liveRelayAnonymity:false}));
app.post('/api/transport/config',async request=>{const mode=z.object({mode:z.enum(['DIRECT_TOR_P2P','HYBRID_TOR_RELAY','RELAY_ONLY'])}).parse(request.body).mode;initializeTorSchema(vault.database());vault.database().prepare('INSERT OR REPLACE INTO tor_settings VALUES(1,?)').run([mode]);stopTor();relayClient.clearSession();await ensureTor();return torStatus();});
app.post('/api/duress/config',async request=>vault.configureDuress(z.object({duressId:z.string().min(16).max(256)}).parse(request.body).duressId));

// POST /api/vault/open
app.post('/api/vault/open', async (request: FastifyRequest, reply: FastifyReply) => {
  const { vaultId,password,clientShard,decoyClientShard } = vaultOpenSchema.parse(request.body);
  try {
    const shard7Payload=z.string().max(4096).optional().parse((request.body as any).shard7Payload);
    stopTor();relayClient.clearSession();let imported:{}={};
    if(pendingStorage){if(!shard7Payload)throw new Error('SHARD7_FILE_REQUIRED');const capsule=Buffer.from(shard7Payload,'base64');try{imported=await vault.importStorage(pendingStorage,vaultId,password,capsule);pendingStorage.fill(0);pendingStorage=null;}finally{capsule.fill(0);}}
    else await vault.unlockSecure(vaultId,password,clientShard,decoyClientShard,shard7Payload);
    store = new LocalSignalStore(vault.database());
    return { ok: true,...imported };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'invalid_password' });
  }
});

// POST /api/vault/lock
app.post('/api/vault/lock', async () => {
  pendingStorage?.fill(0);pendingStorage=null;
  stopTor();quickLocked=false;typingUntil.clear();backups.cancel();relayClient.clearSession();changes.publish('LOCKED');
  let backupSynced=true;
  const pendingBackup=vault.syncBackup();
  // Snapshot encryption runs before syncBackup first yields. Wipe local keys
  // before waiting for the network, even if the relay is slow or unavailable.
  vault.lock();store=null;
  try {await pendingBackup;}catch {backupSynced=false;}
  return {ok:true,backupSynced,bootstrapSecret:nextBootstrapSecret()};
});
app.post('/api/vault/sync-backup',async()=>{backups.cancel();await backups.drain();return vault.syncBackup();});
app.get('/api/vault/storage',async()=>vault.storageStatus());
app.post('/api/vault/storage',async request=>{backups.cancel();await backups.drain();const state=await vault.setCloudBackup(z.object({cloudBackupEnabled:z.boolean()}).parse(request.body).cloudBackupEnabled);if(state.cloudBackupEnabled)backups.schedule();return state;});
app.post('/api/vault/storage/import',async request=>{
  if(!vault.isLocked())throw new Error('LOCK_BEFORE_STORAGE_SWITCH');
  const payload=z.object({storagePayload:z.string().max(24*1024*1024)}).parse(request.body).storagePayload;
  const bytes=Buffer.from(payload,'base64');try{fileEnvelope(bytes,STORAGE_HEADER,18*1024*1024);}catch(error){bytes.fill(0);throw error;}
  pendingStorage?.fill(0);pendingStorage=bytes;return {ok:true,storageSelected:true};
});
app.get('/api/vault/files/shard7',async(_request,reply)=>reply.type('application/octet-stream').send(vault.shard7File()));
app.get('/api/vault/files/storage',async(_request,reply)=>reply.type('application/octet-stream').send(vault.exportStorage()));
app.post('/api/vault/shard7/saved',async()=>{await vault.confirmShard7Saved();return {ok:true};});
app.get('/api/events',async(request,reply)=>{
  if(vault.isLocked())return reply.code(409).send({error:'vault_locked'});
  const after=z.coerce.number().int().min(0).default(0).parse((request.query as any).after);
  const abort=new AbortController();request.raw.on('close',()=>abort.abort());
  return changes.after(after,abort.signal);
});
app.get('/api/vault/horcrux-status',async request=>({...await vault.status((request.query as any).clientPresent==='true'),configured:vault.exists(),locked:vault.isLocked()}));
app.post('/api/vault/restore',async(request,reply)=>{
  const {vaultId,password}=vaultRestoreSchema.parse(request.body);
  try {
    stopTor();const result=await vault.restoreSecure(vaultId,password);
    store=new LocalSignalStore(vault.database());
    return {ok:true,...result};
  }catch {return reply.code(400).send({error:'RESTORE_FAILED_CHECK_CREDENTIALS_AND_RELAY'});}
});

// POST /api/vault/change-password
app.post('/api/vault/change-password', async (request: FastifyRequest, reply: FastifyReply) => {
  backups.cancel();await backups.drain();
  const { vaultId, oldPassword, newPassword } = z.object({
    vaultId: z.string().min(8).max(256),
    oldPassword: z.string(),
    newPassword: z.string()
  }).parse(request.body);

  try {
    stopTor();const result=await vault.changeSecurePassword(vaultId,oldPassword,newPassword);
    store=new LocalSignalStore(vault.database());
    return { ok: true,...result };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'password_change_failed' });
  }
});

async function activateIdentity(requestId:string,activationCode:string){
 const activeStore=getStore();if(activeStore.isRegistered())throw new Error('ALREADY_REGISTERED');
 const bundle=await activeStore.ensureIdentity();
 const result=await relayClient.activateAccess({...bundle,identityPublicKey:undefined,signalIdentityPublicKey:bundle.identityPublicKey,requestId,activationCode});
 activeStore.completeRegistration({userId:result.userId,deviceId:result.deviceId,username:result.username,sessionToken:result.sessionToken,publicUid:result.publicUid});
 relayClient.acceptSession(result.sessionToken,result.expiresAt);
 backups.schedule();return {ok:true,activated:true,publicUid:result.publicUid};
}
async function selfActivate(username:string){
 await ensureTor();
 if(getStore().isRegistered())throw new Error('ALREADY_REGISTERED');
 if(torRouting.mode==='DIRECT_TOR_P2P'){
  username=z.string().regex(/^[a-z0-9_]{3,32}$/).parse(username);const active=getStore(),bundle=await active.ensureIdentity(),uid=formatPublicUid(bundle.identityPublicKey),db=vault.database();
  db.transaction(()=>{active.setAccount(bundle.deviceId);db.prepare("INSERT OR REPLACE INTO activation_state(singleton,request_id,username,status,updated_at) VALUES(1,?,?,'activated',?)").run([crypto.randomUUID(),username,Date.now()]);db.prepare('INSERT OR REPLACE INTO account_public VALUES(1,?)').run([uid]);})();await ensureTor();backups.schedule();return {ok:true,activated:true,publicUid:uid};
 }
 const saved=vault.database().prepare('SELECT request_id,token FROM access_claim WHERE singleton=1 AND username=?').get<any>([username]);
 if(saved)return activateIdentity(saved.request_id,saved.token);
 const result=await relayClient.applyAccess(username);
 if(!result.activationCode)throw new Error('SELF_SERVE_UNAVAILABLE');
 vault.database().prepare("INSERT OR REPLACE INTO activation_state(singleton,request_id,username,status,expires_at,updated_at) VALUES(1,?,?,'pending',?,?)").run([result.requestId,result.username,result.expiresAt??null,Date.now()]);
 vault.database().prepare('INSERT OR REPLACE INTO access_claim(singleton,request_id,username,token) VALUES(1,?,?,?)').run([result.requestId,result.username,result.activationCode]);
 return activateIdentity(result.requestId,result.activationCode);
}
app.post('/api/access/apply',async(request,reply)=>{try{return await selfActivate(z.object({username:z.string()}).parse(request.body).username);}catch(error){return reply.code(error instanceof RelayClientError?error.status:400).send({error:error instanceof Error?error.message:'ACTIVATION_FAILED'});}});

app.get('/api/access/state', async () => {
  if(vault.isDecoyActive())return {status:'activated'};
  const value = vault.database().prepare(
    'SELECT request_id, username, status, expires_at FROM activation_state WHERE singleton=1'
  ).get<{ request_id: string; username: string; status: 'pending' | 'activated'; expires_at: string | null }>();
  if (!value) return { status: 'idle' as const };
  return {
    requestId: value.request_id,
    username: value.username,
    status: value.status,
    publicUid: vault.database().prepare('SELECT public_uid FROM account_public WHERE singleton=1').get<{public_uid:string}>()?.public_uid,
    expiresAt: value.expires_at ?? undefined
  };
});

app.post('/api/access/activate',async(request)=>{const body=z.object({requestId:z.string().uuid(),activationCode:z.string().min(20).max(256)}).parse(request.body);return activateIdentity(body.requestId,body.activationCode);});
app.get('/api/profile',async()=>profile(vault));
app.post('/api/profile',async request=>{
 const value=z.object({displayName:z.string().trim().max(64),statusLine:z.string().trim().max(140)}).parse(request.body);
 const db=vault.database();db.prepare('INSERT OR REPLACE INTO consumer_profile(singleton,display_name,status_line) VALUES(1,?,?)').run([value.displayName,value.statusLine]);
 db.exec('BEGIN IMMEDIATE');try{for(const peer of db.prepare('SELECT conversation_id FROM conversations').all<any>())await queueControl(vault,getStore(),peer.conversation_id,{type:'profile'});db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
 backups.schedule();await flushControls(vault,getStore(),relayClient);return value;
});
app.post('/api/control',async request=>{
 const body=z.object({conversationId:z.string().uuid(),type:z.enum(['typing','read_receipt'])}).parse(request.body);
 const db=vault.database(),payload:any={type:body.type};
 if(body.type==='typing')payload.expiresAt=Date.now()+5000;
 else{const link=db.prepare("SELECT l.remote_id FROM message_links l JOIN messages m ON m.message_id=l.message_id WHERE m.conversation_id=? AND m.direction='received' ORDER BY m.rowid DESC LIMIT 1").get<any>([body.conversationId]);if(!link)return {ok:true};payload.upToMessageId=link.remote_id;}
 db.exec('BEGIN IMMEDIATE');try{await queueControl(vault,getStore(),body.conversationId,payload);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
 backups.schedule();await flushControls(vault,getStore(),relayClient);return {ok:true};
});
app.post('/api/session/pin',async request=>{const {pin}=z.object({pin:z.string().regex(/^[0-9]{4}$/)}).parse(request.body);const salt=crypto.randomBytes(32);vault.database().prepare('INSERT OR REPLACE INTO session_pin(singleton,salt,digest) VALUES(1,?,?)').run([salt,crypto.createHash('sha256').update(salt).update(pin).digest()]);backups.schedule();return {ok:true};});
app.post('/api/session/lock',async(request,reply)=>{if(!vault.database().prepare('SELECT 1 FROM session_pin WHERE singleton=1').get())return reply.code(409).send({error:'SET_SESSION_PIN_FIRST'});stopTor();relayClient.clearSession();quickLocked=true;return {ok:true};});
app.post('/api/session/unlock',async(request,reply)=>{
 if(Date.now()<pinRetryAt)return reply.code(429).send({error:'PIN_RETRY_LATER'});
 const {pin}=z.object({pin:z.string()}).parse(request.body),row=vault.database().prepare('SELECT salt,digest FROM session_pin WHERE singleton=1').get<any>();
 if(!row||!crypto.timingSafeEqual(row.digest,crypto.createHash('sha256').update(row.salt).update(pin).digest())){if(++pinFailures>=5){pinRetryAt=Date.now()+30000;pinFailures=0;}return reply.code(401).send({error:'INVALID_SESSION_PIN'});}
 quickLocked=false;pinFailures=0;return {ok:true};
});

// GET /api/contacts
app.get('/api/contacts', async () => {
  const db = vault.database();
  const contacts = db.prepare(
    `SELECT p.display_name AS displayName,p.status_line AS statusLine,c.contact_id, c.username, c.public_uid, c.verified, c.identity_changed, c.safety_number_hash, r.user_id, conv.conversation_id, conv.disappearing_seconds
     FROM contacts c LEFT JOIN peer_profiles p ON p.contact_id=c.contact_id JOIN conversations conv ON conv.contact_id = c.contact_id LEFT JOIN remote_contacts r ON r.contact_id=c.contact_id
     ORDER BY c.username`
  ).all();
  return contacts.map((c:any)=>({...c, publicUid:c.public_uid??(c.user_id?formatPublicUid(c.user_id):undefined)}));
});

// POST /api/contacts/add
app.post('/api/contacts/add', async (request: FastifyRequest) => {
  const { username } = z.object({ username: z.string() }).parse(request.body);
  const activeStore = getStore();
  const result=await addContactAndSession(vault, activeStore, relayClient, username);
  backups.schedule();return {...result,backupPending:true};
});
app.get('/api/contacts/invite',async(_request,reply)=>{await ensureTor();if(!torRouting.transport?.status().serverless)return reply.code(503).send({error:'TOR_NOT_READY'});return {uri:await ownServerlessInvite(vault,getStore(),torRouting.transport.address())};});
app.post('/api/contacts/import',async request=>{const {uri}=z.object({uri:z.string().max(4096)}).parse(request.body);const contact=await importServerlessContact(vault,getStore(),uri);backups.schedule();changes.publish('CONTACTS_CHANGED');return contact;});

// Conversation authorization is recipient-controlled.  A contact prekey
app.post('/api/contacts/:contactId/verify',async(request,reply)=>{
  const id=z.string().parse((request.params as any).contactId);
  const {safetyNumber}=z.object({safetyNumber:z.string().regex(/^\d{60}$/)}).parse(request.body);
  const result=vault.database().prepare('UPDATE contacts SET verified=1 WHERE contact_id=? AND safety_number_hash=? AND identity_changed=0').run([id,safetyNumber]);
  if(!result.changes)return reply.code(409).send({error:'SAFETY_NUMBER_CHANGED'});
  backups.schedule();return {ok:true,backupPending:true};
});
// bundle cannot be fetched until the recipient has accepted this request.
app.post('/api/conversations/requests', async (request: FastifyRequest, reply: FastifyReply) => {
  const { recipientUsername } = z.object({ recipientUsername: z.string().trim().transform(v=>v.toUpperCase().startsWith('CP-')?v.toUpperCase():v.toLowerCase()) }).parse(request.body);
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, '/api/conversations/requests', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipientUsername })
  });
  return reply.code(res.status).send(await res.json());
});

app.get('/api/conversations/requests', async (request: FastifyRequest, reply: FastifyReply) => {
  if(torRouting.mode==='DIRECT_TOR_P2P')return [];
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, '/api/conversations/requests');
  return reply.code(res.status).send(await res.json());
});

app.post('/api/conversations/requests/:requestId/:decision', async (request: FastifyRequest, reply: FastifyReply) => {
  const params = z.object({ requestId: z.string().uuid(), decision: z.enum(['accept', 'reject']) }).parse(request.params);
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, `/api/conversations/requests/${params.requestId}/${params.decision}`, { method: 'POST' });
  if(res.ok)backups.schedule();
  return reply.code(res.status).send({...await res.json(),backupPending:res.ok});
});

// POST /api/send
app.post('/api/send', async (request: FastifyRequest) => {
  const { conversationId, plaintext, attachmentManifest } = z.object({
    conversationId: z.string().uuid(),
    plaintext: z.string(),
    attachmentManifest: z.any().optional()
  }).parse(request.body);

  const activeStore = getStore();
  const result=await sendMessage(vault, activeStore, relayClient, conversationId, plaintext, attachmentManifest);
  backups.schedule();
  return {...result,backupPending:true};
});

app.post('/api/conversations/:conversationId/timer',async request=>{
  const id=z.string().uuid().parse((request.params as any).conversationId);
  const {seconds}=z.object({seconds:z.union([z.literal(0),z.literal(3600),z.literal(86400),z.literal(604800)])}).parse(request.body);
  vault.database().prepare('UPDATE conversations SET disappearing_seconds=? WHERE conversation_id=?').run([seconds||null,id]);
  backups.schedule();return {ok:true,backupPending:true};
});

function conversationMessages(conversationId:string) {const db=vault.database();
  return db.prepare(
    `SELECT m.message_id, m.conversation_id, m.direction, m.plaintext, m.sent_at, m.received_at, m.status, a.attachment_id, a.file_size, a.encrypted_local_path IS NOT NULL AS attachment_ready
     FROM messages m LEFT JOIN attachments a ON a.message_id=m.message_id
     WHERE m.conversation_id = ? AND (m.disappear_at IS NULL OR m.disappear_at>?)
     ORDER BY COALESCE(m.sent_at, m.received_at), m.rowid ASC`
  ).all([conversationId,Date.now()]);

}
// GET /api/messages/:conversationId
app.get('/api/messages/:conversationId', async (request: FastifyRequest) => {
  const conversationId = z.string().uuid().parse((request.params as any).conversationId);
  const db = vault.database();
  
  return conversationMessages(conversationId);
});

// POST /api/fetch-messages
app.post('/api/fetch-messages', async (request: FastifyRequest, reply: FastifyReply) => {
  if(vault.isDecoyActive()){const id=(request.body as any)?.conversationId;return {received:0,sent:0,typing:false,...(id?{conversationId:id,messages:conversationMessages(id)}:{})};}
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  void relayClient.watch(vault,activeStore,type=>changes.publish(type));
  const sent = await flushOutbox(vault, activeStore, relayClient);
  const count = await syncMessages(vault, activeStore, relayClient);
  await flushControls(vault,activeStore,relayClient);
  if(count||sent)backups.schedule();
  const conversationId=z.object({conversationId:z.string().uuid().optional()}).parse(request.body??{}).conversationId;
  return { typing:!!conversationId&&(typingUntil.get(conversationId)??0)>Date.now(), received: count, sent, backupPending:backups.pending(),...(conversationId?{conversationId,messages:conversationMessages(conversationId)}:{}) };
});

app.setErrorHandler((error, request, reply) => {
  logRouteError(error, request, 'Unhandled local-daemon error');
  if (error instanceof z.ZodError) {
    return reply.code(400).send({ error: 'INVALID_REQUEST' });
  }
  return reply.code(500).send({ error: 'INTERNAL_ERROR' });
});

// POST /api/attachments/encrypt
app.post('/api/attachments/encrypt', {bodyLimit:36*1024*1024}, async (request: FastifyRequest) => {
  const { filedataB64, filename, mimeType } = z.object({
    filedataB64: z.string(),
    filename: z.string(),
    mimeType: z.string()
  }).parse(request.body);

  const activeStore = getStore();
  const filedata = Buffer.from(filedataB64, 'base64');
  if(filedata.length>25*1024*1024)throw new Error('attachment_too_large');
  return encryptAndUploadAttachment(vault, activeStore, relayClient, filedata, filename, mimeType);
});

// GET /api/attachments/:attachmentId/decrypt
app.get('/api/attachments/:attachmentId/decrypt', async (request: FastifyRequest, reply: FastifyReply) => {
  const attachmentId = z.string().regex(/^[a-f0-9]{32}$/).parse((request.params as any).attachmentId);
  const attachment = vault.database().prepare('SELECT encrypted_local_path FROM attachments WHERE attachment_id=?').get<any>([attachmentId]);
  if (!attachment) return reply.code(404).send({error:'attachment_not_found'});
  if (!attachment.encrypted_local_path) return reply.code(409).send({error:'attachment_pending'});
  const { filename, filedata } = await readDecryptedAttachment(vault, attachmentId);
  if((request.query as any).play==='1' && /^voice-note\.(webm|ogg|m4a)$/.test(filename)) {
    return reply.type(filename.endsWith('.m4a')?'audio/mp4':filename.endsWith('.ogg')?'audio/ogg':'audio/webm').send(filedata);
  }
  if((request.query as any).download==='1'){
    reply.header('Content-Disposition',`attachment; filename="${filename.replace(/[^\x20-\x7E]|["\\;]/g,'_')}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
    return reply.type('application/octet-stream').send(filedata);
  }
  return {
    filename,
    filedataB64: filedata.toString('base64')
  };
});

// Start disappearing message worker loop
startDisappearingMessageJob(() => vault.database(),task=>{
  const pending=requestTail.then(task);
  requestTail=pending.catch(()=>{});
  return requestTail;
});

// Try to serve React built frontend from static path
const staticUiDir = join(__dirname, '../../local-ui/dist');
try {
  // Only serve known build assets. Request paths never become filesystem paths.
  // The UI needs no directory listing, globbing or general-purpose file server.
  const assets=new Map(readdirSync(join(staticUiDir,'assets'),{withFileTypes:true})
    .filter(file=>file.isFile() && /\.(?:js|css|png|svg|woff2?)$/.test(file.name))
    .map(file=>[file.name,readFileSync(join(staticUiDir,'assets',file.name))]));
  app.get('/assets/:asset',async(request,reply)=>{
    const name=(request.params as {asset:string}).asset,bytes=assets.get(name);
    if(!bytes)return reply.code(404).send({error:'asset_not_found'});
    const extension=name.split('.').pop()!;
    const types:Record<string,string>={js:'text/javascript',css:'text/css',png:'image/png',svg:'image/svg+xml',woff:'font/woff',woff2:'font/woff2'};
    return reply.type(types[extension]).send(bytes);
  });

  // Handle SPA frontend route fallbacks
  app.setNotFoundHandler(async (request, reply) => {
    if (!request.url.startsWith('/api/')) {
      try {
        const indexHtml = readFileSync(join(staticUiDir, 'index.html'), 'utf8');
        return reply.type('text/html').send(indexHtml);
      } catch {
        // Fallback if index.html not found
      }
    }
    return reply.code(404).send({ error: 'not_found' });
  });
} catch {
  // If static directory doesn't exist yet, we will just serve API endpoints
}

// Binds server to localhost on a random available port
const port = z.coerce.number().default(0).parse(process.env.PORT);
await app.listen({ host: '127.0.0.1', port });

const resolvedPort = (app.server.address() as any).port;
const bootstrapSecret = generateBootstrapSecret(resolvedPort);

logger.info(`Local Daemon running on http://127.0.0.1:${resolvedPort}`);
const bootstrapUrl = `http://127.0.0.1:${resolvedPort}/bootstrap#${bootstrapSecret}`;
if (process.send) {
  // Bootstrap credentials travel over the parent's private IPC channel, never logs.
  process.send({ type: 'desktop-ready', url: bootstrapUrl });
  process.on('message', message => {
    if ((message as { type?: string })?.type !== 'desktop-stop') return;
    stopTor();backups.cancel();relayClient.clearSession();vault.lock(); store = null; invalidateSession();
    void app.close().finally(() => process.exit(0));
  });
  process.on('disconnect', () => { stopTor();backups.cancel();relayClient.clearSession();vault.lock(); process.exit(0); });
} else {
  console.log(`Open: ${bootstrapUrl}`);
}
