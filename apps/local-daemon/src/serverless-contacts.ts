import crypto from 'node:crypto';
import { ProtocolAddress,PublicKey } from '@signalapp/libsignal-client';
import { createServerlessInvite,parseServerlessInvite } from '@crypto-pigeon/protocol';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import { establishSession } from './signal-adapter.js';
import { computeSafetyNumber } from './fingerprint.js';
import { initializeTorSchema } from './tor-transport.js';

export async function ownServerlessInvite(vault:Vault,store:LocalSignalStore,onion:string){
  const bundle=await store.ensureIdentity(),db=vault.database();
  const username=db.prepare('SELECT username FROM activation_state WHERE singleton=1').get<{username:string}>()?.username;
  const uid=db.prepare('SELECT public_uid FROM account_public WHERE singleton=1').get<{public_uid:string}>()?.public_uid;
  if(!username||!uid)throw new Error('DEVICE_NOT_REGISTERED');
  const {privateKey}=store.getDeviceAuthKeyPair();try{return createServerlessInvite({version:2,username,publicUid:uid,onion,userId:store.localAddress().name(),deviceId:bundle.deviceId,signalDeviceId:bundle.signalDeviceId,registrationId:bundle.registrationId,
    deviceAuthPublicKey:bundle.deviceAuthPublicKey,identityPublicKey:bundle.identityPublicKey,signedPrekey:bundle.signedPrekey,pqLastResortPrekey:bundle.pqLastResortPrekey},privateKey);}finally{privateKey.fill(0);}
}
export async function importServerlessContact(vault:Vault,store:LocalSignalStore,uri:string){
  const invite=parseServerlessInvite(uri),db=vault.database();initializeTorSchema(db);
  if(invite.deviceId===(await store.ensureIdentity()).deviceId)throw new Error('SELF_INVITE');
  const identity=PublicKey.deserialize(Buffer.from(invite.identityPublicKey,'base64'));
  for(const prekey of [invite.signedPrekey,invite.pqLastResortPrekey])if(!identity.verify(Buffer.from(prekey.publicKey,'base64'),Buffer.from(prekey.signature,'base64')))throw new Error('INVALID_SIGNAL_PREKEY_SIGNATURE');
  const address=ProtocolAddress.new(invite.userId,invite.signalDeviceId),contact=address.toString();
  const pins=db.prepare('SELECT contact_id,onion,auth_key FROM peer_onions WHERE device_id=? OR contact_id=?').all<any>([invite.deviceId,contact]);
  if(pins.some(pinned=>pinned.contact_id!==contact||pinned.auth_key!==invite.deviceAuthPublicKey||pinned.onion!==invite.onion))throw new Error('PINNED_INVITE_CHANGED');
  const remote=db.prepare('SELECT * FROM remote_contacts WHERE device_id=? OR contact_id=?').all<any>([invite.deviceId,contact]);
  if(remote.some(row=>row.contact_id!==contact||row.device_id!==invite.deviceId||row.user_id!==invite.userId||row.signal_device_id!==invite.signalDeviceId))throw new Error('PINNED_DEVICE_CHANGED');
  if(db.prepare('SELECT 1 FROM contacts WHERE contact_id=? AND identity_changed=1').get([contact]))throw new Error('IDENTITY_CHANGED_REQUIRES_REVIEW');
  db.exec('BEGIN IMMEDIATE');try{
    // Reimporting the same contact must not reset an established Signal session.
    if(!db.prepare('SELECT 1 FROM signal_sessions WHERE contact_id=?').get([contact]))await establishSession(store,address,{...invite,oneTimePrekey:null,pqOneTimePrekey:null});
    else{const pinnedIdentity=db.prepare('SELECT identity_public_key FROM contacts WHERE contact_id=?').get<{identity_public_key:Uint8Array<ArrayBuffer>}>([contact]);if(!pinnedIdentity||!Buffer.from(pinnedIdentity.identity_public_key).equals(Buffer.from(invite.identityPublicKey,'base64')))throw new Error('PINNED_IDENTITY_CHANGED');}
    const safetyNumber=await computeSafetyNumber(store,address);
    db.prepare('INSERT OR IGNORE INTO remote_contacts VALUES(?,?,?,?)').run([contact,invite.userId,invite.deviceId,invite.signalDeviceId]);
    db.prepare('INSERT OR REPLACE INTO peer_onions VALUES(?,?,?,?,?)').run([invite.deviceId,contact,invite.onion,invite.deviceAuthPublicKey,uri]);
    db.prepare('UPDATE contacts SET username=?,public_uid=?,verified=1,identity_changed=0,safety_number_hash=? WHERE contact_id=?').run([invite.username,invite.publicUid,safetyNumber,contact]);
    let conversation=db.prepare('SELECT conversation_id FROM conversations WHERE contact_id=?').get<{conversation_id:string}>([contact])?.conversation_id;
    if(!conversation){conversation=crypto.randomUUID();db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,Date.now()]);}
    db.exec('COMMIT');return {conversationId:conversation,verified:true,safetyNumber};
  }catch(error){db.exec('ROLLBACK');throw error;}
}
