import crypto from 'node:crypto';
import type {Vault} from './vault.js';
import type {LocalSignalStore} from './signal-store.js';
import type {RelayClient} from './relay-client.js';
import {ProtocolAddress} from '@signalapp/libsignal-client';
import {encryptPayload} from './signal-adapter.js';
export const typingUntil=new Map<string,number>();
export function profile(vault:Vault){return vault.database().prepare('SELECT display_name AS displayName,status_line AS statusLine FROM consumer_profile WHERE singleton=1').get()??{displayName:'',statusLine:''};}
// Caller owns the serialized vault transaction; encrypt and commit the ratchet
// with these exact retry bytes before any envelope goes onto the network.
export async function queueControl(vault:Vault,store:LocalSignalStore,conversation:string,payload:any){
 const db=vault.database(),peer=db.prepare(`SELECT r.*,c.identity_changed FROM conversations v JOIN remote_contacts r ON r.contact_id=v.contact_id JOIN contacts c ON c.contact_id=v.contact_id WHERE v.conversation_id=?`).get<any>([conversation]);
 if(!peer||peer.identity_changed)throw new Error('IDENTITY_NOT_READY');
 const encrypted=await encryptPayload(store,ProtocolAddress.new(peer.user_id,peer.signal_device_id),JSON.stringify({...payload,profile:profile(vault)}));
 const ciphertext=Buffer.concat([Buffer.from([encrypted.type]),Buffer.from(encrypted.ciphertext,'base64')]).toString('base64');
 db.prepare('INSERT INTO control_outbox(envelope_id,contact_id,mailbox_id,ciphertext,created_at,expires_at) VALUES(?,?,?,?,?,?)').run([crypto.randomBytes(16).toString('hex'),peer.contact_id,peer.device_id,ciphertext,Date.now(),payload.type==='typing'?payload.expiresAt:null]);
}
export async function flushControls(vault:Vault,store:LocalSignalStore,relay:RelayClient){
 const db=vault.database(),rows=db.prepare('SELECT o.* FROM control_outbox o JOIN contacts c ON c.contact_id=o.contact_id WHERE c.identity_changed=0 ORDER BY o.created_at,o.rowid').all<any>();
 for(const row of rows){
  if(row.expires_at!=null&&row.expires_at<=Date.now()){db.prepare('DELETE FROM control_outbox WHERE envelope_id=?').run([row.envelope_id]);continue;}
  const ephemeral=row.expires_at==null?{}:{envelopeType:'TYPING',createdAtMs:row.created_at,ttlMs:Math.max(1,Math.min(10000,row.expires_at-row.created_at))};
  try{const r=await relay.request(vault,store,'/api/messages/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:1,envelopeId:row.envelope_id,mailboxId:row.mailbox_id,ciphertext:row.ciphertext,...ephemeral})});if(!r.ok)return;db.prepare('DELETE FROM control_outbox WHERE envelope_id=?').run([row.envelope_id]);}catch{return;}
 }
}
