import crypto from 'node:crypto';
import type {FastifyInstance} from 'fastify';
import {z} from 'zod';
import {pool} from './db.js';
import {authMiddleware} from './auth.js';
import {blindDropboxEnvelopeSchema} from '@crypto-pigeon/protocol';
import {notifyBlindActivity} from './ws-handler.js';

/** At-rest sender/recipient minimization. Bearer authentication is NOT network anonymity. */
export function setupBlindDropboxRoutes(app:FastifyInstance){
  app.get('/api/privacy/capabilities',async()=>({blindDropbox:true,sealedIdentityInsideSignal:true,liveRelayAnonymity:false}));
  app.post('/api/contacts/exchange-ack',{preHandler:authMiddleware},async request=>{
    const {peerDeviceId}=z.object({peerDeviceId:z.string().uuid()}).parse(request.body);
    const client=await pool.connect();try{await client.query('BEGIN');
      const devices=(await client.query('SELECT device_id,user_id FROM device_identity_keys WHERE device_id=ANY($1::uuid[]) AND revoked_at IS NULL',[[request.user!.deviceId,peerDeviceId]])).rows;
      const own=devices.find(d=>d.device_id===request.user!.deviceId)?.user_id,peer=devices.find(d=>d.device_id===peerDeviceId)?.user_id;
      if(!own||!peer)throw new Error('CONTACT_NOT_FOUND');
      const permission=await client.query('SELECT 1 FROM conversation_permissions WHERE user_one=LEAST($1::uuid,$2::uuid) AND user_two=GREATEST($1::uuid,$2::uuid) AND revoked_at IS NULL',[own,peer]);if(!permission.rowCount)throw new Error('CONTACT_NOT_APPROVED');
      await client.query('INSERT INTO contact_exchange_acks VALUES($1,$2) ON CONFLICT DO NOTHING',[own,peer]);
      const both=await client.query('SELECT 1 FROM contact_exchange_acks WHERE user_id=$1 AND peer_id=$2',[peer,own]);
      if(both.rowCount){await client.query("DELETE FROM connection_requests WHERE status='accepted' AND ((requester_user_id=$1 AND recipient_user_id=$2) OR (requester_user_id=$2 AND recipient_user_id=$1))",[own,peer]);await client.query('DELETE FROM contact_exchange_acks WHERE (user_id=$1 AND peer_id=$2) OR (user_id=$2 AND peer_id=$1)',[own,peer]);}
      await client.query('COMMIT');return {ok:true,purged:!!both.rowCount};
    }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  });
  app.post('/api/blind/send',{preHandler:authMiddleware},async(request,reply)=>{
    const body=blindDropboxEnvelopeSchema.parse(request.body);
    const senderHash=crypto.createHash('sha256').update(crypto.randomBytes(32)).update(request.user!.deviceId).digest('hex');
    await pool.query(`INSERT INTO blind_messages(id,dropbox_id,ciphertext,sender_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '30 days') ON CONFLICT(id) DO NOTHING`,[body.envelopeId,body.blindDropboxId,Buffer.from(body.ciphertext,'base64'),senderHash]);
    // A data-free global poke avoids storing a tag-to-recipient mapping.
    notifyBlindActivity();
    return reply.code(202).send({envelopeId:body.envelopeId});
  });
  const access=z.object({dropboxIds:z.array(z.string().regex(/^[a-f0-9]{64}$/)).min(1).max(2000),envelopeIds:z.array(z.string().uuid()).max(256).optional()});
  app.post('/api/blind/fetch',{preHandler:authMiddleware,config:{rateLimit:{max:240,timeWindow:60000}}},async request=>{
    const {dropboxIds}=access.parse(request.body);
    return (await pool.query('SELECT id,dropbox_id,ciphertext FROM blind_messages WHERE dropbox_id=ANY($1) AND expires_at>now() ORDER BY created_at LIMIT 256',[dropboxIds])).rows.map(row=>({envelopeId:row.id,blindDropboxId:row.dropbox_id,ciphertext:row.ciphertext.toString('base64'),version:1}));
  });
  app.post('/api/blind/ack',{preHandler:authMiddleware},async request=>{
    const {dropboxIds,envelopeIds}=access.parse(request.body);
    await pool.query('DELETE FROM blind_messages WHERE id=ANY($1::uuid[]) AND dropbox_id=ANY($2)',[envelopeIds??[],dropboxIds]);return {ok:true};
  });
}
