import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { vaultBackupPutSchema, backupSigningPayload, lookupTokenSchema, verifyChallenge } from '@crypto-pigeon/protocol';
import { z } from 'zod';
import { pool } from './db.js';

export function setupVaultBackupRoutes(app: FastifyInstance) {
  app.delete('/api/vault-backup/:lookupToken',async(request,reply)=>{
    const token=lookupTokenSchema.parse((request.params as any).lookupToken);
    const {version,signature}=z.object({version:z.number().int().positive(),signature:z.string().max(128)}).parse(request.body);
    const row=(await pool.query('SELECT writer_public_key FROM vault_backups WHERE lookup_token=$1',[token])).rows[0];
    if(!row || !verifyChallenge(row.writer_public_key,Buffer.from(`cp-backup-delete-v1:${token}:${version}`),Buffer.from(signature,'base64')))return reply.code(403).send({error:'INVALID_BACKUP_SIGNATURE'});
    const result=await pool.query('DELETE FROM vault_backups WHERE lookup_token=$1 AND version=$2',[token,version]);
    return result.rowCount?{ok:true}:reply.code(409).send({error:'BACKUP_CONFLICT'});
  });
  const put = async (request: any, reply: any) => {
    const body=vaultBackupPutSchema.parse(request.body);
    if(request.params?.lookupToken && request.params.lookupToken!==body.lookupToken)return reply.code(400).send({error:'LOOKUP_MISMATCH'});
    const ciphertext=Buffer.from(body.ciphertext,'base64');
    if(ciphertext.length<16 || ciphertext.length>25*1024*1024)return reply.code(413).send({error:'BACKUP_TOO_LARGE'});
    const key=Buffer.from(body.writerPublicKey,'base64');
    if(key.length!==44 || !verifyChallenge(key,backupSigningPayload(body),Buffer.from(body.signature,'base64')))
      return reply.code(403).send({error:'INVALID_BACKUP_SIGNATURE'});
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      // Serializes initial creation as well as updates, including concurrent first writers.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[body.lookupToken]);
      const old=(await client.query('SELECT version,writer_public_key FROM vault_backups WHERE lookup_token=$1 FOR UPDATE',[body.lookupToken])).rows[0];
      if((old && !Buffer.from(old.writer_public_key).equals(key)) || body.version!==(old?.version??0)+1) {
        await client.query('ROLLBACK');return reply.code(409).send({error:'BACKUP_CONFLICT'});
      }
      if(body.deviceId || body.instanceHash || body.deviceSignature) {
        if(!body.deviceId || !body.instanceHash || !body.deviceSignature)throw new Error('invalid_device_proof');
        const device=(await client.query('SELECT auth_public_key FROM device_identity_keys WHERE device_id=$1 AND revoked_at IS NULL',[body.deviceId])).rows[0];
        if(!device || !verifyChallenge(device.auth_public_key,Buffer.from('cp-vault-instance-v1:'+body.instanceHash),Buffer.from(body.deviceSignature,'base64'))) {
          await client.query('ROLLBACK');return reply.code(403).send({error:'INVALID_DEVICE_PROOF'});
        }
        const lock=(await client.query('SELECT instance_hash FROM device_vault_locks WHERE device_id=$1 FOR UPDATE',[body.deviceId])).rows[0];
        if(lock && lock.instance_hash!==body.instanceHash && !body.claim) {
          await client.query('ROLLBACK');return reply.code(409).send({error:'VAULT_MOVED_RESTORE_REQUIRED'});
        }
        await client.query(`INSERT INTO device_vault_locks(device_id,instance_hash) VALUES($1,$2)
          ON CONFLICT(device_id) DO UPDATE SET instance_hash=excluded.instance_hash`,[body.deviceId,body.instanceHash]);
        if(body.claim)await client.query('DELETE FROM sessions WHERE device_id=$1',[body.deviceId]);
      }
      await client.query(`INSERT INTO vault_backups(lookup_token,version,nonce,ciphertext,fragment7_shard,writer_public_key,signature,signed_at,device_id,instance_hash,device_signature,claim)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT(lookup_token) DO UPDATE SET version=excluded.version,nonce=excluded.nonce,ciphertext=excluded.ciphertext,
        fragment7_shard=excluded.fragment7_shard,signature=excluded.signature,signed_at=excluded.signed_at,
        device_id=excluded.device_id,instance_hash=excluded.instance_hash,device_signature=excluded.device_signature,claim=excluded.claim,updated_at=now()`,
        [body.lookupToken,body.version,Buffer.from(body.nonce,'base64'),ciphertext,Buffer.from(body.fragment7Shard,'base64'),key,
          body.signature,body.updatedAt,body.deviceId??null,body.instanceHash??null,body.deviceSignature??null,body.claim]);
      await client.query('COMMIT');return {ok:true,version:body.version};
    } catch(e){await client.query('ROLLBACK');throw e;} finally{client.release();}
  };
  // Body limit includes base64/JSON overhead; decoded ciphertext remains capped at 25 MiB.
  app.put('/api/vault-backup/:lookupToken',{bodyLimit:36*1024*1024,config:{rateLimit:{max:20,timeWindow:60000}}},put);
  app.post('/api/vault-backup/put',{bodyLimit:36*1024*1024,config:{rateLimit:{max:20,timeWindow:60000}}},put);
  app.get('/api/vault-backup/:lookupToken',{config:{rateLimit:{max:30,timeWindow:60000}}},async(request,reply)=>{
    const token=lookupTokenSchema.parse((request.params as any).lookupToken);
    const row=(await pool.query('SELECT * FROM vault_backups WHERE lookup_token=$1',[token])).rows[0];
    reply.header('Cache-Control','no-store');
    if(!row)return reply.code(404).send({error:'BACKUP_NOT_FOUND'});
    return {lookupToken:token,version:row.version,nonce:row.nonce.toString('base64'),ciphertext:row.ciphertext.toString('base64'),
      fragment7Shard:row.fragment7_shard.toString('base64'),writerPublicKey:row.writer_public_key.toString('base64'),
      signature:row.signature,updatedAt:row.signed_at,deviceId:row.device_id??undefined,instanceHash:row.instance_hash??undefined,
      deviceSignature:row.device_signature??undefined,claim:row.claim};
  });
}
