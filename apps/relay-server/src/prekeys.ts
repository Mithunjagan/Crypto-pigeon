import type { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { pool } from './db.js';
import { authMiddleware, adminAuthMiddleware } from './auth.js';
import { logger, routeErrorDetails } from './logger.js';
import { env } from './config.js';
import {
  signedPrekeySchema,
  oneTimePrekeySchema,
  pqOneTimePrekeySchema,
  deviceIdSchema
} from '@crypto-pigeon/protocol';
import { notifyClient } from './ws-handler.js';

export function setupPrekeysRoutes(app: any) {
  // POST /api/prekeys/signed
  app.post('/api/prekeys/signed', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const deviceId = request.user!.deviceId;
    const body = signedPrekeySchema.parse(request.body);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Update signed prekey
      await client.query(
        `INSERT INTO signed_prekeys (device_id, signal_prekey_id, public_key, signature)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (device_id, signal_prekey_id) 
         DO UPDATE SET public_key = $3, signature = $4, uploaded_at = now()`,
        [deviceId, body.id, Buffer.from(body.publicKey, 'base64'), Buffer.from(body.signature, 'base64')]
      );

      // Track key version
      const fingerprint = crypto.subtle 
        ? await crypto.subtle.digest('SHA-256', Buffer.from(body.publicKey, 'base64'))
        : Buffer.from(body.publicKey, 'base64').slice(0, 32); // fallback
      
      await client.query(
        `INSERT INTO device_key_versions (device_id, key_type, version, fingerprint)
         VALUES ($1, 'signed_prekey', (SELECT COALESCE(MAX(version), 0) + 1 FROM device_key_versions WHERE device_id = $1 AND key_type = 'signed_prekey'), $2)`,
        [deviceId, Buffer.from(fingerprint as ArrayBuffer)]
      );

      await client.query('COMMIT');
      return { ok: true };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to upload signed prekey');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  // POST /api/prekeys/one-time
  app.post('/api/prekeys/one-time', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const deviceId = request.user!.deviceId;
    const body = z.object({
      oneTimePrekeys: z.array(oneTimePrekeySchema).min(1).max(200)
    }).parse(request.body);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const prekey of body.oneTimePrekeys) {
        await client.query(
          `INSERT INTO one_time_prekeys (device_id, signal_prekey_id, public_key, consumed)
           VALUES ($1, $2, $3, false)
           ON CONFLICT (device_id, signal_prekey_id) DO UPDATE SET public_key = $3, consumed = false, consumed_at = null`,
          [deviceId, prekey.id, Buffer.from(prekey.publicKey, 'base64')]
        );
      }
      await client.query('COMMIT');
      return { ok: true };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to upload one-time prekeys');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  // POST /api/prekeys/pq-one-time
  app.post('/api/prekeys/pq-one-time', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const deviceId = request.user!.deviceId;
    const body = z.object({
      pqOneTimePrekeys: z.array(pqOneTimePrekeySchema).min(1).max(200),
      pqLastResortPrekey: pqOneTimePrekeySchema.optional()
    }).parse(request.body);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const prekey of body.pqOneTimePrekeys) {
        await client.query(
          `INSERT INTO pq_one_time_prekeys (device_id, signal_prekey_id, public_key, signature, prekey_type, consumed)
           VALUES ($1, $2, $3, $4, 'one_time', false)
           ON CONFLICT (device_id, signal_prekey_id) DO UPDATE SET public_key = $3, signature = $4, consumed = false, consumed_at = null`,
          [deviceId, prekey.id, Buffer.from(prekey.publicKey, 'base64'), Buffer.from(prekey.signature, 'base64')]
        );
      }
      if (body.pqLastResortPrekey) {
        await client.query(
          `INSERT INTO pq_one_time_prekeys (device_id, signal_prekey_id, public_key, signature, prekey_type, consumed)
           VALUES ($1, $2, $3, $4, 'last_resort', false)
           ON CONFLICT (device_id, signal_prekey_id) DO UPDATE SET public_key = $3, signature = $4, consumed = false, consumed_at = null`,
          [deviceId, body.pqLastResortPrekey.id, Buffer.from(body.pqLastResortPrekey.publicKey, 'base64'), Buffer.from(body.pqLastResortPrekey.signature, 'base64')]
        );
      }
      await client.query('COMMIT');
      return { ok: true };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to upload PQ prekeys');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  // GET /api/prekeys/count
  app.get('/api/prekeys/count', { preHandler: authMiddleware }, async (request: FastifyRequest) => {
    const deviceId = request.user!.deviceId;
    
    const otpRes = await pool.query(
      'SELECT count(*) FROM one_time_prekeys WHERE device_id = $1 AND consumed = false',
      [deviceId]
    );
    const pqOtpRes = await pool.query(
      'SELECT count(*) FROM pq_one_time_prekeys WHERE device_id = $1 AND consumed = false AND prekey_type = \'one_time\'',
      [deviceId]
    );

    return {
      oneTimePrekeysCount: parseInt(otpRes.rows[0].count, 10),
      pqOneTimePrekeysCount: parseInt(pqOtpRes.rows[0].count, 10)
    };
  });

  // POST /api/prekeys/bundle
  // Post is used as it consumes one-time prekeys (mutating state)
  app.post('/api/prekeys/bundle', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const body = z.object({
      recipientDeviceId: deviceIdSchema.optional(),
      recipientUsername: z.string().trim().toLowerCase().optional()
    }).parse(request.body);

    if (!body.recipientDeviceId && !body.recipientUsername) {
      return reply.code(400).send({ error: 'recipient_required' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Resolve deviceId
      let targetDeviceId = body.recipientDeviceId;
      if (body.recipientUsername) {
        const userRes = await client.query(
          `SELECT d.device_id 
           FROM users u 
           JOIN device_identity_keys d ON d.user_id = u.user_id 
           WHERE u.username = $1 AND d.revoked_at IS NULL`,
          [body.recipientUsername]
        );
        if (userRes.rows.length === 0) {
          await client.query('ROLLBACK');
          return reply.code(404).send({ error: 'user_not_found' });
        }
        targetDeviceId = userRes.rows[0].device_id;
      }

      // Check conversation permissions
      const requesterUserRes = await client.query(
        'SELECT user_id FROM device_identity_keys WHERE device_id = $1',
        [request.user!.deviceId]
      );
      const recipientUserRes = await client.query(
        'SELECT user_id FROM device_identity_keys WHERE device_id = $1',
        [targetDeviceId]
      );
      
      const u1 = requesterUserRes.rows[0].user_id;
      const u2 = recipientUserRes.rows[0].user_id;
      const [left, right] = u1 < u2 ? [u1, u2] : [u2, u1];

      const permissionRes = await client.query(
        'SELECT 1 FROM conversation_permissions WHERE user_one = $1 AND user_two = $2 AND revoked_at IS NULL',
        [left, right]
      );
      if (permissionRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(403).send({ error: 'conversation_not_approved' });
      }

      // 2. Fetch device identity details
      const deviceRes = await client.query(
        `SELECT d.user_id, d.identity_public_key, d.registration_id, d.signal_device_id, u.username
         FROM device_identity_keys d
         JOIN users u ON u.user_id = d.user_id
         WHERE d.device_id = $1 AND d.revoked_at IS NULL`,
        [targetDeviceId]
      );

      if (deviceRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(404).send({ error: 'device_not_found' });
      }

      const deviceRow = deviceRes.rows[0];

      // 3. Fetch latest signed prekey
      const signedRes = await client.query(
        `SELECT signal_prekey_id, public_key, signature 
         FROM signed_prekeys 
         WHERE device_id = $1 
         ORDER BY uploaded_at DESC LIMIT 1`,
        [targetDeviceId]
      );
      if (signedRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(404).send({ error: 'signed_prekey_not_found' });
      }

      const signedRow = signedRes.rows[0];

      // 4. Consume classical one-time prekey
      const otpUpdate = await client.query(
        `UPDATE one_time_prekeys
         SET consumed = true, consumed_at = now()
         WHERE id = (
           SELECT id FROM one_time_prekeys
           WHERE device_id = $1 AND consumed = false
           ORDER BY uploaded_at ASC
           LIMIT 1
           FOR UPDATE SKIP LOCKED
         )
         RETURNING signal_prekey_id, public_key`,
        [targetDeviceId]
      );

      const consumedOtp = otpUpdate.rows[0] || null;

      // 5. Consume PQ one-time prekey
      const pqOtpUpdate = await client.query(
        `UPDATE pq_one_time_prekeys
         SET consumed = true, consumed_at = now()
         WHERE id = (
           SELECT id FROM pq_one_time_prekeys
           WHERE device_id = $1 AND consumed = false AND prekey_type = 'one_time'
           ORDER BY uploaded_at ASC
           LIMIT 1
           FOR UPDATE SKIP LOCKED
         )
         RETURNING signal_prekey_id, public_key, signature`,
        [targetDeviceId]
      );

      const consumedPqOtp = pqOtpUpdate.rows[0] || null;

      // Fetch last resort PQ prekey
      const pqLastResortRes = await client.query(
        `SELECT signal_prekey_id, public_key, signature 
         FROM pq_one_time_prekeys 
         WHERE device_id = $1 AND prekey_type = 'last_resort'
         LIMIT 1`,
        [targetDeviceId]
      );

      if (pqLastResortRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(404).send({ error: 'last_resort_pq_prekey_not_found' });
      }

      const lastResortRow = pqLastResortRes.rows[0];

      await client.query('COMMIT');

      // Check replenishment inventory and notify recipient if counts are low
      const checkOtpCount = await pool.query(
        'SELECT count(*) FROM one_time_prekeys WHERE device_id = $1 AND consumed = false',
        [targetDeviceId]
      );
      const checkPqOtpCount = await pool.query(
        'SELECT count(*) FROM pq_one_time_prekeys WHERE device_id = $1 AND consumed = false AND prekey_type = \'one_time\'',
        [targetDeviceId]
      );
      
      const otpCount = parseInt(checkOtpCount.rows[0].count, 10);
      const pqOtpCount = parseInt(checkPqOtpCount.rows[0].count, 10);

      if (otpCount < 20 || pqOtpCount < 20) {
        // Send a replenishing warning over websocket if online
        notifyClient(targetDeviceId!, {
          type: 'replenish_warning',
          oneTimePrekeysRemaining: otpCount,
          pqOneTimePrekeysRemaining: pqOtpCount
        });
      }

      return {
        recipientUserId: deviceRow.user_id,
        recipientDeviceId: targetDeviceId,
        recipientUsername: deviceRow.username,
        identityKey: Buffer.from(deviceRow.identity_public_key).toString('base64'),
        registrationId: deviceRow.registration_id,
        signedPrekey: {
          id: signedRow.signal_prekey_id,
          publicKey: Buffer.from(signedRow.public_key).toString('base64'),
          signature: Buffer.from(signedRow.signature).toString('base64')
        },
        oneTimePrekey: consumedOtp ? {
          id: consumedOtp.signal_prekey_id,
          publicKey: Buffer.from(consumedOtp.public_key).toString('base64')
        } : null,
        pqOneTimePrekey: consumedPqOtp ? {
          id: consumedPqOtp.signal_prekey_id,
          publicKey: Buffer.from(consumedPqOtp.public_key).toString('base64'),
          signature: Buffer.from(consumedPqOtp.signature).toString('base64')
        } : null,
        pqLastResortPrekey: {
          id: lastResortRow.signal_prekey_id,
          publicKey: Buffer.from(lastResortRow.public_key).toString('base64'),
          signature: Buffer.from(lastResortRow.signature).toString('base64')
        }
      };
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to fetch prekey bundle');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  // POST /api/prekeys/cleanup
  app.post('/api/prekeys/cleanup', { preHandler: adminAuthMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Remove signed prekeys older than 30 days, keeping the latest one for each device
      await pool.query(`
        DELETE FROM signed_prekeys 
        WHERE uploaded_at < now() - INTERVAL '30 days'
        AND id NOT IN (
          SELECT DISTINCT ON (device_id) id 
          FROM signed_prekeys 
          ORDER BY device_id, uploaded_at DESC
        )
      `);
      return { ok: true };
    } catch (error) {
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Prekey cleanup failed');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    }
  });
}
