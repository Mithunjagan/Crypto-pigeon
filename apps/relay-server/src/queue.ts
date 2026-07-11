import type { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { pool } from './db.js';
import { authMiddleware } from './auth.js';
import { logger, routeErrorDetails } from './logger.js';
import { envelopeSchema } from '@crypto-pigeon/protocol';
import { notifyClient } from './ws-handler.js';

export function hexToUuid(hex: string): string {
  if (hex.includes('-')) return hex;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`.toLowerCase();
}

export function uuidToHex(uuid: string): string {
  return uuid.replace(/-/g, '').toLowerCase();
}

export function setupQueueRoutes(app: any) {
  // POST /api/messages/send
  app.post('/api/messages/send', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const senderDeviceId = request.user!.deviceId;
    const body = envelopeSchema.parse(request.body);

    const recipientDeviceId = body.mailboxId;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Verify conversation permission between sender and recipient users
      const senderUser = await client.query('SELECT user_id FROM device_identity_keys WHERE device_id = $1', [senderDeviceId]);
      const recipientUser = await client.query('SELECT user_id FROM device_identity_keys WHERE device_id = $1', [recipientDeviceId]);

      if (senderUser.rows.length === 0 || recipientUser.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(404).send({ error: 'recipient_not_found' });
      }

      const u1 = senderUser.rows[0].user_id;
      const u2 = recipientUser.rows[0].user_id;
      const [left, right] = u1 < u2 ? [u1, u2] : [u2, u1];

      const permissionRes = await client.query(
        'SELECT 1 FROM conversation_permissions WHERE user_one = $1 AND user_two = $2 AND revoked_at IS NULL',
        [left, right]
      );

      if (permissionRes.rows.length === 0) {
        await client.query('ROLLBACK');
        return reply.code(403).send({ error: 'conversation_not_approved' });
      }

      const messageId = hexToUuid(body.envelopeId);
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days TTL

      // Store in messages database table
      await client.query(
        `INSERT INTO messages (id, sender_id, recipient_id, encrypted_payload, type, timestamp, expires_at)
         VALUES ($1, $2, $3, $4, 'message', $5, $6)
         ON CONFLICT (id) DO NOTHING`,
        [
          messageId,
          senderDeviceId,
          recipientDeviceId,
          Buffer.from(body.ciphertext, 'base64'),
          Date.now(),
          expiresAt
        ]
      );

      await client.query('COMMIT');

      // Attempt WebSocket real-time delivery
      const deliveredViaWs = notifyClient(recipientDeviceId, {
        type: 'envelope',
        envelope: {
          version: 1,
          envelopeId: body.envelopeId,
          mailboxId: body.mailboxId,
          ciphertext: body.ciphertext
        }
      });

      if (deliveredViaWs) {
        logger.debug({ messageId }, 'Delivered message immediately via WebSocket');
      }

      return reply.code(202).send({ envelopeId: body.envelopeId });
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to enqueue message');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  // GET /api/messages/pending
  app.get('/api/messages/pending', { preHandler: authMiddleware }, async (request: FastifyRequest) => {
    const deviceId = request.user!.deviceId;
    
    // Auto-cleanup expired queue messages
    await pool.query('DELETE FROM messages WHERE expires_at < now()');

    const result = await pool.query(
      `SELECT id, sender_id, recipient_id, encrypted_payload 
       FROM messages 
       WHERE recipient_id = $1 AND delivered = false 
       ORDER BY timestamp ASC`,
      [deviceId]
    );

    return result.rows.map(row => ({
      version: 1,
      envelopeId: uuidToHex(row.id),
      senderId: row.sender_id,
      mailboxId: row.recipient_id,
      ciphertext: Buffer.from(row.encrypted_payload).toString('base64')
    }));
  });

  // POST /api/messages/ack
  app.post('/api/messages/ack', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const deviceId = request.user!.deviceId;
    const body = z.object({
      envelopeIds: z.array(z.string().regex(/^[0-9a-fA-F]{32}$/))
    }).parse(request.body);

    const messageUuids = body.envelopeIds.map(hexToUuid);

    try {
      // Delete acknowledged messages from database queue table
      await pool.query(
        'DELETE FROM messages WHERE id = ANY($1) AND recipient_id = $2',
        [messageUuids, deviceId]
      );
      return reply.code(204).send();
    } catch (error) {
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Failed to acknowledge messages');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    }
  });
}
