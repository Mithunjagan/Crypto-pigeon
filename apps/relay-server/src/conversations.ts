import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { usernameSchema } from '@crypto-pigeon/protocol';
import { authMiddleware } from './auth.js';
import { pool } from './db.js';
import { logger, routeErrorDetails } from './logger.js';

const requestIdSchema = z.string().uuid();

async function currentUserId(deviceId: string): Promise<string | null> {
  const result = await pool.query(
    `SELECT d.user_id FROM device_identity_keys d
     JOIN users u ON u.user_id = d.user_id
     WHERE d.device_id = $1 AND d.revoked_at IS NULL AND u.revoked_at IS NULL`,
    [deviceId]
  );
  return result.rows[0]?.user_id ?? null;
}

export function setupConversationRoutes(app: any) {
  // The recipient controls authorization. Searching/adding a contact does not
  // disclose its prekey bundle or permit delivery until this is accepted.
  app.post('/api/conversations/requests', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { recipientUsername } = z.object({ recipientUsername: usernameSchema }).parse(request.body);
    const requesterUserId = await currentUserId(request.user!.deviceId);
    if (!requesterUserId) return reply.code(401).send({ error: 'device_not_active' });

    const recipient = await pool.query(
      'SELECT user_id FROM users WHERE username = $1 AND revoked_at IS NULL',
      [recipientUsername]
    );
    // Do not distinguish an unknown and a non-connectable user to callers.
    if (!recipient.rows[0] || recipient.rows[0].user_id === requesterUserId) {
      return reply.code(202).send({ status: 'received' });
    }

    await pool.query(
      `INSERT INTO connection_requests (requester_user_id, recipient_user_id, status, expires_at)
       VALUES ($1, $2, 'pending', now() + interval '7 days')
       ON CONFLICT (requester_user_id, recipient_user_id) DO UPDATE
       SET status = 'pending', expires_at = EXCLUDED.expires_at, created_at = now(), decided_at = NULL
       WHERE connection_requests.status = 'rejected'`,
      [requesterUserId, recipient.rows[0].user_id]
    );
    return reply.code(202).send({ status: 'received' });
  });

  app.get('/api/conversations/requests', { preHandler: authMiddleware }, async (request: FastifyRequest) => {
    const userId = await currentUserId(request.user!.deviceId);
    if (!userId) return [];
    const result = await pool.query(
      `SELECT r.request_id, u.username AS requester_username, r.created_at, r.expires_at
       FROM connection_requests r JOIN users u ON u.user_id = r.requester_user_id
       WHERE r.recipient_user_id = $1 AND r.status = 'pending' AND r.expires_at > now()
       ORDER BY r.created_at`,
      [userId]
    );
    return result.rows;
  });

  app.post('/api/conversations/requests/:requestId/accept', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const requestId = requestIdSchema.parse((request.params as { requestId: string }).requestId);
    const recipientUserId = await currentUserId(request.user!.deviceId);
    if (!recipientUserId) return reply.code(401).send({ error: 'device_not_active' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const pending = await client.query(
        `SELECT requester_user_id, recipient_user_id FROM connection_requests
         WHERE request_id = $1 AND recipient_user_id = $2 AND status = 'pending' AND expires_at > now()
         FOR UPDATE`,
        [requestId, recipientUserId]
      );
      if (!pending.rows[0]) {
        await client.query('ROLLBACK');
        return reply.code(404).send({ error: 'pending_conversation_request_not_found' });
      }
      const { requester_user_id, recipient_user_id } = pending.rows[0];
      const [userOne, userTwo] = requester_user_id < recipient_user_id
        ? [requester_user_id, recipient_user_id] : [recipient_user_id, requester_user_id];
      await client.query('UPDATE connection_requests SET status = \'accepted\', decided_at = now() WHERE request_id = $1', [requestId]);
      await client.query(
        `INSERT INTO conversation_permissions (user_one, user_two) VALUES ($1, $2)
         ON CONFLICT (user_one, user_two) DO UPDATE SET revoked_at = NULL`,
        [userOne, userTwo]
      );
      await client.query('COMMIT');
      return { ok: true, status: 'accepted' };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      logger.error(routeErrorDetails(error, request.method, request.routeOptions.url ?? request.url), 'Conversation request acceptance failed');
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    } finally {
      client.release();
    }
  });

  app.post('/api/conversations/requests/:requestId/reject', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const requestId = requestIdSchema.parse((request.params as { requestId: string }).requestId);
    const recipientUserId = await currentUserId(request.user!.deviceId);
    const result = await pool.query(
      `UPDATE connection_requests SET status = 'rejected', decided_at = now()
       WHERE request_id = $1 AND recipient_user_id = $2 AND status = 'pending'`,
      [requestId, recipientUserId]
    );
    return result.rowCount ? { ok: true, status: 'rejected' } : reply.code(404).send({ error: 'pending_conversation_request_not_found' });
  });
}
