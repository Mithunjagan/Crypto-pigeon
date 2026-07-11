import crypto from 'node:crypto';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { pool } from './db.js';
import { env } from './config.js';
import { logger } from './logger.js';
import {
  deviceIdSchema,
  challengeRequestSchema,
  challengeVerifySchema,
  activationPayloadSchema,
  verifyChallenge,
  usernameSchema
} from '@crypto-pigeon/protocol';

// In-memory challenge store: deviceId -> { challenge, expiresAt }
export const activeChallenges = new Map<string, { challenge: string; expiresAt: number }>();

// Helper to compute HMAC-SHA256 for activation codes
export function computeHmac(code: string, pepper: string): string {
  return crypto.createHmac('sha256', pepper).update(code).digest('hex');
}

// Timing-safe comparison of strings
export function timingSafeCompare(a: string, b: string): boolean {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
  } catch {
    return false;
  }
}

// Authentication middleware for Fastify
export const authMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.code(401).send({ error: 'unauthorized_missing_token' });
  }

  const token = authHeader.substring(7);
  try {
    const nowMs = Date.now();
    const result = await pool.query(
      'SELECT device_id FROM sessions WHERE token = $1 AND expires_at > $2',
      [token, nowMs]
    );

    if (result.rows.length === 0) {
      return reply.code(401).send({ error: 'unauthorized_invalid_token' });
    }

    request.user = {
      deviceId: result.rows[0].device_id
    };
  } catch (error) {
    logger.error({ err: error }, 'Token verification failed');
    return reply.code(500).send({ error: 'internal_error' });
  }
};

// Admin authentication middleware
export const adminAuthMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return reply.code(401).send({ error: 'admin_auth_required' });
  }

  const token = authHeader.substring(7);
  const submitted = Buffer.from(token);
  const expected = Buffer.from(env.ADMIN_TOKEN);

  const isValid = submitted.length === expected.length && crypto.timingSafeEqual(submitted, expected);
  if (!isValid) {
    return reply.code(401).send({ error: 'invalid_admin_token' });
  }
};

export function setupAuthRoutes(app: any) {
  // POST /api/auth/challenge
  app.post('/api/auth/challenge', async (request: FastifyRequest, reply: FastifyReply) => {
    const { deviceId } = challengeRequestSchema.parse(request.body);

    // Verify that device exists in DB before generating challenge
    const devCheck = await pool.query('SELECT 1 FROM device_identity_keys WHERE device_id = $1 AND revoked_at IS NULL', [deviceId]);
    if (devCheck.rows.length === 0) {
      return reply.code(401).send({ error: 'device_not_registered' });
    }

    const challenge = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60 * 1000; // 60s validity

    activeChallenges.set(deviceId, { challenge, expiresAt });

    return { challenge, expiresAt };
  });

  // POST /api/auth/respond
  app.post('/api/auth/respond', async (request: FastifyRequest, reply: FastifyReply) => {
    const { deviceId, challenge, signature, relayHostname } = challengeVerifySchema.parse(request.body);

    const stored = activeChallenges.get(deviceId);
    if (!stored) {
      return reply.code(401).send({ error: 'challenge_not_found' });
    }

    // Single-use: consume challenge immediately
    activeChallenges.delete(deviceId);

    if (stored.challenge !== challenge) {
      return reply.code(401).send({ error: 'challenge_mismatch' });
    }

    if (Date.now() > stored.expiresAt) {
      return reply.code(401).send({ error: 'challenge_expired' });
    }

    // Lookup device's auth_public_key
    const devRes = await pool.query(
      'SELECT auth_public_key FROM device_identity_keys WHERE device_id = $1 AND revoked_at IS NULL',
      [deviceId]
    );

    if (devRes.rows.length === 0) {
      return reply.code(401).send({ error: 'device_not_registered' });
    }

    const authPublicKey = devRes.rows[0].auth_public_key;
    const msg = Buffer.from(deviceId + challenge + relayHostname, 'utf8');
    const isValid = verifyChallenge(authPublicKey, msg, Buffer.from(signature, 'hex'));

    if (!isValid) {
      return reply.code(401).send({ error: 'invalid_signature' });
    }

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    await pool.query(
      'INSERT INTO sessions (token, device_id, expires_at) VALUES ($1, $2, $3)',
      [sessionToken, deviceId, expiresAt]
    );

    return { sessionToken, expiresAt };
  });

  // POST /api/access/apply
  app.post('/api/access/apply', async (request: FastifyRequest, reply: FastifyReply) => {
    const { username } = z.object({ username: usernameSchema }).parse(request.body);
    const requestId = crypto.randomUUID();

    try {
      const existing = await pool.query(
        'SELECT 1 FROM users WHERE username=$1 UNION ALL SELECT 1 FROM access_requests WHERE username=$1 LIMIT 1',
        [username]
      );

      if (existing.rows.length > 0) {
        return reply.code(202).send({ request_id: requestId, status: 'received' });
      }

      await pool.query(
        'INSERT INTO access_requests (request_id, username, status) VALUES ($1, $2, \'pending\')',
        [requestId, username]
      );
    } catch {
      // Return 202 to avoid enumerability of requests
      return reply.code(202).send({ request_id: requestId, status: 'received' });
    }

    return reply.code(202).send({ request_id: requestId, status: 'received' });
  });

  // POST /api/access/activate
  app.post('/api/access/activate', async (request: FastifyRequest, reply: FastifyReply) => {
    const payload = activationPayloadSchema.parse(request.body);
    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      // Fetch request with lock
      const appQuery = await client.query(
        `SELECT username, status, activation_code_hash, attempt_count, activation_expires_at 
         FROM access_requests 
         WHERE request_id = $1 FOR UPDATE`,
        [payload.requestId]
      );

      const requestRow = appQuery.rows[0];
      if (!requestRow) {
        await client.query('ROLLBACK');
        return reply.code(401).send({ error: 'activation_failed' });
      }

      if (requestRow.status !== 'approved') {
        await client.query('ROLLBACK');
        return reply.code(401).send({ error: 'activation_failed' });
      }

      if (new Date() > new Date(requestRow.activation_expires_at)) {
        await client.query('ROLLBACK');
        return reply.code(401).send({ error: 'activation_failed' });
      }

      if (requestRow.attempt_count >= 5) {
        await client.query('ROLLBACK');
        return reply.code(401).send({ error: 'activation_failed' });
      }

      // Increment attempt count
      await client.query(
        'UPDATE access_requests SET attempt_count = attempt_count + 1 WHERE request_id = $1',
        [payload.requestId]
      );

      const computedHash = computeHmac(payload.activationCode, env.ACTIVATION_PEPPER);
      const isMatch = timingSafeCompare(requestRow.activation_code_hash, computedHash);

      if (!isMatch) {
        await client.query('COMMIT'); // Commit incremented attempt count
        return reply.code(401).send({ error: 'activation_failed' });
      }

      const userId = crypto.randomUUID();
      const deviceId = payload.requestId; // Bind requestId directly to device_id

      // 1. Create User
      await client.query(
        'INSERT INTO users (user_id, username, password_hash) VALUES ($1, $2, \'device_auth_only\')',
        [userId, requestRow.username]
      );

      // 2. Create Device
      await client.query(
        `INSERT INTO device_identity_keys (
          device_id, user_id, identity_public_key, auth_public_key, registration_id, signal_device_id
        ) VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          deviceId,
          userId,
          Buffer.from(payload.signalIdentityPublicKey, 'base64'),
          Buffer.from(payload.deviceAuthPublicKey, 'base64'),
          payload.registrationId,
          payload.signalDeviceId
        ]
      );

      // 3. Insert Signed Prekey
      await client.query(
        `INSERT INTO signed_prekeys (device_id, signal_prekey_id, public_key, signature) 
         VALUES ($1, $2, $3, $4)`,
        [
          deviceId,
          payload.signedPrekey.id,
          Buffer.from(payload.signedPrekey.publicKey, 'base64'),
          Buffer.from(payload.signedPrekey.signature, 'base64')
        ]
      );

      // 4. Insert One-Time Prekeys
      for (const prekey of payload.oneTimePrekeys) {
        await client.query(
          `INSERT INTO one_time_prekeys (device_id, signal_prekey_id, public_key) 
           VALUES ($1, $2, $3)`,
          [deviceId, prekey.id, Buffer.from(prekey.publicKey, 'base64')]
        );
      }

      // 5. Insert PQ One-Time Prekeys
      for (const prekey of payload.pqOneTimePrekeys) {
        await client.query(
          `INSERT INTO pq_one_time_prekeys (device_id, signal_prekey_id, public_key, signature, prekey_type) 
           VALUES ($1, $2, $3, $4, 'one_time')`,
          [deviceId, prekey.id, Buffer.from(prekey.publicKey, 'base64'), Buffer.from(prekey.signature, 'base64')]
        );
      }

      // 6. Insert PQ Last-Resort Prekey
      await client.query(
        `INSERT INTO pq_one_time_prekeys (device_id, signal_prekey_id, public_key, signature, prekey_type) 
         VALUES ($1, $2, $3, $4, 'last_resort')`,
        [
          deviceId,
          payload.pqLastResortPrekey.id,
          Buffer.from(payload.pqLastResortPrekey.publicKey, 'base64'),
          Buffer.from(payload.pqLastResortPrekey.signature, 'base64')
        ]
      );

      // Update access request status to activated
      await client.query(
        'UPDATE access_requests SET status = \'activated\', activation_used_at = now() WHERE request_id = $1',
        [payload.requestId]
      );

      await client.query('COMMIT');

      // Generate session token to log them in immediately
      const sessionToken = crypto.randomBytes(32).toString('base64url');
      const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

      await pool.query(
        'INSERT INTO sessions (token, device_id, expires_at) VALUES ($1, $2, $3)',
        [sessionToken, deviceId, expiresAt]
      );

      return reply.code(201).send({ sessionToken, expiresAt, userId });
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error({ err: error }, 'Activation failed');
      return reply.code(500).send({ error: 'internal_error' });
    } finally {
      client.release();
    }
  });
}
