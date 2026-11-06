import type { FastifyInstance } from 'fastify';
import { webRtcSignalSchema } from '@crypto-pigeon/protocol';
import { authMiddleware } from './auth.js';
import { pool } from './db.js';
import { notifyClient } from './ws-handler.js';

/** Rolling peer-pair budget, shared by both directions. Expired memory is capped. */
export class SignalBudget {
  private pairs = new Map<string, number[]>();
  take(from: string, to: string, now = Date.now()): boolean {
    for (const [key, times] of this.pairs) if (times[times.length - 1] <= now - 60000) this.pairs.delete(key);
    const key = [from, to].sort().join(':');
    const times = (this.pairs.get(key) ?? []).filter(time => time > now - 60000);
    if (times.length >= 30 || (!this.pairs.has(key) && this.pairs.size >= 10000)) return false;
    times.push(now); this.pairs.set(key, times); return true;
  }
}
const budget = new SignalBudget();

export async function forwardSignal(deviceId: string, input: unknown, stillAuthorized: () => Promise<boolean> = async () => true) {
  const signal = webRtcSignalSchema.parse(input), receivedAt = Date.now();
  if (!(await stillAuthorized())) return { delivered: false, reason: 'UNAUTHORIZED' };
  const sender = (await pool.query(`SELECT u.user_id, u.public_uid FROM device_identity_keys d
    JOIN users u ON u.user_id=d.user_id WHERE d.device_id=$1 AND d.revoked_at IS NULL AND u.revoked_at IS NULL`, [deviceId])).rows[0];
  if (!sender || sender.public_uid !== signal.fromUid || signal.fromUid === signal.toUid)
    return { delivered: false, reason: 'SENDER_MISMATCH' };
  if (!budget.take(signal.fromUid, signal.toUid)) return { delivered: false, reason: 'RATE_LIMITED' };
  const peer = (await pool.query(`SELECT d.device_id FROM users u JOIN device_identity_keys d ON d.user_id=u.user_id
    JOIN conversation_permissions p ON p.user_one=LEAST(u.user_id,$2::uuid) AND p.user_two=GREATEST(u.user_id,$2::uuid)
    WHERE u.public_uid=$1 AND u.revoked_at IS NULL AND d.revoked_at IS NULL AND p.revoked_at IS NULL`, [signal.toUid, sender.user_id])).rows[0];
  if (!peer) return { delivered: false, reason: 'CONTACT_NOT_APPROVED' };
  if (!(await stillAuthorized())) return { delivered: false, reason: 'UNAUTHORIZED' };
  if (Date.now() - receivedAt >= signal.ttlMs) return { delivered: false, reason: 'EXPIRED' };
  // No INSERT, offline queue, plaintext SDP/ICE, or unbounded socket buffering.
  return notifyClient(peer.device_id, signal, 256 * 1024)
    ? { delivered: true } : { delivered: false, reason: 'PEER_OFFLINE' };
}

export function setupSignalRoutes(app: FastifyInstance) {
  app.post('/api/signal', { bodyLimit: 128 * 1024, preHandler: authMiddleware }, async (request, reply) => {
    const result = await forwardSignal(request.user!.deviceId, request.body);
    return reply.code(result.reason === 'RATE_LIMITED' ? 429 : result.reason === 'SENDER_MISMATCH' || result.reason === 'CONTACT_NOT_APPROVED' ? 403 : 200).send(result);
  });
}
