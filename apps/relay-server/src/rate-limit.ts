import crypto from 'node:crypto';
import type { FastifyRequest } from 'fastify';

// Daily rotating salt to hash client IP addresses
let dailySalt = crypto.randomBytes(16).toString('hex');

// Rotate salt every 24 hours
setInterval(() => {
  dailySalt = crypto.randomBytes(16).toString('hex');
}, 24 * 60 * 60 * 1000).unref();

export function privacyPreservingKeyGenerator(req: FastifyRequest): string {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  // If request is authenticated, we can rate limit by device ID; otherwise by hashed IP
  if (req.user?.deviceId) {
    return `device:${req.user.deviceId}`;
  }
  const hashedIp = crypto.createHash('sha256').update(ip + dailySalt).digest('hex');
  return `ip:${hashedIp}`;
}
