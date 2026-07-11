import crypto from 'node:crypto';
import type { FastifyRequest, FastifyReply } from 'fastify';
import { logger } from './logger.js';
import type { Vault } from './vault.js';

export interface SessionState {
  cookieToken: string;
  csrfToken: string;
  generation: number;
}

let activeSession: SessionState | null = null;
let bootstrapSecret: string | null = null;
let currentPort = 3100;

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function generateBootstrapSecret(port: number): string {
  currentPort = port;
  bootstrapSecret = crypto.randomBytes(32).toString('hex');
  return bootstrapSecret;
}

export function invalidateSession() {
  activeSession = null;
  logger.info('Local session invalidated (vault locked/unlocked/logged out)');
}

export function verifyLocalSession(request: FastifyRequest, reply: FastifyReply, vault: Vault) {
  // 1. Check Host header (DNS Rebinding Protection)
  const host = request.headers.host || '';
  const allowedHosts = [`127.0.0.1:${currentPort}`];
  if (!allowedHosts.includes(host)) {
    return reply.code(403).send({ error: 'invalid_host_header' });
  }

  // 2. Check Origin header (Cross-Origin Protection)
  const origin = request.headers.origin;
  if (origin) {
    const allowedOrigins = [`http://127.0.0.1:${currentPort}`];
    if (!allowedOrigins.includes(origin)) {
      return reply.code(403).send({ error: 'invalid_origin_header' });
    }
  }

  // Skip session check for static assets and HTML routes
  const url = request.url;
  if (!url.startsWith('/api/')) {
    return;
  }

  // Skip session check for bootstrap, session query, and vault create/open
  if (url === '/api/bootstrap' || url === '/api/session' || url === '/api/vault/create' || url === '/api/vault/open' || url === '/api/vault/status') {
    return;
  }

  // 3. Verify Session Cookie
  const cookieHeader = request.headers.cookie || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map(c => c.trim().split('='))
    .find(([name]) => name === 'crypto_pigeon_session')?.[1];

  if (!sessionCookie || !activeSession || sessionCookie !== activeSession.cookieToken) {
    return reply.code(401).send({ error: 'unauthorized_local_session' });
  }

  // 4. Verify CSRF Token (for write operations)
  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    const csrfHeader = request.headers['x-csrf-token'];
    if (!csrfHeader || csrfHeader !== activeSession.csrfToken) {
      return reply.code(403).send({ error: 'invalid_csrf_token' });
    }
  }

  // 5. Verify Vault is unlocked
  if (vault.isLocked()) {
    return reply.code(400).send({ error: 'vault_locked' });
  }
}

export function setupAuthRoutes(app: any, vault: Vault) {
  // POST /api/bootstrap
  app.post('/api/bootstrap', async (request: FastifyRequest, reply: FastifyReply) => {
    const { secret } = request.body as { secret?: string };
    
    if (!bootstrapSecret || !secret || !safeEqual(secret, bootstrapSecret)) {
      return reply.code(401).send({ error: 'invalid_bootstrap_secret' });
    }

    // Invalidate secret immediately (single-use)
    bootstrapSecret = null;

    // Initialize new session
    const cookieToken = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(32).toString('hex');
    
    activeSession = {
      cookieToken,
      csrfToken,
      generation: (activeSession?.generation ?? 0) + 1
    };

    reply.header('Set-Cookie', `crypto_pigeon_session=${cookieToken}; HttpOnly; SameSite=Strict; Path=/`);
    return { csrfToken, vaultState: vault.exists() ? (vault.isLocked() ? 'locked' : 'unlocked') : 'unconfigured' };
  });

  // GET /api/session
  app.get('/api/session', async (request: FastifyRequest, reply: FastifyReply) => {
    const cookieHeader = request.headers.cookie || '';
    const sessionCookie = cookieHeader
      .split(';')
      .map(c => c.trim().split('='))
      .find(([name]) => name === 'crypto_pigeon_session')?.[1];

    if (!sessionCookie || !activeSession || sessionCookie !== activeSession.cookieToken) {
      return reply.code(401).send({ error: 'unauthorized' });
    }

    // Re-establish CSRF token in memory
    const newCsrf = crypto.randomBytes(32).toString('hex');
    activeSession.csrfToken = newCsrf;

    return {
      csrfToken: newCsrf,
      vaultState: vault.exists() ? (vault.isLocked() ? 'locked' : 'unlocked') : 'unconfigured'
    };
  });
}

export function getSessionGeneration(): number {
  return activeSession?.generation ?? 0;
}
