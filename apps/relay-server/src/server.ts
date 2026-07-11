import http from 'node:http';
import Fastify from 'fastify';
import type { FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
import { env, loggerLevel, maxBodySize } from './config.js';
import { logger } from './logger.js';
import { initDb, pool } from './db.js';
import { setupAuthRoutes, adminAuthMiddleware, computeHmac } from './auth.js';
import { setupPrekeysRoutes } from './prekeys.js';
import { setupQueueRoutes } from './queue.js';
import { setupAttachmentsRoutes } from './attachments.js';
import { setupWebSocket } from './ws-handler.js';
import { privacyPreservingKeyGenerator } from './rate-limit.js';

// Setup Fastify with standard settings
const app = Fastify({
  logger: false, // Use our custom redacting structured logger instead
  bodyLimit: maxBodySize
});

// Configure CORS and rate limiter
await app.register(cors, {
  origin: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true
});

await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
  keyGenerator: privacyPreservingKeyGenerator
});

// Setup endpoints for different modules
setupAuthRoutes(app);
setupPrekeysRoutes(app);
setupQueueRoutes(app);
setupAttachmentsRoutes(app);

// Helper for escaping HTML in admin dashboard
const escapeHtml = (value: string) => value.replace(/[&<>'"]/g, char => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  "'": '&#39;',
  '"': '&quot;'
})[char]!);

// Helper for cookie parsing
const cookie = (header: string | undefined, name: string) => 
  header?.split(';').map(value => value.trim().split('=')).find(([key]) => key === name)?.slice(1).join('=');

const getAdminSession = (request: FastifyRequest): boolean => {
  const token = cookie(request.headers.cookie, 'crypto_pigeon_admin');
  return token === env.ADMIN_TOKEN;
};

// Admin authentication guard for routes
const requireAdminGuard = async (request: FastifyRequest, reply: FastifyReply) => {
  if (!getAdminSession(request)) {
    return reply.code(401).send({ error: 'admin_auth_required' });
  }
};

// Admin UI Dashboard Routes
app.post('/api/admin/login', async (request: FastifyRequest, reply: FastifyReply) => {
  const { username, password } = z.object({ username: z.string(), password: z.string() }).parse(request.body);
  const isValid = username === env.ADMIN_USERNAME && password === env.ADMIN_TOKEN;
  if (!isValid) {
    return reply.code(401).send({ error: 'invalid_admin_credentials' });
  }
  reply.header('Set-Cookie', `crypto_pigeon_admin=${env.ADMIN_TOKEN}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
  return { ok: true };
});

app.post('/api/admin/logout', async (_request: FastifyRequest, reply: FastifyReply) => {
  reply.header('Set-Cookie', 'crypto_pigeon_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  return reply.code(204).send();
});

app.get('/api/admin/appeals', { preHandler: requireAdminGuard }, async () => {
  const result = await pool.query(
    `SELECT a.appeal_id, a.status, a.created_at, requester.username AS requester, target.username AS target 
     FROM connection_appeals a 
     JOIN users requester ON requester.user_id = a.requester_user_id 
     JOIN users target ON target.user_id = a.target_user_id 
     WHERE a.status = 'pending' 
     ORDER BY a.created_at`
  );
  return result.rows;
});

app.post('/api/admin/appeals/:appealId/approve', { preHandler: requireAdminGuard }, async (request: FastifyRequest, reply: FastifyReply) => {
  const appealId = z.string().uuid().parse((request.params as any).appealId);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const appeal = await client.query(
      "SELECT requester_user_id, target_user_id FROM connection_appeals WHERE appeal_id = $1 AND status = 'pending' FOR UPDATE",
      [appealId]
    );
    if (appeal.rows.length === 0) {
      await client.query('ROLLBACK');
      return reply.code(404).send({ error: 'pending_appeal_not_found' });
    }
    
    const u1 = appeal.rows[0].requester_user_id;
    const u2 = appeal.rows[0].target_user_id;
    const [userOne, userTwo] = u1 < u2 ? [u1, u2] : [u2, u1];

    await client.query(
      `INSERT INTO approved_connections (user_one, user_two) 
       VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [userOne, userTwo]
    );
    await client.query(
      "UPDATE connection_appeals SET status = 'approved', decided_at = now() WHERE appeal_id = $1",
      [appealId]
    );
    await client.query('COMMIT');
    return { ok: true };
  } catch (error) {
    await client.query('ROLLBACK');
    logger.error({ err: error }, 'Failed to approve appeal');
    return reply.code(500).send({ error: 'internal_error' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/appeals/:appealId/reject', { preHandler: requireAdminGuard }, async (request: FastifyRequest, reply: FastifyReply) => {
  const appealId = z.string().uuid().parse((request.params as any).appealId);
  const result = await pool.query(
    "UPDATE connection_appeals SET status = 'rejected', decided_at = now() WHERE appeal_id = $1 AND status = 'pending'",
    [appealId]
  );
  return result.rowCount ? { ok: true } : reply.code(404).send({ error: 'pending_appeal_not_found' });
});

app.post('/api/admin/connections/:userOne/:userTwo/cancel', { preHandler: requireAdminGuard }, async (request: FastifyRequest, reply: FastifyReply) => {
  const params = z.object({ userOne: z.string().uuid(), userTwo: z.string().uuid() }).parse(request.params as any);
  const [userOne, userTwo] = params.userOne < params.userTwo ? [params.userOne, params.userTwo] : [params.userTwo, params.userOne];

  const result = await pool.query(
    'UPDATE approved_connections SET active = false, cancelled_at = now() WHERE user_one = $1 AND user_two = $2 AND active = true',
    [userOne, userTwo]
  );
  return result.rowCount ? { ok: true } : reply.code(404).send({ error: 'active_connection_not_found' });
});

app.get('/admin', async (request: FastifyRequest, reply: FastifyReply) => {
  const isAdmin = getAdminSession(request);
  if (!isAdmin) {
    return reply.type('text/html').send(`<!doctype html><title>Crypto Pigeon Admin</title><style>body{font:16px system-ui;background:#102018;color:#eaf3ef;max-width:480px;margin:10vh auto;padding:24px}input,button{display:block;width:100%;box-sizing:border-box;padding:11px;margin:10px 0;border-radius:7px}button{background:#8fd4a8;border:0;font-weight:700}</style><h1>Crypto Pigeon Admin</h1><p>Manage connection appeals. This dashboard cannot read messages.</p><input id="username" placeholder="Username" autocomplete="username"><input id="password" type="password" placeholder="Password" autocomplete="current-password"><button onclick="login()">Sign in</button><p id="error"></p><script>async function login(){let r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:username.value,password:password.value})});if(r.ok)location.reload();else error.textContent='Invalid credentials';}</script>`);
  }
  
  const appeals = await pool.query(
    `SELECT a.appeal_id, a.created_at, requester.username AS requester, target.username AS target 
     FROM connection_appeals a 
     JOIN users requester ON requester.user_id = a.requester_user_id 
     JOIN users target ON target.user_id = a.target_user_id 
     WHERE a.status = 'pending' 
     ORDER BY a.created_at`
  );
  
  const rows = appeals.rows.map(value => `<tr><td>${escapeHtml(value.requester)}</td><td>${escapeHtml(value.target)}</td><td>${new Date(value.created_at).toLocaleString()}</td><td><button onclick="decide('${value.appeal_id}','approve')">Approve</button> <button class="cancel" onclick="decide('${value.appeal_id}','reject')">Reject</button></td></tr>`).join('') || '<tr><td colspan="4">No pending appeals.</td></tr>';
  
  const active = await pool.query(
    `SELECT c.user_one, c.user_two, one_user.username AS one_name, two_user.username AS two_name, c.activated_at 
     FROM approved_connections c 
     JOIN users one_user ON one_user.user_id = c.user_one 
     JOIN users two_user ON two_user.user_id = c.user_two 
     WHERE c.active = true AND c.cancelled_at IS NULL 
     ORDER BY c.activated_at DESC`
  );
  
  const activeRows = active.rows.map(value => `<tr><td>${escapeHtml(value.one_name)}</td><td>${escapeHtml(value.two_name)}</td><td>${new Date(value.activated_at).toLocaleString()}</td><td><button class="cancel" onclick="cancelConnection('${value.user_one}','${value.user_two}')">Cancel connection</button></td></tr>`).join('') || '<tr><td colspan="4">No active connections.</td></tr>';
  
  return reply.type('text/html').send(`<!doctype html><title>Crypto Pigeon Admin</title><style>body{font:16px system-ui;background:#102018;color:#eaf3ef;max-width:900px;margin:5vh auto;padding:24px}table{width:100%;border-collapse:collapse;margin-bottom:32px}td,th{padding:12px;border-bottom:1px solid #456;text-align:left}button{padding:8px 12px;border:0;border-radius:6px;background:#8fd4a8;font-weight:700}.cancel{background:#e8a29b}</style><h1>Crypto Pigeon Admin</h1><p>Approve or cancel connections. This dashboard cannot read messages, files, or connection passkeys.</p><h2>Pending appeals</h2><table><thead><tr><th>Requester</th><th>Target</th><th>Requested</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table><h2>Active chats</h2><table><thead><tr><th>User one</th><th>User two</th><th>Activated</th><th>Control</th></tr></thead><tbody>${activeRows}</tbody></table><p><button onclick="logout()">Sign out</button></p><script>async function decide(id,action){let r=await fetch('/api/admin/appeals/'+id+'/'+action,{method:'POST'});if(r.ok)location.reload();else alert('Action failed');}async function cancelConnection(a,b){let r=await fetch('/api/admin/connections/'+a+'/'+b+'/cancel',{method:'POST'});if(r.ok)location.reload();else alert('Cancel failed');}async function logout(){await fetch('/api/admin/logout',{method:'POST'});location.reload();}</script>`);
});

// Health check
app.get('/healthz', async () => ({ ok: true }));

// Global error handler mapping Zod errors to 400
app.setErrorHandler((error, _request, reply) => {
  if (error instanceof z.ZodError) {
    return reply.code(400).send({ error: 'invalid_request', details: error.errors });
  }
  logger.error({ err: error }, 'Unhandled server error');
  return reply.code(500).send({ error: 'internal_error' });
});

// Run DB setup and migrations
await initDb();

// Bind WebSocket to standard server
setupWebSocket(app.server);

// Start listening
await app.listen({ port: env.PORT, host: env.HOST });
logger.info(`Relay Server running on ${env.HOST}:${env.PORT} with log level ${loggerLevel}`);
