import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
import Fastify from 'fastify';
import type { FastifyRequest, FastifyReply } from 'fastify';
import fastifyStatic from '@fastify/static';
import { z } from 'zod';
import { env } from './config.js';
import { logger } from './logger.js';
import { Vault } from './vault.js';
import { LocalSignalStore } from './signal-store.js';
import { RelayClient, RelayClientError } from './relay-client.js';
import { setSecurityHeaders } from './security.js';
import {
  generateBootstrapSecret,
  invalidateSession,
  verifyLocalSession,
  setupAuthRoutes
} from './auth.js';
import {
  addContactAndSession,
  sendMessage,
  syncMessages
} from './messages.js';
import {
  encryptAndUploadAttachment,
  readDecryptedAttachment
} from './attachments.js';
import { startDisappearingMessageJob } from './disappearing.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const vault = new Vault(env.CRYPTO_PIGEON_HOME);
let store: LocalSignalStore | null = null;
const relayClient = new RelayClient(env.RELAY_URL);

const app = Fastify({
  logger: false,
  bodyLimit: 25 * 1024 * 1024 // 25 MB limit for attachments
});

// Setup Host/Origin/CSRF validation hook
app.addHook('preHandler', (request: FastifyRequest, reply: FastifyReply, done) => {
  setSecurityHeaders(reply);
  const err = verifyLocalSession(request, reply, vault);
  if (err) return; // Hook already replied
  done();
});

// Setup auth endpoints (bootstrap, CSRF refresh)
await vault.initialize();
setupAuthRoutes(app, vault);

// Helper to get active store
function getStore(): LocalSignalStore {
  if (vault.isLocked()) throw new Error('vault_locked');
  if (!store) {
    store = new LocalSignalStore(vault.database());
  }
  return store;
}

function errorCode(error: unknown): string {
  return error instanceof RelayClientError ? error.code : 'LOCAL_VAULT_PERSISTENCE_FAILED';
}

function logRouteError(error: unknown, request: FastifyRequest, message: string) {
  const cause = error instanceof Error ? error : new Error('unknown_error');
  logger.error({
    errorName: cause.name,
    safeMessage: cause.message,
    stack: process.env.NODE_ENV === 'development' ? cause.stack : undefined,
    method: request.method,
    route: request.routeOptions.url
  }, message);
}

function requireRegistered(reply: FastifyReply): LocalSignalStore | null {
  const activeStore = getStore();
  if (!activeStore.isRegistered()) {
    reply.code(409).send({ error: 'DEVICE_NOT_REGISTERED' });
    return null;
  }
  return activeStore;
}

// Local API Endpoints

// GET /api/vault/status
app.get('/api/vault/status', async () => {
  return {
    vaultState: vault.exists() ? (vault.isLocked() ? 'locked' : 'unlocked') : 'unconfigured'
  };
});

// POST /api/vault/create
app.post('/api/vault/create', async (request: FastifyRequest, reply: FastifyReply) => {
  const { password } = z.object({ password: z.string() }).parse(request.body);
  try {
    await vault.create(password);
    store = new LocalSignalStore(vault.database());
    return { ok: true };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'vault_creation_failed' });
  }
});

// POST /api/vault/open
app.post('/api/vault/open', async (request: FastifyRequest, reply: FastifyReply) => {
  const { password } = z.object({ password: z.string() }).parse(request.body);
  try {
    await vault.unlock(password);
    store = new LocalSignalStore(vault.database());
    return { ok: true };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'invalid_password' });
  }
});

// POST /api/vault/lock
app.post('/api/vault/lock', async () => {
  vault.lock();
  store = null;
  invalidateSession();
  return { ok: true };
});

// POST /api/vault/change-password
app.post('/api/vault/change-password', async (request: FastifyRequest, reply: FastifyReply) => {
  const { oldPassword, newPassword } = z.object({
    oldPassword: z.string(),
    newPassword: z.string()
  }).parse(request.body);

  try {
    await vault.changePassword(oldPassword, newPassword);
    return { ok: true };
  } catch (error: any) {
    return reply.code(400).send({ error: error.message || 'password_change_failed' });
  }
});

// POST /api/access/apply
app.post('/api/access/apply', async (request: FastifyRequest, reply: FastifyReply) => {
  const { username } = z.object({ username: z.string() }).parse(request.body);
  try {
    const result = await relayClient.applyAccess(username);
    vault.database().prepare(
      `INSERT INTO activation_state (singleton, request_id, username, status, expires_at, updated_at)
       VALUES (1, ?, ?, 'pending', ?, ?)
       ON CONFLICT(singleton) DO UPDATE SET request_id=excluded.request_id, username=excluded.username,
         status='pending', expires_at=excluded.expires_at, updated_at=excluded.updated_at`
    ).run([result.requestId, result.username, result.expiresAt ?? null, Date.now()]);
    return reply.code(202).send(result);
  } catch (error) {
    logRouteError(error, request, 'Access application failed');
    return reply.code(error instanceof RelayClientError ? error.status : 503).send({ error: errorCode(error) });
  }
});

app.get('/api/access/state', async () => {
  const value = vault.database().prepare(
    'SELECT request_id, username, status, expires_at FROM activation_state WHERE singleton=1'
  ).get<{ request_id: string; username: string; status: 'pending' | 'activated'; expires_at: string | null }>();
  if (!value) return { status: 'idle' as const };
  return {
    requestId: value.request_id,
    username: value.username,
    status: value.status,
    expiresAt: value.expires_at ?? undefined
  };
});

// POST /api/access/activate
app.post('/api/access/activate', async (request: FastifyRequest, reply: FastifyReply) => {
  const body = (request.body ?? {}) as Record<string, unknown>;
  if (typeof body.requestId !== 'string' || body.requestId.trim() === '') {
    return reply.code(400).send({ error: 'REQUEST_ID_REQUIRED' });
  }
  if (typeof body.activationCode !== 'string' || body.activationCode.trim() === '') {
    return reply.code(400).send({ error: 'ACTIVATION_CODE_REQUIRED' });
  }
  const { requestId, activationCode } = z.object({
    requestId: z.string().uuid(),
    activationCode: z.string().min(20).max(256)
  }).parse(body);

  if (vault.isLocked()) {
    return reply.code(400).send({ error: 'vault_locked' });
  }

  try {
    const activeStore = getStore();
    // 1. Generate identity public bundle locally
    const bundle = await activeStore.ensureIdentity();

    // 2. Activate on relay sending the full activation payload
    const activateRes = await relayClient.activateAccess({
      requestId,
      activationCode,
      deviceId: bundle.deviceId,
      deviceAuthPublicKey: bundle.deviceAuthPublicKey,
      signalIdentityPublicKey: bundle.identityPublicKey,
      registrationId: bundle.registrationId,
      signalDeviceId: bundle.signalDeviceId,
      signedPrekey: bundle.signedPrekey,
      oneTimePrekeys: bundle.oneTimePrekeys,
      pqOneTimePrekeys: bundle.pqOneTimePrekeys,
      pqLastResortPrekey: bundle.pqLastResortPrekey
    });

    // Account id, device id, token, and registration state are committed in
    // one local-vault transaction. Retrying the same activation is idempotent.
    activeStore.completeRegistration({
      userId: activateRes.userId,
      deviceId: activateRes.deviceId,
      username: activateRes.username,
      sessionToken: activateRes.sessionToken
    });

    return { ok: true, deviceId: activateRes.deviceId };
  } catch (error) {
    logRouteError(error, request, 'Activation failed');
    return reply.code(error instanceof RelayClientError ? error.status : 500).send({ error: errorCode(error) });
  }
});

// GET /api/contacts
app.get('/api/contacts', async () => {
  const db = vault.database();
  const contacts = db.prepare(
    `SELECT c.contact_id, c.username, c.verified, c.identity_changed, conv.conversation_id
     FROM contacts c JOIN conversations conv ON conv.contact_id = c.contact_id
     ORDER BY c.username`
  ).all();
  return contacts;
});

// POST /api/contacts/add
app.post('/api/contacts/add', async (request: FastifyRequest) => {
  const { username } = z.object({ username: z.string() }).parse(request.body);
  const activeStore = getStore();
  return addContactAndSession(vault, activeStore, relayClient, username);
});

// Conversation authorization is recipient-controlled.  A contact prekey
// bundle cannot be fetched until the recipient has accepted this request.
app.post('/api/conversations/requests', async (request: FastifyRequest, reply: FastifyReply) => {
  const { recipientUsername } = z.object({ recipientUsername: z.string().trim().toLowerCase() }).parse(request.body);
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, '/api/conversations/requests', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ recipientUsername })
  });
  return reply.code(res.status).send(await res.json());
});

app.get('/api/conversations/requests', async (request: FastifyRequest, reply: FastifyReply) => {
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, '/api/conversations/requests');
  return reply.code(res.status).send(await res.json());
});

app.post('/api/conversations/requests/:requestId/:decision', async (request: FastifyRequest, reply: FastifyReply) => {
  const params = z.object({ requestId: z.string().uuid(), decision: z.enum(['accept', 'reject']) }).parse(request.params);
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const res = await relayClient.request(vault, activeStore, `/api/conversations/requests/${params.requestId}/${params.decision}`, { method: 'POST' });
  return reply.code(res.status).send(await res.json());
});

// POST /api/send
app.post('/api/send', async (request: FastifyRequest) => {
  const { conversationId, plaintext, attachmentManifest } = z.object({
    conversationId: z.string().uuid(),
    plaintext: z.string(),
    attachmentManifest: z.any().optional()
  }).parse(request.body);

  const activeStore = getStore();
  return sendMessage(vault, activeStore, relayClient, conversationId, plaintext, attachmentManifest);
});

// GET /api/messages/:conversationId
app.get('/api/messages/:conversationId', async (request: FastifyRequest) => {
  const conversationId = z.string().uuid().parse((request.params as any).conversationId);
  const db = vault.database();
  
  const messages = db.prepare(
    `SELECT message_id, conversation_id, direction, plaintext, sent_at, received_at, status 
     FROM messages 
     WHERE conversation_id = ? 
     ORDER BY sent_at, received_at ASC`
  ).all([conversationId]);

  return messages;
});

// POST /api/fetch-messages
app.post('/api/fetch-messages', async (_request: FastifyRequest, reply: FastifyReply) => {
  const activeStore = requireRegistered(reply);
  if (!activeStore) return;
  const count = await syncMessages(vault, activeStore, relayClient);
  return { received: count };
});

app.setErrorHandler((error, request, reply) => {
  logRouteError(error, request, 'Unhandled local-daemon error');
  if (error instanceof z.ZodError) {
    return reply.code(400).send({ error: 'INVALID_REQUEST' });
  }
  return reply.code(500).send({ error: 'INTERNAL_ERROR' });
});

// POST /api/attachments/encrypt
app.post('/api/attachments/encrypt', async (request: FastifyRequest) => {
  const { filedataB64, filename, mimeType } = z.object({
    filedataB64: z.string(),
    filename: z.string(),
    mimeType: z.string()
  }).parse(request.body);

  const activeStore = getStore();
  const filedata = Buffer.from(filedataB64, 'base64');
  return encryptAndUploadAttachment(vault, activeStore, relayClient, filedata, filename, mimeType);
});

// GET /api/attachments/:attachmentId/decrypt
app.get('/api/attachments/:attachmentId/decrypt', async (request: FastifyRequest) => {
  const attachmentId = z.string().parse((request.params as any).attachmentId);
  const { filename, filedata } = await readDecryptedAttachment(vault, attachmentId);
  return {
    filename,
    filedataB64: filedata.toString('base64')
  };
});

// Start disappearing message worker loop
startDisappearingMessageJob(() => vault.database());

// Try to serve React built frontend from static path
const staticUiDir = join(__dirname, '../../local-ui/dist');
try {
  app.register(fastifyStatic, {
    root: staticUiDir,
    prefix: '/'
  });

  // Handle SPA frontend route fallbacks
  app.setNotFoundHandler(async (request, reply) => {
    if (!request.url.startsWith('/api/')) {
      try {
        const indexHtml = readFileSync(join(staticUiDir, 'index.html'), 'utf8');
        return reply.type('text/html').send(indexHtml);
      } catch {
        // Fallback if index.html not found
      }
    }
    return reply.code(404).send({ error: 'not_found' });
  });
} catch {
  // If static directory doesn't exist yet, we will just serve API endpoints
}

// Binds server to localhost on a random available port
const port = z.coerce.number().default(0).parse(process.env.PORT);
await app.listen({ host: '127.0.0.1', port });

const resolvedPort = (app.server.address() as any).port;
const bootstrapSecret = generateBootstrapSecret(resolvedPort);

logger.info(`Local Daemon running on http://127.0.0.1:${resolvedPort}`);
console.log(`Open: http://127.0.0.1:${resolvedPort}/bootstrap#${bootstrapSecret}`);
