import { parse } from 'node:url';
import { accessApplyResponseSchema, signChallenge } from '@crypto-pigeon/protocol';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import { logger } from './logger.js';

export class RelayClientError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(code);
    this.name = 'RelayClientError';
  }
}

async function relayError(response: Response): Promise<RelayClientError> {
  let code = 'RELAY_UNAVAILABLE';
  try {
    const body = await response.json() as { error?: string };
    if (body.error) code = body.error;
  } catch {
    // Do not surface or log response bodies; an intermediary might include secrets.
  }
  return new RelayClientError(response.status, code);
}

export class RelayClient {
  private relayUrl: string;

  constructor(relayUrl = process.env.RELAY_URL ?? 'http://127.0.0.1:8443') {
    this.relayUrl = relayUrl.replace(/\/$/, '');
  }

  private getHostname(): string {
    const parsed = parse(this.relayUrl);
    return parsed.host || '127.0.0.1:8443';
  }

  private async getSessionToken(vault: Vault): Promise<string | null> {
    try {
      const db = vault.database();
      const row = db.prepare('SELECT access_token FROM relay_auth WHERE singleton=1').get<{ access_token: string }>();
      return row ? row.access_token : null;
    } catch {
      return null;
    }
  }

  private async saveSessionToken(vault: Vault, token: string) {
    const db = vault.database();
    db.prepare('INSERT INTO relay_auth (singleton, access_token) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET access_token = excluded.access_token')
      .run([token]);
  }

  async authenticate(vault: Vault, store: LocalSignalStore): Promise<string> {
    const { deviceId } = await store.ensureIdentity();
    const { privateKey } = store.getDeviceAuthKeyPair();

    // 1. Fetch challenge
    const chalRes = await fetch(`${this.relayUrl}/api/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId })
    });

    if (!chalRes.ok) {
      throw await relayError(chalRes);
    }

    const { challenge } = (await chalRes.json()) as { challenge: string };
    const hostname = this.getHostname();

    // 2. Sign challenge
    const msg = Buffer.from(deviceId + challenge + hostname, 'utf8');
    const signature = signChallenge(privateKey, msg).toString('hex');

    // 3. Respond to challenge
    const respRes = await fetch(`${this.relayUrl}/api/auth/respond`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId,
        challenge,
        signature,
        relayHostname: hostname
      })
    });

    if (!respRes.ok) {
      throw await relayError(respRes);
    }

    const { sessionToken } = (await respRes.json()) as { sessionToken: string };
    await this.saveSessionToken(vault, sessionToken);

    return sessionToken;
  }

  async request(vault: Vault, store: LocalSignalStore, path: string, options: RequestInit = {}): Promise<Response> {
    let token = await this.getSessionToken(vault);
    if (!token) {
      token = await this.authenticate(vault, store);
    }

    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    options.headers = headers;

    let res = await fetch(`${this.relayUrl}${path}`, options);
    
    // Auto-reauthenticate on 401
    if (res.status === 401) {
      logger.debug('Relay returned 401, re-authenticating');
      token = await this.authenticate(vault, store);
      headers.set('Authorization', `Bearer ${token}`);
      options.headers = headers;
      res = await fetch(`${this.relayUrl}${path}`, options);
    }

    return res;
  }

  async applyAccess(username: string) {
    const res = await fetch(`${this.relayUrl}/api/access/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    if (!res.ok) throw await relayError(res);
    return accessApplyResponseSchema.parse(await res.json());
  }

  async activateAccess(payload: unknown) {
    const res = await fetch(`${this.relayUrl}/api/access/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw await relayError(res);
    return res.json();
  }
}
