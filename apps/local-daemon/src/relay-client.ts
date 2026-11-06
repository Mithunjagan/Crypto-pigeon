import WebSocket from 'ws';
import { accessApplyResponseSchema, signChallenge, normalizeRelayUrl } from '@crypto-pigeon/protocol';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import { logger } from './logger.js';
import type { TorRouting } from './tor-routing.js';

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
  torRouting?:TorRouting;
  private relayUrl: string;
  private cachedToken: string | null = null;
  private expiresAt = 0;
  private refreshing: Promise<string> | null = null;
  private socket: WebSocket | null = null;
  private reconnect: ReturnType<typeof setTimeout> | undefined;
  private watching = false;
  private generation=0;
  private pushed:any[]=[];
  takePushedEnvelopes(){return this.pushed.splice(0,256);}
  clearSession() {this.pushed=[];this.generation++;this.stopEvents();this.cachedToken=null;this.expiresAt=0;this.refreshing=null;}
  stopEvents() {this.watching=false;clearTimeout(this.reconnect);const old=this.socket;this.socket=null;old?.terminate();}
  async watch(vault:Vault,store:LocalSignalStore,onEvent:(type:string)=>void) {
    if(this.torRouting?.mode==='DIRECT_TOR_P2P')return;
    if(this.watching)return;this.watching=true;
    const connect=async()=>{
      if(!this.watching||vault.isLocked())return;
      try {
        const token=await this.getToken(vault,store);
        if(!this.watching||vault.isLocked())return;
        const instance=vault.database().prepare('SELECT token FROM vault_instance WHERE singleton=1').get<{token:string}>();
        const socket=new WebSocket(this.relayUrl.replace(/^http/,'ws')+'/ws',{headers:{Authorization:`Bearer ${token}`,...(instance?{'X-Vault-Instance':instance.token}:{})},handshakeTimeout:10000});
        this.socket=socket;
        socket.on('open',()=>onEvent('CONNECTED'));
        socket.on('message',raw=>{if(this.socket!==socket)return;try{const packet=JSON.parse(raw.toString()),type=packet.type;if(type==='ENCRYPTED_ENVELOPE'&&packet.envelope&&this.pushed.length<256){this.pushed.push(packet.envelope);return;}if(type==='NEW_ENVELOPE'||type==='envelope')onEvent('NEW_ENVELOPE');}catch{}});
        socket.on('error',()=>socket.terminate());
        socket.on('close',()=>{if(this.socket===socket)this.socket=null;if(this.watching)this.reconnect=setTimeout(()=>void connect(),1000);});
      } catch {if(this.watching)this.reconnect=setTimeout(()=>void connect(),2000);}
    };
    void connect();
  }
  private async getToken(vault:Vault,store:LocalSignalStore):Promise<string> {
    if(this.cachedToken&&Date.now()<this.expiresAt-5000)return this.cachedToken;
    if(!this.refreshing){
      const pending=this.authenticateFresh(vault,store);this.refreshing=pending;
      void pending.finally(()=>{if(this.refreshing===pending)this.refreshing=null;}).catch(()=>{});
    }
    return this.refreshing;
  }

  constructor(relayUrl = process.env.RELAY_URL ?? 'http://127.0.0.1:8443') {
    this.relayUrl = normalizeRelayUrl(relayUrl);
  }

  private fetch(path: string, options: RequestInit = {}) {
    const headers=new Headers(options.headers);headers.set('ngrok-skip-browser-warning','1');
    return fetch(`${this.relayUrl}${path}`, { ...options, headers, redirect: 'error',
      signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000) });
  }

  private getHostname(): string {
    return new URL(this.relayUrl).host;
  }

  private async saveSessionToken(vault: Vault, token: string) {
    const db = vault.database();
    db.prepare('INSERT INTO relay_auth (singleton, access_token) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET access_token = excluded.access_token')
      .run([token]);
  }

  acceptSession(token:string,expiresAt:number){this.cachedToken=token;this.expiresAt=expiresAt;}
  async authenticate(vault:Vault,store:LocalSignalStore):Promise<string> {return this.getToken(vault,store);}
  private async authenticateFresh(vault: Vault, store: LocalSignalStore): Promise<string> {
    const generation=this.generation;
    const { deviceId } = await store.ensureIdentity();
    const { privateKey } = store.getDeviceAuthKeyPair();

    // 1. Fetch challenge
    const chalRes = await this.fetch('/api/auth/challenge', {
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
    const respRes = await this.fetch('/api/auth/respond', {
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

    const { sessionToken, expiresAt } = (await respRes.json()) as { sessionToken: string; expiresAt:number };
    if(vault.isLocked()||generation!==this.generation)throw new Error('vault_locked');
    this.cachedToken=sessionToken;this.expiresAt=expiresAt;
    await this.saveSessionToken(vault, sessionToken);

    return sessionToken;
  }

  async request(vault: Vault, store: LocalSignalStore, path: string, options: RequestInit = {}): Promise<Response> {
    if(this.torRouting){const direct=await this.torRouting.route(path,options);if(direct)return direct;}
    let token = await this.getToken(vault,store);

    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    const instance = vault.database().prepare('SELECT token FROM vault_instance WHERE singleton=1').get<{token:string}>();
    if(instance)headers.set('X-Vault-Instance',instance.token);
    options.headers = headers;

    let res = await this.fetch(path, options);
    
    // Auto-reauthenticate on 401
    if (res.status === 401) {
      logger.debug('Relay returned 401, re-authenticating');
      if(this.cachedToken===token){this.cachedToken=null;this.expiresAt=0;}
      token = await this.getToken(vault, store);
      headers.set('Authorization', `Bearer ${token}`);
      options.headers = headers;
      res = await this.fetch(path, options);
    }

    return res;
  }
  async prepareRequest(vault:Vault,store:LocalSignalStore,path:string,options:RequestInit):Promise<()=>Promise<Response>>{
    const generation=this.generation,token=await this.getToken(vault,store),headers=new Headers(options.headers);
    headers.set('Authorization',`Bearer ${token}`);
    const instance=vault.database().prepare('SELECT token FROM vault_instance WHERE singleton=1').get<{token:string}>();if(instance)headers.set('X-Vault-Instance',instance.token);
    return async()=>{if(generation!==this.generation)throw new Error('VAULT_SESSION_CHANGED');const response=await this.fetch(path,{...options,headers});if(response.status===401&&this.cachedToken===token){this.cachedToken=null;this.expiresAt=0;}return response;};
  }

  async applyAccess(username: string) {
    const res = await this.fetch('/api/access/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    if (!res.ok) throw await relayError(res);
    return accessApplyResponseSchema.parse(await res.json());
  }

  async activateAccess(payload: unknown) {
    const res = await this.fetch('/api/access/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw await relayError(res);
    return res.json();
  }
}
