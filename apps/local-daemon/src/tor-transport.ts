import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Database } from '@signalapp/sqlcipher';
import { signChallenge, verifyChallenge, envelopeSchema } from '@crypto-pigeon/protocol';

export type TorMode = 'DIRECT_TOR_P2P' | 'HYBRID_TOR_RELAY' | 'RELAY_ONLY';
export const onionPattern = /^[a-z2-7]{56}\.onion$/;
export function torErrorCode(error:unknown){const code=(error as any)?.code;if(typeof code==='string'&&/^[A-Z0-9_]{1,64}$/.test(code))return code;return error instanceof Error&&/^[A-Z0-9_]{1,64}$/.test(error.message)?error.message:'TOR_REQUEST_FAILED';}
export function p2pSigningBytes(sender:string,time:number,nonce:string,method:string,path:string,body:string) {
  return Buffer.from(JSON.stringify(['cp-onion-request-v1',sender,time,nonce,method,path,body]));
}
export function initializeTorSchema(db:Database) {
  db.exec(`CREATE TABLE IF NOT EXISTS tor_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),private_key TEXT NOT NULL,onion TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tor_settings(singleton INTEGER PRIMARY KEY CHECK(singleton=1),mode TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS peer_onions(device_id TEXT PRIMARY KEY,contact_id TEXT NOT NULL,onion TEXT NOT NULL,auth_key TEXT NOT NULL,invite TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tor_inbox(envelope_id TEXT PRIMARY KEY,envelope TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tor_attachment_links(attachment_id TEXT PRIMARY KEY,blob_id TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tor_download_chunks(blob_id TEXT NOT NULL,chunk_index INTEGER NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(blob_id,chunk_index));
    CREATE TABLE IF NOT EXISTS tor_blobs(blob_id TEXT PRIMARY KEY,chunk_count INTEGER NOT NULL,total_size INTEGER NOT NULL,created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS tor_chunks(blob_id TEXT NOT NULL REFERENCES tor_blobs(blob_id) ON DELETE CASCADE,chunk_index INTEGER NOT NULL,nonce TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(blob_id,chunk_index));`);
}
export function cleanupTorSpool(db:Database){
  if(!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tor_blobs'").get())return;
  db.exec(`DELETE FROM tor_blobs WHERE blob_id IN (SELECT l.blob_id FROM tor_attachment_links l LEFT JOIN attachments a ON a.attachment_id=l.attachment_id WHERE a.attachment_id IS NULL)
    OR (created_at<${Date.now()-86400000} AND blob_id NOT IN (SELECT blob_id FROM tor_attachment_links));
    DELETE FROM tor_attachment_links WHERE attachment_id NOT IN (SELECT attachment_id FROM attachments);
    DELETE FROM tor_download_chunks WHERE blob_id NOT IN (SELECT json_extract(manifest,'$.blobId') FROM attachment_downloads);`);
}

/** Cookie-authenticated, app-owned Tor. Onion secrets exist only in SQLCipher and Tor memory. */
export class TorOnionTransport {
  private process?:ChildProcess;
  private server?:http.Server;
  private control?:net.Socket;
  private socksPort=0;
  private timer?:ReturnType<typeof setInterval>;
  private stopped=false;
  private boot=0;
  private failure='';
  private peerEnvelopes=0;private peerChunks=0;private peerError='';
  private onion='';
  private publishedServices=new Set<string>();
  private circuitReady=false;
  onReady?:()=>void;
  private deviceId='';
  private sockets=new Set<net.Socket>();
  private abort=new AbortController();
  isStopped(){return this.stopped;}
  private lines='';
  private replies:string[]=[];
  private waiter?:{resolve:(lines:string[])=>void;reject:(e:Error)=>void};
  constructor(private db:()=>Database,private local:()=>{deviceId:string;privateKey:Buffer},private serialize:<T>(fn:()=>Promise<T>)=>Promise<T>) {}
  status(){return {activeTransport:this.boot===100&&this.onion?'Direct Tor Onion P2P':'Tor connecting',serverless:this.boot===100&&!!this.onion,bootstrapPercent:this.boot,descriptorPublished:this.publishedServices.has(this.onion.replace(/\.onion$/,'')),errorCode:this.failure||undefined,peerEnvelopes:this.peerEnvelopes,peerChunks:this.peerChunks,peerError:this.peerError||undefined};}
  address(){if(!this.onion)throw new Error('TOR_NOT_READY');return this.onion;}
  async start(binary:string,directory:string) {
    initializeTorSchema(this.db());
    const identity=this.local();this.deviceId=identity.deviceId;identity.privateKey.fill(0);
    mkdirSync(directory,{recursive:true,mode:0o700});
    const controlPort=await freePort();this.socksPort=await freePort();
    if(this.stopped)throw new Error('TOR_CLOSED');
    this.server=http.createServer((req,res)=>{void this.receive(req,res);});
    await new Promise<void>((resolve,reject)=>{this.server!.once('error',reject);this.server!.listen(0,'127.0.0.1',resolve);});
    if(this.stopped){this.server.close();throw new Error('TOR_CLOSED');}
    const endpoint=(this.server.address() as net.AddressInfo).port;
    this.process=spawn(binary,['--DataDirectory',directory,'--SocksPort',`127.0.0.1:${this.socksPort}`,'--ControlPort',`127.0.0.1:${controlPort}`,'--CookieAuthentication','1','--CookieAuthFile',join(directory,'control.cookie'),'--Log','err stdout','--SafeLogging','1'],{stdio:'ignore',windowsHide:true});
    this.process.on('error',()=>{this.failure='TOR_PROCESS_START_FAILED';this.close();});this.process.on('exit',code=>{if(!this.stopped)this.failure='TOR_PROCESS_EXIT_'+code;this.close();});
    for(let i=0;i<100&&!this.stopped;i++){
      try{if(!existsSync(join(directory,'control.cookie')))throw new Error();this.control=await connect(controlPort);break;}catch{await new Promise(r=>setTimeout(r,200));}
    }
    if(this.stopped||!this.control)throw new Error('TOR_START_FAILED');
    this.control.setEncoding('utf8');this.control.on('data',data=>this.onData(String(data)));
    this.control.on('error',()=>{if(!this.stopped)this.failure='TOR_CONTROL_SOCKET_ERROR';this.close();});this.control.on('close',()=>{if(!this.stopped)this.failure='TOR_CONTROL_SOCKET_CLOSED';this.close();});
    await this.command('AUTHENTICATE '+readFileSync(join(directory,'control.cookie')).toString('hex'));
    await this.command('SETEVENTS STATUS_CLIENT HS_DESC CIRC NETWORK_LIVENESS');
    const saved=await this.serialize(async()=>{if(this.stopped)throw new Error('TOR_CLOSED');return this.db().prepare('SELECT private_key,onion FROM tor_identity WHERE singleton=1').get<{private_key:string;onion:string}>();});
    const answer=await this.command(`ADD_ONION ${saved?.private_key??'NEW:ED25519-V3'} Port=80,127.0.0.1:${endpoint}`);
    const onion=answer.find(l=>l.startsWith('250-ServiceID='))?.slice(14)+'.onion';
    if(!onionPattern.test(onion))throw new Error('TOR_INVALID_SERVICE');
    if(!saved){const key=answer.find(l=>l.startsWith('250-PrivateKey='))?.slice(15);if(!key?.startsWith('ED25519-V3:'))throw new Error('TOR_INVALID_SERVICE');await this.serialize(async()=>{if(this.stopped)throw new Error('TOR_CLOSED');this.db().prepare('INSERT INTO tor_identity VALUES(1,?,?)').run([key,onion]);});}
    else if(onion!==saved.onion)throw new Error('TOR_IDENTITY_MISMATCH');
    this.onion=onion;
    const poll=async()=>{try{const reply=await this.command('GETINFO status/bootstrap-phase');const progress=reply.join(' ').match(/PROGRESS=(\d+)/);this.boot=progress?Math.min(100,Number(progress[1])):0;}catch{if(!this.stopped)this.failure='TOR_CONTROL_POLL_FAILED';this.close();}};
    await poll();this.timer=setInterval(()=>{if(!this.waiter)void poll();},3000);this.timer.unref();
  }
  private onData(chunk:string){this.lines+=chunk;let end;while((end=this.lines.indexOf('\r\n'))>=0){const line=this.lines.slice(0,end);this.lines=this.lines.slice(end+2);
    // Async 650 events can interleave with a 250 multi-line command reply.
    if(line.startsWith('650')){
      const uploaded=line.match(/^650[ -]HS_DESC UPLOADED ([a-z2-7]{56})(?:\.onion)?(?: |$)/);
      let wake=false;
      if(uploaded){wake=!this.publishedServices.has(uploaded[1]);this.publishedServices.add(uploaded[1]);}
      if(/^650[ -]NETWORK_LIVENESS DOWN/.test(line)){this.circuitReady=false;this.publishedServices.clear();}
      if(/^650[ -](?:CIRC \d+ BUILT|NETWORK_LIVENESS UP)/.test(line)&&!this.circuitReady){this.circuitReady=true;wake=true;}
      if(line.includes('BOOTSTRAP')){const progress=line.match(/PROGRESS=(\d+)/);if(progress){const next=Math.min(100,Number(progress[1]));wake ||= this.boot!==100&&next===100;this.boot=next;}}
      if(wake&&!this.stopped)queueMicrotask(()=>{if(!this.stopped)this.onReady?.();});
      continue;
    }
    this.replies.push(line);if(/^\d{3} /.test(line)){const waiter=this.waiter;this.waiter=undefined;const reply=this.replies;this.replies=[];if(line.startsWith('250 '))waiter?.resolve(reply);else waiter?.reject(new Error('TOR_CONTROL_'+line.slice(0,3)));}}}
  private command(command:string):Promise<string[]>{return new Promise((resolve,reject)=>{if(this.waiter||this.stopped){reject(new Error('TOR_CONTROL_UNAVAILABLE'));return;}const timeout=setTimeout(()=>{this.failure='TOR_CONTROL_TIMEOUT';this.waiter=undefined;reject(new Error('TOR_CONTROL_TIMEOUT'));this.close();},30000);this.waiter={resolve:lines=>{clearTimeout(timeout);resolve(lines);},reject:e=>{clearTimeout(timeout);reject(e);}};this.control!.write(command+'\r\n');});}
  private async receive(req:http.IncomingMessage,res:http.ServerResponse){
    try{
      const chunks:Buffer[]=[];let size=0;
      const arrivedAt=Date.now();
      req.setTimeout(90000,()=>req.destroy());
      for await(const chunk of req){size+=chunk.length;if(size>768*1024)throw new Error('BODY_TOO_LARGE');chunks.push(chunk);}
      const body=Buffer.concat(chunks).toString('utf8'),path=req.url??'',method=req.method??'';
      const sender=String(req.headers['x-pigeon-sender']??''),time=Number(req.headers['x-pigeon-time']),nonce=String(req.headers['x-pigeon-nonce']??''),signature=String(req.headers['x-pigeon-signature']??'');
      const result=await this.serialize(async()=>{
        if(this.stopped||Math.abs(arrivedAt-time)>120000||!Number.isSafeInteger(time)||!nonce.match(/^[a-f0-9]{32}$/))throw new Error('UNAUTHORIZED');
        const peer=this.db().prepare('SELECT * FROM peer_onions WHERE device_id=?').get<any>([sender]);
        if(!peer||!verifyChallenge(Buffer.from(peer.auth_key,'base64'),p2pSigningBytes(sender,time,nonce,method,path,Buffer.from(body).toString('base64')),Buffer.from(signature,'base64')))throw new Error('UNAUTHORIZED');
        if(this.db().prepare('SELECT 1 FROM contacts WHERE contact_id=? AND identity_changed=1').get([peer.contact_id]))throw new Error('IDENTITY_CHANGED');
        if(method==='POST'&&path==='/p2p/v1/envelopes'){
          this.peerEnvelopes++;
          const envelope=envelopeSchema.parse(JSON.parse(body));if(envelope.mailboxId!==this.deviceId||Buffer.from(envelope.ciphertext,'base64').length>512*1024)throw new Error('INVALID_ENVELOPE');
          this.db().prepare('INSERT OR IGNORE INTO tor_inbox VALUES(?,?)').run([envelope.envelopeId,JSON.stringify({...envelope,senderId:sender})]);return {accepted:true};
        }
        const match=path.match(/^\/p2p\/v1\/attachments\/([a-f0-9-]{36})\/chunks\/(\d{1,3})$/);
        if(method==='GET'&&match){
          this.peerChunks++;
          const allowed=this.db().prepare(`SELECT 1 FROM attachments a JOIN messages m ON m.message_id=a.message_id JOIN conversations c ON c.conversation_id=m.conversation_id
            WHERE c.contact_id=? AND m.direction='sent' AND (m.disappear_at IS NULL OR m.disappear_at>?) AND a.attachment_id IN
            (SELECT attachment_id FROM tor_attachment_links WHERE blob_id=?)`).get([peer.contact_id,Date.now(),match[1]]);
          if(!allowed)throw new Error('UNAUTHORIZED');
          const part=this.db().prepare('SELECT nonce,ciphertext FROM tor_chunks WHERE blob_id=? AND chunk_index=?').get([match[1],Number(match[2])]);if(!part)throw new Error('CHUNK_MISSING');return part;
        }
        throw new Error('NOT_FOUND');
      });
      const encoded=JSON.stringify(result);res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','Content-Length':Buffer.byteLength(encoded)});res.end(encoded);
    }catch(error){this.peerError=torErrorCode(error);res.writeHead(403);res.end();}
  }
  async request(peerOnion:string,path:string,method:string,body=''):Promise<Response>{
    if(!onionPattern.test(peerOnion)||!path.startsWith('/p2p/v1/')||this.stopped||this.boot!==100)throw new Error('TOR_NOT_READY');
    const socket=await socksConnect(this.socksPort,peerOnion,80,this.abort.signal);
    if(this.stopped){socket.destroy();throw new Error('TOR_CLOSED');}this.sockets.add(socket);socket.once('close',()=>this.sockets.delete(socket));
    // Sign once the onion connection exists; circuit setup must not age the request.
    const identity=this.local(),time=Date.now(),nonce=crypto.randomBytes(16).toString('hex');
    let signature:string;try{signature=signChallenge(identity.privateKey,p2pSigningBytes(identity.deviceId,time,nonce,method,path,Buffer.from(body).toString('base64'))).toString('base64');}finally{identity.privateKey.fill(0);}
    return new Promise<Response>((resolve,reject)=>{
      const agent=new http.Agent();agent.createConnection=()=>socket;
      const request=http.request({host:peerOnion,port:80,path,method,agent,headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),'X-Pigeon-Sender':identity.deviceId,'X-Pigeon-Time':time,'X-Pigeon-Nonce':nonce,'X-Pigeon-Signature':signature}},response=>{
        const chunks:Buffer[]=[];let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>192*1024){response.destroy();reject(new Error('BODY_TOO_LARGE'));}else chunks.push(chunk);});response.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:response.statusCode})));response.on('error',reject);
      });request.setTimeout(90000,()=>request.destroy(new Error('TOR_PEER_OFFLINE')));request.on('error',reject);request.end(body);socket.resume();
    });
  }
  close(){if(this.stopped)return;this.stopped=true;this.abort.abort();this.boot=0;this.onion='';clearInterval(this.timer);this.waiter?.reject(new Error('TOR_CLOSED'));this.waiter=undefined;this.control?.destroy();for(const socket of this.sockets)socket.destroy();this.sockets.clear();this.server?.close();this.server?.closeAllConnections();this.process?.kill();}
}
async function freePort(){const server=net.createServer();await new Promise<void>((r,e)=>{server.once('error',e);server.listen(0,'127.0.0.1',r);});const port=(server.address() as net.AddressInfo).port;await new Promise<void>(r=>server.close(()=>r()));return port;}
async function connect(port:number,signal?:AbortSignal){return new Promise<net.Socket>((resolve,reject)=>{const socket=net.connect({port,host:'127.0.0.1',signal},()=>resolve(socket));socket.once('error',reject);});}
/** Explicit SOCKS domain form prevents DNS leakage or accidental clearnet fallback. */
export async function socksConnect(port:number,host:string,destinationPort:number,signal?:AbortSignal){
  if(!onionPattern.test(host))throw new Error('ONION_REQUIRED');
  const socket=await connect(port,signal);socket.setTimeout(90000,()=>socket.destroy(new Error('TOR_TIMEOUT')));
  let buffered=Buffer.alloc(0),readWaiter:(()=>void)|undefined;
  const onData=(b:Buffer)=>{buffered=Buffer.concat([buffered,b]);readWaiter?.();};socket.on('data',onData);
  let failure:Error|undefined;const onError=(e:Error)=>{failure=e;readWaiter?.();};socket.on('error',onError);
  const onClose=()=>onError(new Error('SOCKS_CLOSED'));socket.once('close',onClose);
  const read=async(n:number)=>{while(buffered.length<n){if(failure)throw failure;await new Promise<void>(r=>{readWaiter=r;});readWaiter=undefined;}const b=buffered.subarray(0,n);buffered=buffered.subarray(n);return b;};
  try{socket.write(Buffer.from([5,1,0]));const hello=await read(2);if(hello[0]!==5||hello[1]!==0)throw new Error('SOCKS_AUTH_FAILED');const name=Buffer.from(host);socket.write(Buffer.concat([Buffer.from([5,1,0,3,name.length]),name,Buffer.from([destinationPort>>8,destinationPort&255])]));const head=await read(4);if(head[0]!==5||head[1]!==0)throw new Error('TOR_PEER_OFFLINE');const length=head[3]===1?4:head[3]===4?16:head[3]===3?(await read(1))[0]:-1;if(length<0)throw new Error('SOCKS_INVALID');await read(length+2);socket.pause();socket.off('data',onData);socket.off('error',onError);socket.off('close',onClose);if(buffered.length)socket.unshift(buffered);return socket;}catch(e){socket.destroy();throw e;}
}
