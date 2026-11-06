import type { Database } from '@signalapp/sqlcipher';
import { TorOnionTransport, type TorMode, initializeTorSchema,torErrorCode } from './tor-transport.js';

/** The relay-shaped adapter keeps Signal persistence and retry logic transport independent. */
export class TorRouting {
  mode:TorMode='DIRECT_TOR_P2P';
  transport?:TorOnionTransport;
  private jobs=new Set<string>();
  lastTransferError='';
  prepareRelay?: (body:any)=>Promise<(()=>Promise<Response>)|undefined>;
  prepareRelayDownload?: (path:string)=>Promise<(()=>Promise<Response>)|undefined>;
  constructor(private database:()=>Database,private serialize:<T>(fn:()=>Promise<T>)=>Promise<T> = fn=>fn()){}
  async route(path:string,options:RequestInit={}):Promise<Response|undefined>{
    if(this.mode==='RELAY_ONLY')return;
    const db=this.database();initializeTorSchema(db);
    const method=options.method??'GET',body=typeof options.body==='string'?JSON.parse(options.body):null;
    if(path==='/api/messages/pending'){const incoming=db.prepare('SELECT envelope FROM tor_inbox LIMIT 256').all<{envelope:string}>().map(row=>JSON.parse(row.envelope));return incoming.length||this.mode==='DIRECT_TOR_P2P'?Response.json(incoming):undefined;}
    if(path==='/api/messages/ack'){
      const relayIds:string[]=[];db.transaction(()=>{for(const id of body.envelopeIds){const removed=db.prepare('DELETE FROM tor_inbox WHERE envelope_id=?').run([id]);if(!removed.changes)relayIds.push(id);}})();
      if(this.mode==='HYBRID_TOR_RELAY'&&relayIds.length){options.body=JSON.stringify({envelopeIds:relayIds});return;}
      return new Response(null,{status:204});
    }
    if(path==='/api/messages/send'){
      const peer=db.prepare('SELECT onion FROM peer_onions WHERE device_id=?').get<{onion:string}>([body.mailboxId]);
      const transport=this.transport;
      if(peer&&transport?.status().serverless||this.mode==='HYBRID_TOR_RELAY'&&this.prepareRelay){
        if(!this.jobs.has(body.envelopeId)){
          this.jobs.add(body.envelopeId);
          // The socket wait must run outside the serialized vault API queue.
          setTimeout(()=>{void (async()=>{try{
            let accepted=false;
            try{if(peer&&transport){const response=await transport.request(peer.onion,'/p2p/v1/envelopes','POST',JSON.stringify(body));accepted=response.ok&&(await response.json() as any).accepted===true;}}catch{/* Explicit hybrid mode may fall back below. */}
            if(!accepted&&this.mode==='HYBRID_TOR_RELAY'&&this.prepareRelay){
              const prepared=await this.serialize(async()=>this.transport===transport&&!transport?.isStopped()&&this.database()===db?this.prepareRelay!(body):undefined);
              if(prepared)accepted=(await prepared()).ok;
            }
            if(!accepted)return;
            await this.serialize(async()=>{if(this.transport!==transport||transport?.isStopped()||this.database()!==db)return;const active=this.database();
              active.transaction(()=>{active.prepare("UPDATE messages SET status='sent' WHERE message_id IN (SELECT message_id FROM message_outbox WHERE envelope_id=?) AND status='queued'").run([body.envelopeId]);active.prepare('DELETE FROM message_outbox WHERE envelope_id=?').run([body.envelopeId]);active.prepare('DELETE FROM control_outbox WHERE envelope_id=?').run([body.envelopeId]);})();
            });
          }catch{/* Keep identical ciphertext queued. */}finally{this.jobs.delete(body.envelopeId);}})();},0);
        }
        return new Response(null,{status:503});
      }
      if(this.mode==='HYBRID_TOR_RELAY')return;
      return new Response(null,{status:503});
    }
    // Sender-side encrypted blob spool; uploading never needs the other phone online.
    if(path==='/api/attachments/upload'&&method==='POST'){
      if(!/^[a-f0-9-]{36}$/.test(body.blobId)||!Number.isInteger(body.chunkCount)||body.chunkCount<1||body.chunkCount>400||!Number.isInteger(body.totalSize)||body.totalSize<0||body.totalSize>25*1024*1024||body.chunkCount!==Math.max(1,Math.ceil(body.totalSize/65536)))throw new Error('INVALID_BLOB');
      db.prepare('INSERT INTO tor_blobs VALUES(?,?,?,?)').run([body.blobId,body.chunkCount,body.totalSize,Date.now()]);return Response.json({ok:true});
    }
    const upload=path.match(/^\/api\/attachments\/([a-f0-9-]{36})\/chunks$/);
    if(upload&&method==='POST'){
      const meta=db.prepare('SELECT chunk_count FROM tor_blobs WHERE blob_id=?').get<{chunk_count:number}>([upload[1]]);
      if(!meta||!Number.isInteger(body.chunkIndex)||body.chunkIndex<0||body.chunkIndex>=meta.chunk_count||Buffer.from(body.nonce,'base64').length!==12||Buffer.from(body.ciphertext,'base64').length<16||Buffer.from(body.ciphertext,'base64').length>65552)throw new Error('INVALID_CHUNK');
      db.prepare('INSERT INTO tor_chunks VALUES(?,?,?,?)').run([upload[1],body.chunkIndex,body.nonce,body.ciphertext]);return Response.json({ok:true});
    }
    const download=path.match(/^\/api\/attachments\/([a-f0-9-]{36})\/chunks\/(\d+)$/);
    if(download&&method==='GET'){
      const cached=db.prepare('SELECT nonce,ciphertext FROM tor_download_chunks WHERE blob_id=? AND chunk_index=?').get([download[1],Number(download[2])]);if(cached)return Response.json(cached);
      const pending=db.prepare(`SELECT d.manifest,r.device_id FROM attachment_downloads d JOIN attachments a ON a.attachment_id=d.attachment_id JOIN messages m ON m.message_id=a.message_id JOIN conversations c ON c.conversation_id=m.conversation_id JOIN remote_contacts r ON r.contact_id=c.contact_id`).all<{manifest:string;device_id:string}>().find(row=>JSON.parse(row.manifest).blobId===download[1]);
      const peer=pending&&db.prepare('SELECT onion FROM peer_onions WHERE device_id=?').get<{onion:string}>([pending.device_id]);
      const transport=this.transport;
      if(peer&&transport?.status().serverless&&pending){
        const job='blob:'+download[1];if(!this.jobs.has(job)){this.jobs.add(job);const manifest=JSON.parse(pending.manifest);
          setTimeout(()=>{void (async()=>{try{for(let i=0;i<manifest.chunkCount;i++){
            let response:Response|undefined;
            try{response=await transport.request(peer.onion,`/p2p/v1/attachments/${manifest.blobId}/chunks/${i}`,'GET');}catch(error){this.lastTransferError=torErrorCode(error);}
            if(!response?.ok&&this.mode==='HYBRID_TOR_RELAY'&&this.prepareRelayDownload){const prepared=await this.serialize(async()=>this.transport===transport&&!transport.isStopped()&&this.database()===db?this.prepareRelayDownload!(`/api/attachments/${manifest.blobId}/chunks/${i}`):undefined);if(prepared)response=await prepared();}
            if(!response?.ok)throw new Error(response?'CHUNK_HTTP_'+response.status:this.lastTransferError||'CHUNK_UNAVAILABLE');
            const part=await response.json() as any;if(part.nonce!==manifest.chunkNonces[i]||typeof part.ciphertext!=='string'||Buffer.from(part.ciphertext,'base64').length>65552)throw new Error('INVALID_CHUNK');
            await this.serialize(async()=>{if(this.transport!==transport||transport.isStopped())throw new Error('VAULT_SESSION_CHANGED');this.database().prepare('INSERT OR REPLACE INTO tor_download_chunks VALUES(?,?,?,?)').run([manifest.blobId,i,part.nonce,part.ciphertext]);});
          }this.lastTransferError='';}catch(error){this.lastTransferError=error instanceof Error&&/^[A-Z_0-9]{1,64}$/.test(error.message)?error.message:'TOR_CHUNK_PERSIST_FAILED';}finally{this.jobs.delete(job);}})();},0);
        }return new Response(null,{status:503});
      }
      if(this.mode==='HYBRID_TOR_RELAY')return;throw new Error('PEER_ONION_MISSING');
    }
    if(/^\/api\/attachments\/[a-f0-9-]{36}$/.test(path)&&method==='DELETE'){db.prepare('DELETE FROM tor_download_chunks WHERE blob_id=?').run([path.split('/')[3]]);return new Response(null,{status:204});}
    if(this.mode==='DIRECT_TOR_P2P')throw new Error('RELAY_DISABLED_IN_DIRECT_MODE');
  }
}
