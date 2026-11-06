import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../../../apps/local-daemon/dist/vault.js';
import { encryptAndUploadAttachment, retryAttachmentDownloads, readDecryptedAttachment, attachmentManifestSchema } from '../../../apps/local-daemon/dist/attachments.js';
import { generateBootstrapSecret, setupAuthRoutes, invalidateSession } from '../../../apps/local-daemon/dist/auth.js';
import Fastify from 'fastify';

export function registerAttachmentTests(test:(name:string,fn:()=>void|Promise<void>)=>void) {
  test('Attachment retry survives restart, preserves sender/recipient bytes and detects local tampering',async()=>{
    const root=await mkdtemp(join(tmpdir(),'cp-attachments-'));
    const sender=new Vault(join(root,'sender')),receiver=new Vault(join(root,'receiver'));
    const password='StrongPassword123!';
    try {
      await sender.create(password);await receiver.create(password);
      const chunks=new Map<string,any>();let failDownload=true,deleted=false;
      const relay={request:async(_v:any,_s:any,path:string,options:any={})=>{
        if(path==='/api/attachments/upload')return Response.json({ok:true});
        if(options.method==='POST'){const body=JSON.parse(options.body);chunks.set(String(body.chunkIndex),body);return Response.json({ok:true});}
        if(options.method==='DELETE'){deleted=true;return new Response(null,{status:204});}
        if(failDownload)return new Response(null,{status:503});
        return Response.json(chunks.get(path.split('/').pop()!));
      }} as any;
      const content=Buffer.concat([Buffer.from('Private attachment: தமிழ் 🕊️\n'),crypto.randomBytes(150000)]);
      const manifest=await encryptAndUploadAttachment(sender,{} as any,relay,content,'notes.txt','text/plain');
      assert.ok(!Buffer.from([...chunks.values()][0].ciphertext,'base64').includes(content.subarray(0,24)));
      assert.ok(!(await readFile(sender.attachmentPath(manifest.attachmentId))).includes(content.subarray(0,24)));
      const conversation=crypto.randomUUID(),message=crypto.randomUUID();
      const addRecord=(vault:Vault,download:boolean)=>{
        const db=vault.database();
        db.prepare('INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES(?,?,?,?)').run(['contact','alice',crypto.randomBytes(33),Date.now()]);
        db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,'contact',Date.now()]);
        db.prepare("INSERT INTO messages(message_id,conversation_id,direction,plaintext,status) VALUES(?,?,'received','file','received')").run([message,conversation]);
        const iv=crypto.randomBytes(16),cipher=crypto.createCipheriv('aes-256-cbc',vault.getAttachmentKey(),iv);
        const filename=Buffer.concat([iv,cipher.update(Buffer.from(manifest.originalFilename)),cipher.final()]);
        db.prepare('INSERT INTO attachments(attachment_id,message_id,encrypted_local_path,file_name_encrypted,file_size,file_hash,file_key) VALUES(?,?,?,?,?,?,?)')
          .run([manifest.attachmentId,message,download?null:vault.attachmentPath(manifest.attachmentId),filename,content.length,Buffer.from(manifest.fullFileDigest,'hex'),Buffer.from(manifest.attachmentKey,'base64')]);
        if(download)db.prepare('INSERT INTO attachment_downloads(attachment_id,manifest) VALUES(?,?)').run([manifest.attachmentId,JSON.stringify(manifest)]);
      };
      addRecord(sender,false);addRecord(receiver,true);
      assert.deepEqual((await readDecryptedAttachment(sender,manifest.attachmentId)).filedata,content);
      assert.equal(await retryAttachmentDownloads(receiver,{} as any,relay),0);
      assert.equal(deleted,false);
      receiver.lock();await receiver.unlock(password);
      failDownload=false;
      assert.equal(await retryAttachmentDownloads(receiver,{} as any,relay),1);
      assert.equal(deleted,true);
      assert.equal(receiver.database().prepare('SELECT count(*) AS n FROM attachment_downloads').get<{n:number}>()!.n,0);
      assert.deepEqual((await readDecryptedAttachment(receiver,manifest.attachmentId)).filedata,content);
      const path=receiver.attachmentPath(manifest.attachmentId),bytes=await readFile(path);
      const stored=JSON.parse(bytes.subarray(8).toString());
      const damaged=Buffer.from(stored.ciphertext,'base64');damaged[0]^=1;stored.ciphertext=damaged.toString('base64');
      await writeFile(path,Buffer.concat([Buffer.from('CPAGCM1:'),Buffer.from(JSON.stringify(stored))]));
      await assert.rejects(()=>readDecryptedAttachment(receiver,manifest.attachmentId));
      assert.equal(attachmentManifestSchema.safeParse({...manifest,attachmentId:'../../secret'}).success,false);
      assert.equal(attachmentManifestSchema.safeParse({...manifest,chunkCount:4000000}).success,false);
    }finally{sender.lock();receiver.lock();await rm(root,{recursive:true,force:true});}
  });

  test('Persistent pairing remains single-use, CSRF-stable across reload and revoked on lock',async()=>{
    const app=Fastify(),vault={exists:()=>true,isLocked:()=>true} as any;
    setupAuthRoutes(app,vault);
    try {
      const secret=generateBootstrapSecret(17420);
      const boot=await app.inject({method:'POST',url:'/api/bootstrap',payload:{secret}});
      assert.equal(boot.statusCode,200);
      const cookie=String(boot.headers['set-cookie']);assert.match(cookie,/HttpOnly/);assert.match(cookie,/SameSite=Strict/);assert.match(cookie,/Max-Age=86400/);
      assert.equal((await app.inject({method:'POST',url:'/api/bootstrap',payload:{secret}})).statusCode,401);
      const headers={cookie:cookie.split(';')[0]};
      const a=await app.inject({url:'/api/session',headers}),b=await app.inject({url:'/api/session',headers});
      assert.equal(a.json().csrfToken,boot.json().csrfToken);assert.equal(b.json().csrfToken,a.json().csrfToken);
      invalidateSession();assert.equal((await app.inject({url:'/api/session',headers})).statusCode,401);
    }finally{await app.close();}
  });
}
