import crypto from 'node:crypto';
import { deflateRawSync,inflateRawSync } from 'node:zlib';
import { z } from 'zod';

const b64=(length:number)=>z.string().max(Math.ceil(length/3)*4).refine(s=>Buffer.from(s,'base64').length===length&&Buffer.from(s,'base64').toString('base64')===s);
const signed=z.object({id:z.number().int().min(0).max(2147483647),publicKey:b64(33),signature:b64(64)}).strict();
export const serverlessInviteSchema=z.object({
  version:z.literal(2),publicUid:z.string().regex(/^CP-[A-F0-9]{4}-[A-F0-9]{4}$/),username:z.string().regex(/^[a-z0-9_]{3,32}$/),
  onion:z.string().regex(/^[a-z2-7]{56}\.onion$/),userId:z.string().uuid(),deviceId:z.string().uuid(),signalDeviceId:z.number().int().min(1).max(127),registrationId:z.number().int().min(1).max(1073741823),
  deviceAuthPublicKey:b64(44),identityPublicKey:b64(33),signedPrekey:signed,pqLastResortPrekey:signed.extend({publicKey:b64(1569)})
}).strict();
export type ServerlessInvite=z.infer<typeof serverlessInviteSchema>;
export function inviteSigningBytes(invite:ServerlessInvite):Buffer {
  const v=serverlessInviteSchema.parse(invite);
  return Buffer.from(JSON.stringify(['cp-invite-v2',v.publicUid,v.username,v.onion,v.userId,v.deviceId,v.signalDeviceId,v.registrationId,v.deviceAuthPublicKey,v.identityPublicKey,
    v.signedPrekey.id,v.signedPrekey.publicKey,v.signedPrekey.signature,v.pqLastResortPrekey.id,v.pqLastResortPrekey.publicKey,v.pqLastResortPrekey.signature]));
}
/** Byte-mode QR at level L supports up to 2953 bytes. Compression keeps Kyber invites within it. */
export function createServerlessInvite(invite:ServerlessInvite,privateKeyDer:Buffer):string {
  const bytes=inviteSigningBytes(invite),key=crypto.createPrivateKey({key:privateKeyDer,type:'pkcs8',format:'der'});
  const uri='pigeon://invite?v=2&data='+deflateRawSync(bytes,{level:9}).toString('base64url')+'&sig='+crypto.sign(null,bytes,key).toString('base64url');
  if(Buffer.byteLength(uri)>2953)throw new Error('INVITE_TOO_LARGE');return uri;
}
export function parseServerlessInvite(uri:string):ServerlessInvite {
  if(uri.length>4096)throw new Error('INVALID_INVITE');const url=new URL(uri);
  if(url.protocol!=='pigeon:'||url.hostname!=='invite'||url.pathname||url.hash||url.username||url.password||url.port||url.searchParams.get('v')!=='2'||[...url.searchParams.keys()].sort().join(',')!=='data,sig,v')throw new Error('INVALID_INVITE');
  const data=url.searchParams.get('data')!,sig=url.searchParams.get('sig')!;
  if(!/^[A-Za-z0-9_-]+$/.test(data)||! /^[A-Za-z0-9_-]{86}$/.test(sig))throw new Error('INVALID_INVITE');
  const raw=inflateRawSync(Buffer.from(data,'base64url'),{maxOutputLength:8192}),a=JSON.parse(raw.toString('utf8'));
  if(!Array.isArray(a)||a.length!==16||a[0]!=='cp-invite-v2')throw new Error('INVALID_INVITE');
  const invite=serverlessInviteSchema.parse({version:2,publicUid:a[1],username:a[2],onion:a[3],userId:a[4],deviceId:a[5],signalDeviceId:a[6],registrationId:a[7],deviceAuthPublicKey:a[8],identityPublicKey:a[9],signedPrekey:{id:a[10],publicKey:a[11],signature:a[12]},pqLastResortPrekey:{id:a[13],publicKey:a[14],signature:a[15]}});
  const publicKey=crypto.createPublicKey({key:Buffer.from(invite.deviceAuthPublicKey,'base64'),format:'der',type:'spki'});
  if(publicKey.asymmetricKeyType!=='ed25519'||!crypto.verify(null,inviteSigningBytes(invite),publicKey,Buffer.from(sig,'base64url')))throw new Error('INVALID_INVITE_SIGNATURE');
  return invite;
}
