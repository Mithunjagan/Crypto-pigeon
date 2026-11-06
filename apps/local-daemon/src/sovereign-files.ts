import crypto from 'node:crypto';
import { seal, unseal, type VaultKeys } from './vault-dual-key.js';
import { deriveSubkey } from './vault-keys.js';
export const SHARD_HEADER='CPSHR701\n', STORAGE_HEADER='CPVAULT1\n';
export function fileEnvelope(file:Buffer,header:string,limit:number){
  if(file.length<=header.length||file.length>limit||!file.subarray(0,header.length).equals(Buffer.from(header)))throw new Error('INVALID_SOVEREIGN_FILE');
  return file.subarray(header.length);
}
function sealedFile(file:Buffer,header:string,limit:number){const value=JSON.parse(fileEnvelope(file,header,limit).toString());if(!value||typeof value.nonce!=='string'||typeof value.ciphertext!=='string'||Buffer.from(value.nonce,'base64').length!==12||Buffer.from(value.nonce,'base64').toString('base64')!==value.nonce||Buffer.from(value.ciphertext,'base64').length<16||Buffer.from(value.ciphertext,'base64').toString('base64')!==value.ciphertext)throw new Error('INVALID_SOVEREIGN_FILE');return value as {nonce:string;ciphertext:string};}
export function seventh(capsule:Buffer,keys:VaultKeys){
  const share=unseal(sealedFile(capsule,SHARD_HEADER,2048),keys.backup,'cp-shard7-v1');
  if(share.length!==48){share.fill(0);throw new Error('INVALID_SHARD7_FILE');}return share;
}
function storageKey(capsule:Buffer,keys:VaultKeys){const share=seventh(capsule,keys);try{return deriveSubkey(keys.backup,crypto.createHash('sha256').update(share).digest(),'cp-app-storage-v1');}finally{share.fill(0);}}
export function encodeStorage(snapshot:Buffer,capsule:Buffer,keys:VaultKeys){const key=storageKey(capsule,keys);try{return Buffer.concat([Buffer.from(STORAGE_HEADER),Buffer.from(JSON.stringify(seal(snapshot,key,'cp-app-storage-v1')))]);}finally{key.fill(0);}}
export function decodeStorage(file:Buffer,capsule:Buffer,keys:VaultKeys){const key=storageKey(capsule,keys);try{return unseal(sealedFile(file,STORAGE_HEADER,64*1024*1024),key,'cp-app-storage-v1');}finally{key.fill(0);}}
