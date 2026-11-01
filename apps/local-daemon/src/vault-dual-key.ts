import crypto from 'node:crypto';
import argon2 from 'argon2';
import { gzipSync, gunzipSync } from 'node:zlib';
import { deriveSubkey } from './vault-keys.js';

export const MAX_BACKUP_BYTES = 25 * 1024 * 1024;
export async function deriveVaultKeys(vaultId: string, password: string) {
  // Public deterministic salt is necessary for file-free restore. Vault IDs
  // are exact UTF-8 strings: do not silently trim or normalize user secrets.
  const salt = crypto.createHash('sha256').update('cp-vault-root-v1\0').update(vaultId).digest();
  const root = await argon2.hash(password, { type: argon2.argon2id, salt,
    memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32, raw: true });
  try {
    const key = (context: string) => deriveSubkey(root, salt, context);
    return { kek: key('cp-vault-kek-v1'), lookup: key('cp-vault-lookup-v1'),
      backup: key('cp-vault-backup-cipher-v1'), mask: key('cp-horcrux-share6-mask-v1'),
      writer: key('cp-vault-backup-writer-v1') };
  } finally { root.fill(0); salt.fill(0); }
}
export type VaultKeys = Awaited<ReturnType<typeof deriveVaultKeys>>;
export function wipeKeys(keys: VaultKeys | null) { if(keys) Object.values(keys).forEach(k => k.fill(0)); }
export function seal(data: Buffer, key: Buffer, aad: string) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad));
  return { nonce: nonce.toString('base64'), ciphertext: Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]).toString('base64') };
}
export function unseal(value: {nonce: string; ciphertext: string}, key: Buffer, aad: string): Buffer {
  const nonce = Buffer.from(value.nonce, 'base64');
  const bytes = Buffer.from(value.ciphertext, 'base64');
  if(nonce.length !== 12 || bytes.length < 16) throw new Error('invalid_ciphertext');
  const cipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(aad)); cipher.setAuthTag(bytes.subarray(-16));
  return Buffer.concat([cipher.update(bytes.subarray(0, -16)), cipher.final()]);
}
export function encryptBackup(snapshot: Buffer, key: Buffer) {
  const compressed = gzipSync(snapshot);
  try {
    if(compressed.length + 16 > MAX_BACKUP_BYTES) throw new Error('backup_too_large');
    return seal(compressed, key, 'vault-backup-v1');
  } finally { compressed.fill(0); }
}
export function decryptBackup(envelope: {nonce: string; ciphertext: string}, key: Buffer) {
  const compressed = unseal(envelope, key, 'vault-backup-v1');
  try { return gunzipSync(compressed, { maxOutputLength: 100 * 1024 * 1024 }); }
  finally { compressed.fill(0); }
}
export function writerKeyPair(seed: Buffer) {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  try {
    const privateKey = crypto.createPrivateKey({key: der, format:'der', type:'pkcs8'});
    return { privateKey, publicKey: crypto.createPublicKey(privateKey).export({format:'der', type:'spki'}).toString('base64') };
  } finally { der.fill(0); }
}
