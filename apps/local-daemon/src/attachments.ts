import crypto from 'node:crypto';
import { mkdir, writeFile, readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import type { RelayClient } from './relay-client.js';
import type { AttachmentManifest } from '@crypto-pigeon/shared-types';
import { logger } from './logger.js';

const CHUNK_SIZE = 64 * 1024; // 64 KiB

function makeAad(attachmentId: Buffer, chunkIndex: number, totalChunkCount: number): Buffer {
  const aad = Buffer.alloc(28);
  attachmentId.copy(aad, 0);
  aad.writeUInt32BE(chunkIndex, 16);
  aad.writeUInt32BE(totalChunkCount, 20);
  aad.writeUInt32BE(1, 24); // protocolVersion = 1
  return aad;
}

// Timing-safe comparison helper
function timingSafeCompare(a: string, b: string): boolean {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

export function sanitizeFilename(filename: string): string {
  // Strip control chars, null bytes, path separators, limit to 255 chars
  return filename
    .replace(/[\0\x00-\x1F\x7F]/g, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .substring(0, 255);
}

export async function encryptAndUploadAttachment(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  plaintext: Buffer,
  filename: string,
  mimeType: string
): Promise<AttachmentManifest> {
  const attachmentIdBuffer = crypto.randomBytes(16);
  const attachmentId = attachmentIdBuffer.toString('hex');
  const attachmentKey = crypto.randomBytes(32);
  const blobId = crypto.randomUUID();

  const totalSize = plaintext.length;
  const chunkCount = Math.ceil(totalSize / CHUNK_SIZE) || 1;

  const chunkNonces: string[] = [];
  const encryptedChunks: Array<{ nonce: string; ciphertext: string }> = [];

  // Calculate full-file digest
  const fullFileDigest = crypto.createHash('sha256').update(plaintext).digest('hex');

  // Encrypt chunks
  for (let i = 0; i < chunkCount; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, totalSize);
    const chunkPlaintext = plaintext.slice(start, end);

    const nonce = crypto.randomBytes(12);
    const aad = makeAad(attachmentIdBuffer, i, chunkCount);

    const cipher = crypto.createCipheriv('aes-256-gcm', attachmentKey, nonce);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(chunkPlaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const finalCiphertext = Buffer.concat([ciphertext, tag]);

    chunkNonces.push(nonce.toString('base64'));
    encryptedChunks.push({
      nonce: nonce.toString('base64'),
      ciphertext: finalCiphertext.toString('base64')
    });
  }

  // Upload metadata to relay
  const metaRes = await relayClient.request(vault, store, '/api/attachments/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      blobId,
      chunkCount,
      totalSize: plaintext.length
    })
  });

  if (!metaRes.ok) {
    throw new Error(`Failed to upload attachment metadata: ${metaRes.statusText}`);
  }

  // Upload chunks to relay
  for (let i = 0; i < chunkCount; i++) {
    const chunk = encryptedChunks[i];
    const chunkRes = await relayClient.request(vault, store, `/api/attachments/${blobId}/chunks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chunkIndex: i,
        nonce: chunk.nonce,
        ciphertext: chunk.ciphertext
      })
    });

    if (!chunkRes.ok) {
      throw new Error(`Failed to upload attachment chunk ${i}: ${chunkRes.statusText}`);
    }
  }

  return {
    attachmentId,
    blobId,
    originalFilename: sanitizeFilename(filename),
    claimedMimeType: mimeType,
    totalPlaintextSize: totalSize,
    chunkCount,
    chunkSize: CHUNK_SIZE,
    chunkNonces,
    fullFileDigest,
    attachmentKey: attachmentKey.toString('base64'),
    encryptionVersion: 1
  };
}

export async function downloadAndDecryptAttachment(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  manifest: AttachmentManifest,
  messageId: string
): Promise<Buffer> {
  const attachmentIdBuffer = Buffer.from(manifest.attachmentId, 'hex');
  const attachmentKey = Buffer.from(manifest.attachmentKey, 'base64');
  
  const decryptedChunks: Buffer[] = [];

  // Download chunks
  for (let i = 0; i < manifest.chunkCount; i++) {
    const chunkRes = await relayClient.request(vault, store, `/api/attachments/${manifest.blobId}/chunks/${i}`);
    if (!chunkRes.ok) {
      throw new Error(`Failed to download attachment chunk ${i}: ${chunkRes.statusText}`);
    }

    const { nonce: resNonceB64, ciphertext: resCiphertextB64 } = (await chunkRes.json()) as { nonce: string; ciphertext: string };

    // Verify nonces match manifest nonces exactly (prevents reordering/substitution)
    if (manifest.chunkNonces[i] !== resNonceB64) {
      throw new Error(`Security Alert: Nonce mismatch at chunk ${i}`);
    }

    const nonce = Buffer.from(resNonceB64, 'base64');
    const fullCiphertext = Buffer.from(resCiphertextB64, 'base64');

    const encrypted = fullCiphertext.slice(0, -16);
    const tag = fullCiphertext.slice(-16);

    const aad = makeAad(attachmentIdBuffer, i, manifest.chunkCount);

    const decipher = crypto.createDecipheriv('aes-256-gcm', attachmentKey, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const chunkPlaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    decryptedChunks.push(chunkPlaintext);
  }

  const fullPlaintext = Buffer.concat(decryptedChunks);

  // Verify full-file digest
  const computedHash = crypto.createHash('sha256').update(fullPlaintext).digest('hex');
  if (!timingSafeCompare(manifest.fullFileDigest, computedHash)) {
    throw new Error('Security Alert: Integrity verification failed. Attachment digest mismatch.');
  }

  // Store attachment file durably in local directory encrypted with vault's attachmentMetaKey
  const vaultRootDir = join(process.env.CRYPTO_PIGEON_HOME ?? process.env.USERPROFILE ?? process.cwd(), '.crypto_pigeon');
  const attachmentsDir = join(vaultRootDir, 'attachments');
  await mkdir(attachmentsDir, { recursive: true });

  const localPath = join(attachmentsDir, manifest.attachmentId);
  
  // Encrypt file at rest using AES-256-CBC/GCM with attachmentMetaKey
  const localFileKey = vault.getAttachmentKey();
  const localIv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', localFileKey, localIv);
  const localEncrypted = Buffer.concat([localIv, cipher.update(fullPlaintext), cipher.final()]);

  await writeFile(localPath, localEncrypted);

  // Encrypt original filename for DB
  const filenameIv = crypto.randomBytes(16);
  const filenameCipher = crypto.createCipheriv('aes-256-cbc', localFileKey, filenameIv);
  const filenameEncrypted = Buffer.concat([filenameIv, filenameCipher.update(Buffer.from(manifest.originalFilename, 'utf8')), filenameCipher.final()]);

  // Insert into attachments database table
  const db = vault.database();
  db.prepare(
    `INSERT INTO attachments (attachment_id, message_id, encrypted_local_path, file_name_encrypted, file_size, file_hash, file_key)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run([
    manifest.attachmentId,
    messageId,
    localPath,
    filenameEncrypted,
    manifest.totalPlaintextSize,
    Buffer.from(manifest.fullFileDigest, 'hex'),
    attachmentKey
  ]);

  // Send blob deletion acknowledgment to relay
  const deleteRes = await relayClient.request(vault, store, `/api/attachments/${manifest.blobId}`, {
    method: 'DELETE'
  });
  if (!deleteRes.ok) {
    logger.warn({ blobId: manifest.blobId }, 'Failed to delete attachment blob from relay');
  }

  return fullPlaintext;
}

export async function readDecryptedAttachment(vault: Vault, attachmentId: string): Promise<{ filename: string; filedata: Buffer }> {
  const db = vault.database();
  const row = db.prepare('SELECT encrypted_local_path, file_name_encrypted FROM attachments WHERE attachment_id = ?').get([attachmentId]) as any;
  if (!row) throw new Error('attachment_not_found');

  const localFileKey = vault.getAttachmentKey();

  // Read and decrypt file data
  const encryptedData = await readFile(row.encrypted_local_path);
  const iv = encryptedData.slice(0, 16);
  const ciphertext = encryptedData.slice(16);
  const decipher = crypto.createDecipheriv('aes-256-cbc', localFileKey, iv);
  const filedata = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  // Decrypt filename
  const fnIv = row.file_name_encrypted.slice(0, 16);
  const fnCiphertext = row.file_name_encrypted.slice(16);
  const fnDecipher = crypto.createDecipheriv('aes-256-cbc', localFileKey, fnIv);
  const filename = Buffer.concat([fnDecipher.update(fnCiphertext), fnDecipher.final()]).toString('utf8');

  return {
    filename,
    filedata
  };
}
