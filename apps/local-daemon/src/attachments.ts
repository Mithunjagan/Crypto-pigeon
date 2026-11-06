import crypto from 'node:crypto';
import { mkdir, writeFile, readFile, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { z } from 'zod';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import type { RelayClient } from './relay-client.js';
import type { AttachmentManifest } from '@crypto-pigeon/shared-types';
import { logger } from './logger.js';

const CHUNK_SIZE = 64 * 1024; // 64 KiB

export const attachmentManifestSchema = z.object({
  attachmentId: z.string().regex(/^[a-f0-9]{32}$/),
  blobId: z.string().uuid(),
  originalFilename: z.string().min(1).max(255),
  claimedMimeType: z.string().max(255),
  totalPlaintextSize: z.number().int().min(0).max(25 * 1024 * 1024),
  chunkCount: z.number().int().min(1).max(400),
  chunkSize: z.literal(CHUNK_SIZE),
  chunkNonces: z.array(z.string().refine(v => Buffer.from(v, 'base64').length === 12)).max(400),
  fullFileDigest: z.string().regex(/^[a-f0-9]{64}$/),
  attachmentKey: z.string().refine(v => Buffer.from(v, 'base64').length === 32),
  encryptionVersion: z.literal(1)
}).refine(v => v.chunkCount === Math.max(1, Math.ceil(v.totalPlaintextSize / CHUNK_SIZE)) && v.chunkNonces.length === v.chunkCount);

// Versioned authenticated local storage; legacy CBC remains readable below.
export async function cacheAttachment(vault: Vault, id: string, plaintext: Buffer): Promise<void> {
  const path = vault.attachmentPath(id);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', vault.getAttachmentKey(), nonce);
  cipher.setAAD(Buffer.from('cp-local-attachment-v1:' + id));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  await mkdir(dirname(path), {recursive: true, mode: 0o700});
  await writeFile(path, Buffer.concat([Buffer.from('CPAGCM1:'), Buffer.from(JSON.stringify({version:1, nonce:nonce.toString('base64'),
    tag:cipher.getAuthTag().toString('base64'), ciphertext:encrypted.toString('base64')}))]), {mode:0o600});
}

export async function retryAttachmentDownloads(vault: Vault, store: LocalSignalStore, relay: RelayClient): Promise<number> {
  const rows = vault.database().prepare(`SELECT d.attachment_id, d.manifest FROM attachment_downloads d
    JOIN attachments a ON a.attachment_id=d.attachment_id JOIN messages m ON m.message_id=a.message_id
    WHERE m.disappear_at IS NULL OR m.disappear_at>? LIMIT 8`).all<{attachment_id:string;manifest:string}>([Date.now()]);
  let completed = 0;
  for (const row of rows) {
    try {
      const message = vault.database().prepare('SELECT message_id FROM attachments WHERE attachment_id=?').get<{message_id:string}>([row.attachment_id]);
      if (!message) continue;
      await downloadAndDecryptAttachment(vault, store, relay, attachmentManifestSchema.parse(JSON.parse(row.manifest)), message.message_id);
      completed++;
    } catch {
      logger.warn({attachmentId:row.attachment_id}, 'Attachment unavailable; durable download will retry');
    }
  }
  return completed;
}

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

  await cacheAttachment(vault, attachmentId, plaintext);
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
  manifest = attachmentManifestSchema.parse(manifest);
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

  if (fullPlaintext.length !== manifest.totalPlaintextSize) throw new Error('attachment_size_mismatch');
  await cacheAttachment(vault, manifest.attachmentId, fullPlaintext);
  const db = vault.database();
  db.transaction(() => {
    const result = db.prepare('UPDATE attachments SET encrypted_local_path=? WHERE attachment_id=? AND message_id=?')
      .run([vault.attachmentPath(manifest.attachmentId), manifest.attachmentId, messageId]);
    if (result.changes !== 1) throw new Error('attachment_record_missing');
    db.prepare('DELETE FROM attachment_downloads WHERE attachment_id=?').run([manifest.attachmentId]);
  })();

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

  if (!row.encrypted_local_path) throw new Error('attachment_pending');
  const encryptedData = await readFile(row.encrypted_local_path);
  let filedata: Buffer;
  if (encryptedData.subarray(0,8).toString() === 'CPAGCM1:') {
    const local = JSON.parse(encryptedData.subarray(8).toString('utf8'));
    if (local.version !== 1) throw new Error('invalid_local_attachment_version');
    const decipher = crypto.createDecipheriv('aes-256-gcm', localFileKey, Buffer.from(local.nonce, 'base64'));
    decipher.setAAD(Buffer.from('cp-local-attachment-v1:' + attachmentId));
    decipher.setAuthTag(Buffer.from(local.tag, 'base64'));
    filedata = Buffer.concat([decipher.update(Buffer.from(local.ciphertext, 'base64')), decipher.final()]);
  } else {
    const decipher = crypto.createDecipheriv('aes-256-cbc', localFileKey, encryptedData.subarray(0,16));
    filedata = Buffer.concat([decipher.update(encryptedData.subarray(16)), decipher.final()]);
  }
  const integrity = db.prepare('SELECT file_hash, file_size FROM attachments WHERE attachment_id=?').get<any>([attachmentId]);
  if (filedata.length !== integrity.file_size || !crypto.timingSafeEqual(crypto.createHash('sha256').update(filedata).digest(), Buffer.from(integrity.file_hash))) {
    throw new Error('attachment_integrity_failed');
  }

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
