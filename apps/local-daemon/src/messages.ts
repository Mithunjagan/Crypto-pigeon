import {profile,queueControl,typingUntil} from './consumer.js';
import crypto from 'node:crypto';
import type { Database } from '@signalapp/sqlcipher';
import { ProtocolAddress } from '@signalapp/libsignal-client';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import type { RelayClient } from './relay-client.js';
import { establishSession, encryptPayload, decryptPayload } from './signal-adapter.js';
import { retryAttachmentDownloads, attachmentManifestSchema } from './attachments.js';
import { logger } from './logger.js';
import { env } from './config.js';
import { join } from 'node:path';
import type { AttachmentManifest } from '@crypto-pigeon/shared-types';

function findOrCreateConversation(db: Database, contactId: string): string {
  const existing = db.prepare('SELECT conversation_id FROM conversations WHERE contact_id = ?').get<{ conversation_id: string }>([contactId]);
  if (existing) return existing.conversation_id;

  const id = crypto.randomUUID();
  db.prepare('INSERT INTO conversations (conversation_id, contact_id, created_at) VALUES (?, ?, ?)')
    .run([id, contactId, Date.now()]);
  return id;
}

export async function addContactAndSession(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  username: string
) {
  const db = vault.database();

  // 1. Fetch remote user bundle
  const res = await relayClient.request(vault, store, '/api/prekeys/bundle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipientUsername: username })
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch bundle: ${res.statusText}`);
  }

  const bundle = (await res.json()) as any;

  const address = ProtocolAddress.new(bundle.recipientUserId, bundle.signalDeviceId);
  await establishSession(store, address, bundle);

  const contactId = address.toString();

  // Save or update remote_contacts and contacts in local DB
  db.prepare(`
    INSERT INTO remote_contacts (contact_id, user_id, device_id, signal_device_id)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(contact_id)
    DO UPDATE SET user_id=excluded.user_id, device_id=excluded.device_id, signal_device_id=excluded.signal_device_id
  `).run([contactId, bundle.recipientUserId, bundle.recipientDeviceId, bundle.signalDeviceId]);

  // Retrieve safety number
  const { computeSafetyNumber } = await import('./fingerprint.js');
  const safetyNumber = await computeSafetyNumber(store, address);

  // Update contacts table (username and safety number)
  db.prepare('UPDATE contacts SET username = ?, public_uid = ?, safety_number_hash = ?, identity_changed = 0 WHERE contact_id = ?')
    .run([bundle.recipientUsername ?? username, bundle.publicUid ?? null, safetyNumber, contactId]);

  return {
    conversationId: findOrCreateConversation(db, contactId),
    verified: false,
    safetyNumber
  };
}

export async function sendMessage(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  conversationId: string,
  plaintext: string,
  attachmentManifest?: any
) {
  const db = vault.database();
  if (attachmentManifest) attachmentManifest = attachmentManifestSchema.parse(attachmentManifest);

  // 1. Get destination
  const dest = db.prepare(
    `SELECT c.contact_id, r.user_id, r.device_id, r.signal_device_id, con.identity_changed, c.disappearing_seconds
     FROM conversations c
     JOIN remote_contacts r ON r.contact_id = c.contact_id
     JOIN contacts con ON con.contact_id = c.contact_id
     WHERE c.conversation_id = ?`
  ).get<{ contact_id: string; user_id: string; device_id: string; signal_device_id: number; identity_changed: number; disappearing_seconds: number | null }>([conversationId]);

  if (!dest) throw new Error('conversation_not_found');
  if (dest.identity_changed === 1) {
    throw new Error('identity_changed_blocked');
  }

  const address = ProtocolAddress.new(dest.user_id, dest.signal_device_id);

  // 2. Build E2EE payload
  const e2eePayload: any = {
    type: 'text',
    messageId: crypto.randomUUID(),
    profile: profile(vault),
    text: plaintext,
    disappearingSeconds: dest.disappearing_seconds ?? 0
  };

  if (attachmentManifest) {
    e2eePayload.attachment = attachmentManifest;
  }
  if(attachmentManifest&&relayClient.torRouting){
    db.prepare('INSERT OR REPLACE INTO tor_attachment_links VALUES(?,?)').run([attachmentManifest.attachmentId,attachmentManifest.blobId]);
  }

  // Persist the Signal ratchet advance and the exact retry envelope together.
  // API access is serialized by server.ts while this asynchronous encryption runs.
  const messageId = e2eePayload.messageId;
  db.exec('BEGIN IMMEDIATE');
  try {
  // 3. Encrypt payload
  const { type, ciphertext } = await encryptPayload(store, address, JSON.stringify(e2eePayload));

  // Combine type and ciphertext into indivisible bytes: type (1 byte) + ciphertext
  const typeByte = Buffer.from([type]);
  const ciphertextBytes = Buffer.from(ciphertext, 'base64');
  const combined = Buffer.concat([typeByte, ciphertextBytes]).toString('base64');

  // 4. Queue encrypted bytes before any network operation. Retrying must never
  // encrypt again, because the relay may have accepted a timed-out request.
  const envelopeId = crypto.randomBytes(16).toString('hex');

  // Store sent message locally
  db.prepare(
    `INSERT INTO messages (message_id, conversation_id, direction, plaintext, sent_at, status, disappear_at)
     VALUES (?, ?, 'sent', ?, ?, 'queued', ?)`
  ).run([messageId, conversationId, plaintext, Date.now(), dest.disappearing_seconds ? Date.now()+dest.disappearing_seconds*1000 : null]);
  db.prepare('INSERT INTO message_outbox (envelope_id,message_id,mailbox_id,ciphertext,created_at) VALUES (?,?,?,?,?)')
    .run([envelopeId,messageId,dest.device_id,combined,Date.now()]);

  // If there's an attachment, save it locally linked to the message
  if (attachmentManifest) {
    const localFileKey = vault.getAttachmentKey();

    // Encrypt filename for DB
    const filenameIv = crypto.randomBytes(16);
    const filenameCipher = crypto.createCipheriv('aes-256-cbc', localFileKey, filenameIv);
    const filenameEncrypted = Buffer.concat([filenameIv, filenameCipher.update(Buffer.from(attachmentManifest.originalFilename, 'utf8')), filenameCipher.final()]);

    db.prepare(
      `INSERT INTO attachments (attachment_id, message_id, encrypted_local_path, file_name_encrypted, file_size, file_hash, file_key)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run([
      attachmentManifest.attachmentId,
      messageId,
      vault.attachmentPath(attachmentManifest.attachmentId),
      filenameEncrypted,
      attachmentManifest.totalPlaintextSize,
      Buffer.from(attachmentManifest.fullFileDigest, 'hex'),
      Buffer.from(attachmentManifest.attachmentKey, 'base64')
    ]);
  }

  db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  await flushOutbox(vault, store, relayClient);
  const row = db.prepare('SELECT status FROM messages WHERE message_id=?').get<{status:string}>([messageId]);
  return { messageId, status: row?.status ?? 'queued' };
}

export async function flushOutbox(vault: Vault, store: LocalSignalStore, relayClient: RelayClient): Promise<number> {
  const db = vault.database();
  const queued = db.prepare(`SELECT o.* FROM message_outbox o
    JOIN messages m ON m.message_id=o.message_id
    JOIN conversations c ON c.conversation_id=m.conversation_id
    JOIN contacts contact ON contact.contact_id=c.contact_id
    WHERE contact.identity_changed=0 AND (m.disappear_at IS NULL OR m.disappear_at>?) ORDER BY o.created_at, o.rowid`).all<{
      envelope_id:string; message_id:string; mailbox_id:string; ciphertext:string;
    }>([Date.now()]);
  let sent = 0;
  for (const envelope of queued) {
    try {
      const response = await relayClient.request(vault, store, '/api/messages/send', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({version:1,envelopeId:envelope.envelope_id,mailboxId:envelope.mailbox_id,ciphertext:envelope.ciphertext})
      });
      if (!response.ok) break;
      db.transaction(() => {
        db.prepare("UPDATE messages SET status='sent' WHERE message_id=?").run([envelope.message_id]);
        db.prepare('DELETE FROM message_outbox WHERE envelope_id=?').run([envelope.envelope_id]);
      })();
      sent++;
    } catch {
      // The persisted envelope survives network failure, app restart and lost ACKs.
      break;
    }
  }
  return sent;
}

export async function syncMessages(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient
): Promise<number> {
  const db = vault.database();

  // The relay retains every pushed envelope until durable decryption and ACK.
  // If the socket was unavailable (or the process restarted), GET is the fallback.
  let pendingList=relayClient.takePushedEnvelopes();
  if(!pendingList.length){const res=await relayClient.request(vault,store,'/api/messages/pending');if(!res.ok)throw new Error('RELAY_SYNC_UNAVAILABLE');pendingList=await res.json() as any[];}

  if (pendingList.length === 0) { await retryAttachmentDownloads(vault, store, relayClient); return 0; }

  let receivedCount = 0;
  const acks: string[] = [];

  for (const envelope of pendingList) {
    if (envelope.version !== 1 || !envelope.envelopeId || !envelope.ciphertext) {
      logger.warn('Skipping malformed envelope');
      continue;
    }

    // Deduplicate against seen_envelope_ids
    const seen = db.prepare('SELECT 1 FROM seen_envelope_ids WHERE envelope_id = ?').get([envelope.envelopeId]);
    if (seen) {
      acks.push(envelope.envelopeId);
      continue;
    }

    // Decode indivisible bytes: type (1 byte) + ciphertext
    const combinedBytes = Buffer.from(envelope.ciphertext, 'base64');
    const type = combinedBytes[0];
    const ciphertextBase64 = combinedBytes.slice(1).toString('base64');

    // Retrieve sender details
    let contactRow = db.prepare('SELECT contact_id, user_id, signal_device_id FROM remote_contacts WHERE device_id = ?').get<{ contact_id: string; user_id: string; signal_device_id: number }>([envelope.senderId]);

    // If not found in remote_contacts, it means a new contact sent us a message!
    // We should fetch their prekey bundle from the relay, establish a session, and create the contact!
    if (!contactRow) {
      const bundleRes = await relayClient.request(vault, store, '/api/prekeys/bundle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipientDeviceId: envelope.senderId })
      });

      if (!bundleRes.ok) {
        logger.error(`Failed to fetch bundle for sender ${envelope.senderId}: ${bundleRes.statusText}`);
        continue;
      }

      const bundle = (await bundleRes.json()) as any;
      const address = ProtocolAddress.new(bundle.recipientUserId, bundle.signalDeviceId);
      await establishSession(store, address, bundle);

      const contactId = address.toString();

      db.prepare(`
        INSERT INTO remote_contacts (contact_id, user_id, device_id, signal_device_id)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(contact_id)
        DO UPDATE SET user_id=excluded.user_id, device_id=excluded.device_id, signal_device_id=excluded.signal_device_id
      `).run([contactId, bundle.recipientUserId, bundle.recipientDeviceId, bundle.signalDeviceId]);

      const { computeSafetyNumber } = await import('./fingerprint.js');
      const safetyNumber = await computeSafetyNumber(store, address);

      // Save username and safety number in contacts
      // establishSession already pins the identity and creates this contact.
      db.prepare('UPDATE contacts SET username = ?, public_uid = ?, safety_number_hash = ? WHERE contact_id = ?')
        .run([bundle.recipientUsername, bundle.publicUid ?? null, safetyNumber, contactId]);

      contactRow = {
        contact_id: contactId,
        user_id: bundle.recipientUserId,
        signal_device_id: bundle.signalDeviceId
      };
    }

    // Check if the contact has blocked identity change (TOFU warnings)
    const contactStatus = db.prepare('SELECT identity_changed FROM contacts WHERE contact_id = ?').get<{ identity_changed: number }>([contactRow.contact_id]);
    if (contactStatus?.identity_changed === 1) {
      logger.warn(`Skipped message from ${contactRow.contact_id} due to unapproved identity key change`);
      continue;
    }

    const address = ProtocolAddress.new(contactRow.user_id, contactRow.signal_device_id);

    db.exec('BEGIN IMMEDIATE');
    try {
      // Decrypt E2EE payload via Signal adapter
      const decryptedText = await decryptPayload(store, address, ciphertextBase64, type);
      const e2eePayload = JSON.parse(decryptedText);
      const conv=findOrCreateConversation(db,contactRow!.contact_id);
      const metadata=e2eePayload.profile;
      if(metadata&&typeof metadata.displayName==='string'&&metadata.displayName.length<=64&&typeof metadata.statusLine==='string'&&metadata.statusLine.length<=140)
        db.prepare('INSERT OR REPLACE INTO peer_profiles(contact_id,display_name,status_line) VALUES(?,?,?)').run([contactRow!.contact_id,metadata.displayName,metadata.statusLine]);
      if(e2eePayload.type!=='text'){
        const id=typeof e2eePayload.upToMessageId==='string'?e2eePayload.upToMessageId:'';
        if(e2eePayload.type==='typing'&&e2eePayload.expiresAt>Date.now()&&e2eePayload.expiresAt<Date.now()+10000)typingUntil.set(conv,Date.now()+5000);
        else if(e2eePayload.type==='delivered')db.prepare("UPDATE messages SET status='delivered' WHERE message_id=? AND conversation_id=? AND direction='sent' AND status IN ('queued','sent')").run([id,conv]);
        else if(e2eePayload.type==='read_receipt')db.prepare("UPDATE messages SET status='read' WHERE conversation_id=? AND direction='sent' AND rowid<=(SELECT rowid FROM messages WHERE message_id=? AND conversation_id=? AND direction='sent')").run([conv,id,conv]);
        db.prepare('INSERT INTO seen_envelope_ids(envelope_id,received_at) VALUES(?,?)').run([envelope.envelopeId,Date.now()]);db.exec('COMMIT');receivedCount++;acks.push(envelope.envelopeId);continue;
      }
      if (e2eePayload.attachment) e2eePayload.attachment = attachmentManifestSchema.parse(e2eePayload.attachment);

      // Start durable SQLite transaction (PRAGMA synchronous = FULL)
      {
        const conversationId = findOrCreateConversation(db, contactRow!.contact_id);
        const messageId = crypto.randomUUID();

        // 3. Store message in messages table
        db.prepare(
          `INSERT INTO messages (message_id, conversation_id, direction, plaintext, received_at, remote_blob_id, status, disappear_at)
           VALUES (?, ?, 'received', ?, ?, ?, 'received', ?)`
        ).run([messageId, conversationId, e2eePayload.text || '', Date.now(), envelope.envelopeId, [3600,86400,604800].includes(e2eePayload.disappearingSeconds) ? Date.now()+e2eePayload.disappearingSeconds*1000 : null]);

        if(typeof e2eePayload.messageId==='string'&&/^[a-f0-9-]{36}$/.test(e2eePayload.messageId)){
          db.prepare('INSERT INTO message_links(message_id,remote_id) VALUES(?,?)').run([messageId,e2eePayload.messageId]);
          await queueControl(vault,store,conversationId,{type:'delivered',upToMessageId:e2eePayload.messageId});
        }
        typingUntil.delete(conversationId);
        // 4. Save attachment placeholder if any
        if (e2eePayload.attachment) {
          const manifest = e2eePayload.attachment as AttachmentManifest;
          const localFileKey = vault.getAttachmentKey();

          // Encrypt original filename for DB
          const filenameIv = crypto.randomBytes(16);
          const filenameCipher = crypto.createCipheriv('aes-256-cbc', localFileKey, filenameIv);
          const filenameEncrypted = Buffer.concat([filenameIv, filenameCipher.update(Buffer.from(manifest.originalFilename, 'utf8')), filenameCipher.final()]);

          db.prepare(
            `INSERT INTO attachments (attachment_id, message_id, encrypted_local_path, file_name_encrypted, file_size, file_hash, file_key)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).run([
            manifest.attachmentId,
            messageId,
            null, // populated after download completes
            filenameEncrypted,
            manifest.totalPlaintextSize,
            Buffer.from(manifest.fullFileDigest, 'hex'),
            Buffer.from(manifest.attachmentKey, 'base64')
          ]);
        }

        if (e2eePayload.attachment) {
          db.prepare('INSERT INTO attachment_downloads(attachment_id,manifest) VALUES(?,?)')
            .run([e2eePayload.attachment.attachmentId, JSON.stringify(e2eePayload.attachment)]);
        }

        // 5. Insert envelopeId into seen_envelope_ids
        db.prepare('INSERT INTO seen_envelope_ids (envelope_id, received_at) VALUES (?, ?) ON CONFLICT DO NOTHING')
          .run([envelope.envelopeId, Date.now()]);
      }
      db.exec('COMMIT');

      receivedCount++;
      acks.push(envelope.envelopeId);
    } catch (err) {
      db.exec('ROLLBACK');
      logger.error({ err, envelopeId: envelope.envelopeId }, 'Failed to decrypt or process envelope');
    }
  }

  // 6. Acknowledge delivery to relay so it clears the queue
  if (acks.length > 0) {
    const ackRes = await relayClient.request(vault, store, '/api/messages/ack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelopeIds: acks })
    });
    if (!ackRes.ok) {
      logger.error({ status: ackRes.statusText }, 'Failed to send acks to relay');
    }
  }

  await retryAttachmentDownloads(vault, store, relayClient);
  return receivedCount;
}
