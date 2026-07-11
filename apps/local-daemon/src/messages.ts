import crypto from 'node:crypto';
import type { Database } from '@signalapp/sqlcipher';
import { ProtocolAddress } from '@signalapp/libsignal-client';
import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import type { RelayClient } from './relay-client.js';
import { establishSession, encryptPayload, decryptPayload } from './signal-adapter.js';
import { downloadAndDecryptAttachment } from './attachments.js';
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
  db.prepare('UPDATE contacts SET username = ?, safety_number_hash = ?, identity_changed = 0 WHERE contact_id = ?')
    .run([username, safetyNumber, contactId]);

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

  // 1. Get destination
  const dest = db.prepare(
    `SELECT c.contact_id, r.user_id, r.device_id, r.signal_device_id, con.identity_changed
     FROM conversations c 
     JOIN remote_contacts r ON r.contact_id = c.contact_id 
     JOIN contacts con ON con.contact_id = c.contact_id
     WHERE c.conversation_id = ?`
  ).get<{ contact_id: string; user_id: string; device_id: string; signal_device_id: number; identity_changed: number }>([conversationId]);

  if (!dest) throw new Error('conversation_not_found');
  if (dest.identity_changed === 1) {
    throw new Error('identity_changed_blocked');
  }

  const address = ProtocolAddress.new(dest.user_id, dest.signal_device_id);

  // 2. Build E2EE payload
  const e2eePayload: any = {
    type: 'text',
    text: plaintext
  };

  if (attachmentManifest) {
    e2eePayload.attachment = attachmentManifest;
  }

  // 3. Encrypt payload
  const { type, ciphertext } = await encryptPayload(store, address, JSON.stringify(e2eePayload));

  // Combine type and ciphertext into indivisible bytes: type (1 byte) + ciphertext
  const typeByte = Buffer.from([type]);
  const ciphertextBytes = Buffer.from(ciphertext, 'base64');
  const combined = Buffer.concat([typeByte, ciphertextBytes]).toString('base64');

  // 4. Send message to relay
  const envelopeId = crypto.randomBytes(16).toString('hex');
  const res = await relayClient.request(vault, store, '/api/messages/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      version: 1,
      envelopeId,
      mailboxId: dest.device_id,
      ciphertext: combined
    })
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`Failed to send message: ${res.statusText} ${errBody}`);
  }

  const messageId = crypto.randomUUID();

  // Store sent message locally
  db.prepare(
    `INSERT INTO messages (message_id, conversation_id, direction, plaintext, sent_at, status) 
     VALUES (?, ?, 'sent', ?, ?, 'sent')`
  ).run([messageId, conversationId, plaintext, Date.now()]);

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
      join(env.CRYPTO_PIGEON_HOME, 'attachments', attachmentManifest.attachmentId),
      filenameEncrypted,
      attachmentManifest.totalPlaintextSize,
      Buffer.from(attachmentManifest.fullFileDigest, 'hex'),
      Buffer.from(attachmentManifest.attachmentKey, 'base64')
    ]);
  }

  return { messageId, status: 'sent' };
}

export async function syncMessages(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient
): Promise<number> {
  const db = vault.database();
  
  // 1. Fetch pending envelopes from relay
  const res = await relayClient.request(vault, store, '/api/messages/pending');
  if (!res.ok) {
    logger.error('Failed to fetch pending messages');
    return 0;
  }

  const pendingList = (await res.json()) as Array<{
    version: 1;
    envelopeId: string;
    senderId: string;
    mailboxId: string;
    ciphertext: string;
  }>;

  if (pendingList.length === 0) return 0;

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
      db.prepare('INSERT INTO contacts (contact_id, username, identity_public_key, verified, safety_number_hash, identity_changed, created_at) VALUES (?, ?, ?, 0, ?, 0, ?)')
        .run([contactId, bundle.recipientUsername, Buffer.from(bundle.identityKey, 'base64'), safetyNumber, Date.now()]);

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

    try {
      // Decrypt E2EE payload via Signal adapter
      const decryptedText = await decryptPayload(store, address, ciphertextBase64, type);
      const e2eePayload = JSON.parse(decryptedText);

      // Start durable SQLite transaction (PRAGMA synchronous = FULL)
      db.transaction(() => {
        const conversationId = findOrCreateConversation(db, contactRow!.contact_id);
        const messageId = crypto.randomUUID();

        // 3. Store message in messages table
        db.prepare(
          `INSERT INTO messages (message_id, conversation_id, direction, plaintext, received_at, remote_blob_id, status)
           VALUES (?, ?, 'received', ?, ?, ?, 'received')`
        ).run([messageId, conversationId, e2eePayload.text || '', Date.now(), envelope.envelopeId]);

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

        // 5. Insert envelopeId into seen_envelope_ids
        db.prepare('INSERT INTO seen_envelope_ids (envelope_id, received_at) VALUES (?, ?) ON CONFLICT DO NOTHING')
          .run([envelope.envelopeId, Date.now()]);
      })();

      // Asynchronously download attachment if present
      if (e2eePayload.attachment) {
        const manifest = e2eePayload.attachment;
        const msgRow = db.prepare('SELECT message_id FROM messages WHERE remote_blob_id = ?').get<{ message_id: string }>([envelope.envelopeId]);
        if (msgRow) {
          downloadAndDecryptAttachment(vault, store, relayClient, manifest, msgRow.message_id)
            .then(() => logger.info({ blobId: manifest.blobId }, 'Attachment download/decrypt completed'))
            .catch(err => logger.error({ err, blobId: manifest.blobId }, 'Attachment download/decrypt failed'));
        }
      }

      receivedCount++;
      acks.push(envelope.envelopeId);
    } catch (err) {
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

  return receivedCount;
}
