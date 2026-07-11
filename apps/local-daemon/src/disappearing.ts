import { unlink } from 'node:fs/promises';
import type { Database } from '@signalapp/sqlcipher';
import { logger } from './logger.js';

export function startDisappearingMessageJob(db: any) {
  setInterval(async () => {
    try {
      const nowMs = Date.now();
      
      // 1. Find all messages that have expired
      // Fastify db might be locked/null if vault is locked
      let expired: Array<{ message_id: string; remote_blob_id: string | null }> = [];
      try {
        expired = db().prepare(
          'SELECT message_id, remote_blob_id FROM messages WHERE disappear_at IS NOT NULL AND disappear_at <= ?'
        ).all([nowMs]) as any[];
      } catch {
        // Vault is locked or DB not open, skip this tick
        return;
      }

      if (expired.length === 0) return;

      for (const msg of expired) {
        // 2. Find and delete local attachment files
        const attachments = db().prepare(
          'SELECT encrypted_local_path FROM attachments WHERE message_id = ?'
        ).all([msg.message_id]) as Array<{ encrypted_local_path: string | null }>;

        for (const attachment of attachments) {
          if (attachment.encrypted_local_path) {
            try {
              await unlink(attachment.encrypted_local_path);
              logger.debug({ path: attachment.encrypted_local_path }, 'Deleted local expired attachment file');
            } catch (err) {
              logger.warn({ err, path: attachment.encrypted_local_path }, 'Failed to delete expired attachment file');
            }
          }
        }

        // 3. Delete message from DB (cascades to attachments table)
        db().prepare('DELETE FROM messages WHERE message_id = ?').run([msg.message_id]);
        logger.info({ messageId: msg.message_id }, 'Disappearing message logically deleted');
      }
    } catch (error) {
      logger.error({ err: error }, 'Disappearing message job failed');
    }
  }, 1000).unref();
}
