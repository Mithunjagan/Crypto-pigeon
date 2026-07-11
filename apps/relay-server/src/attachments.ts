import type { FastifyRequest, FastifyReply } from 'fastify';
import { z } from 'zod';
import { pool } from './db.js';
import { authMiddleware } from './auth.js';
import { logger } from './logger.js';
import { base64Schema } from '@crypto-pigeon/protocol';

export function setupAttachmentsRoutes(app: any) {
  // POST /api/attachments/upload
  app.post('/api/attachments/upload', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const deviceId = request.user!.deviceId;
    const body = z.object({
      blobId: z.string().uuid(),
      chunkCount: z.number().int().positive(),
      totalSize: z.number().int().nonnegative()
    }).parse(request.body);

    try {
      await pool.query(
        `INSERT INTO attachment_blobs (blob_id, owner_device_id, chunk_count, total_size)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (blob_id) DO NOTHING`,
        [body.blobId, deviceId, body.chunkCount, body.totalSize]
      );
      return { ok: true };
    } catch (error) {
      logger.error({ err: error }, 'Failed to initialize attachment upload');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  // POST /api/attachments/:blobId/chunks
  app.post('/api/attachments/:blobId/chunks', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const blobId = z.string().uuid().parse((request.params as any).blobId);
    const body = z.object({
      chunkIndex: z.number().int().nonnegative(),
      nonce: base64Schema,
      ciphertext: base64Schema
    }).parse(request.body);

    try {
      // Check if blob metadata exists
      const blobRes = await pool.query('SELECT chunk_count FROM attachment_blobs WHERE blob_id = $1', [blobId]);
      if (blobRes.rows.length === 0) {
        return reply.code(404).send({ error: 'blob_not_found' });
      }

      if (body.chunkIndex >= blobRes.rows[0].chunk_count) {
        return reply.code(400).send({ error: 'chunk_index_out_of_bounds' });
      }

      await pool.query(
        `INSERT INTO attachment_chunks (blob_id, chunk_index, nonce, ciphertext)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (blob_id, chunk_index) DO UPDATE SET nonce = $3, ciphertext = $4`,
        [
          blobId,
          body.chunkIndex,
          Buffer.from(body.nonce, 'base64'),
          Buffer.from(body.ciphertext, 'base64')
        ]
      );
      return { ok: true };
    } catch (error) {
      logger.error({ err: error }, 'Failed to upload chunk');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  // GET /api/attachments/:blobId/chunks/:chunkIndex
  app.get('/api/attachments/:blobId/chunks/:chunkIndex', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const blobId = z.string().uuid().parse((request.params as any).blobId);
    const chunkIndex = z.coerce.number().int().nonnegative().parse((request.params as any).chunkIndex);

    try {
      const result = await pool.query(
        `SELECT nonce, ciphertext 
         FROM attachment_chunks 
         WHERE blob_id = $1 AND chunk_index = $2`,
        [blobId, chunkIndex]
      );

      if (result.rows.length === 0) {
        return reply.code(404).send({ error: 'chunk_not_found' });
      }

      const row = result.rows[0];
      return {
        chunkIndex,
        nonce: Buffer.from(row.nonce).toString('base64'),
        ciphertext: Buffer.from(row.ciphertext).toString('base64')
      };
    } catch (error) {
      logger.error({ err: error }, 'Failed to fetch chunk');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });

  // DELETE /api/attachments/:blobId
  // Called by recipient to delete the blob and all its chunks once download completes
  app.delete('/api/attachments/:blobId', { preHandler: authMiddleware }, async (request: FastifyRequest, reply: FastifyReply) => {
    const blobId = z.string().uuid().parse((request.params as any).blobId);

    try {
      const result = await pool.query('DELETE FROM attachment_blobs WHERE blob_id = $1', [blobId]);
      if (result.rowCount === 0) {
        return reply.code(404).send({ error: 'blob_not_found' });
      }
      return reply.code(204).send();
    } catch (error) {
      logger.error({ err: error }, 'Failed to delete blob');
      return reply.code(500).send({ error: 'internal_error' });
    }
  });
}
