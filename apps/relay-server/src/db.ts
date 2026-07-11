import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { env } from './config.js';
import { logger } from './logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function initDb() {
  const client = await pool.connect();
  try {
    // Check if old devices table exists
    const devicesCheck = await client.query(`
      SELECT 1 FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'devices'
    `);
    const oldDevicesExist = devicesCheck.rows.length > 0;

    // Check if new device_identity_keys table exists
    const identityKeysCheck = await client.query(`
      SELECT 1 FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'device_identity_keys'
    `);
    const newKeysExist = identityKeysCheck.rows.length > 0;

    // Rename old one_time_prekeys table before running schema.sql if we are migrating
    if (oldDevicesExist && !newKeysExist) {
      logger.info('Migration detected: Renaming old one_time_prekeys table');
      await client.query('ALTER TABLE IF EXISTS one_time_prekeys RENAME TO one_time_prekeys_old');
      await client.query('DROP INDEX IF EXISTS one_time_prekeys_device_signal_id');
    }

    // Run schema.sql
    const schemaSqlPath = join(__dirname, 'schema.sql');
    const schemaSql = await readFile(schemaSqlPath, 'utf8');
    await client.query(schemaSql);

    // If migrating, copy data and drop old tables
    if (oldDevicesExist && !newKeysExist) {
      logger.info('Migrating data from devices table to device_identity_keys');
      await client.query('BEGIN');

      // Migrate devices
      await client.query(`
        INSERT INTO device_identity_keys (
          device_id, user_id, identity_public_key, auth_public_key, 
          registration_id, signal_device_id, registered_at, revoked_at
        )
        SELECT 
          device_id, user_id, identity_public_key, 
          '\\x0000000000000000000000000000000000000000000000000000000000000000'::bytea, 
          registration_id, signal_device_id, created_at, revoked_at
        FROM devices
        ON CONFLICT (device_id) DO NOTHING
      `);

      // Migrate signed prekeys
      await client.query(`
        INSERT INTO signed_prekeys (device_id, signal_prekey_id, public_key, signature, uploaded_at)
        SELECT device_id, signed_prekey_id, signed_prekey, signed_prekey_signature, created_at
        FROM devices
        ON CONFLICT (device_id, signal_prekey_id) DO NOTHING;
      `);

      // Migrate Kyber/PQ prekey as last-resort prekey
      await client.query(`
        INSERT INTO pq_one_time_prekeys (device_id, signal_prekey_id, public_key, signature, prekey_type, consumed, uploaded_at)
        SELECT device_id, kyber_prekey_id, kyber_prekey, kyber_prekey_signature, 'last_resort', false, created_at
        FROM devices
        ON CONFLICT (device_id, signal_prekey_id) DO NOTHING;
      `);

      // Migrate old one_time_prekeys if table exists
      const oldOtpCheck = await client.query(`
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'one_time_prekeys_old'
      `);
      if (oldOtpCheck.rows.length > 0) {
        await client.query(`
          INSERT INTO one_time_prekeys (id, device_id, signal_prekey_id, public_key, consumed, uploaded_at)
          SELECT prekey_id, device_id, signal_prekey_id, public_key, consumed, created_at
          FROM one_time_prekeys_old
          ON CONFLICT (device_id, signal_prekey_id) DO NOTHING
        `);
        await client.query('DROP TABLE IF EXISTS one_time_prekeys_old');
      }

      await client.query('DROP TABLE IF EXISTS devices');
      await client.query('COMMIT');
      logger.info('Migration from devices completed successfully');
    }
  } catch (error) {
    logger.error({ err: error }, 'Database initialization or migration failed');
    throw error;
  } finally {
    client.release();
  }
}
