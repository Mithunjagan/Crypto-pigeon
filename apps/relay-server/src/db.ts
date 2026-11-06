import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { env } from './config.js';
import { formatPublicUid } from '@crypto-pigeon/protocol';
import { logger } from './logger.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: env.DATABASE_POOL_MAX, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function initDb() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);

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

    // Run the idempotent base schema before applying compatibility repairs.
    const schemaSqlPath = join(__dirname, 'schema.sql');
    const schemaSql = await readFile(schemaSqlPath, 'utf8');
    await client.query(schemaSql);

    // Earlier development schemas used prekey_id as the primary key.  The
    // relay now selects prekeys by an opaque generated id, so existing tables
    // are repaired in place rather than made nullable or silently discarded.
    await client.query(`ALTER TABLE one_time_prekeys ADD COLUMN IF NOT EXISTS id UUID`);
    await client.query(`UPDATE one_time_prekeys SET id = gen_random_uuid() WHERE id IS NULL`);
    await client.query(`ALTER TABLE one_time_prekeys ALTER COLUMN id SET DEFAULT gen_random_uuid()`);
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS one_time_prekeys_generated_id_idx ON one_time_prekeys(id)`);

    // Development schema v3 used UNIQUE(user_id), which made it impossible to
    // retain a revoked device record during replacement.  Replace it with the
    // partial unique index defined in schema.sql. This is idempotent and keeps
    // existing device history intact.
    await client.query('ALTER TABLE device_identity_keys DROP CONSTRAINT IF EXISTS device_identity_keys_user_id_key');
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS one_active_device_per_user
      ON device_identity_keys(user_id) WHERE revoked_at IS NULL`);

    // If migrating, copy data and drop old tables
    if (oldDevicesExist && !newKeysExist) {
      logger.info('Migrating data from devices table to device_identity_keys');
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
      logger.info('Migration from devices completed successfully');
    }

    await client.query(`CREATE TABLE IF NOT EXISTS vault_backups (
      lookup_token TEXT PRIMARY KEY CHECK (lookup_token ~ '^[a-f0-9]{64}$'),
      version INTEGER NOT NULL DEFAULT 1, nonce BYTEA NOT NULL CHECK(octet_length(nonce)=12),
      ciphertext BYTEA NOT NULL CHECK(octet_length(ciphertext)<=26214400), fragment7_shard BYTEA,
      writer_public_key BYTEA NOT NULL, signature TEXT NOT NULL, signed_at TEXT NOT NULL,
      device_id UUID, instance_hash TEXT, device_signature TEXT, claim BOOLEAN NOT NULL DEFAULT false,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    await client.query(`CREATE TABLE IF NOT EXISTS device_vault_locks (
      device_id UUID PRIMARY KEY REFERENCES device_identity_keys(device_id), instance_hash TEXT NOT NULL
    )`);
    if(!(await client.query('SELECT 1 FROM schema_migrations WHERE version=3')).rowCount){
      await client.query('ALTER TABLE vault_backups DROP CONSTRAINT IF EXISTS vault_backups_ciphertext_check');
      await client.query('ALTER TABLE vault_backups ADD CONSTRAINT vault_backups_ciphertext_check CHECK(octet_length(ciphertext)<=67108864)');
      await client.query('INSERT INTO schema_migrations(version) VALUES(3)');
    }
    await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS public_uid TEXT UNIQUE');
    await client.query(`CREATE TABLE IF NOT EXISTS blind_messages(id UUID PRIMARY KEY,dropbox_id TEXT NOT NULL,ciphertext BYTEA NOT NULL,sender_hash TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),expires_at TIMESTAMPTZ NOT NULL)`);
    await client.query('CREATE INDEX IF NOT EXISTS blind_dropbox_pending ON blind_messages(dropbox_id)');
    await client.query('CREATE TABLE IF NOT EXISTS contact_exchange_acks(user_id UUID NOT NULL,peer_id UUID NOT NULL,PRIMARY KEY(user_id,peer_id))');
    await client.query('ALTER TABLE vault_backups ADD COLUMN IF NOT EXISTS ciphertext_sha256 TEXT');
    // One current signed revision already bounds storage more tightly than the two-revision ceiling.
    const missingUids = await client.query('SELECT user_id FROM users WHERE public_uid IS NULL');
    for (const row of missingUids.rows) {
      let uid = formatPublicUid(row.user_id), attempt = 0;
      while ((await client.query('SELECT 1 FROM users WHERE public_uid=$1',[uid])).rowCount) uid = formatPublicUid(row.user_id+':'+(++attempt));
      await client.query('UPDATE users SET public_uid=$1 WHERE user_id=$2',[uid,row.user_id]);
    }
    await client.query('INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT DO NOTHING');
    await client.query('INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING');
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    logger.error({ err: error }, 'Database initialization or migration failed');
    throw error;
  } finally {
    client.release();
  }
}
