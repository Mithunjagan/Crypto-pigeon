import crypto from 'node:crypto';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import Database, { setLogger } from '@signalapp/sqlcipher';
import {
  validatePasswordStrength,
  wrapVmk,
  unwrapVmk,
  deriveSubkey,
  type WrappedVmkConfig,
  type KdfParams
} from './vault-keys.js';
import { logger } from './logger.js';

const execPromise = promisify(exec);

// Suppress diagnostics mlock warnings
setLogger((_code, message) => {
  if (!message.includes('sqlcipher_mlock')) {
    process.stderr.write('SQLCipher native diagnostic occurred.\n');
  }
});

async function setPlatformPermissions(dir: string, configPath: string, dbPath: string) {
  const isWindows = process.platform === 'win32';
  if (isWindows) {
    try {
      // Disable inheritance, grant current user full access
      await execPromise(`icacls "${dir}" /inheritance:r /grant:r "%USERNAME%":(OI)(CI)F`);
    } catch (e) {
      logger.warn({ err: e }, 'Failed to restrict directory permissions on Windows');
    }
  } else {
    try {
      await execPromise(`chmod 700 "${dir}"`);
      await execPromise(`chmod 600 "${configPath}"`);
      if (require('fs').existsSync(dbPath)) {
        await execPromise(`chmod 600 "${dbPath}"`);
      }
    } catch (e) {
      logger.warn({ err: e }, 'Failed to restrict directory permissions on Unix');
    }
  }
}

export class Vault {
  private readonly rootDir: string;
  private readonly configPath: string;
  private readonly databasePath: string;
  
  private config: WrappedVmkConfig | null = null;
  private db: Database | null = null;
  
  // In-memory derived subkeys
  private fieldEncryptionKey: Buffer | null = null;
  private attachmentMetaKey: Buffer | null = null;
  private localTokenKey: Buffer | null = null;

  constructor(root = join(process.env.CRYPTO_PIGEON_HOME ?? process.env.USERPROFILE ?? process.cwd(), '.crypto_pigeon')) {
    this.rootDir = root;
    this.configPath = join(root, 'config.json');
    this.databasePath = join(root, 'data', 'chat.db');
  }

  async initialize() {
    try {
      this.config = JSON.parse(await readFile(this.configPath, 'utf8')) as WrappedVmkConfig;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }

  exists(): boolean {
    return this.config !== null;
  }

  isLocked(): boolean {
    return this.db === null;
  }

  getFieldKey(): Buffer {
    if (!this.fieldEncryptionKey) throw new Error('vault_locked');
    return this.fieldEncryptionKey;
  }

  getAttachmentKey(): Buffer {
    if (!this.attachmentMetaKey) throw new Error('vault_locked');
    return this.attachmentMetaKey;
  }

  getLocalTokenKey(): Buffer {
    if (!this.localTokenKey) throw new Error('vault_locked');
    return this.localTokenKey;
  }

  database(): Database {
    if (!this.db) throw new Error('vault_locked');
    return this.db;
  }

  async create(password: string) {
    if (this.config) throw new Error('vault_already_exists');

    const strength = validatePasswordStrength(password);
    if (!strength.valid) {
      throw new Error(strength.error || 'Password is too weak');
    }

    const argon2Salt = crypto.randomBytes(16);
    const hkdfSalt = crypto.randomBytes(16);
    const vmk = crypto.randomBytes(32);

    const kdfParams: KdfParams = {
      algorithm: 'argon2id',
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
      argon2Salt: argon2Salt.toString('base64')
    };

    const { wrappedVmk, vmkNonce } = await wrapVmk(vmk, password, kdfParams);

    this.config = {
      version: 2,
      kdfParams,
      wrappedVmk: wrappedVmk.toString('base64'),
      vmkNonce: vmkNonce.toString('base64'),
      hkdfSalt: hkdfSalt.toString('base64'),
      vmkVersion: 1,
      createdAt: new Date().toISOString()
    };

    await mkdir(this.rootDir, { recursive: true });
    await mkdir(join(this.databasePath, '..'), { recursive: true });

    await writeFile(this.configPath, JSON.stringify(this.config), 'utf8');

    // Restrict permissions
    await setPlatformPermissions(this.rootDir, this.configPath, this.databasePath);

    // Open & initialize database
    await this.openDb(vmk, hkdfSalt);

    // Zeroize VMK
    vmk.fill(0);
  }

  async unlock(password: string) {
    if (this.db) return;
    if (!this.config) throw new Error('vault_not_configured');

    const wrapped = Buffer.from(this.config.wrappedVmk, 'base64');
    const nonce = Buffer.from(this.config.vmkNonce, 'base64');
    const hkdfSalt = Buffer.from(this.config.hkdfSalt, 'base64');

    let vmk: Buffer;
    try {
      vmk = await unwrapVmk(wrapped, password, this.config.kdfParams, nonce);
    } catch (e) {
      throw new Error('invalid_vault_password', { cause: e });
    }

    try {
      await this.openDb(vmk, hkdfSalt);
    } finally {
      vmk.fill(0);
    }
  }

  private async openDb(vmk: Buffer, hkdfSalt: Buffer) {
    // Derive contextual subkeys
    const sqlcipherKey = deriveSubkey(vmk, hkdfSalt, 'sqlcipher-key-v1');
    this.fieldEncryptionKey = deriveSubkey(vmk, hkdfSalt, 'field-aead-v1');
    this.attachmentMetaKey = deriveSubkey(vmk, hkdfSalt, 'attachment-meta-v1');
    this.localTokenKey = deriveSubkey(vmk, hkdfSalt, 'local-token-v1');

    const db = new Database(this.databasePath, { cacheStatements: true });
    
    // PRAGMA key authentication
    db.pragma(`key = "x'${sqlcipherKey.toString('hex')}'"`);

    // Zeroize database key buffer
    sqlcipherKey.fill(0);

    try {
      // Force database check to verify auth key
      db.prepare('SELECT count(*) AS count FROM sqlite_master').get();
    } catch (e) {
      db.close();
      this.fieldEncryptionKey.fill(0);
      this.attachmentMetaKey.fill(0);
      this.localTokenKey.fill(0);
      this.fieldEncryptionKey = null;
      this.attachmentMetaKey = null;
      this.localTokenKey = null;
      throw new Error('invalid_vault_password', { cause: e });
    }

    this.db = db;
    this.initializeSchema();
  }

  private initializeSchema() {
    if (!this.db) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS contacts (
        contact_id TEXT PRIMARY KEY, 
        username TEXT NOT NULL, 
        identity_public_key BLOB NOT NULL, 
        verified INTEGER NOT NULL DEFAULT 0, 
        safety_number_hash TEXT, 
        identity_changed INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS conversations (
        conversation_id TEXT PRIMARY KEY, 
        contact_id TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        disappearing_seconds INTEGER, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY, 
        conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE, 
        direction TEXT NOT NULL CHECK(direction IN ('sent','received')), 
        plaintext TEXT NOT NULL, 
        sent_at INTEGER, 
        received_at INTEGER, 
        read_at INTEGER, 
        disappear_at INTEGER, 
        remote_blob_id TEXT, 
        status TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_sessions (
        contact_id TEXT PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        ratchet_state BLOB NOT NULL, 
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS identity_keys (
        device_id TEXT PRIMARY KEY, 
        identity_private_key BLOB NOT NULL, 
        identity_public_key BLOB NOT NULL, 
        signed_prekey_private BLOB NOT NULL, 
        signed_prekey_public BLOB NOT NULL, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS attachments (
        attachment_id TEXT PRIMARY KEY, 
        message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE, 
        encrypted_local_path TEXT, 
        file_name_encrypted BLOB, 
        file_size INTEGER, 
        file_hash BLOB, 
        file_key BLOB, 
        disappear_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS signal_account (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), 
        identity_key_pair BLOB NOT NULL, 
        registration_id INTEGER NOT NULL, 
        user_id TEXT, 
        device_id TEXT NOT NULL, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_signed_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_kyber_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS relay_auth (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), 
        access_token TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS remote_contacts (
        contact_id TEXT PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        user_id TEXT NOT NULL, 
        device_id TEXT NOT NULL, 
        signal_device_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_auth_key (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen_envelope_ids (
        envelope_id TEXT PRIMARY KEY,
        received_at INTEGER NOT NULL
      );
    `);
  }

  async changePassword(oldPassword: string, newPassword: string) {
    if (!this.config) throw new Error('vault_not_configured');

    const strength = validatePasswordStrength(newPassword);
    if (!strength.valid) {
      throw new Error(strength.error || 'Password is too weak');
    }

    const wrapped = Buffer.from(this.config.wrappedVmk, 'base64');
    const nonce = Buffer.from(this.config.vmkNonce, 'base64');

    // Decrypt VMK with old password
    const vmk = await unwrapVmk(wrapped, oldPassword, this.config.kdfParams, nonce);

    // Re-wrap VMK with new password and new random salt
    const newArgonSalt = crypto.randomBytes(16);
    const newKdfParams: KdfParams = {
      algorithm: 'argon2id',
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
      argon2Salt: newArgonSalt.toString('base64')
    };

    const { wrappedVmk: newWrapped, vmkNonce: newNonce } = await wrapVmk(vmk, newPassword, newKdfParams);

    // Save configuration update
    this.config = {
      ...this.config,
      kdfParams: newKdfParams,
      wrappedVmk: newWrapped.toString('base64'),
      vmkNonce: newNonce.toString('base64')
    };

    await writeFile(this.configPath, JSON.stringify(this.config), 'utf8');

    // Zeroize key material
    vmk.fill(0);
  }

  lock() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    
    // Zeroize and clear subkeys in memory
    this.fieldEncryptionKey?.fill(0);
    this.attachmentMetaKey?.fill(0);
    this.localTokenKey?.fill(0);

    this.fieldEncryptionKey = null;
    this.attachmentMetaKey = null;
    this.localTokenKey = null;
  }
}
