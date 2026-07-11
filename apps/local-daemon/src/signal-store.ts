import crypto from 'node:crypto';
import Database from '@signalapp/sqlcipher';
import {
  Direction, IdentityChange, IdentityKeyPair, IdentityKeyStore, KEMKeyPair, KyberPreKeyRecord,
  KyberPreKeyStore, PreKeyRecord, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey,
  SessionRecord, SessionStore, SignedPreKeyRecord, SignedPreKeyStore
} from '@signalapp/libsignal-client';
import { generateDeviceKeyPair } from '@crypto-pigeon/protocol';

const bytes = (value: Uint8Array) => new Uint8Array(value) as Uint8Array<ArrayBuffer>;
const now = () => Date.now();
const row = <T>(db: Database, sql: string, params?: ReadonlyArray<string | number | Uint8Array<ArrayBuffer>>) => db.prepare(sql).get(params) as T | undefined;

export interface PublishedPreKeyBundle {
  deviceId: string;
  signalDeviceId: number;
  registrationId: number;
  identityPublicKey: string; // base64
  deviceAuthPublicKey: string; // base64
  signedPrekey: {
    id: number;
    publicKey: string; // base64
    signature: string; // base64
  };
  oneTimePrekeys: Array<{ id: number; publicKey: string }>; // base64
  pqOneTimePrekeys: Array<{ id: number; publicKey: string; signature: string }>; // base64
  pqLastResortPrekey: { id: number; publicKey: string; signature: string }; // base64
}

export class LocalSignalStore extends SessionStore implements IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore {
  constructor(private readonly db: Database) {
    super();
  }

  private account() {
    const value = row<{ identity_key_pair: Uint8Array; registration_id: number; user_id: string | null; device_id: string }>(
      this.db,
      'SELECT identity_key_pair, registration_id, user_id, device_id FROM signal_account WHERE singleton=1'
    );
    if (!value) throw new Error('signal_identity_missing');
    return value;
  }

  async ensureIdentity(): Promise<PublishedPreKeyBundle> {
    let account = row<{ device_id: string }>(this.db, 'SELECT device_id FROM signal_account WHERE singleton=1');
    
    if (!account) {
      // 1. Generate Signal Identity
      const identity = IdentityKeyPair.generate();
      const registrationId = crypto.randomInt(1, 0x3fffffff);
      const deviceId = crypto.randomUUID();

      // 2. Generate Device Auth Signing Key (Domain 3, separate Ed25519)
      const authKeypair = generateDeviceKeyPair();

      // 3. Generate Signed Prekey
      const signedPrivate = PrivateKey.generate();
      const signedPublic = signedPrivate.getPublicKey();
      const signed = SignedPreKeyRecord.new(1, now(), signedPublic, signedPrivate, identity.privateKey.sign(signedPublic.serialize()));

      // 4. Generate 100 One-time Prekeys
      const oneTimeKeys: Array<{ id: number; record: PreKeyRecord }> = [];
      for (let id = 1; id <= 100; id++) {
        const privateKey = PrivateKey.generate();
        const record = PreKeyRecord.new(id, privateKey.getPublicKey(), privateKey);
        oneTimeKeys.push({ id, record });
      }

      // 5. Generate PQ Last Resort Prekey (Kyber ID 1)
      const kem = KEMKeyPair.generate();
      const kyber = KyberPreKeyRecord.new(1, now(), kem, identity.privateKey.sign(kem.getPublicKey().serialize()));

      // 6. Generate 100 PQ One-time Prekeys (Kyber ID 2 to 101)
      const pqOneTimeKeys: Array<{ id: number; record: KyberPreKeyRecord }> = [];
      for (let id = 2; id <= 101; id++) {
        const kemKey = KEMKeyPair.generate();
        const record = KyberPreKeyRecord.new(id, now(), kemKey, identity.privateKey.sign(kemKey.getPublicKey().serialize()));
        pqOneTimeKeys.push({ id, record });
      }

      // Save to database
      this.db.transaction(() => {
        this.db.prepare(
          'INSERT INTO signal_account (singleton, identity_key_pair, registration_id, device_id, created_at) VALUES (1,?,?,?,?)'
        ).run([bytes(identity.serialize()), registrationId, deviceId, now()]);

        this.db.prepare(
          'INSERT INTO device_auth_key (singleton, private_key, public_key) VALUES (1,?,?)'
        ).run([bytes(authKeypair.privateKey), bytes(authKeypair.publicKey)]);

        this.db.prepare(
          'INSERT INTO signal_signed_prekeys (prekey_id, record) VALUES (?,?)'
        ).run([1, bytes(signed.serialize())]);

        for (const { id, record } of oneTimeKeys) {
          this.db.prepare('INSERT INTO signal_prekeys (prekey_id, record) VALUES (?,?)')
            .run([id, bytes(record.serialize())]);
        }

        // Store last resort under ID 1
        this.db.prepare('INSERT INTO signal_kyber_prekeys (prekey_id, record) VALUES (?,?)')
          .run([1, bytes(kyber.serialize())]);

        // Store other PQ one-time prekeys
        for (const { id, record } of pqOneTimeKeys) {
          this.db.prepare('INSERT INTO signal_kyber_prekeys (prekey_id, record) VALUES (?,?)')
            .run([id, bytes(record.serialize())]);
        }
      })();

      account = { device_id: deviceId };
    }

    const current = this.account();
    const identity = IdentityKeyPair.deserialize(bytes(current.identity_key_pair));
    const authKeyRes = row<{ public_key: Uint8Array }>(this.db, 'SELECT public_key FROM device_auth_key WHERE singleton=1');
    if (!authKeyRes) throw new Error('device_auth_key_missing');

    const signed = await this.getSignedPreKey(1);
    
    // Fetch classical one-time prekeys
    const prekeys = this.db.prepare('SELECT prekey_id, record FROM signal_prekeys ORDER BY prekey_id LIMIT 100').all() as Array<{ prekey_id: number; record: Uint8Array }>;
    
    // Fetch last resort (Kyber ID 1)
    const kyberLastResort = await this.getKyberPreKey(1);

    // Fetch PQ one-time prekeys (Kyber ID >= 2)
    const pqPrekeys = this.db.prepare('SELECT prekey_id, record FROM signal_kyber_prekeys WHERE prekey_id >= 2 ORDER BY prekey_id LIMIT 100').all() as Array<{ prekey_id: number; record: Uint8Array }>;

    return {
      deviceId: current.device_id,
      signalDeviceId: 1,
      registrationId: current.registration_id,
      identityPublicKey: Buffer.from(identity.publicKey.serialize()).toString('base64'),
      deviceAuthPublicKey: Buffer.from(authKeyRes.public_key).toString('base64'),
      signedPrekey: {
        id: signed.id(),
        publicKey: Buffer.from(signed.publicKey().serialize()).toString('base64'),
        signature: Buffer.from(signed.signature()).toString('base64')
      },
      oneTimePrekeys: prekeys.map(value => ({
        id: value.prekey_id,
        publicKey: Buffer.from(PreKeyRecord.deserialize(bytes(value.record)).publicKey().serialize()).toString('base64')
      })),
      pqOneTimePrekeys: pqPrekeys.map(value => {
        const record = KyberPreKeyRecord.deserialize(bytes(value.record));
        return {
          id: value.prekey_id,
          publicKey: Buffer.from(record.publicKey().serialize()).toString('base64'),
          signature: Buffer.from(record.signature()).toString('base64')
        };
      }),
      pqLastResortPrekey: {
        id: kyberLastResort.id(),
        publicKey: Buffer.from(kyberLastResort.publicKey().serialize()).toString('base64'),
        signature: Buffer.from(kyberLastResort.signature()).toString('base64')
      }
    };
  }

  getDeviceAuthKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
    const authKeyRes = row<{ private_key: Uint8Array; public_key: Uint8Array }>(this.db, 'SELECT private_key, public_key FROM device_auth_key WHERE singleton=1');
    if (!authKeyRes) throw new Error('device_auth_key_missing');
    return {
      privateKey: Buffer.from(authKeyRes.private_key),
      publicKey: Buffer.from(authKeyRes.public_key)
    };
  }

  setAccount(userId: string) {
    this.db.prepare('UPDATE signal_account SET user_id=? WHERE singleton=1').run([userId]);
  }

  localAddress() {
    const account = this.account();
    if (!account.user_id) throw new Error('remote_account_not_registered');
    return ProtocolAddress.new(account.user_id, 1);
  }

  async saveSession(name: ProtocolAddress, record: SessionRecord) {
    this.db.prepare(
      `INSERT INTO signal_sessions (contact_id, ratchet_state, updated_at) 
       VALUES (?,?,?) 
       ON CONFLICT(contact_id) 
       DO UPDATE SET ratchet_state=excluded.ratchet_state, updated_at=excluded.updated_at`
    ).run([name.toString(), bytes(record.serialize()), now()]);
  }

  async getSession(name: ProtocolAddress) {
    const value = row<{ ratchet_state: Uint8Array }>(
      this.db,
      'SELECT ratchet_state FROM signal_sessions WHERE contact_id=?',
      [name.toString()]
    );
    return value ? SessionRecord.deserialize(bytes(value.ratchet_state)) : null;
  }

  async getExistingSessions(addresses: ProtocolAddress[]) {
    const values = await Promise.all(addresses.map(value => this.getSession(value)));
    return values.filter((value): value is SessionRecord => value !== null);
  }

  async getIdentityKey() {
    return IdentityKeyPair.deserialize(bytes(this.account().identity_key_pair)).privateKey;
  }

  async getIdentityKeyPair() {
    return IdentityKeyPair.deserialize(bytes(this.account().identity_key_pair));
  }

  async getLocalRegistrationId() {
    return this.account().registration_id;
  }

  async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
    const existing = row<{ identity_public_key: Uint8Array }>(
      this.db,
      'SELECT identity_public_key FROM contacts WHERE contact_id=?',
      [name.toString()]
    );
    const serialized = bytes(key.serialize());
    if (!existing) {
      this.db.prepare(
        'INSERT INTO contacts (contact_id, username, identity_public_key, verified, identity_changed, created_at) VALUES (?,?,?,0,0,?)'
      ).run([name.toString(), name.name(), serialized, now()]);
      return IdentityChange.NewOrUnchanged;
    }
    const changed = !PublicKey.deserialize(bytes(existing.identity_public_key)).equals(key);
    
    // Set identity_changed to 1 if the key differs (TOFU warning block)
    this.db.prepare(
      'UPDATE contacts SET identity_public_key=?, verified=CASE WHEN ? THEN 0 ELSE verified END, identity_changed=CASE WHEN ? THEN 1 ELSE identity_changed END WHERE contact_id=?'
    ).run([serialized, changed ? 1 : 0, changed ? 1 : 0, name.toString()]);
    
    return changed ? IdentityChange.ReplacedExisting : IdentityChange.NewOrUnchanged;
  }

  async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, _direction: Direction) {
    const existing = await this.getIdentity(name);
    return existing === null || existing.equals(key);
  }

  async getIdentity(name: ProtocolAddress) {
    const value = row<{ identity_public_key: Uint8Array }>(
      this.db,
      'SELECT identity_public_key FROM contacts WHERE contact_id=?',
      [name.toString()]
    );
    return value ? PublicKey.deserialize(bytes(value.identity_public_key)) : null;
  }

  async savePreKey(id: number, record: PreKeyRecord) {
    this.db.prepare(
      'INSERT INTO signal_prekeys (prekey_id, record) VALUES (?,?) ON CONFLICT(prekey_id) DO UPDATE SET record=excluded.record'
    ).run([id, bytes(record.serialize())]);
  }

  async getPreKey(id: number) {
    const value = row<{ record: Uint8Array }>(this.db, 'SELECT record FROM signal_prekeys WHERE prekey_id=?', [id]);
    if (!value) throw new Error('prekey_not_found');
    return PreKeyRecord.deserialize(bytes(value.record));
  }

  async removePreKey(id: number) {
    this.db.prepare('DELETE FROM signal_prekeys WHERE prekey_id=?').run([id]);
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord) {
    this.db.prepare(
      'INSERT INTO signal_signed_prekeys (prekey_id, record) VALUES (?,?) ON CONFLICT(prekey_id) DO UPDATE SET record=excluded.record'
    ).run([id, bytes(record.serialize())]);
  }

  async getSignedPreKey(id: number) {
    const value = row<{ record: Uint8Array }>(this.db, 'SELECT record FROM signal_signed_prekeys WHERE prekey_id=?', [id]);
    if (!value) throw new Error('signed_prekey_not_found');
    return SignedPreKeyRecord.deserialize(bytes(value.record));
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord) {
    this.db.prepare(
      'INSERT INTO signal_kyber_prekeys (prekey_id, record) VALUES (?,?) ON CONFLICT(prekey_id) DO UPDATE SET record=excluded.record'
    ).run([id, bytes(record.serialize())]);
  }

  async getKyberPreKey(id: number) {
    const value = row<{ record: Uint8Array }>(this.db, 'SELECT record FROM signal_kyber_prekeys WHERE prekey_id=?', [id]);
    if (!value) throw new Error('kyber_prekey_not_found');
    return KyberPreKeyRecord.deserialize(bytes(value.record));
  }

  async markKyberPreKeyUsed(_id: number, _signedPreKeyId: number, _baseKey: PublicKey) {
    // Retained until scheduled rotation
  }
}
