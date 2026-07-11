import { Fingerprint, ProtocolAddress, PublicKey } from '@signalapp/libsignal-client';
import type { LocalSignalStore } from './signal-store.js';

const bytes = (input: Uint8Array) => new Uint8Array(input) as Uint8Array<ArrayBuffer>;

export async function computeSafetyNumber(
  store: LocalSignalStore,
  contactAddress: ProtocolAddress
): Promise<string> {
  const localIdentity = await store.getIdentityKeyPair();
  const remoteIdentityKey = await store.getIdentity(contactAddress);

  if (!remoteIdentityKey) {
    throw new Error('remote_identity_key_missing_for_safety_number');
  }

  const localAddress = store.localAddress();

  const fingerprint = Fingerprint.new(
    5200, // iterations
    1, // version
    bytes(Buffer.from(localAddress.name(), 'utf8')),
    localIdentity.publicKey,
    bytes(Buffer.from(contactAddress.name(), 'utf8')),
    remoteIdentityKey
  );

  return fingerprint.displayableFingerprint().toString();
}
