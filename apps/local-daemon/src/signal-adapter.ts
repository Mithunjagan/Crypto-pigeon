import {
  CiphertextMessageType,
  KEMPublicKey,
  PreKeyBundle,
  PreKeySignalMessage,
  ProtocolAddress,
  PublicKey,
  SignalMessage,
  processPreKeyBundle,
  signalDecrypt,
  signalDecryptPreKey,
  signalEncrypt
} from '@signalapp/libsignal-client';
import { LocalSignalStore } from './signal-store.js';

const bytes = (input: Uint8Array) => new Uint8Array(input) as Uint8Array<ArrayBuffer>;

export async function establishSession(
  store: LocalSignalStore,
  address: ProtocolAddress,
  bundle: {
    registrationId: number;
    signalDeviceId: number;
    identityPublicKey: string; // base64
    signedPrekey: { id: number; publicKey: string; signature: string };
    oneTimePrekey: { id: number; publicKey: string } | null;
    pqOneTimePrekey: { id: number; publicKey: string; signature: string } | null;
    pqLastResortPrekey: { id: number; publicKey: string; signature: string };
  }
) {
  const one = bundle.oneTimePrekey;
  const pqOne = bundle.pqOneTimePrekey || bundle.pqLastResortPrekey;

  const prekey = PreKeyBundle.new(
    bundle.registrationId,
    bundle.signalDeviceId,
    one?.id ?? null,
    one ? PublicKey.deserialize(bytes(Buffer.from(one.publicKey, 'base64'))) : null,
    bundle.signedPrekey.id,
    PublicKey.deserialize(bytes(Buffer.from(bundle.signedPrekey.publicKey, 'base64'))),
    bytes(Buffer.from(bundle.signedPrekey.signature, 'base64')),
    PublicKey.deserialize(bytes(Buffer.from(bundle.identityPublicKey, 'base64'))),
    pqOne.id,
    KEMPublicKey.deserialize(bytes(Buffer.from(pqOne.publicKey, 'base64'))),
    bytes(Buffer.from(pqOne.signature, 'base64'))
  );

  // Establish and save Signal session
  await processPreKeyBundle(prekey, address, store.localAddress(), store, store);
  
  // Save/pin contact's identity key (TOFU)
  await store.saveIdentity(address, PublicKey.deserialize(bytes(Buffer.from(bundle.identityPublicKey, 'base64'))));
}

export async function encryptPayload(
  store: LocalSignalStore,
  address: ProtocolAddress,
  plaintext: string
): Promise<{ type: number; ciphertext: string }> {
  const encrypted = await signalEncrypt(
    bytes(Buffer.from(plaintext, 'utf8')),
    address,
    store.localAddress(),
    store,
    store
  );

  return {
    type: encrypted.type(),
    ciphertext: Buffer.from(encrypted.serialize()).toString('base64')
  };
}

export async function decryptPayload(
  store: LocalSignalStore,
  address: ProtocolAddress,
  ciphertextBase64: string,
  type: number
): Promise<string> {
  const ciphertextBytes = bytes(Buffer.from(ciphertextBase64, 'base64'));
  let decryptedBytes: Uint8Array;

  if (type === CiphertextMessageType.PreKey) {
    decryptedBytes = await signalDecryptPreKey(
      PreKeySignalMessage.deserialize(ciphertextBytes),
      address,
      store.localAddress(),
      store,
      store,
      store,
      store,
      store
    );
  } else if (type === CiphertextMessageType.Whisper) {
    decryptedBytes = await signalDecrypt(
      SignalMessage.deserialize(ciphertextBytes),
      address,
      store.localAddress(),
      store,
      store
    );
  } else {
    throw new Error('unsupported_ciphertext_type');
  }

  return Buffer.from(decryptedBytes).toString('utf8');
}
