export interface RelayEnvelopeV1 {
  version: 1;
  envelopeId: string;     // 128-bit random hex (not UUIDv7)
  mailboxId: string;      // opaque routing identifier
  ciphertext: Uint8Array; // opaque sealed payload
}

export interface AttachmentManifest {
  attachmentId: string;          // 128-bit random
  blobId: string;                // relay blob capability
  originalFilename: string;      // sanitized filename
  claimedMimeType: string;       // not trusted for rendering
  totalPlaintextSize: number;
  chunkCount: number;
  chunkSize: number;             // 65536
  chunkNonces: string[];         // base64-encoded per-chunk nonces
  fullFileDigest: string;        // SHA-256 hex of full plaintext
  attachmentKey: string;         // base64 AES-256-GCM key
  encryptionVersion: 1;
}

export interface ActivationPayload {
  requestId: string;
  activationCode: string;
  deviceAuthPublicKey: Uint8Array;          // Ed25519 public key
  signalIdentityPublicKey: Uint8Array;      // opaque libsignal public key
  registrationId: number;                   // required by PreKeyBundle.new()
  signalDeviceId: number;                   // numeric Signal device ID
  signedPrekey: {
    id: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
  oneTimePrekeys: Array<{
    id: number;
    publicKey: Uint8Array;
  }>;
  pqOneTimePrekeys: Array<{
    id: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  }>;
  pqLastResortPrekey: {
    id: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  };
}

export type VaultState = 'locked' | 'unlocked' | 'unconfigured';
