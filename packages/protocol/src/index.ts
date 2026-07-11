import crypto from 'node:crypto';
import { z } from 'zod';

// Base validation schemas
export const usernameSchema = z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,32}$/);
export const deviceIdSchema = z.string().uuid();
export const base64Schema = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/);
export const hexSchema = z.string().regex(/^[0-9a-fA-F]+$/);

// Protocol Envelopes
export const envelopeSchema = z.object({
  version: z.literal(1),
  envelopeId: hexSchema.length(32), // 128-bit random hex (32 characters)
  mailboxId: z.string().min(1),
  ciphertext: base64Schema
});

// Authentication challenges
export const challengeRequestSchema = z.object({
  deviceId: deviceIdSchema
});

export const challengeResponseSchema = z.object({
  challenge: hexSchema.length(64), // 256-bit challenge hex
  expiresAt: z.number()
});

export const challengeVerifySchema = z.object({
  deviceId: deviceIdSchema,
  challenge: hexSchema.length(64),
  signature: hexSchema.length(128), // Ed25519 signature is 64 bytes (128 hex chars)
  relayHostname: z.string().min(1)
});

export const sessionTokenSchema = z.object({
  sessionToken: z.string().min(1),
  expiresAt: z.number()
});

// Prekey schemas
export const signedPrekeySchema = z.object({
  id: z.number().int().nonnegative(),
  publicKey: base64Schema,
  signature: base64Schema
});

export const oneTimePrekeySchema = z.object({
  id: z.number().int().nonnegative(),
  publicKey: base64Schema
});

export const pqOneTimePrekeySchema = z.object({
  id: z.number().int().nonnegative(),
  publicKey: base64Schema,
  signature: base64Schema
});

export const prekeyBundleSchema = z.object({
  identityKey: base64Schema,
  registrationId: z.number().int().positive(),
  signedPrekey: signedPrekeySchema,
  oneTimePrekey: oneTimePrekeySchema.nullable(),
  pqOneTimePrekey: pqOneTimePrekeySchema.nullable(),
  pqLastResortPrekey: pqOneTimePrekeySchema
});

// Activation Payload
export const activationPayloadSchema = z.object({
  requestId: deviceIdSchema,
  activationCode: z.string().min(20).max(256),
  // The daemon creates this UUID before activation and uses it for every
  // subsequent challenge-response authentication.  It must therefore be the
  // same value that is persisted as the relay device_id (not the request ID).
  deviceId: deviceIdSchema,
  deviceAuthPublicKey: base64Schema,
  signalIdentityPublicKey: base64Schema,
  registrationId: z.number().int().positive(),
  signalDeviceId: z.number().int().positive(),
  signedPrekey: signedPrekeySchema,
  oneTimePrekeys: z.array(oneTimePrekeySchema).min(20).max(200),
  pqOneTimePrekeys: z.array(pqOneTimePrekeySchema).min(20).max(200),
  pqLastResortPrekey: pqOneTimePrekeySchema
});

export const accessApplyResponseSchema = z.object({
  requestId: deviceIdSchema,
  username: usernameSchema,
  status: z.literal('pending'),
  expiresAt: z.string().datetime().optional()
});

// Ed25519 Crypto Helpers
export function generateDeviceKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' })
  };
}

export function signChallenge(privateKeyDer: Buffer, data: Buffer): Buffer {
  const key = crypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, data, key);
}

export function verifyChallenge(publicKeyDer: Buffer, data: Buffer, signature: Buffer): boolean {
  try {
    const key = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    return crypto.verify(null, data, key, signature);
  } catch {
    return false;
  }
}
