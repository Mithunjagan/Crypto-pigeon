import crypto from 'node:crypto';
import argon2 from 'argon2';

export interface KdfParams {
  algorithm: 'argon2id';
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  argon2Salt: string; // base64
}

export interface WrappedVmkConfig {
  version: 2;
  kdfParams: KdfParams;
  wrappedVmk: string; // base64
  vmkNonce: string; // base64 12-byte nonce
  hkdfSalt: string; // base64 separate salt
  vmkVersion: 1;
  createdAt: string;
}

// Common/breached password checks (top common list stub + basic checks)
const commonPasswords = new Set([
  'password', 'password123', '123456789', '12345678', 'qwertyuiop',
  'adminadmin', 'letmein123', 'iloveyou', 'p@ssword', 'changeit'
]);

export function validatePasswordStrength(password: string): { valid: boolean; error?: string } {
  if (password.length < 12) {
    return { valid: false, error: 'Password must be at least 12 characters long.' };
  }
  
  if (commonPasswords.has(password.toLowerCase())) {
    return { valid: false, error: 'Password is too common/weak.' };
  }

  // Basic complexity checks
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  
  if (!hasUpper || !hasLower || !hasDigit) {
    return { valid: false, error: 'Password should contain uppercase, lowercase, and numbers.' };
  }

  return { valid: true };
}

/**
 * Derives the Key Encryption Key (KEK) using Argon2id
 */
async function deriveKek(password: string, params: KdfParams): Promise<Buffer> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    salt: Buffer.from(params.argon2Salt, 'base64'),
    memoryCost: params.memoryCost,
    timeCost: params.timeCost,
    parallelism: params.parallelism,
    hashLength: 32,
    raw: true
  });
}

/**
 * Wraps the Vault Master Key (VMK) with KEK using AES-256-GCM
 */
export async function wrapVmk(vmk: Buffer, password: string, params: KdfParams): Promise<{ wrappedVmk: Buffer; vmkNonce: Buffer }> {
  const kek = await deriveKek(password, params);
  const vmkNonce = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', kek, vmkNonce);
  cipher.setAAD(Buffer.from('vmk-wrap-v1', 'utf8'));

  const encrypted = Buffer.concat([cipher.update(vmk), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Combine encrypted data and auth tag
  const wrapped = Buffer.concat([encrypted, tag]);

  // Zeroize KEK
  kek.fill(0);

  return {
    wrappedVmk: wrapped,
    vmkNonce
  };
}

/**
 * Unwraps the Vault Master Key (VMK) using the derived KEK
 */
export async function unwrapVmk(wrapped: Buffer, password: string, params: KdfParams, nonce: Buffer): Promise<Buffer> {
  const kek = await deriveKek(password, params);

  const encrypted = wrapped.slice(0, -16);
  const tag = wrapped.slice(-16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, nonce);
  decipher.setAAD(Buffer.from('vmk-wrap-v1', 'utf8'));
  decipher.setAuthTag(tag);

  const vmk = Buffer.concat([decipher.update(encrypted), decipher.final()]);

  // Zeroize KEK
  kek.fill(0);

  return vmk;
}

/**
 * Derives context-specific subkeys from VMK using HKDF-SHA256
 */
export function deriveSubkey(vmk: Buffer, hkdfSalt: Buffer, context: string): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', vmk, hkdfSalt, Buffer.from(context, 'utf8'), 32));
}
