import { z } from 'zod';
import dotenv from 'dotenv';
import { join } from 'node:path';

// Load .env from root if present
dotenv.config({ path: join(process.cwd(), '../../.env') });
dotenv.config({ path: join(process.cwd(), '.env') });

const placeholder = /(?:paste_|replace-|your_|change[-_]?me|example|placeholder)/i;
const secret = (name: string) => z.string().min(32, `${name} must contain at least 32 characters.`)
  .refine(value => !placeholder.test(value), `${name} must not contain placeholder text.`);
const postgresPassword = z.string().min(16, 'POSTGRES_PASSWORD must contain at least 16 characters.')
  .refine(value => !placeholder.test(value), 'POSTGRES_PASSWORD must not contain placeholder text.');

// Compose passes these two values only to construct a database URL inside the
// relay container. encodeURIComponent prevents reserved password characters
// from changing URI parsing. Direct local runs must supply DATABASE_URL.
const databaseUrl = process.env.DATABASE_URL ?? (() => {
  if (!process.env.POSTGRES_PASSWORD || !process.env.DATABASE_HOST) return undefined;
  const password = postgresPassword.parse(process.env.POSTGRES_PASSWORD);
  return `postgresql://crypto_pigeon:${encodeURIComponent(password)}@${process.env.DATABASE_HOST}:5432/crypto_pigeon`;
})();

const envSchema = z.object({
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid URL.').refine(value => /^(?:postgres|postgresql):\/\//.test(value), 'DATABASE_URL must use postgres:// or postgresql://.'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  HOST: z.string().min(1).max(255).default('127.0.0.1').refine(value => !placeholder.test(value), 'HOST must not be placeholder text.'),
  RELAY_HOSTNAME: z.string().min(1).max(255).optional().refine(value => !value || !placeholder.test(value), 'RELAY_HOSTNAME must not be placeholder text.'),
  ADMIN_USERNAME: z.string().trim().min(3).max(64).refine(value => !placeholder.test(value), 'ADMIN_USERNAME must not be placeholder text.'),
  ADMIN_TOKEN: secret('ADMIN_TOKEN'),
  ACTIVATION_PEPPER: secret('ACTIVATION_PEPPER')
});

// Secrets are mandatory: insecure defaults are not valid deployment settings.
const rawEnv = {
  DATABASE_URL: databaseUrl,
  PORT: process.env.PORT,
  HOST: process.env.HOST,
  RELAY_HOSTNAME: process.env.RELAY_HOSTNAME,
  ADMIN_USERNAME: process.env.ADMIN_USERNAME,
  ADMIN_TOKEN: process.env.ADMIN_TOKEN,
  ACTIVATION_PEPPER: process.env.ACTIVATION_PEPPER
};

export const env = envSchema.parse(rawEnv);
export const relayHostname = env.RELAY_HOSTNAME ?? `${env.HOST}:${env.PORT}`;
export const isDev = process.env.NODE_ENV !== 'production';
export const loggerLevel = process.env.LOG_LEVEL ?? (isDev ? 'debug' : 'warn');
export const maxBodySize = 25 * 1024 * 1024; // 25 MB limit for attachments
