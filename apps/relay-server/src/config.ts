import { z } from 'zod';
import dotenv from 'dotenv';
import { join } from 'node:path';

// Load .env from root if present
dotenv.config({ path: join(process.cwd(), '../../.env') });
dotenv.config({ path: join(process.cwd(), '.env') });

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  PORT: z.coerce.number().default(8443),
  HOST: z.string().default('127.0.0.1'),
  RELAY_HOSTNAME: z.string().min(1).optional(),
  ADMIN_USERNAME: z.string().min(1).default('admin'),
  ADMIN_TOKEN: z.string().min(32),
  ACTIVATION_PEPPER: z.string().min(32)
});

// Secrets are mandatory: insecure defaults are not valid deployment settings.
const rawEnv = {
  DATABASE_URL: process.env.DATABASE_URL,
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
