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
  ADMIN_TOKEN: z.string().default('admin-change-me'),
  ACTIVATION_PEPPER: z.string().default('stable-default-pepper-must-be-changed-in-production')
});

// Fallback logic to reuse ADMIN_PASSWORD from old config if ADMIN_TOKEN is not set
const rawEnv = {
  DATABASE_URL: process.env.DATABASE_URL,
  PORT: process.env.PORT,
  HOST: process.env.HOST,
  ADMIN_TOKEN: process.env.ADMIN_TOKEN || process.env.ADMIN_PASSWORD,
  ACTIVATION_PEPPER: process.env.ACTIVATION_PEPPER
};

export const env = envSchema.parse(rawEnv);
export const isDev = process.env.NODE_ENV !== 'production';
export const loggerLevel = process.env.LOG_LEVEL ?? (isDev ? 'debug' : 'warn');
export const maxBodySize = 25 * 1024 * 1024; // 25 MB limit for attachments
