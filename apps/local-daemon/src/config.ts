import { join } from 'node:path';
import dotenv from 'dotenv';

// Load root env if present
dotenv.config({ path: join(process.cwd(), '../../.env') });
dotenv.config({ path: join(process.cwd(), '.env') });

export const env = {
  RELAY_URL: process.env.RELAY_URL ?? 'http://127.0.0.1:8443',
  CRYPTO_PIGEON_HOME: process.env.CRYPTO_PIGEON_HOME ?? join(process.env.USERPROFILE ?? process.env.HOME ?? process.cwd(), '.crypto_pigeon')
};
