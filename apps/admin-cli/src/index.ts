import crypto from 'node:crypto';
import { join } from 'node:path';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import { z } from 'zod';

// Workspace scripts run with this package as cwd; direct invocations may run
// from the repository root. Loading both paths keeps local development
// consistent without asking operators to echo secrets into PowerShell.
dotenv.config({ path: join(process.cwd(), '../../.env') });
dotenv.config({ path: join(process.cwd(), '.env') });

const placeholder = /(?:paste_|replace-|your_|change[-_]?me|example|placeholder)/i;
const requiredSecret = (name: string) => z.string()
  .min(32, `${name} must contain at least 32 characters. Load the exact value from .env; do not use placeholder text.`)
  .refine(value => !placeholder.test(value), `${name} contains placeholder text. Replace it with a generated secret.`);

const configSchema = z.object({
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid PostgreSQL URL.').refine(value => value.startsWith('postgresql://') || value.startsWith('postgres://'), 'DATABASE_URL must use postgresql:// or postgres://.'),
  ACTIVATION_PEPPER: requiredSecret('ACTIVATION_PEPPER')
});

const requestIdSchema = z.string().uuid('request ID must be a UUID copied from `admin -- requests`.');
const [command, argument] = process.argv.slice(2);
const usage = 'Usage: npm run admin -- requests | inspect <request-id> | approve <request-id> | reject <request-id> | revoke <user-id>';

function print(value: unknown) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function failUsage(message: string): never {
  process.stderr.write(`Command error: ${message}\n${usage}\n`);
  process.exit(2);
}

function validateCommand() {
  if (command === '--help' || command === '-h' || !command) {
    process.stdout.write(`${usage}\n`);
    process.exit(0);
  }
  if (command === 'requests' && !argument) return;
  if (['inspect', 'approve', 'reject', 'revoke'].includes(command) && argument) {
    requestIdSchema.parse(argument);
    return;
  }
  failUsage('Unknown command or missing request/user ID.');
}

function safeDiagnostic(error: unknown): string {
  if (error instanceof z.ZodError) return `Configuration error: ${error.issues.map(issue => issue.message).join(' ')}`;
  if (error && typeof error === 'object') {
    const value = error as { code?: string; message?: string; name?: string };
    if (value.code === '28P01') return 'Database authentication failed. Check POSTGRES_PASSWORD and the existing Docker volume state.';
    if (value.code === '3D000') return 'Database does not exist. Start PostgreSQL with `npm run docker:up`.';
    if (value.code === '42P01' || value.code === '42703') return 'Database schema is missing or outdated. Start the relay so migrations can complete.';
    if (value.code === 'ECONNREFUSED' || value.code === 'ENOTFOUND') return 'Database connection failed. Confirm PostgreSQL is running and DATABASE_URL is correct.';
    if (value.message === 'request_not_found') return 'Command error: the requested activation request was not found.';
    if (value.message === 'request_not_pending') return 'Command error: only a pending activation request can be approved or rejected.';
    if (value.message === 'active_user_not_found') return 'Command error: the user was not found or has already been revoked.';
    if (value.message) return `${value.name ?? 'Error'}: ${value.message.replace(/postgres(?:ql)?:\/\/[^\s@]+@/gi, 'postgresql://[REDACTED]@')}`;
  }
  return 'Unexpected admin command failure.';
}

validateCommand();

let pool: Pool | undefined;
try {
  const env = configSchema.parse(process.env);
  pool = new Pool({ connectionString: env.DATABASE_URL });

  if (command === 'requests') {
    const result = await pool.query("SELECT request_id,username,status,created_at,decided_at FROM access_requests WHERE status IN ('pending','approved') ORDER BY created_at");
    print(result.rows);
  } else if (command === 'inspect') {
    const result = await pool.query('SELECT request_id,username,status,created_at,decided_at,activation_expires_at,activation_used_at FROM access_requests WHERE request_id=$1', [argument]);
    if (!result.rows[0]) throw new Error('request_not_found');
    print(result.rows[0]);
  } else if (command === 'approve') {
    const activationCode = crypto.randomBytes(16).toString('base64url');
    const codeHash = crypto.createHmac('sha256', env.ACTIVATION_PEPPER).update(activationCode).digest('hex');
    const result = await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$2,activation_expires_at=NOW()+INTERVAL '10 minutes',attempt_count=0,decided_at=NOW() WHERE request_id=$1 AND status='pending' RETURNING request_id,username,activation_expires_at", [argument, codeHash]);
    if (!result.rows[0]) throw new Error('request_not_pending');
    // Shown once. The code is never written to the database or application logs.
    print({ request: result.rows[0], activation_code: activationCode });
  } else if (command === 'reject') {
    const result = await pool.query("UPDATE access_requests SET status='rejected',decided_at=NOW() WHERE request_id=$1 AND status='pending' RETURNING request_id", [argument]);
    if (!result.rows[0]) throw new Error('request_not_pending');
    print({ rejected: result.rows[0].request_id });
  } else if (command === 'revoke') {
    const result = await pool.query('UPDATE users SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL RETURNING user_id', [argument]);
    if (!result.rows[0]) throw new Error('active_user_not_found');
    print({ revoked: result.rows[0].user_id });
  }
} catch (error) {
  process.stderr.write(`${safeDiagnostic(error)}\n`);
  if (process.env.DEBUG === '1' && error instanceof Error) process.stderr.write(`${error.stack}\n`);
  process.exitCode = 1;
} finally {
  await pool?.end();
}
