import crypto from 'node:crypto';
import { Pool } from 'pg';
import { z } from 'zod';

const env = z.object({
  DATABASE_URL: z.string().url(),
  ACTIVATION_PEPPER: z.string().min(32)
}).parse(process.env);
const [command, argument] = process.argv.slice(2);
const pool = new Pool({ connectionString: env.DATABASE_URL });
const print = (value: unknown) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);

try {
  if (command === 'requests') {
    const result = await pool.query("SELECT request_id,username,status,created_at,decided_at FROM access_requests WHERE status IN ('pending','approved') ORDER BY created_at");
    print(result.rows);
  } else if (command === 'inspect' && argument) {
    const result = await pool.query('SELECT request_id,username,status,created_at,decided_at,activation_expires_at,activation_used_at FROM access_requests WHERE request_id=$1', [argument]);
    if (!result.rows[0]) throw new Error('request_not_found');
    print(result.rows[0]);
  } else if (command === 'approve' && argument) {
    const activationCode = crypto.randomBytes(16).toString('base64url');
    // Must match relay-side activation verification.  The code itself is
    // terminal-only; the database retains a keyed, versionable HMAC instead.
    const codeHash = crypto.createHmac('sha256', env.ACTIVATION_PEPPER).update(activationCode).digest('hex');
    const result = await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$2,activation_expires_at=NOW()+INTERVAL '10 minutes',decided_at=NOW() WHERE request_id=$1 AND status='pending' RETURNING request_id,username,activation_expires_at", [argument, codeHash]);
    if (!result.rows[0]) throw new Error('request_not_pending');
    // Shown once. The code is never written to the database or logs.
    print({ request: result.rows[0], activation_code: activationCode });
  } else if (command === 'reject' && argument) {
    const result = await pool.query("UPDATE access_requests SET status='rejected',decided_at=NOW() WHERE request_id=$1 AND status='pending' RETURNING request_id", [argument]);
    if (!result.rows[0]) throw new Error('request_not_pending');
    print({ rejected: result.rows[0].request_id });
  } else if (command === 'revoke' && argument) {
    const result = await pool.query('UPDATE users SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL RETURNING user_id', [argument]);
    if (!result.rows[0]) throw new Error('active_user_not_found');
    print({ revoked: result.rows[0].user_id });
  } else {
    process.stderr.write('Usage: npm run admin -- requests|inspect <request-id>|approve <request-id>|reject <request-id>|revoke <user-id>\n');
    process.exitCode = 2;
  }
} catch (error) {
  process.stderr.write('Admin command failed.\n');
  process.exitCode = 1;
} finally { await pool.end(); }
