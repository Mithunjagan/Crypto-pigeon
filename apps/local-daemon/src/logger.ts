type LogFn = (obj: any, msg?: string) => void;

function redact(val: any): any {
  if (!val) return val;
  if (typeof val === 'string') {
    if (val.startsWith('Bearer ')) return 'Bearer [REDACTED]';
    if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(val)) return '[REDACTED_BASE64]';
    if (/^[0-9a-fA-F]{64,}$/.test(val)) return '[REDACTED_HEX]';
    return val;
  }
  if (Array.isArray(val)) {
    return val.map(redact);
  }
  if (typeof val === 'object') {
    const next: any = {};
    for (const k of Object.keys(val)) {
      if (['password', 'passkey', 'token', 'authorization', 'signature', 'ciphertext', 'public_key', 'publicKey', 'identityKey', 'signedPrekey', 'oneTimePrekeys', 'pqOneTimePrekeys'].includes(k.toLowerCase())) {
        next[k] = '[REDACTED]';
      } else {
        next[k] = redact(val[k]);
      }
    }
    return next;
  }
  return val;
}

function log(level: string, obj: any, msg?: string) {
  const time = new Date().toISOString();
  if (typeof obj === 'string') {
    console.log(JSON.stringify({ time, level, msg: redact(obj) }));
  } else {
    console.log(JSON.stringify({ time, level, msg, ...redact(obj) }));
  }
}

export const logger = {
  debug: ((obj, msg) => log('debug', obj, msg)) as LogFn,
  info: ((obj, msg) => log('info', obj, msg)) as LogFn,
  warn: ((obj, msg) => log('warn', obj, msg)) as LogFn,
  error: ((obj, msg) => log('error', obj, msg)) as LogFn
};
