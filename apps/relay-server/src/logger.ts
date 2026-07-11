import { loggerLevel } from './config.js';

type LogFn = (obj: any, msg?: string) => void;

export function redact(val: any): any {
  if (!val) return val;
  if (typeof val === 'string') {
    // Redact base64 key patterns, hex signatures, authorization tokens, passwords, IPs
    if (val.startsWith('Bearer ')) return 'Bearer [REDACTED]';
    if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(val)) return '[REDACTED_BASE64]';
    if (/^[0-9a-fA-F]{64,}$/.test(val)) return '[REDACTED_HEX]';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) return '[REDACTED_IP]';
    return val;
  }
  if (Array.isArray(val)) {
    return val.map(redact);
  }
  if (typeof val === 'object') {
    const next: any = {};
    for (const k of Object.keys(val)) {
      if (['password', 'passkey', 'token', 'authorization', 'signature', 'ciphertext', 'public_key', 'publickey', 'identitykey', 'signedprekey', 'onetimeprekeys', 'pqonetimeprekeys', 'activationcode', 'privatekey', 'private_key', 'pepper', 'database_url', 'databaseurl'].includes(k.toLowerCase())) {
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
  const levels = ['debug', 'info', 'warn', 'error'];
  if (levels.indexOf(level) < levels.indexOf(loggerLevel)) return;
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

export function routeErrorDetails(error: unknown, method: string, route: string) {
  const cause = error instanceof Error ? error : new Error('unknown_error');
  const safeMessage = cause.message.replace(/postgres(?:ql)?:\/\/[^\s]+/gi, '[REDACTED_DATABASE_URL]');
  return {
    errorName: cause.name,
    safeMessage,
    stack: process.env.NODE_ENV === 'development' ? cause.stack?.replace(/postgres(?:ql)?:\/\/[^\s]+/gi, '[REDACTED_DATABASE_URL]') : undefined,
    method,
    route
  };
}
