import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
const [domain,email] = process.argv.slice(2);
if (!domain || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain) || !email || !/^[^\s@\r\n]+@[^\s@\r\n]+\.[^\s@\r\n]+$/.test(email)) {
  throw new Error('Usage: node scripts/setup-production.mjs relay.your-domain.com operator@your-domain.com');
}
const random = () => randomBytes(32).toString('hex');
writeFileSync(resolve(import.meta.dirname,'../.env.production'), [
  `RELAY_DOMAIN=${domain}`,`TLS_EMAIL=${email}`,`POSTGRES_PASSWORD=${random()}`,
  'ADMIN_USERNAME=admin',`ADMIN_TOKEN=${random()}`,`ACTIVATION_PEPPER=${random()}`,'TRUST_PROXY=1',''
].join('\n'), { flag:'wx', mode:0o600 });
console.log('Created .env.production with separate random secrets. Existing files are never overwritten.');
