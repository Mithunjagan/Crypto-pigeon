import { existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
const file=resolve(import.meta.dirname,'../.env');
if(existsSync(file)){
  console.log('Preserved existing .env. Verify DATABASE_URL and relay settings using the README.');
}else{
  const random=()=>randomBytes(32).toString('hex'),password=random();
  writeFileSync(file,[
    'POSTGRES_PASSWORD='+password,
    'DATABASE_URL=postgresql://crypto_pigeon:'+password+'@127.0.0.1:5432/crypto_pigeon',
    'ADMIN_USERNAME=admin',
    'ADMIN_TOKEN='+random(),
    'ACTIVATION_PEPPER='+random(),
    'RELAY_HOSTNAME=127.0.0.1:8443',
    'RELAY_URL=http://127.0.0.1:8443',''
  ].join('\n'),{mode:0o600,flag:'wx'});
  console.log('Created ignored .env with random local development credentials. No secrets were printed.');
}
