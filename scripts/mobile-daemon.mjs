import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
const child=spawn(process.execPath,['--env-file-if-exists=.env','apps/local-daemon/dist/server.js'],{
  cwd:resolve(import.meta.dirname,'..'),stdio:'inherit',env:{...process.env,PORT:process.env.CRYPTO_PIGEON_MOBILE_PORT ?? '17420',
    CRYPTO_PIGEON_HOME:process.env.CRYPTO_PIGEON_MOBILE_HOME ?? resolve(import.meta.dirname,'../.crypto_pigeon_mobile')}
});
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>child.kill(signal));
child.on('exit',code=>process.exitCode=code??1);
