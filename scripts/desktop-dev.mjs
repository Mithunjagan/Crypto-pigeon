import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
const require = createRequire(resolve(import.meta.dirname, '../apps/desktop/package.json'));
const electron = require('electron');
const child = spawn(electron, [resolve(import.meta.dirname, '../apps/desktop')], {
  stdio: 'inherit', windowsHide: true,
  env: { ...process.env, CRYPTO_PIGEON_NODE: process.execPath }
});
child.on('exit', code => { process.exitCode = code ?? 1; });
child.on('error', error => { console.error(error.message); process.exitCode = 1; });
