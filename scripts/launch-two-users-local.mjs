import { spawn } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(import.meta.url);
const root = resolve(dirname(script), '..');
const users = [{ name: 'Alice', port: 17422 }, { name: 'Bob', port: 17423 }];

// The same script is the Electron entry point: no installer or desktop rebuild.
async function runUi() {
  const { app, BrowserWindow, session, screen } = createRequire(import.meta.url)('electron');
  const name = process.env.CP_DEMO_USER;
  const user = users.find(value => value.name === name);
  if (!user || !process.send) throw new Error('Start demo windows through npm run demo:two-users.');
  // Keep Chromium outside the vault directory, which Restore renames/replaces.
  const profile = join(root, 'node_modules/.cache/crypto-pigeon-two-users', name.toLowerCase());
  mkdirSync(profile, { recursive: true });
  app.setPath('userData', profile);
  const origin = `http://127.0.0.1:${user.port}`;
  const local = value => { try { return new URL(value).origin === origin; } catch { return false; } };
  process.on('disconnect', () => app.quit());
  await app.whenReady();
  const browser = session.fromPartition('persist:demo');
  browser.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  browser.setPermissionCheckHandler(() => false);
  browser.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !local(details.url) && !details.url.startsWith(`blob:${origin}/`) }));
  const area = screen.getPrimaryDisplay().workArea;
  const width = Math.floor(area.width / 2);
  const window = new BrowserWindow({ title: `Crypto Pigeon — ${name}`, width, height: area.height,
    x: area.x + users.indexOf(user) * width, y: area.y,
    webPreferences: { session: browser, nodeIntegration: false, contextIsolation: true, sandbox: true, webviewTag: false } });
  window.setMenu(null);
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => { if (!local(url)) event.preventDefault(); });
  window.webContents.on('page-title-updated', event => event.preventDefault());
  process.on('message', message => {
    if (message?.type === 'stop') app.quit();
    if (message?.type === 'open' && local(message.url)) {
      void window.loadURL(message.url).catch(() => { console.error(`${name}: unable to load the local UI.`); app.exit(1); });
    }
  });
  app.on('window-all-closed', () => app.quit());
  process.send({ type: 'ui-ready' });
}

async function launch() {
  const flags = process.argv.slice(2);
  if (flags.includes('--help') || flags.includes('-h')) {
    console.log('Usage: npm run demo:two-users -- [--approve-all]\n' +
      'Uses RELAY_URL (default http://127.0.0.1:8443) and existing compiled daemon/UI files.\n' +
      '--approve-all watches PostgreSQL for ALL pending access requests and prints one-time activation codes.\n' +
      'Requires DATABASE_URL and the relay\'s ACTIVATION_PEPPER (shell or root .env).\n' +
      'Ctrl+C or closing either window stops both users. Vaults and browser profiles are preserved.');
    return;
  }
  if (flags.some(flag => flag !== '--approve-all')) throw new Error('Unknown flag. Use --help.');
  if (existsSync(join(root, '.env'))) process.loadEnvFile(join(root, '.env'));
  const relay = new URL(process.env.RELAY_URL ?? 'http://127.0.0.1:8443');
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(relay.hostname);
  if ((relay.protocol !== 'https:' && !(relay.protocol === 'http:' && loopback)) || relay.username || relay.password || relay.pathname !== '/' || relay.search || relay.hash) {
    throw new Error('RELAY_URL must be an HTTPS origin, or HTTP on loopback for this local demo.');
  }
  try {
    const response = await fetch(`${relay.origin}/readyz`, { signal: AbortSignal.timeout(5000), redirect: 'error' });
    if (!response.ok) throw new Error('not ready');
  } catch { throw new Error(`Relay unavailable at ${relay.origin}/readyz. Start the relay and PostgreSQL first.`); }
  const entry = join(root, 'apps/local-daemon/dist/server.js');
  if (!existsSync(entry) || !existsSync(join(root, 'apps/local-ui/dist/index.html'))) {
    throw new Error('Compiled daemon/UI files are missing. Build the source once with npm run build; no installer is needed.');
  }
  const desktopRequire = createRequire(join(root, 'apps/desktop/package.json'));
  const electronDirectory = dirname(desktopRequire.resolve('electron/package.json'));
  const electronPathFile = join(electronDirectory, 'path.txt');
  const electron = existsSync(electronPathFile) ? join(electronDirectory, 'dist', readFileSync(electronPathFile, 'utf8').trim()) : '';
  if (!electron || !existsSync(electron)) throw new Error('Electron runtime is missing. Install desktop dependencies and its Electron binary before starting the demo.');
  for (const { port } of users) {
    await new Promise((accept, reject) => {
      const probe = createServer();
      probe.once('error', () => reject(new Error(`Local port ${port} is busy. Stop the previous demo first.`)));
      probe.listen(port, '127.0.0.1', () => probe.close(accept));
    });
  }

  const children = new Set();
  let stopping = false, pool, approvalTimer;
  function stop(code = 0) {
    if (stopping) return;
    stopping = true; process.exitCode = code; clearTimeout(approvalTimer);
    for (const child of children) {
      if (child.connected) child.send({ type: child.demoRole === 'daemon' ? 'desktop-stop' : 'stop' }, () => {});
      else child.kill();
    }
    const timeout = setTimeout(() => { for (const child of children) child.kill('SIGKILL'); }, 5000);
    timeout.unref();
    void pool?.end().catch(() => {});
  }
  process.once('SIGINT', () => stop());
  process.once('SIGTERM', () => stop());
  function start(executable, args, env, role, user) {
    const child = spawn(executable, args, { cwd: root, env, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    child.demoRole = role; children.add(child);
    child.stderr.on('data', chunk => process.stderr.write(`[${user.name} ${role}] ${chunk}`));
    child.on('error', () => { console.error(`${user.name}: failed to start ${role}.`); stop(1); });
    child.once('exit', code => { children.delete(child); if (!stopping) { console.log(`${user.name} ${role} closed; stopping demo.`); stop(code === 0 ? 0 : 1); } });
    return child;
  }
  try {
    if (flags.includes('--approve-all')) {
      const pepper = process.env.ACTIVATION_PEPPER;
      const databaseUrl = process.env.DATABASE_URL ?? (process.env.POSTGRES_PASSWORD
        ? `postgresql://crypto_pigeon:${encodeURIComponent(process.env.POSTGRES_PASSWORD)}@127.0.0.1:5432/crypto_pigeon` : '');
      if (!databaseUrl || !pepper || pepper.length < 32) throw new Error('--approve-all needs DATABASE_URL (or POSTGRES_PASSWORD) and the relay\'s ACTIVATION_PEPPER in .env or the shell.');
      const { Pool } = createRequire(join(root, 'apps/admin-cli/package.json'))('pg');
      pool = new Pool({ connectionString: databaseUrl, max: 1, connectionTimeoutMillis: 5000, query_timeout: 5000 });
      pool.on('error', () => { console.error('PostgreSQL connection lost; stopping demo.'); stop(1); });
      async function approvePending() {
        const pending = await pool.query("SELECT request_id FROM access_requests WHERE status='pending' ORDER BY created_at");
        for (const request of pending.rows) {
          if (stopping) return;
          const code = randomBytes(16).toString('base64url');
          const hash = createHmac('sha256', pepper).update(code).digest('hex');
          const result = await pool.query("UPDATE access_requests SET status='approved',activation_code_hash=$2,activation_expires_at=NOW()+INTERVAL '10 minutes',attempt_count=0,decided_at=NOW() WHERE request_id=$1 AND status='pending' RETURNING request_id,username,activation_expires_at", [request.request_id, hash]);
          if (result.rows[0]) console.log('\nAccess approved:', JSON.stringify({ ...result.rows[0], activation_code: code }, null, 2));
        }
      }
      console.log('--approve-all enabled: watching ALL pending access requests; codes expire in 10 minutes.');
      await approvePending();
      async function watch() {
        if (stopping) return;
        try { await approvePending(); } catch { console.error('Access approval failed. Check PostgreSQL, its schema and the relay pepper.'); stop(1); }
        if (!stopping) approvalTimer = setTimeout(watch, 2000);
      }
      approvalTimer = setTimeout(watch, 2000);
    }
    // Avoid passing administrator credentials and Node injection options to children.
    const environment = { ...process.env, NODE_ENV: 'development', RELAY_URL: relay.origin };
    for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'ELECTRON_RUN_AS_NODE', 'DATABASE_URL', 'POSTGRES_PASSWORD', 'ADMIN_TOKEN', 'ACTIVATION_PEPPER']) delete environment[key];
    for (const user of users) {
      const home = join(root, `.crypto_pigeon_${user.name.toLowerCase()}`);
      mkdirSync(home, { recursive: true });
      const daemon = start(process.execPath, [entry], { ...environment, PORT: String(user.port), CRYPTO_PIGEON_HOME: home }, 'daemon', user);
      const timeout = setTimeout(() => { console.error(`${user.name}: daemon startup timed out.`); stop(1); }, 30000);
      daemon.once('exit', () => clearTimeout(timeout));
      daemon.on('message', message => {
        if (stopping || message?.type !== 'desktop-ready') return;
        const url = new URL(message.url);
        if (url.origin !== `http://127.0.0.1:${user.port}` || url.pathname !== '/bootstrap' || !/^#[a-f0-9]{64}$/.test(url.hash)) return;
        clearTimeout(timeout);
        console.log(`\n${user.name} vault: ${home}\n${user.name} bootstrap: ${url.href}`);
        const ui = start(electron, [script], { ...environment, CP_DEMO_USER: user.name }, 'UI', user);
        const uiTimeout = setTimeout(() => { console.error(`${user.name}: UI startup timed out.`); stop(1); }, 30000);
        ui.once('exit', () => clearTimeout(uiTimeout));
        ui.once('message', ready => {
          if (!stopping && ready?.type === 'ui-ready') {
            clearTimeout(uiTimeout); ui.send({ type: 'open', url: url.href }, () => {});
          }
        });
      });
    }
    const activation = flags.includes('--approve-all') ? 'activate with the printed codes' : 'approve access with npm run admin -- approve <request-id> and enter its code';
    console.log(`Relay: ${relay.origin}\nCreate separate Vault IDs and accounts, ${activation}, then exchange public UIDs and accept a follow request.\nFor restore testing: sync and lock Alice, lock Bob, then use Restore in Bob with Alice's Vault ID/password. This transfers Alice's active instance and replaces Bob's local vault (old files are preserved by Restore).\nBootstrap links are single-use; the isolated windows consume them automatically. Ctrl+C closes both users.`);
  } catch (error) { stop(1); throw error; }
}

// Keep the entry module synchronous: Electron emits app.ready after loading it.
void (process.versions.electron ? runUi() : launch()).catch(error => {
  // Do not echo PostgreSQL error objects, connection strings or environment secrets.
  const message = error?.code ? `Demo failed (${error.code}). Check dependencies and PostgreSQL configuration.` : error.message;
  console.error(message); process.exitCode = 1;
  if (process.versions.electron) createRequire(import.meta.url)('electron').app.exit(1);
});
