const { app, BrowserWindow, dialog, ipcMain, Menu, session } = require('electron');
const { spawn } = require('node:child_process');
const { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { relayUrl, localUrl, daemonEnvironment } = require('./policy.cjs');

let window, child, origin, stopping = false, quitting = false;
app.setName('Crypto Pigeon');
app.setAppUserModelId('app.cryptopigeon.desktop');
const setupUrl = pathToFileURL(join(__dirname, 'setup.html')).href;
const singleInstance = app.requestSingleInstanceLock();
if (!singleInstance) app.quit();
app.on('second-instance', () => { if (window) { window.restore(); window.focus(); } });

function showError(message) { dialog.showErrorBox('Crypto Pigeon', message); }

function startDaemon(relay) {
  if (child) throw new Error('The local service is already running.');
  const root = app.isPackaged ? join(process.resourcesPath, 'daemon') : resolve(__dirname, '../..');
  const node = app.isPackaged ? join(root, process.platform === 'win32' ? 'node.exe' : 'node') : process.env.CRYPTO_PIGEON_NODE;
  if (!node || !existsSync(node)) throw new Error('Bundled Node runtime is missing. For development, start with npm run desktop:dev.');
  child = spawn(node, [join(root, 'apps/local-daemon/dist/server.js')], {
    cwd: root, windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    env: daemonEnvironment(process.env, join(app.getPath('userData'), 'vault'), relay)
  });
  const startupTimeout = setTimeout(() => { showError('The local service did not start. Close the app and check that port 17421 is available.'); app.quit(); }, 30000);
  child.on('message', message => {
    if (message?.type !== 'desktop-ready' || typeof message.url !== 'string') return;
    const url = new URL(message.url);
    if (url.origin !== 'http://127.0.0.1:17421' || url.pathname !== '/bootstrap' || !/^#[a-f0-9]{64}$/.test(url.hash)) return;
    clearTimeout(startupTimeout);
    origin = url.origin;
    // Persistent Chromium storage preserves the browser vault fragment across launches.
    void window.loadURL(url.href);
  });
  child.once('error', () => { clearTimeout(startupTimeout); showError('Unable to start the bundled local service. Reinstall Crypto Pigeon.'); app.quit(); });
  child.once('exit', () => {
    clearTimeout(startupTimeout); child = null;
    if (!stopping) { showError('The local service stopped. Close and reopen Crypto Pigeon. Your vault remains on disk.'); app.quit(); }
  });
}

async function ready() {
  if (!singleInstance) return;
  const profile = app.getPath('userData');
  mkdirSync(profile, { recursive: true });
  const configPath = join(profile, 'desktop.json');
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'Crypto Pigeon', submenu: [{ label: 'Quit', role: 'quit' }] },
    { label: 'Edit', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: 'View', submenu: [{ role: 'reload' }, { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' }] }
  ]));
  const desktopSession = session.fromPartition('persist:crypto-pigeon');
  desktopSession.setPermissionRequestHandler(async (contents, permission, callback, details) => {
    if (contents !== window?.webContents || !origin || !localUrl(details.requestingUrl, origin) ||
        permission !== 'media' || !details.mediaTypes?.length || details.mediaTypes.some(type => type !== 'audio')) {
      callback(false); return;
    }
    const result = await dialog.showMessageBox(window, { type: 'question', title: 'Microphone access',
      message: 'Allow Crypto Pigeon to record a voice message?', buttons: ['Allow microphone', 'Cancel'], defaultId: 1, cancelId: 1 });
    callback(result.response === 0);
  });
  desktopSession.setPermissionCheckHandler((contents, permission, requestingOrigin, details) =>
    contents === window?.webContents && !!origin && localUrl(requestingOrigin, origin) && permission === 'media' && details.mediaType === 'audio');
  desktopSession.webRequest.onBeforeRequest((details, callback) => {
    const allowed = origin ? localUrl(details.url, origin) || details.url.startsWith('blob:' + origin + '/') : details.url.startsWith(pathToFileURL(__dirname + '/').href);
    callback({ cancel: !allowed });
  });
  window = new BrowserWindow({
    width: 1180, height: 800, minWidth: 860, minHeight: 620, backgroundColor: '#0b0f19',
    title: 'Crypto Pigeon', icon: join(__dirname,'assets/pigeon.png'), show: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, webviewTag: false,
      preload: join(__dirname, 'preload.cjs'), session: desktopSession }
  });
  window.once('ready-to-show', () => window.show());
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.webContents.on('will-navigate', (event, url) => { if (!(origin && localUrl(url, origin)) && url !== setupUrl) event.preventDefault(); });
  ipcMain.handle('configure-relay', async (event, input) => {
    if (event.sender !== window.webContents || event.senderFrame?.url !== setupUrl || child) throw new Error('Setup is unavailable.');
    const direct=input==='direct';
    const relay = direct?'http://127.0.0.1:9':relayUrl(input);
    if(!direct){
      const response = await fetch(relay + '/readyz', { signal: AbortSignal.timeout(10000), redirect: 'error' });
      if (!response.ok) throw new Error('The relay is not ready. Check its address or contact its operator.');
    }
    writeFileSync(configPath + '.tmp', JSON.stringify({ relayUrl: relay }), { mode: 0o600 });
    renameSync(configPath + '.tmp', configPath);
    startDaemon(relay);
    return true;
  });
  if (existsSync(configPath)) {
    startDaemon(relayUrl(JSON.parse(readFileSync(configPath, 'utf8')).relayUrl));
  } else {
    await window.loadFile(join(__dirname, 'setup.html'));
  }
}

app.whenReady().then(ready).catch(() => { showError('Crypto Pigeon could not start. Check the saved relay configuration or reinstall the app.'); app.quit(); });
app.on('window-all-closed', () => app.quit());
app.on('before-quit', event => {
  if (quitting || !child) return;
  event.preventDefault(); stopping = true;
  const service = child;
  const timer = setTimeout(() => { service.kill(); quitting = true; app.quit(); }, 5000);
  service.once('exit', () => { clearTimeout(timer); quitting = true; app.quit(); });
  if (service.connected) service.send({ type: 'desktop-stop' }); else service.kill();
});
