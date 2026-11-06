// Runs under the packaged Electron executable against the packaged application.
// Isolated profile, hidden window, no real credentials and no external relay.
const { app, BrowserWindow, dialog } = require('electron');
const { join } = require('node:path');
const { writeFileSync } = require('node:fs');
const assert = require('node:assert/strict');
const [resources, profile, mode, report] = process.argv.slice(2);
if (!resources || !profile || !report) throw new Error('desktop-smoke requires resources, isolated profile, mode and report');
app.setPath('userData', profile);
app.disableHardwareAcceleration();
Object.defineProperty(app, 'isPackaged', { value: true });
Object.defineProperty(process, 'resourcesPath', { value: resources });
BrowserWindow.prototype.show = function () {};
dialog.showErrorBox = (_title,message) => { console.error(message); app.exit(1); };
const timer = setTimeout(() => { console.error('Desktop smoke test timed out'); app.exit(1); },75000);
require(join(resources,'app.asar','main.cjs'));
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));
app.whenReady().then(async()=>{
  let window;
  for(let i=0;i<200;i++) {
    window=BrowserWindow.getAllWindows()[0];
    if(window && !window.webContents.isLoading() && (mode==='setup' ? window.webContents.getURL().endsWith('setup.html') : window.webContents.getURL().startsWith('http://127.0.0.1:17421/')))break;
    await pause(100);
  }
  assert.ok(window);
  const preferences=window.webContents.getLastWebPreferences();
  assert.equal(preferences.nodeIntegration,false); assert.equal(preferences.contextIsolation,true); assert.equal(preferences.sandbox,true);
  if(mode==='setup') {
    assert.ok(await window.webContents.executeJavaScript("document.body.textContent.includes('Relay address')"));
    await window.webContents.executeJavaScript("document.getElementById('relay').value='http://insecure.test';document.getElementById('setup').dispatchEvent(new Event('submit',{cancelable:true}));");
    await pause(400);
    assert.ok(await window.webContents.executeJavaScript("document.getElementById('status').textContent.includes('Could not connect')"));
    // Real packaged main-process onboarding starts without a reachable relay.
    await window.webContents.executeJavaScript("document.getElementById('start-direct').click()");
    for(let i=0;i<300&&!window.webContents.getURL().startsWith('http://127.0.0.1:17421/');i++)await pause(100);
    assert.ok(window.webContents.getURL().startsWith('http://127.0.0.1:17421/'),await window.webContents.executeJavaScript("document.getElementById('status')?.textContent"));
    const config=JSON.parse(require('node:fs').readFileSync(join(profile,'desktop.json'),'utf8'));
    assert.equal(config.relayUrl,'http://127.0.0.1:9');
    try { const screenshot=await window.webContents.capturePage();writeFileSync(join(profile,'setup.png'),screenshot.toPNG()); } catch { /* Some Windows sessions cannot capture hidden windows. */ }
  } else {
    let result;
    for(let i=0;i<100;i++) {
      result=await window.webContents.executeJavaScript("fetch('/api/session').then(async r=>({status:r.status,body:await r.json()}))");
      if(result.status===200)break;
      await pause(100);
    }
    assert.equal(result.status,200);assert.equal(result.body.vaultState,'unconfigured');
    assert.equal(await window.webContents.executeJavaScript("typeof require"),'undefined');
    assert.equal(await window.webContents.executeJavaScript("fetch('/api/vault/status').then(r=>r.status)"),200);
    if(mode==='restart') assert.equal(await window.webContents.executeJavaScript("localStorage.getItem('smoke-fragment')"),'preserved');
    else await window.webContents.executeJavaScript("localStorage.setItem('smoke-fragment','preserved')");
    // Renderer networking must remain on the loopback daemon origin.
    assert.equal(await window.webContents.executeJavaScript("fetch('https://outside.invalid').then(()=>false,()=>true)"),true);
    try { const screenshot=await window.webContents.capturePage();writeFileSync(join(profile,'vault.png'),screenshot.toPNG()); } catch { /* Some Windows sessions cannot capture hidden windows. */ }
  }
  writeFileSync(report,JSON.stringify({mode,passed:true,url:window.webContents.getURL().split('#')[0],sandbox:preferences.sandbox}));
  clearTimeout(timer);app.quit();
}).catch(error=>{console.error(error);app.exit(1);});
