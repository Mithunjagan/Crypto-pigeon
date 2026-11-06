import {createRequire} from 'node:module';
import {spawn,spawnSync} from 'node:child_process';
import {existsSync,readFileSync,writeFileSync,mkdirSync,openSync,closeSync,appendFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {networkInterfaces} from 'node:os';

const root=resolve(import.meta.dirname,'..'),artifacts=join(root,'artifacts');
createRequire(join(root,'apps/relay-server/package.json'))('dotenv').config({path:join(root,'.env'),quiet:true});
const defaultsFile=join(root,'apps/mobile-android/relay-defaults.json');
const sessionFile=join(artifacts,'internet-relay-session.json');
const hardwareFile=join(artifacts,'hardware-live-session.private.json');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const alive=pid=>{try{if(!Number.isSafeInteger(pid)||pid<1)return false;process.kill(pid,0);return true;}catch{return false;}};
const ready=origin=>fetch(origin+'/readyz',{headers:{'ngrok-skip-browser-warning':'1'},signal:AbortSignal.timeout(8000)}).then(async r=>r.ok&&(await r.json()).ok===true).catch(()=>false);
let tunnel,relay,stopping=false;
function shutdown(code=0){if(stopping)return;stopping=true;relay?.kill();tunnel?.kill();process.exitCode=code;}
process.once('SIGINT',()=>shutdown());process.once('SIGTERM',()=>shutdown());
async function until(check,label,ms=90000){const end=Date.now()+ms;while(Date.now()<end){if(await check())return;await pause(500);}throw new Error('Timed out: '+label);}

async function publishRelay(publicUrl){
 let discoveryUrl=process.env.RELAY_DISCOVERY_URL||'';
 if(process.env.GITHUB_GIST_TOKEN&&process.env.GITHUB_GIST_ID){
  const filename=process.env.RELAY_DISCOVERY_FILENAME||'relay.json';
  const response=await fetch('https://api.github.com/gists/'+encodeURIComponent(process.env.GITHUB_GIST_ID),{method:'PATCH',headers:{Authorization:'Bearer '+process.env.GITHUB_GIST_TOKEN,Accept:'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28'},body:JSON.stringify({files:{[filename]:{content:JSON.stringify({relayUrl:publicUrl})}}}),signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('Discovery publication failed (HTTP '+response.status+').');
  const gist=await response.json();
  discoveryUrl||='https://gist.githubusercontent.com/'+encodeURIComponent(gist.owner.login)+'/'+encodeURIComponent(gist.id)+'/raw/'+encodeURIComponent(filename);
 }
 if(discoveryUrl){const u=new URL(discoveryUrl);if(u.protocol!=='https:'||u.username||u.password)throw new Error('Discovery URL must use public HTTPS.');}
 writeFileSync(defaultsFile,JSON.stringify({relayUrl:publicUrl,discoveryUrl},null,2));
 if(!discoveryUrl)console.log('Discovery is not configured. Set RELAY_DISCOVERY_URL, or GITHUB_GIST_ID and GITHUB_GIST_TOKEN in .env, then rebuild the APK.');
}
async function main(){
 mkdirSync(artifacts,{recursive:true});
 if(existsSync(sessionFile)){
  const old=JSON.parse(readFileSync(sessionFile,'utf8'));
  if(alive(old.pid)&&(old.provider==='ngrok'||alive(old.tunnelPid))&&(!process.env.NGROK_URL||old.publicUrl===process.env.NGROK_URL)&&await ready(old.publicUrl)){await publishRelay(old.publicUrl);console.log('PUBLIC HTTPS RELAY: '+old.publicUrl);return;}
 }
 const pgBase=join(artifacts,'android-chat-postgres'),pg=JSON.parse(readFileSync(join(pgBase,'connection.json'),'utf8'));
 const pgArgs=['-h','127.0.0.1','-p',String(pg.port)];
 if(spawnSync(join(pgBase,'pgsql/bin/pg_isready.exe'),pgArgs,{windowsHide:true,stdio:'ignore'}).status!==0){
  const log=openSync(join(pgBase,'internet-startup.log'),'a');let result;
  try{result=spawnSync(join(pgBase,'pgsql/bin/pg_ctl.exe'),['start','-D',join(pgBase,'data'),'-l',join(pgBase,'server.log'),'-o',`-h 127.0.0.1 -p ${pg.port}`,'-w','-t','30'],{windowsHide:true,timeout:45000,stdio:['ignore',log,log]});}finally{closeSync(log);}
  if(result.status!==0)throw new Error('PostgreSQL startup failed; inspect its startup log.');
 }
 let publicUrl='';
 if(process.env.TUNNEL_PROVIDER==='ngrok'){
  const local=await fetch('http://127.0.0.1:4040/api/tunnels',{signal:AbortSignal.timeout(2000)}).then(r=>r.json()).catch(()=>null);
  const existing=local?.tunnels?.find(t=>t.public_url===process.env.NGROK_URL);
  if(existing){publicUrl=existing.public_url;console.log('Reusing static ngrok endpoint.');}
  else{
   const args=['http','8443','--log=stdout','--log-format=json'];if(process.env.NGROK_URL)args.push('--url='+process.env.NGROK_URL);
   tunnel=spawn(process.env.NGROK_PATH||'ngrok',args,{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe'],env:process.env});
   tunnel.on('error',()=>{console.error('Ngrok agent could not start.');shutdown(1);});
   tunnel.once('exit',code=>{if(!stopping){console.error('Ngrok exited: '+code);shutdown(1);}});
   const log=chunk=>appendFileSync(join(artifacts,'ngrok-agent-start.log'),chunk);tunnel.stdout.on('data',log);tunnel.stderr.on('data',log);
   await until(async()=>{const state=await fetch('http://127.0.0.1:4040/api/tunnels',{signal:AbortSignal.timeout(2000)}).then(r=>r.json()).catch(()=>null);publicUrl=state?.tunnels?.find(t=>t.public_url.startsWith('https://'))?.public_url||'';return !!publicUrl;},'static ngrok endpoint',45000);
  }
 }else{
 const binary=process.env.CLOUDFLARED_PATH||join(artifacts,'cloudflared.exe');
 if(!existsSync(binary)){
  console.log('Downloading official standalone cloudflared binary…');
  const response=await fetch('https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe',{signal:AbortSignal.timeout(180000)});
  if(!response.ok)throw new Error('cloudflared download failed: '+response.status);
  writeFileSync(binary,Buffer.from(await response.arrayBuffer()));
 }
 let tail='';
 tunnel=spawn(binary,['tunnel','--url','http://127.0.0.1:8443','--protocol','http2','--edge-ip-version','4','--no-autoupdate'],{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});
 tunnel.on('error',error=>{console.error('Tunnel failed: '+error.message);shutdown(1);});
 tunnel.once('exit',code=>{if(!stopping){console.error('Tunnel exited: '+code);shutdown(1);}});
 const record=chunk=>{const text=chunk.toString();appendFileSync(join(artifacts,'internet-tunnel.log'),text);tail=(tail+text).slice(-16000);publicUrl||=tail.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com\b/i)?.[0]||'';};
 tunnel.stdout.on('data',record);tunnel.stderr.on('data',record);
 await until(()=>{if(tunnel.exitCode!==null)throw new Error('cloudflared exited; inspect artifacts/internet-tunnel.log');return !!publicUrl;},'public tunnel URL',120000);
 }
 const hardware=JSON.parse(readFileSync(hardwareFile,'utf8'));
 // Stop only the recorded hardware relay supervisor and its verified server
 // child. Never replace an unrelated process merely because it owns port 8443.
 if(alive(hardware.pid)){
  const inspected=spawnSync('powershell.exe',['-NoProfile','-Command',`Get-CimInstance Win32_Process -Filter 'ProcessId = ${hardware.pid} OR ParentProcessId = ${hardware.pid}' | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress`],{encoding:'utf8',windowsHide:true,timeout:15000});
  if(inspected.status!==0)throw new Error('Could not inspect existing relay supervisor.');
  const value=JSON.parse(inspected.stdout||'[]'),processes=Array.isArray(value)?value:[value];
  const owner=processes.find(p=>p.ProcessId===hardware.pid&&/artifacts[\\/]hardware-live-relay\.cjs(?:["\s]|$)/i.test(p.CommandLine||''));
  if(!owner)throw new Error('Recorded relay PID belongs to another process.');
  for(const p of processes.filter(p=>p.ParentProcessId===hardware.pid&&/apps[\\/]relay-server[\\/]dist[\\/]server\.js/i.test(p.CommandLine||''))){try{process.kill(p.ProcessId);}catch{}}
  try{process.kill(hardware.pid);}catch{}
  await pause(500);
 }
 const aliases=new Set(['127.0.0.1:8443','localhost:8443',new URL(hardware.lanUrl).host]);
 for(const values of Object.values(networkInterfaces()))for(const address of values||[])if(address.family==='IPv4'&&!address.internal)aliases.add(address.address+':8443');
 relay=spawn(process.execPath,[join(artifacts,'hardware-live-relay.cjs')],{cwd:root,windowsHide:true,stdio:['ignore','inherit','inherit'],env:{...process.env,RELAY_URL:publicUrl,RELAY_HOSTNAME:new URL(publicUrl).host,RELAY_HOSTNAME_ALIASES:[...aliases].join(',')}});
 relay.on('error',error=>{console.error('Relay failed: '+error.message);shutdown(1);});
 relay.once('exit',code=>{if(!stopping){console.error('Relay supervisor exited: '+code);shutdown(1);}});
 await until(()=>{if(relay.exitCode!==null)throw new Error('Relay startup failed.');return ready('http://127.0.0.1:8443');},'PostgreSQL relay readiness',45000);
 await until(()=>ready(publicUrl),'public HTTPS readiness',120000);
 await publishRelay(publicUrl).catch(error=>console.error(error.message));
 writeFileSync(sessionFile,JSON.stringify({publicUrl,pid:process.pid,tunnelPid:tunnel?.pid??null,provider:process.env.TUNNEL_PROVIDER||'cloudflare',relaySupervisorPid:relay.pid,startedAt:new Date().toISOString()},null,2));
 console.log('\nPUBLIC HTTPS RELAY: '+publicUrl+'\n');
 console.log('Self-serve PostgreSQL relay is running. Keep this PC and tunnel running.');
}
main().catch(error=>{console.error(error.message);shutdown(1);});
