import {fork} from 'node:child_process';
import {mkdtemp,rm,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
const root=resolve(import.meta.dirname,'..'),home=await mkdtemp(join(tmpdir(),'cp-http-')),results=[];
const child=fork(resolve(root,'apps/local-daemon/dist/server.js'),[],{cwd:root,silent:true,env:{...process.env,PORT:'0',CRYPTO_PIGEON_HOME:home,RELAY_URL:'http://127.0.0.1:9'}});
child.stdout.resume();child.stderr.resume();
function pass(name){results.push({name,status:'pass'});console.log('PASS: '+name);}
try{
  const ready=await new Promise((res,rej)=>{const timeout=setTimeout(()=>rej(new Error('Daemon startup timeout')),30000);child.on('message',message=>{if(message?.type==='desktop-ready'){clearTimeout(timeout);res(new URL(message.url));}});child.once('exit',()=>{clearTimeout(timeout);rej(new Error('Daemon exited'));});});
  const origin=ready.origin;
  const html=await fetch(origin).then(r=>r.text());const asset=html.match(/src="(\/assets\/[^"?]+\.js)"/)?.[1];assert.ok(asset);
  const js=await fetch(origin+asset);assert.equal(js.status,200);assert.match(js.headers.get('content-type'),/javascript/);assert.ok((await js.text()).length>1000);
  pass('Built UI and JavaScript assets are served without the static/glob dependency');
  for(const path of ['/assets/not-a-build-file.js','/assets/%2e%2e%2fconfig.json','/assets/%2e%2e%2f%2e%2e%2f.env'])assert.equal((await fetch(origin+path)).status,404);
  pass('Unknown assets and encoded filesystem traversal are rejected');
  assert.equal((await fetch(origin+'/api/contacts')).status,401);
  assert.equal((await fetch(origin+'/api/session',{headers:{Origin:'https://attacker.invalid'}})).status,403);
  pass('Private API requires pairing and rejects cross-origin access');
  const bootstrap=await fetch(origin+'/api/bootstrap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:ready.hash.slice(1)})});assert.equal(bootstrap.status,200);
  const cookie=bootstrap.headers.get('set-cookie').split(';')[0];
  assert.equal((await fetch(origin+'/api/bootstrap',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:ready.hash.slice(1)})})).status,401);
  assert.equal((await fetch(origin+'/api/vault/create',{method:'POST',headers:{Cookie:cookie,'Content-Type':'application/json'},body:'{}'})).status,403);
  pass('Bootstrap is single-use and writes require CSRF even with the session cookie');
}catch(error){results.push({name:error.message,status:'fail'});console.error(error);process.exitCode=1;}
finally{
  if(child.exitCode===null){const ended=new Promise(res=>child.once('exit',res));child.send({type:'desktop-stop'});await ended;}
  await rm(home,{recursive:true,force:true});await mkdir(resolve(root,'artifacts'),{recursive:true});await writeFile(resolve(root,'artifacts/daemon-http-check.json'),JSON.stringify({results},null,2));
}
