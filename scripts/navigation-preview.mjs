// UI fixtures only: no vault credentials, crypto, message transport or relay.
import http from 'node:http';import fs from 'node:fs';import path from 'node:path';
const dist=path.resolve(import.meta.dirname,'../apps/local-ui/dist'),conv='12345678-1234-1234-1234-123456789abc';
const contacts=[{contact_id:'preview-contact',username:'preview_contact',displayName:'Preview contact',publicUid:'CP-ABCD-1234',conversation_id:conv,verified:0,identity_changed:0,safety_number_hash:'1234567890'.repeat(6),disappearing_seconds:0}];
const messages=Array.from({length:60},(_,i)=>({message_id:'preview-'+i,conversation_id:conv,direction:i%2?'sent':'received',plaintext:'Navigation preview message '+(i+1),sent_at:Date.now()-60000*(60-i),status:i%2?'read':'received'}));
const server=http.createServer(async(req,res)=>{
 const pathname=new URL(req.url,'http://127.0.0.1:18888').pathname,locked=(req.headers.referer||'').includes('/locked');
 if(pathname==='/__navigation-result'){
  let body='';for await(const data of req)body+=data;
  const value=JSON.parse(body);fs.writeFileSync(path.resolve(dist,'../../../artifacts/navigation-20261105/browser-'+(value.reducedMotion?'reduced':'normal')+'.json'),JSON.stringify(value,null,2));res.writeHead(200);res.end('ok');return;
 }
 if(pathname==='/__navigation-test.js'){res.writeHead(200,{'Content-Type':'application/javascript'});res.end(fs.readFileSync(path.resolve(dist,'../../../scripts/navigation-browser-test.js')));return;}
 if(pathname.startsWith('/api/')){
  let body='';for await(const data of req)body+=data;const input=body?JSON.parse(body):{};
  let value;
  if(pathname==='/api/session')value={csrfToken:'offline-ui-preview',vaultState:locked?'locked':'unlocked'};
  else if(pathname==='/api/vault/status')value={requiresVaultId:true,multipleVaults:true,vaultState:locked?'locked':'unlocked'};
  else if(pathname==='/api/vault/horcrux-status')value={configured:true,locked,totalShares:7,sharesPresent:locked?5:7,locations:{},isReconstructable:!locked};
  else if(pathname==='/api/relay/config')value={relayUrl:'https://example.invalid',defaultRelayUrl:'https://example.invalid'};
  else if(pathname==='/api/access/state')value={status:'activated',publicUid:'CP-0000-1111',username:'preview_only'};
  else if(pathname==='/api/profile')value={displayName:'Offline UI preview',statusLine:'Navigation fixtures only'};
  else if(pathname==='/api/contacts')value=contacts;
  else if(pathname.startsWith('/api/messages/'))value=messages;
  else if(pathname==='/api/fetch-messages')value={ok:true,received:0,sent:0,typing:false,...(input.conversationId?{conversationId:input.conversationId,messages}:{})};
  else if(pathname==='/api/conversations/requests')value=[];
  else if(pathname==='/api/transport/privacy')value={relayOnly:true,blindRouting:false,duressArmed:false};
  else if(pathname==='/api/transport/status')value={pushConnected:false,backupPending:false};
  else if(pathname==='/api/events'){res.writeHead(409,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'OFFLINE_UI_PREVIEW_ONLY'}));return;}
  else if(pathname==='/api/transport/chat'||pathname==='/api/control')value={ok:true};
  else{res.writeHead(501,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'OFFLINE_UI_PREVIEW_ONLY'}));return;}
  res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));return;
 }
 const file=pathname.startsWith('/assets/')?path.join(dist,pathname):path.join(dist,'index.html');
 if(!file.startsWith(dist+path.sep)||!fs.existsSync(file)){res.writeHead(404);res.end();return;}
 const type=file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':file.endsWith('.woff2')?'font/woff2':'text/html';res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-store'});
 if(pathname==='/test'){res.end(fs.readFileSync(file,'utf8').replace('</body>','<script type="module" src="/__navigation-test.js"></script></body>'));return;}
 fs.createReadStream(file).pipe(res);
});
server.listen(18888,'127.0.0.1',()=>console.log('Offline navigation UI preview: http://127.0.0.1:18888 (no real vault or messaging)'));
