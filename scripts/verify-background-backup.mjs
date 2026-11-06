import {Phone,pause} from '../artifacts/hardware-control.mjs';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const p=await Phone.connect(19322);
try{
 const [contact]=await p.api('/api/contacts');const before=await p.api('/api/transport/status');
 await p.api('/api/conversations/'+contact.conversation_id+'/timer',{seconds:contact.disappearing_seconds||0});
 assert.ok((await p.api('/api/transport/status')).backupPending);
 let after;const deadline=Date.now()+100000;
 do{await pause(1000);after=await p.api('/api/transport/status');if(after.backupRuns>before.backupRuns&&!after.backupPending)break;}while(Date.now()<deadline);
 assert.ok(after.backupRuns>before.backupRuns&&!after.backupPending&&after.backupFailures===before.backupFailures,'Background backup did not settle successfully');
 const result={debounceMs:60000,backgroundBackupCompleted:true,runs:after.backupRuns-before.backupRuns,additionalAuthRefreshes:after.authRefreshes-before.authRefreshes,pushConnected:after.pushConnected};
 fs.writeFileSync('artifacts/consumer-background-backup.json',JSON.stringify(result,null,2));console.log(JSON.stringify(result));
}finally{p.close();}
