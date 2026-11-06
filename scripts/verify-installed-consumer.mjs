import {Phone,pause} from '../artifacts/hardware-control.mjs';
import fs from 'node:fs';
const phone=await Phone.connect(19322);
try{
 const serial='10BEAN0MX8001J4',rows=JSON.parse(fs.readFileSync('artifacts/hardware-active-phone-credentials.private.json','utf8'));
 const credential=rows.find(c=>c.currentSerial===serial)||rows.find(c=>c.serial===serial);
 const url=JSON.parse(fs.readFileSync('apps/mobile-android/relay-defaults.json','utf8')).relayUrl;
 await phone.api('/api/relay/config',{relayUrl:url});
 const status=await phone.api('/api/vault/status');
 if(status.vaultState==='locked'){
  await phone.click('Unlock');await phone.fill('input[aria-label="Vault ID"]',credential.vaultId);await phone.fill('input[aria-label="Master passphrase"]',credential.password);await phone.click('Unlock vault');await phone.wait('Conversations',90000);
 }
 const account=await phone.api('/api/access/state');
 if(account.publicUid!==credential.uid)throw new Error('Installed vault UID does not match prior identity');
 const contacts=await phone.api('/api/contacts');let count=0;for(const contact of contacts)count+=(await phone.api('/api/messages/'+contact.conversation_id)).length;
 await phone.snapshot('artifacts/consumer-existing-inbox.png');
 console.log(JSON.stringify({serial,existingUidPreserved:true,contacts:contacts.length,messages:count,relay:(await phone.api('/api/relay/config')).relayUrl,push:(await phone.api('/api/transport/status')).pushConnected}));
}finally{phone.close();}
