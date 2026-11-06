import crypto from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {SHARD_HEADER,encodeStorage,decodeStorage,seventh,fileEnvelope} from './sovereign-files.js';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { mkdir, readFile, writeFile, rename, rm, cp } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { z } from 'zod';
import { Vault } from './vault.js';
import { validatePasswordStrength, type WrappedVmkConfig } from './vault-keys.js';
import { HorcruxStore } from './horcrux.js';
import { deriveVaultKeys, wipeKeys, seal, unseal, encryptBackup, decryptBackup, writerKeyPair, type VaultKeys } from './vault-dual-key.js';
import { backupSigningPayload, vaultBackupPutSchema, vaultBackupEnvelopeSchema, verifyChallenge, normalizeRelayUrl } from '@crypto-pigeon/protocol';

type SecureConfig = WrappedVmkConfig & { secureVersion: 3; hashes: string[]; fragment7Shard?: string; backupVersion: number; shard7Mode?:'external'; cloudBackupEnabled?:boolean;creationPending?:boolean };
const snapshotSchema = z.object({format:z.literal(1), vmk:z.string().length(44), hkdfSalt:z.string().length(24),
  database:z.string().max(256*1024*1024), files:z.record(z.string(),z.string()).default({})});
export class SecureVault extends Vault {
  private decoy:SecureVault|null=null;
  private remoteFragment7:string|null=null;
  private external7:Buffer|null=null;
  cloudBackupEnabled():boolean{return this.decoy?this.decoy.cloudBackupEnabled():!!(this.config as SecureConfig|null)?.cloudBackupEnabled;}
  storageStatus(){return {cloudBackupEnabled:this.cloudBackupEnabled(),externalShard7:(this.config as SecureConfig|null)?.shard7Mode==='external',storageBound:false};}
  async setCloudBackup(enabled:boolean){this.database();this.secureConfig().cloudBackupEnabled=enabled;await this.saveConfig();return this.storageStatus();}
  shard7File(){this.database();const sealed=this.external7??(this.remoteFragment7?Buffer.from(this.remoteFragment7):null);if(!sealed)throw new Error('SHARD7_FILE_REQUIRED');return Buffer.concat([Buffer.from(SHARD_HEADER),sealed]);}
  override async initialize(){await super.initialize();if((this.config as SecureConfig|null)?.creationPending){await rename(this.rootDir,this.rootDir+'.abandoned-create-'+Date.now());this.config=null;}}
  async confirmShard7Saved(){this.database();this.secureConfig().shard7Mode='external';this.secureConfig().cloudBackupEnabled=false;this.secureConfig().creationPending=false;await this.saveConfig();}
  isDecoyActive(){return !!this.decoy;}
  duressArmed(){return existsSync(join(this.rootDir,'duress.json'));}
  override database():ReturnType<Vault['database']>{return this.decoy?this.decoy.database():super.database();}
  override isLocked():boolean{return this.decoy?this.decoy.isLocked():super.isLocked();}
  private decoyPassword(id:string){return crypto.createHash('sha256').update('cp-decoy-password-v1:'+id).digest('hex')+'Aa1!';}
  async configureDuress(id:string){
    if(this.decoy||this.isLocked())throw new Error('PRIMARY_VAULT_REQUIRED');if(id.length<16||id.length>256)throw new Error('DURESS_ID_MINIMUM_16_CHARACTERS');
    const salt=crypto.randomBytes(32).toString('hex'),tag=crypto.createHash('sha256').update(salt+id).digest('hex'),root=this.rootDir+'.decoy-'+tag.slice(0,24);
    const decoy=new SecureVault(root,this.relayUrl);let browser='';
    try{browser=(await decoy.createSecure(id,this.decoyPassword(id),true)).clientShard;
      const db=decoy.database(),contact=crypto.randomUUID(),conversation=crypto.randomUUID(),now=Date.now();
      db.prepare('INSERT INTO contacts(contact_id,username,identity_public_key,created_at) VALUES(?,?,?,?)').run([contact,'Daily notes',crypto.randomBytes(33),now]);
      db.prepare('INSERT INTO remote_contacts(contact_id,user_id,device_id,signal_device_id) VALUES(?,?,?,1)').run([contact,crypto.randomUUID(),crypto.randomUUID()]);
      db.prepare('INSERT INTO conversations(conversation_id,contact_id,created_at) VALUES(?,?,?)').run([conversation,contact,now]);
      for(const note of ['Pick up groceries after work.','Walk in the park this weekend.','Remember to water the plants.'])db.prepare("INSERT INTO messages(message_id,conversation_id,direction,plaintext,received_at,status) VALUES(?,?,'received',?,?,'received')").run([crypto.randomUUID(),conversation,note,now]);
      await decoy.syncBackup();await writeFile(join(this.rootDir,'duress.json'),JSON.stringify({salt,tag,root}),{mode:0o600});return {ok:true,decoyClientShard:browser};
    }finally{decoy.lock();}
  }
  private backupTail: Promise<unknown> = Promise.resolve();
  private keys: VaultKeys | null = null;
  private vmk: Buffer | null = null;
  private fragments: HorcruxStore;
  private clientPresent = false;
  private relayPresent = false;
  constructor(root: string, private relayUrl: string) {super(root);this.relayUrl=normalizeRelayUrl(relayUrl);this.fragments=new HorcruxStore(root);}
  isSecure() {return !!(this.config as SecureConfig | null)?.secureVersion;}
  setRelayUrl(url:string, trustedAlias=false){if(!this.isLocked()&&!trustedAlias)throw new Error('LOCK_BEFORE_RELAY_CHANGE');this.relayUrl=normalizeRelayUrl(url);}
  private secureConfig() {if(!this.isSecure())throw new Error('LEGACY_VAULT_USE_EXISTING_PASSWORD');return this.config as SecureConfig;}
  private async saveConfig() {
    await writeFile(this.configPath+'.tmp',JSON.stringify(this.config),{mode:0o600});
    await rename(this.configPath+'.tmp',this.configPath);
  }
  private async download(keys: VaultKeys) {
    const res=await fetch(`${this.relayUrl}/api/vault-backup/${keys.lookup.toString('hex')}`,{redirect:'error',signal:AbortSignal.timeout(15000)});
    if(res.status===404){const body=await res.json().catch(()=>null);if(body?.error==='BACKUP_NOT_FOUND')return null;throw new Error('RELAY_BACKUP_UNAVAILABLE');}
    if(!res.ok)throw new Error('RELAY_BACKUP_UNAVAILABLE');
    const text=await res.text();
    if(text.length>90*1024*1024)throw new Error('backup_too_large');
    const remote=vaultBackupPutSchema.parse(JSON.parse(text));
    const expected=writerKeyPair(keys.writer).publicKey;
    if(remote.writerPublicKey!==expected || !verifyChallenge(Buffer.from(expected,'base64'),backupSigningPayload(remote),Buffer.from(remote.signature,'base64')))throw new Error('INVALID_BACKUP_SIGNATURE');
    return remote;
  }
  private async provision(vmk: Buffer, keys: VaultKeys, hkdfSalt: string, externalSeventh?:Buffer) {
    const wrapped=seal(vmk,keys.kek,'vmk-wrap-v1');
    const bytes=Buffer.from(wrapped.ciphertext,'base64');
    try {
      const split=await this.fragments.scatter(bytes,keys.mask,keys.backup,externalSeventh);
      this.config={version:2,secureVersion:3,wrappedVmk:'',vmkNonce:wrapped.nonce,hkdfSalt,vmkVersion:1,
        createdAt:new Date().toISOString(),kdfParams:{algorithm:'argon2id',memoryCost:65536,timeCost:3,parallelism:1,argon2Salt:''},
        hashes:split.hashes,backupVersion:0} as SecureConfig;
      this.remoteFragment7=split.fragment7Shard;this.keys=keys;this.vmk=Buffer.from(vmk);this.clientPresent=true;
      return split.clientShard;
    } finally {bytes.fill(0);}
  }
  async createSecure(vaultId: string,password: string, relayBacked=false) {
    if(this.exists())throw new Error('vault_already_exists');
    const strength=validatePasswordStrength(password);if(!strength.valid)throw new Error(strength.error);
    const keys=await deriveVaultKeys(vaultId,password);
    const vmk=crypto.randomBytes(32);const existed=existsSync(this.rootDir);
    try {
      if(relayBacked&&await this.download(keys))throw new Error('VAULT_ID_ALREADY_EXISTS_USE_RESTORE');
      await mkdir(dirname(this.databasePath),{recursive:true,mode:0o700});
      const salt=crypto.randomBytes(16);
      const clientShard=await this.provision(vmk,keys,salt.toString('base64'));
      await this.openDb(vmk,salt);
      const config=this.secureConfig();config.cloudBackupEnabled=relayBacked;
      if(!relayBacked){config.shard7Mode='external';config.creationPending=true;this.external7=Buffer.from(this.remoteFragment7!);this.remoteFragment7=null;this.relayPresent=true;}
      if(relayBacked)await this.syncBackup();await this.saveConfig();
      const capsule=this.shard7File();try{return {clientShard,shard7FileBytes:capsule.toString('base64')};}finally{capsule.fill(0);}
    } catch(e) {
      this.lock();wipeKeys(keys);this.config=null;
      if(!existed)await rm(this.rootDir,{recursive:true,force:true});
      throw e;
    } finally {vmk.fill(0);}
  }
  async unlockSecure(vaultId:string,password:string,clientShard?:string,decoyClientShard?:string,shard7Payload?:string) {
    if(this.duressArmed()){
      const registry=JSON.parse(await readFile(join(this.rootDir,'duress.json'),'utf8'));
      if(crypto.createHash('sha256').update(registry.salt+vaultId).digest('hex')===registry.tag){
        this.lock();this.decoy=null;const decoy=new SecureVault(registry.root,this.relayUrl);await decoy.initialize();await decoy.unlockSecure(vaultId,this.decoyPassword(vaultId),decoyClientShard);this.decoy=decoy;return;
      }
    }
    if(this.decoy){this.decoy.lock();this.decoy=null;}
    if(!this.isLocked())throw new Error('vault_already_unlocked');
    if(!this.isSecure()){await super.unlock(password);return;}
    const config=this.secureConfig();const keys=await deriveVaultKeys(vaultId,password);
    let wrapped:Buffer|undefined;let vmk:Buffer|undefined;
    try {
      if(config.shard7Mode==='external'){
        if(!shard7Payload)throw new Error('SHARD7_FILE_REQUIRED');const capsule=Buffer.from(shard7Payload,'base64');
        let share:Buffer|undefined;
        try{share=seventh(capsule,keys);if(crypto.createHash('sha256').update(share).digest('hex')!==config.hashes[6])throw new Error('SHARD7_FILE_MISMATCH');
          const sealed=fileEnvelope(capsule,SHARD_HEADER,2048);
          wrapped=await this.fragments.collect(clientShard,sealed.toString(),keys.mask,keys.backup,config.hashes);
          vmk=unseal({nonce:config.vmkNonce,ciphertext:wrapped.toString('base64')},keys.kek,'vmk-wrap-v1');
          await this.openDb(vmk,Buffer.from(config.hkdfSalt,'base64'));this.keys=keys;this.vmk=Buffer.from(vmk);this.external7=Buffer.from(sealed);this.clientPresent=true;this.relayPresent=true;return;
        }finally{share?.fill(0);capsule.fill(0);}
      }
      let remote;
      try{remote=await this.download(keys);}catch(error){if(error instanceof z.ZodError||(error as Error).message==='INVALID_BACKUP_SIGNATURE')throw new Error('HORCRUX_INCOMPLETE_RESTORE_REQUIRED');throw error;}
      this.relayPresent=!!remote;
      if(!remote)throw new Error('BACKUP_NOT_FOUND_OR_INVALID_CREDENTIALS');
      wrapped=await this.fragments.collect(clientShard,Buffer.from(remote.fragment7Shard,'base64').toString(),keys.mask,keys.backup,config.hashes);
      vmk=unseal({nonce:config.vmkNonce,ciphertext:wrapped.toString('base64')},keys.kek,'vmk-wrap-v1');
      await this.openDb(vmk,Buffer.from(config.hkdfSalt,'base64'));
      this.remoteFragment7=Buffer.from(remote.fragment7Shard,'base64').toString();delete config.fragment7Shard;await this.saveConfig();
      this.keys=keys;this.vmk=Buffer.from(vmk);this.clientPresent=true;
      config.backupVersion=remote.version;
    } catch(e){this.lock();wipeKeys(keys);throw e;}
    finally {wrapped?.fill(0);vmk?.fill(0);}
  }
  async status(clientPresent=this.clientPresent):Promise<any> {
    if(this.decoy)return this.decoy.status(clientPresent);
    return {...await this.fragments.status(clientPresent,this.relayPresent,(this.config as SecureConfig|null)?.hashes??[]),externalShard7:(this.config as SecureConfig|null)?.shard7Mode==='external'};
  }
  async syncBackup(claim=false):Promise<any> {
    if(this.decoy)return this.decoy.syncBackup(claim);
    if(!this.cloudBackupEnabled())return {ok:true,skipped:true,cloudBackupEnabled:false};
    if(!this.isSecure())return {ok:true,legacy:true};
    if(!this.keys || !this.vmk || this.isLocked())throw new Error('vault_locked');
    const keys=this.keys, config=this.secureConfig();
    if(!this.database().prepare('SELECT 1 FROM vault_instance WHERE singleton=1').get())this.database().prepare('INSERT INTO vault_instance(singleton,token) VALUES(1,?)').run([crypto.randomBytes(32).toString('hex')]);
    this.database().pragma('wal_checkpoint(TRUNCATE)');
    const files:Record<string,string>={};
    const dir=join(this.rootDir,'attachments');
    if(existsSync(dir))for(const file of readdirSync(dir)) {
      if(/^[a-f0-9]{32}$/.test(file))files[file]=readFileSync(join(dir,file)).toString('base64');
    }
    const snapshot=Buffer.from(JSON.stringify({format:1,vmk:this.vmk.toString('base64'),hkdfSalt:config.hkdfSalt,
      database:readFileSync(this.databasePath).toString('base64'),files}));
    try {
      const encrypted=encryptBackup(snapshot,keys.backup);
      snapshot.fill(0);
      const writer=writerKeyPair(keys.writer);
      let instance=this.database().prepare('SELECT token FROM vault_instance WHERE singleton=1').get<{token:string}>();
      if(!instance){instance={token:crypto.randomBytes(32).toString('hex')};this.database().prepare('INSERT INTO vault_instance(singleton,token) VALUES(1,?)').run([instance.token]);}
      const account=this.database().prepare('SELECT device_id,user_id FROM signal_account WHERE singleton=1').get<{device_id:string;user_id:string|null}>();
      const auth=this.database().prepare('SELECT private_key FROM device_auth_key WHERE singleton=1').get<{private_key:Uint8Array<ArrayBuffer>}>();
      const instanceHash=crypto.createHash('sha256').update(instance.token).digest('hex');
      const proof=account?.user_id && auth ? {deviceId:account.device_id,instanceHash,
        deviceSignature:crypto.sign(null,Buffer.from('cp-vault-instance-v1:'+instanceHash),crypto.createPrivateKey({key:Buffer.from(auth.private_key),format:'der',type:'pkcs8'})).toString('base64')} : {};
      const body={...proof,claim,lookupToken:keys.lookup.toString('hex'),version:config.backupVersion+1,...encrypted,
        updatedAt:new Date().toISOString(),fragment7Shard:(this.external7??Buffer.from(this.remoteFragment7??'')).toString('base64'),writerPublicKey:writer.publicKey};
      const operation=this.backupTail.catch(()=>{}).then(async()=>{
        if(!config.cloudBackupEnabled)return {ok:true,skipped:true};
        // Sign the next version only once earlier uploads have settled. Snapshot
        // encryption and the writer key were captured before a caller can lock.
        body.version=config.backupVersion+1;
        const signature=crypto.sign(null,backupSigningPayload(body),writer.privateKey).toString('base64');
        const res=await fetch(`${this.relayUrl}/api/vault-backup/${body.lookupToken}`,{redirect:'error',method:'PUT',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({...body,signature}),signal:AbortSignal.timeout(30000)});
        if(!res.ok)throw new Error(res.status===409?'BACKUP_CONFLICT_RESTORE_REQUIRED':'RELAY_BACKUP_UNAVAILABLE');
        config.backupVersion=body.version;this.relayPresent=true;
        await this.saveConfig();return {ok:true,version:body.version};
      });
      this.backupTail=operation.catch(()=>{});
      return await operation;
    } finally {snapshot.fill(0);}
  }
  exportStorage(){
    if(!this.keys||!this.vmk)throw new Error('vault_locked');this.database().pragma('wal_checkpoint(TRUNCATE)');
    const files:Record<string,string>={},dir=join(this.rootDir,'attachments');
    if(existsSync(dir))for(const name of readdirSync(dir))if(/^[a-f0-9]{32}$/.test(name))files[name]=readFileSync(join(dir,name)).toString('base64');
    const plain=Buffer.from(JSON.stringify({format:1,vmk:this.vmk.toString('base64'),hkdfSalt:this.secureConfig().hkdfSalt,database:readFileSync(this.databasePath).toString('base64'),files}));
    let compressed:Buffer|undefined;const capsule=this.shard7File();
    try{compressed=gzipSync(plain);return encodeStorage(compressed,capsule,this.keys);}finally{plain.fill(0);compressed?.fill(0);capsule.fill(0);}
  }
  async importStorage(file:Buffer,vaultId:string,password:string,capsule:Buffer){
    if(!this.isLocked())throw new Error('LOCK_BEFORE_STORAGE_SWITCH');
    const keys=await deriveVaultKeys(vaultId,password),stage=this.rootDir+'.restore-'+crypto.randomBytes(8).toString('hex'),staged=new SecureVault(stage,this.relayUrl);
    let compressed:Buffer|undefined,plain:Buffer|undefined,master:Buffer|undefined,share:Buffer|undefined;
    try{
      compressed=decodeStorage(file,capsule,keys);plain=gunzipSync(compressed,{maxOutputLength:256*1024*1024});const snapshot=snapshotSchema.parse(JSON.parse(plain.toString()));
      master=Buffer.from(snapshot.vmk,'base64');if(master.length!==32||Buffer.from(snapshot.hkdfSalt,'base64').length!==16)throw new Error('INVALID_STORAGE_FILE');share=seventh(capsule,keys);
      await mkdir(join(stage,'data'),{recursive:true,mode:0o700});await writeFile(join(stage,'data/chat.db'),Buffer.from(snapshot.database,'base64'),{mode:0o600});
      const clientShard=await staged.provision(master,keys,snapshot.hkdfSalt,share);
      staged.secureConfig().shard7Mode='external';staged.secureConfig().cloudBackupEnabled=false;
      staged.external7=Buffer.from(fileEnvelope(capsule,SHARD_HEADER,2048));staged.remoteFragment7=null;
      await staged.openDb(master,Buffer.from(snapshot.hkdfSalt,'base64'));
      await mkdir(join(stage,'attachments'),{recursive:true,mode:0o700});
      for(const [name,data] of Object.entries(snapshot.files)){if(!/^[a-f0-9]{32}$/.test(name))throw new Error('invalid_snapshot_path');await writeFile(join(stage,'attachments',name),Buffer.from(data,'base64'),{mode:0o600});}
      for(const row of staged.database().prepare('SELECT attachment_id FROM attachments WHERE encrypted_local_path IS NOT NULL').all<{attachment_id:string}>()){
        if(!existsSync(join(stage,'attachments',row.attachment_id)))throw new Error('BACKUP_ATTACHMENT_MISSING');
        staged.database().prepare('UPDATE attachments SET encrypted_local_path=? WHERE attachment_id=?').run([join(this.rootDir,'attachments',row.attachment_id),row.attachment_id]);
      }
      await staged.saveConfig();staged.lock();
      const previous=this.rootDir+'.before-storage-'+Date.now();if(existsSync(this.rootDir))await rename(this.rootDir,previous);
      try{await rename(stage,this.rootDir);}catch(error){if(existsSync(previous))await rename(previous,this.rootDir);throw error;}
      await this.initialize();await this.unlockSecure(vaultId,password,clientShard,undefined,capsule.toString('base64'));return {clientShard};
    }finally{compressed?.fill(0);plain?.fill(0);master?.fill(0);share?.fill(0);staged.lock();wipeKeys(keys);await rm(stage,{recursive:true,force:true});}
  }
  async restoreSecure(vaultId:string,password:string) {
    if(!this.isLocked())throw new Error('LOCK_BEFORE_RESTORE');
    const keys=await deriveVaultKeys(vaultId,password);
    let plaintext:Buffer|undefined;let vmk:Buffer|undefined;
    const stage=this.rootDir+'.restore-'+crypto.randomBytes(8).toString('hex');
    const staged=new SecureVault(stage,this.relayUrl);
    try {
      const remote=await this.download(keys);if(!remote)throw new Error('BACKUP_NOT_FOUND_OR_INVALID_CREDENTIALS');
      plaintext=decryptBackup(vaultBackupEnvelopeSchema.parse(remote),keys.backup);
      const snapshot=snapshotSchema.parse(JSON.parse(plaintext.toString()));
      vmk=Buffer.from(snapshot.vmk,'base64');
      if(vmk.length!==32)throw new Error('invalid_snapshot');
      await mkdir(join(stage,'data'),{recursive:true,mode:0o700});
      await writeFile(join(stage,'data/chat.db'),Buffer.from(snapshot.database,'base64'),{mode:0o600});
      const clientShard=await staged.provision(vmk,keys,snapshot.hkdfSalt);
      await staged.openDb(vmk,Buffer.from(snapshot.hkdfSalt,'base64'));
      // Never restore an old relay bearer token. Device-auth challenge runs anew.
      staged.database().exec('DELETE FROM relay_auth; DELETE FROM vault_instance');
      await mkdir(join(stage,'attachments'),{recursive:true,mode:0o700});
      for(const [file,data]of Object.entries(snapshot.files)) {
        if(!/^[a-f0-9]{32}$/.test(file))throw new Error('invalid_snapshot_path');
        await writeFile(join(stage,'attachments',file),Buffer.from(data,'base64'),{mode:0o600});
      }
      const rows=staged.database().prepare('SELECT attachment_id FROM attachments WHERE encrypted_local_path IS NOT NULL').all<{attachment_id:string}>();
      for(const row of rows)staged.database().prepare('UPDATE attachments SET encrypted_local_path=? WHERE attachment_id=?').run([join(this.rootDir,'attachments',row.attachment_id),row.attachment_id]);
      staged.secureConfig().backupVersion=remote.version;
      staged.secureConfig().shard7Mode='external';staged.secureConfig().cloudBackupEnabled=false;staged.external7=Buffer.from(staged.remoteFragment7!);staged.remoteFragment7=null;await staged.saveConfig();
      const capsule=staged.shard7File();staged.lock();
      // Preserve old local data for recovery; never overwrite an unlocked vault.
      if(existsSync(this.rootDir))await rename(this.rootDir,this.rootDir+'.before-restore-'+Date.now());
      await rename(stage,this.rootDir);
      try{await this.initialize();await this.unlockSecure(vaultId,password,clientShard,undefined,capsule.toString('base64'));
        return {clientShard,shard7FileBytes:capsule.toString('base64')};}finally{capsule.fill(0);}
    } finally {plaintext?.fill(0);vmk?.fill(0);staged.lock();wipeKeys(keys);await rm(stage,{recursive:true,force:true});}
  }
  async changeSecurePassword(vaultId:string,oldPassword:string,newPassword:string) {
    if(!this.isSecure()){await super.changePassword(oldPassword,newPassword);return {};}
    if(!this.keys || !this.vmk || this.isLocked())throw new Error('vault_locked');
    const strength=validatePasswordStrength(newPassword);if(!strength.valid)throw new Error(strength.error);
    const oldKeys=await deriveVaultKeys(vaultId,oldPassword);
    const nextKeys=await deriveVaultKeys(vaultId,newPassword);
    const stage=this.rootDir+'.rotate-'+crypto.randomBytes(8).toString('hex');
    const staged=new SecureVault(stage,this.relayUrl);
    try {
      if(!crypto.timingSafeEqual(oldKeys.kek,this.keys.kek))throw new Error('invalid_vault_password');
      if(crypto.timingSafeEqual(oldKeys.lookup,nextKeys.lookup))throw new Error('NEW_PASSWORD_MUST_DIFFER');
      if(this.secureConfig().shard7Mode==='external'||!this.cloudBackupEnabled()){
        this.database().pragma('wal_checkpoint(TRUNCATE)');await cp(this.rootDir,stage,{recursive:true,errorOnExist:true,force:false});
        const clientShard=await staged.provision(this.vmk,nextKeys,this.secureConfig().hkdfSalt);staged.secureConfig().shard7Mode='external';staged.secureConfig().cloudBackupEnabled=false;staged.external7=Buffer.from(staged.remoteFragment7!);staged.remoteFragment7=null;
        await staged.openDb(this.vmk,Buffer.from(this.secureConfig().hkdfSalt,'base64'));await staged.saveConfig();const capsule=staged.shard7File();staged.lock();this.lock();
        try{await rename(this.rootDir,this.rootDir+'.before-password-change-'+Date.now());await rename(stage,this.rootDir);await this.initialize();await this.unlockSecure(vaultId,newPassword,clientShard,undefined,capsule.toString('base64'));return {clientShard,shard7FileBytes:capsule.toString('base64')};}finally{capsule.fill(0);}
      }
      if(await this.download(nextKeys))throw new Error('NEW_CREDENTIALS_ALREADY_IN_USE');
      await this.syncBackup();
      this.database().pragma('wal_checkpoint(TRUNCATE)');
      await cp(this.rootDir,stage,{recursive:true,errorOnExist:true,force:false});
      const clientShard=await staged.provision(this.vmk,nextKeys,this.secureConfig().hkdfSalt);
      await staged.openDb(this.vmk,Buffer.from(this.secureConfig().hkdfSalt,'base64'));
      staged.secureConfig().cloudBackupEnabled=true;await staged.syncBackup();staged.lock();
      const token=oldKeys.lookup.toString('hex'), version=this.secureConfig().backupVersion;
      const writer=writerKeyPair(oldKeys.writer);
      const signature=crypto.sign(null,Buffer.from(`cp-backup-delete-v1:${token}:${version}`),writer.privateKey).toString('base64');
      const res=await fetch(`${this.relayUrl}/api/vault-backup/${token}`,{redirect:'error',method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({version,signature}),signal:AbortSignal.timeout(15000)});
      if(!res.ok)throw new Error('OLD_BACKUP_REMOVAL_FAILED_PASSWORD_UNCHANGED');
      this.lock();
      await rename(this.rootDir,this.rootDir+'.before-password-change-'+Date.now());
      await rename(stage,this.rootDir);
      await this.initialize();await this.unlockSecure(vaultId,newPassword,clientShard);
      return {clientShard};
    } finally {staged.lock();wipeKeys(oldKeys);wipeKeys(nextKeys);await rm(stage,{recursive:true,force:true});}
  }
  override async changePassword(_old:string,_next:string) {
    if(this.isSecure())throw new Error('DUAL_KEY_PASSWORD_ROTATION_REQUIRES_BACKUP_MIGRATION');
    await super.changePassword(_old,_next);
  }
  override lock(){this.decoy?.lock();super.lock();this.fragments?.lock();wipeKeys(this.keys);this.keys=null;this.vmk?.fill(0);this.vmk=null;this.external7?.fill(0);this.external7=null;this.remoteFragment7=null;this.clientPresent=false;this.relayPresent=false;}
}
