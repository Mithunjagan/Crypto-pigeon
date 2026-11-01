import crypto from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { mkdir, readFile, writeFile, rename, rm, cp } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { z } from 'zod';
import { Vault } from './vault.js';
import { validatePasswordStrength, type WrappedVmkConfig } from './vault-keys.js';
import { HorcruxStore } from './horcrux.js';
import { deriveVaultKeys, wipeKeys, seal, unseal, encryptBackup, decryptBackup, writerKeyPair, type VaultKeys } from './vault-dual-key.js';
import { backupSigningPayload, vaultBackupPutSchema, vaultBackupEnvelopeSchema, verifyChallenge } from '@crypto-pigeon/protocol';

type SecureConfig = WrappedVmkConfig & { secureVersion: 3; hashes: string[]; fragment7Shard: string; backupVersion: number };
const snapshotSchema = z.object({format:z.literal(1), vmk:z.string().length(44), hkdfSalt:z.string().length(24),
  database:z.string().max(140*1024*1024), files:z.record(z.string()).default({})});
export class SecureVault extends Vault {
  private keys: VaultKeys | null = null;
  private vmk: Buffer | null = null;
  private fragments: HorcruxStore;
  private clientPresent = false;
  private relayPresent = false;
  constructor(root: string, private relayUrl: string) {super(root);this.fragments=new HorcruxStore(root);}
  isSecure() {return !!(this.config as SecureConfig | null)?.secureVersion;}
  private secureConfig() {if(!this.isSecure())throw new Error('LEGACY_VAULT_USE_EXISTING_PASSWORD');return this.config as SecureConfig;}
  private async saveConfig() {
    await writeFile(this.configPath+'.tmp',JSON.stringify(this.config),{mode:0o600});
    await rename(this.configPath+'.tmp',this.configPath);
  }
  private async download(keys: VaultKeys) {
    const res=await fetch(`${this.relayUrl}/api/vault-backup/${keys.lookup.toString('hex')}`,{signal:AbortSignal.timeout(15000)});
    if(res.status===404)return null;
    if(!res.ok)throw new Error('RELAY_BACKUP_UNAVAILABLE');
    const text=await res.text();
    if(text.length>36*1024*1024)throw new Error('backup_too_large');
    const remote=vaultBackupPutSchema.parse(JSON.parse(text));
    const expected=writerKeyPair(keys.writer).publicKey;
    if(remote.writerPublicKey!==expected || !verifyChallenge(Buffer.from(expected,'base64'),backupSigningPayload(remote),Buffer.from(remote.signature,'base64')))throw new Error('INVALID_BACKUP_SIGNATURE');
    return remote;
  }
  private async provision(vmk: Buffer, keys: VaultKeys, hkdfSalt: string) {
    const wrapped=seal(vmk,keys.kek,'vmk-wrap-v1');
    const bytes=Buffer.from(wrapped.ciphertext,'base64');
    try {
      const split=await this.fragments.scatter(bytes,keys.mask,keys.backup);
      this.config={version:2,secureVersion:3,wrappedVmk:'',vmkNonce:wrapped.nonce,hkdfSalt,vmkVersion:1,
        createdAt:new Date().toISOString(),kdfParams:{algorithm:'argon2id',memoryCost:65536,timeCost:3,parallelism:1,argon2Salt:''},
        hashes:split.hashes,fragment7Shard:split.fragment7Shard,backupVersion:0} as SecureConfig;
      this.keys=keys;this.vmk=Buffer.from(vmk);this.clientPresent=true;
      return split.clientShard;
    } finally {bytes.fill(0);}
  }
  async createSecure(vaultId: string,password: string) {
    if(this.exists())throw new Error('vault_already_exists');
    const strength=validatePasswordStrength(password);if(!strength.valid)throw new Error(strength.error);
    const keys=await deriveVaultKeys(vaultId,password);
    const vmk=crypto.randomBytes(32);const existed=existsSync(this.rootDir);
    try {
      if(await this.download(keys))throw new Error('VAULT_ID_ALREADY_EXISTS_USE_RESTORE');
      await mkdir(dirname(this.databasePath),{recursive:true,mode:0o700});
      const salt=crypto.randomBytes(16);
      const clientShard=await this.provision(vmk,keys,salt.toString('base64'));
      await this.openDb(vmk,salt);
      await this.syncBackup();await this.saveConfig();
      return {clientShard};
    } catch(e) {
      this.lock();wipeKeys(keys);this.config=null;
      if(!existed)await rm(this.rootDir,{recursive:true,force:true});
      throw e;
    } finally {vmk.fill(0);}
  }
  async unlockSecure(vaultId:string,password:string,clientShard?:string) {
    if(!this.isLocked())throw new Error('vault_already_unlocked');
    if(!this.isSecure()){await super.unlock(password);return;}
    const config=this.secureConfig();const keys=await deriveVaultKeys(vaultId,password);
    let wrapped:Buffer|undefined;let vmk:Buffer|undefined;
    try {
      const remote=await this.download(keys);
      this.relayPresent=!!remote;
      if(!remote)throw new Error('HORCRUX_INCOMPLETE_RESTORE_REQUIRED');
      wrapped=await this.fragments.collect(clientShard,Buffer.from(remote.fragment7Shard,'base64').toString(),keys.mask,keys.backup,config.hashes);
      vmk=unseal({nonce:config.vmkNonce,ciphertext:wrapped.toString('base64')},keys.kek,'vmk-wrap-v1');
      await this.openDb(vmk,Buffer.from(config.hkdfSalt,'base64'));
      this.keys=keys;this.vmk=Buffer.from(vmk);this.clientPresent=true;
      config.backupVersion=remote.version;
    } catch(e){this.lock();wipeKeys(keys);throw e;}
    finally {wrapped?.fill(0);vmk?.fill(0);}
  }
  async status(clientPresent=this.clientPresent) {
    return this.fragments.status(clientPresent,this.relayPresent,(this.config as SecureConfig|null)?.hashes??[]);
  }
  async syncBackup(claim=false) {
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
        updatedAt:new Date().toISOString(),fragment7Shard:Buffer.from(config.fragment7Shard).toString('base64'),writerPublicKey:writer.publicKey};
      const signature=crypto.sign(null,backupSigningPayload(body),writer.privateKey).toString('base64');
      const res=await fetch(`${this.relayUrl}/api/vault-backup/${body.lookupToken}`,{method:'PUT',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({...body,signature}),signal:AbortSignal.timeout(30000)});
      if(!res.ok)throw new Error(res.status===409?'BACKUP_CONFLICT_RESTORE_REQUIRED':'RELAY_BACKUP_UNAVAILABLE');
      config.backupVersion=body.version;this.relayPresent=true;
      await this.saveConfig();return {ok:true,version:body.version};
    } finally {snapshot.fill(0);}
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
      await staged.syncBackup(true);await staged.saveConfig();
      staged.lock();
      // Preserve old local data for recovery; never overwrite an unlocked vault.
      if(existsSync(this.rootDir))await rename(this.rootDir,this.rootDir+'.before-restore-'+Date.now());
      await rename(stage,this.rootDir);
      await this.initialize();await this.unlockSecure(vaultId,password,clientShard);
      return {clientShard};
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
      if(await this.download(nextKeys))throw new Error('NEW_CREDENTIALS_ALREADY_IN_USE');
      await this.syncBackup();
      this.database().pragma('wal_checkpoint(TRUNCATE)');
      await cp(this.rootDir,stage,{recursive:true,errorOnExist:true,force:false});
      const clientShard=await staged.provision(this.vmk,nextKeys,this.secureConfig().hkdfSalt);
      await staged.openDb(this.vmk,Buffer.from(this.secureConfig().hkdfSalt,'base64'));
      await staged.syncBackup();staged.lock();
      const token=oldKeys.lookup.toString('hex'), version=this.secureConfig().backupVersion;
      const writer=writerKeyPair(oldKeys.writer);
      const signature=crypto.sign(null,Buffer.from(`cp-backup-delete-v1:${token}:${version}`),writer.privateKey).toString('base64');
      const res=await fetch(`${this.relayUrl}/api/vault-backup/${token}`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({version,signature}),signal:AbortSignal.timeout(15000)});
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
  override lock(){super.lock();this.fragments?.lock();wipeKeys(this.keys);this.keys=null;this.vmk?.fill(0);this.vmk=null;this.clientPresent=false;this.relayPresent=false;}
}
