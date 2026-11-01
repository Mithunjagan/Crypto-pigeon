import crypto from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import Database from '@signalapp/sqlcipher';
import type { HorcruxStatus } from '@crypto-pigeon/shared-types';
import { seal, unseal } from './vault-dual-key.js';

export function splitSeven(secret: Buffer): Buffer[] {
  if(secret.length !== 48) throw new Error('invalid_wrapped_vmk');
  const shares = Array.from({length: 6}, () => crypto.randomBytes(secret.length));
  const last = Buffer.from(secret);
  for(const share of shares) for(let i=0;i<last.length;i++) last[i] ^= share[i];
  return [...shares, last];
}
export function reconstructSeven(shares: Array<Buffer | null>): Buffer {
  if(shares.length !== 7 || shares.some(s => !s || s.length !== 48)) throw new Error('HORCRUX_INCOMPLETE_RESTORE_REQUIRED');
  const result = Buffer.alloc(48);
  for(const share of shares as Buffer[]) for(let i=0;i<48;i++) result[i] ^= share[i];
  return result;
}
export const shardDigest = (share: Buffer) => crypto.createHash('sha256').update(share).digest('hex');
const names = ['Hardware shard', 'SQLite shard', 'Preferences shard', 'Binary shard', 'WebView shard', 'RAM session shard', 'Relay shard'];
export class HorcruxStore {
  sessionShare: Buffer | null = null;
  constructor(private root: string) {}
  private metadata() {
    const db = new Database(join(this.root, 'shards', 'metadata.db'));
    db.exec('CREATE TABLE IF NOT EXISTS vault_horcrux_shard (id INTEGER PRIMARY KEY CHECK(id=2), shard BLOB NOT NULL)');
    return db;
  }
  async scatter(wrapped: Buffer, mask: Buffer, backupKey: Buffer) {
    const shares = splitSeven(wrapped);
    try {
      for(const dir of ['shards', 'config', 'assets']) await mkdir(join(this.root,dir),{recursive:true,mode:0o700});
      await writeFile(join(this.root,'shards/f1.bin'),shares[0],{mode:0o600});
      const db=this.metadata();
      try {db.prepare('INSERT OR REPLACE INTO vault_horcrux_shard(id,shard) VALUES(2,?)').run([new Uint8Array(shares[1])]);} finally {db.close();}
      await writeFile(join(this.root,'config/f3.json'),JSON.stringify(seal(shares[2],backupKey,'cp-shard3-v1')),{mode:0o600});
      await writeFile(join(this.root,'assets/f4.dat'),shares[3],{mode:0o600});
      await writeFile(join(this.root,'shards/f6.masked'),JSON.stringify(seal(shares[5],mask,'cp-shard6-v1')),{mode:0o600});
      this.lock(); this.sessionShare=Buffer.from(shares[5]);
      return {clientShard:shares[4].toString('base64'), fragment7Shard:JSON.stringify(seal(shares[6],backupKey,'cp-shard7-v1')), hashes:shares.map(shardDigest)};
    } finally {shares.forEach(s=>s.fill(0));}
  }
  async collect(clientShard: string | undefined, fragment7Shard: string | undefined, mask: Buffer, backupKey: Buffer, hashes: string[]) {
    const shares: Array<Buffer | null> = [];
    const read = async (fn:()=>Promise<Buffer>|Buffer) => {try{return await fn();}catch{return null;}};
    shares.push(await read(()=>readFile(join(this.root,'shards/f1.bin'))));
    shares.push(await read(()=> {const db=this.metadata(); try {const row=db.prepare('SELECT shard FROM vault_horcrux_shard WHERE id=2').get<{shard:Uint8Array<ArrayBuffer>}>();return row?Buffer.from(row.shard):Buffer.alloc(0);} finally {db.close();}}));
    shares.push(await read(async()=>unseal(JSON.parse(await readFile(join(this.root,'config/f3.json'),'utf8')),backupKey,'cp-shard3-v1')));
    shares.push(await read(()=>readFile(join(this.root,'assets/f4.dat'))));
    shares.push(clientShard ? Buffer.from(clientShard,'base64'):null);
    shares.push(await read(async()=>unseal(JSON.parse(await readFile(join(this.root,'shards/f6.masked'),'utf8')),mask,'cp-shard6-v1')));
    shares.push(await read(()=>unseal(JSON.parse(fragment7Shard ?? ''),backupKey,'cp-shard7-v1')));
    try {
      if(shares.some((s,i)=>!s || s.length!==48 || shardDigest(s)!==hashes[i])) throw new Error('HORCRUX_INCOMPLETE_RESTORE_REQUIRED');
      this.lock(); this.sessionShare=Buffer.from(shares[5]!);
      return reconstructSeven(shares);
    } finally {shares.forEach(s=>s?.fill(0));}
  }
  async status(clientPresent: boolean, relayPresent: boolean, hashes: string[]): Promise<HorcruxStatus> {
    const present = await Promise.all(['shards/f1.bin','shards/metadata.db','config/f3.json','assets/f4.dat'].map(async path=>{try{await readFile(join(this.root,path));return true;}catch{return false;}}));
    present.push(clientPresent, !!this.sessionShare, relayPresent);
    const locations=Object.fromEntries(names.map((n,i)=>[n,present[i] && hashes.length===7]));
    const sharesPresent=Object.values(locations).filter(Boolean).length;
    return {sharesPresent,totalShares:7,locations,isReconstructable:sharesPresent===7};
  }
  lock(){this.sessionShare?.fill(0);this.sessionShare=null;}
}
