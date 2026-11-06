import { createHash } from 'node:crypto';
import { mkdir,writeFile,readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root=resolve(import.meta.dirname,'..'),cache=resolve(root,'artifacts/tor-dependencies');
if(process.platform!=='win32'||process.arch!=='x64')throw new Error('Set TOR_BINARY to a current Tor executable on this platform.');
await mkdir(cache,{recursive:true});
const archive=resolve(cache,'tor-windows.tar.gz');
const expected='2ee123e9167318a3742778ff704e75f01d4780f05a14522d451fe011011077c4';
let bytes;try{bytes=await readFile(archive);}catch{
  const response=await fetch('https://dist.torproject.org/torbrowser/16.0/tor-expert-bundle-windows-x86_64-16.0.tar.gz');if(!response.ok)throw new Error('Tor download failed');bytes=Buffer.from(await response.arrayBuffer());
}
if(createHash('sha256').update(bytes).digest('hex')!==expected)throw new Error('Tor bundle checksum mismatch');
await writeFile(archive,bytes);
const result=spawnSync('tar',['-xf',archive,'-C',resolve(root,'artifacts'),'tor/tor.exe','docs/tor.txt','docs/libevent.txt','docs/openssl.txt','docs/zlib.txt'],{windowsHide:true,stdio:'inherit'});
if(result.status!==0)throw new Error('Tor extraction failed');
console.log('Pinned Tor Windows runtime prepared.');
