import { cp, mkdir, writeFile, readdir, copyFile, readFile, lstat, unlink, realpath, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

// Keep native modules in a separate Node runtime, outside Electron's ABI.
const root = resolve(import.meta.dirname, '..');
const tor=spawnSync(process.execPath,[join(root,'scripts/prepare-tor.mjs')],{cwd:root,stdio:'inherit',windowsHide:true});
if(tor.status!==0)throw new Error('Tor runtime preparation failed');
const stage = join(root, 'artifacts/desktop-runtime');
await mkdir(stage, { recursive: true });
if ((await readdir(stage)).length) throw new Error('Runtime staging directory is not empty. Move artifacts/desktop-runtime aside before rebuilding.');
await cp(join(root,'artifacts/tor'),join(stage,'artifacts/tor'),{recursive:true});
await cp(join(root,'artifacts/docs'),join(stage,'artifacts/tor/licenses'),{recursive:true});
const workspaces = ['apps/local-daemon', 'packages/protocol', 'packages/shared-types'];
for (const file of ['package.json','package-lock.json','.npmrc']) await copyFile(join(root,file),join(stage,file));
for (const workspace of workspaces) {
  const source = join(root,workspace), target = join(stage,workspace);
  await mkdir(target, {recursive:true});
  await copyFile(join(source,'package.json'),join(target,'package.json'));
  await cp(join(source,'dist'),join(target,'dist'),{recursive:true});

}
// npm preserves nested dependency versions and workspace links from the lockfile.
const args = ['ci','--omit=dev','--workspace=@crypto-pigeon/local-daemon','--workspace=@crypto-pigeon/protocol','--workspace=@crypto-pigeon/shared-types','--no-audit','--no-fund'];
const install = process.platform === 'win32'
  ? spawnSync(process.env.ComSpec ?? 'cmd.exe',['/d','/s','/c','npm ' + args.join(' ')],{cwd:stage,stdio:'inherit',windowsHide:true})
  : spawnSync('npm',args,{cwd:stage,stdio:'inherit'});
if (install.status !== 0) throw new Error('Production runtime dependency installation failed.');
// Ship only native binaries for the build host's OS/architecture.
const boundary=await realpath(stage);
for(const dependency of ['@signalapp/libsignal-client','@signalapp/sqlcipher','argon2']) {
  const prebuilds=join(stage,'node_modules',dependency,'prebuilds');
  for(const entry of await readdir(prebuilds)) {
    if(entry===process.platform+'-'+process.arch)continue;
    const target=join(prebuilds,entry), checked=await realpath(target);
    if(!checked.startsWith(boundary+sep))throw new Error('Native prebuild path escaped staging directory');
    await rm(target,{recursive:true,force:true});
  }
}
// npm workspace junctions contain absolute build-machine paths on Windows.
// Materialize their runtime files before the installer copies this directory.
for (const workspace of workspaces) {
  const source=join(stage,workspace);
  const pkg=JSON.parse(await readFile(join(source,'package.json'),'utf8'));
  const target=join(stage,'node_modules',pkg.name);
  if(!(await lstat(target)).isSymbolicLink())throw new Error('Expected workspace link: '+pkg.name);
  await unlink(target);
  await mkdir(target,{recursive:true});
  await copyFile(join(source,'package.json'),join(target,'package.json'));
  await cp(join(source,'dist'),join(target,'dist'),{recursive:true});
  // Nested npm installs keep runtime dependencies next to each workspace.
  // Materializing only dist loses those dependencies outside the checkout.
  try {
    await lstat(join(source,'node_modules'));
    await cp(join(source,'node_modules'),join(target,'node_modules'),{recursive:true,dereference:true});
  } catch(error) {
    if(error.code!=='ENOENT')throw error;
  }
}
const node = join(stage,process.platform==='win32'?'node.exe':'node');
await copyFile(process.execPath,node);
await cp(join(root,'apps/local-ui/dist'),join(stage,'apps/local-ui/dist'),{recursive:true});
await writeFile(join(stage,'runtime-info.json'),JSON.stringify({node:process.version,platform:process.platform,arch:process.arch},null,2));
const checkScript = `import {createRequire} from 'node:module'; import {resolve,sep} from 'node:path'; import {realpathSync} from 'node:fs'; import {pathToFileURL} from 'node:url';
const root=realpathSync('.'); const require=createRequire(resolve('apps/local-daemon/package.json'));
for(const name of ['@signalapp/libsignal-client','@signalapp/sqlcipher','argon2','fastify','@crypto-pigeon/protocol']) {
 const file=realpathSync(require.resolve(name)); if(!file.startsWith(root+sep))throw new Error('Dependency escaped bundle: '+name);
 const mod=await import(pathToFileURL(file)); if(name==='@signalapp/sqlcipher'){const Database=mod.Database??mod.default.Database??mod.default;const db=new Database(':memory:');db.prepare('SELECT 1').get();db.close();}
}`;
const check = spawnSync(node,['--input-type=module','-e',checkScript],{cwd:stage,encoding:'utf8',windowsHide:true});
if(check.status!==0)throw new Error('Bundled native runtime check failed: '+check.stderr);
for(const file of ['tor-transport','tor-routing','serverless-contacts','tor-recovery']){
  const verify=spawnSync(node,['--input-type=module','-e',`await import('./apps/local-daemon/dist/${file}.js')`],{cwd:stage,encoding:'utf8',windowsHide:true});
  if(verify.status!==0)throw new Error('Bundled serverless module failed to load: '+file);
}
const torCheck=spawnSync(join(stage,'artifacts/tor/tor.exe'),['--version'],{cwd:stage,encoding:'utf8',windowsHide:true});
if(torCheck.status!==0||!torCheck.stdout.startsWith('Tor version '))throw new Error('Bundled Tor executable failed to start');
console.log('Desktop runtime staged and native libraries verified for '+process.platform+'/'+process.arch);
