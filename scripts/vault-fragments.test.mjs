import test from 'node:test';
import assert from 'node:assert/strict';
import {readVaultShards,rememberVaultShard,shardStorageKey,vaultShardsKey,activeVaultKey} from '../apps/local-ui/src/vaultFragments.ts';
const A=Buffer.alloc(48,1).toString('base64'),B=Buffer.alloc(48,2).toString('base64'),rotated=Buffer.alloc(48,3).toString('base64'),handle='a'.repeat(32);
function store(initial={}){const values=new Map(Object.entries(initial));return {getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v)};}
test('creating a second vault preserves the original single-vault fragment',()=>{
 const s=store({[shardStorageKey]:A});rememberVaultShard({clientShard:B,vaultHandle:handle},s);
 assert.deepEqual(readVaultShards(s),{legacy:A,[handle]:B});assert.equal(s.getItem(shardStorageKey),B);
 rememberVaultShard({vaultHandle:'legacy'},s);assert.equal(s.getItem(shardStorageKey),A);
 rememberVaultShard({vaultHandle:handle},s);assert.equal(s.getItem(shardStorageKey),B);
});
test('password rotation changes only the selected vault fragment',()=>{
 const s=store({[shardStorageKey]:A});rememberVaultShard({clientShard:B,vaultHandle:handle},s);rememberVaultShard({clientShard:rotated,vaultHandle:handle},s);
 assert.deepEqual(readVaultShards(s),{legacy:A,[handle]:rotated});assert.equal(s.getItem(activeVaultKey),handle);
});
test('malformed saved fragments are rejected without overwriting them',()=>{
 const s=store({[shardStorageKey]:A,[vaultShardsKey]:'broken-json'});
 assert.throws(()=>rememberVaultShard({clientShard:B,vaultHandle:handle},s),/BROWSER_VAULT_SHARDS_INVALID/);
 assert.equal(s.getItem(shardStorageKey),A);assert.equal(s.getItem(vaultShardsKey),'broken-json');
});
