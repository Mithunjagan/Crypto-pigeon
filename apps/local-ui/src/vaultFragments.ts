// Keep the original key for desktop compatibility and the currently active vault.
export const shardStorageKey = 'cp-browser-shard-v1';
export const vaultShardsKey = 'cp-browser-shards-v2';
export const activeVaultKey = 'cp-active-vault-v2';
const handlePattern=/^(?:legacy|[a-f0-9]{32})$/;
const shardPattern=/^[A-Za-z0-9+/]{64}$/;
type Store=Pick<Storage,'getItem'|'setItem'>;

export function readVaultShards(storage:Store=localStorage):Record<string,string>{
  const text=storage.getItem(vaultShardsKey);
  let parsed:unknown;
  try{parsed=text?JSON.parse(text):{};}catch{throw new Error('BROWSER_VAULT_SHARDS_INVALID');}
  if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error('BROWSER_VAULT_SHARDS_INVALID');
  const shards:Record<string,string>={};
  for(const [handle,value]of Object.entries(parsed)){
    if(!handlePattern.test(handle)||typeof value!=='string'||!shardPattern.test(value))throw new Error('BROWSER_VAULT_SHARDS_INVALID');
    shards[handle]=value;
  }
  const current=storage.getItem(shardStorageKey),handle=storage.getItem(activeVaultKey)||'legacy';
  // Migrate the old fragment before another vault can replace the active key.
  if(current&&shardPattern.test(current)&&handlePattern.test(handle)&&!shards[handle])shards[handle]=current;
  return shards;
}

export function rememberVaultShard(result:{clientShard?:string;vaultHandle?:string},storage:Store=localStorage){
  const shards=readVaultShards(storage),handle=result.vaultHandle||storage.getItem(activeVaultKey)||'legacy';
  if(!handlePattern.test(handle))throw new Error('BROWSER_VAULT_SHARDS_INVALID');
  if(result.clientShard){if(!shardPattern.test(result.clientShard))throw new Error('BROWSER_VAULT_SHARDS_INVALID');shards[handle]=result.clientShard;}
  // Persist all fragments before updating the legacy active-vault pointer.
  storage.setItem(vaultShardsKey,JSON.stringify(shards));
  if(shards[handle])storage.setItem(shardStorageKey,shards[handle]);
  storage.setItem(activeVaultKey,handle);
}
