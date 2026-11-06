import { useEffect, useRef, useState, type FormEvent } from "react";
import {useTapGesture,readSovereignFile,base64Bytes} from './SovereignStorage';
import { AnimatePresence, motion } from "framer-motion";
import {
  Shield,
  ShieldCheck,
  KeyRound,
  Eye,
  EyeOff,
  ArrowRight,
  Network,
  LockKeyhole,
  Loader2,
  Check,
  ChevronDown,
} from "lucide-react";
import { Brand, Sheet, spring } from "./ui";
import { RelayRoutes } from "./RelayRoutes";
import {useBackAction} from './useBackNavigation';

export {shardStorageKey} from './vaultFragments';
// Keys of the status.locations map reported by the daemon. Order matters.
const locations = [
  "Hardware shard",
  "SQLite shard",
  "Preferences shard",
  "Binary shard",
  "WebView shard",
  "RAM session shard",
  "Relay shard",
];
const names = [
  "Hardware key",
  "Database",
  "Preferences",
  "App storage",
  "WebView",
  "Session memory",
  "Relay",
];
const layers = [
  "Android hardware-backed keystore",
  "Encrypted SQLCipher database",
  "Device secure preferences",
  "App binary asset storage",
  "Local WebView storage",
  "Ephemeral in-memory session key",
  "Encrypted remote relay storage",
];

export function FragmentShield({
  status,
  unlocked = false,
  onPickShard7,
  shard7Loaded = false,
}: {
  status: any;
  unlocked?: boolean;
  onPickShard7?:()=>void;
  shard7Loaded?:boolean;
}) {
  const pickSeventh=useTapGesture(5,2500,()=>onPickShard7?.());
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState<number | null>(null);
  const ready = !!status?.isReconstructable;
  const present = locations.filter((l) => status?.locations?.[l]).length;
  return (
    <section
      className={`fragment-shield ${ready ? "quorum-ready" : ""}`}
      aria-label="Vault protection"
    >
      <button
        type="button"
        className="core-summary"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        <span className="core-icon">
          {ready ? <ShieldCheck size={18} /> : <LockKeyhole size={17} />}
        </span>
        <span className="core-copy">
          <strong>
            {ready
              ? "Vault key can be rebuilt"
              : unlocked
                ? "Some vault fragments are unavailable"
                : "Your vault is locked"}
          </strong>
          <small>
            {ready
              ? "All seven protected fragments are in place."
              : unlocked
                ? "Sync your encrypted backup to restore them."
                : status?.externalShard7 ? "Your secrets and external segment file open this vault offline." : "Existing vault: unlock once to save your external segment file."}
          </small>
        </span>
        <span className="core-count mono">{present}/7</span>
        <ChevronDown size={16} className="core-chevron" />
      </button>
      <div className="core-bar">
        {names.map((name, i) => {
          const here = !!status?.locations?.[locations[i]];
          return (
            <span
              key={name}
              className={`core-segment ${here || (i===6&&shard7Loaded) ? "present" : ""} ${ready && here ? "verified" : ""}`}
            >{i===6&&onPickShard7&&<button type="button" className="segment-hit-zone" aria-label="Segment 07" onClick={pickSeventh}/>}</span>
          );
        })}
      </div>
      {onPickShard7&&<p className="segment-file-state mono" role="status">{shard7Loaded?'07 LOADED · ready to unlock':'07 LOCKED / EXTERNAL'}</p>}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            className="core-details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <p>
              Your vault key is split into seven encrypted fragments kept in
              different places. All seven are needed to open the vault.
            </p>
            <ul>
              {names.map((name, i) => {
                const here = !!status?.locations?.[locations[i]];
                return (
                  <li key={name}>
                    <button
                      type="button"
                      aria-expanded={active === i}
                      onClick={() => setActive(active === i ? null : i)}
                    >
                      <span className={`segment-light ${here ? "on" : ""}`} />
                      <span className="segment-name">
                        {i===6&&(status?.externalShard7||onPickShard7)?'External file':name}
                        {active === i && <small>{i===6&&(status?.externalShard7||onPickShard7)?'Encrypted external segment file':layers[i]}</small>}
                      </span>
                      <span className="segment-state">
                        {here ? "Present" : "Locked"}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}

const modes = [
  ["open", "Unlock"],
  ["create", "Create vault"],
  ["restore", "Restore"],
] as const;

export function VaultGate({
  state,
  status,
  requiresVaultId,
  multipleVaults=false,
  busy,
  submit,
  restoreRequired,
  relayUrl,
  saveRelay,
  pendingCreation=false,
  finishCreation,
  selectStorage,
  storageSelected=false,
  onError,
}: {
  state: string;
  status: any;
  requiresVaultId: boolean;
  multipleVaults?:boolean;
  busy: boolean;
  restoreRequired: boolean;
  relayUrl: string;
  saveRelay: (url: string) => Promise<boolean>;
  pendingCreation?:boolean;
  finishCreation:()=>Promise<void>;
  selectStorage:(file:File)=>Promise<void>;
  storageSelected?:boolean;
  onError:(message:string)=>void;
  submit: (
    mode: string,
    id: string,
    password: string,
    confirm: string,
    username?: string,
    shard7Payload?:string,
  ) => Promise<void>;
}) {
  const shardPicker=useRef<HTMLInputElement>(null),storagePicker=useRef<HTMLInputElement>(null),shardBytes=useRef<Uint8Array|null>(null);
  const [shardLoaded,setShardLoaded]=useState(false);
  const pickStorage=useTapGesture(4,2000,()=>storagePicker.current?.click());
  useEffect(()=>()=>{shardBytes.current?.fill(0);shardBytes.current=null;},[]);
  useEffect(()=>{if(storageSelected)setMode('open');},[storageSelected]);
  const [mode, setMode] = useState<string>(
    state === "unconfigured" ? "create" : "open",
  );
  const [id, setId] = useState(""),
    [password, setPassword] = useState(""),
    [confirm, setConfirm] = useState("");
  const [username, setUsername] = useState("");
  const [visible, setVisible] = useState(false),
    [transfer, setTransfer] = useState(false);
  const [relay, setRelay] = useState(relayUrl),
    [networkOpen, setNetworkOpen] = useState(false),
    [networkBusy, setNetworkBusy] = useState(false);
  useBackAction(!pendingCreation&&mode!==(state==='unconfigured'?'create':'open'),()=>{setMode(state==='unconfigured'?'create':'open');setPassword('');setConfirm('');shardBytes.current?.fill(0);shardBytes.current=null;setShardLoaded(false);},10);
  useBackAction(pendingCreation,()=>onError('Save this vault’s seventh-segment file before leaving setup.'),10);
  useEffect(() => {
    if (restoreRequired) setMode("restore");
  }, [restoreRequired]);
  useEffect(() => setRelay(relayUrl), [relayUrl]);
  const policy = [
    ["12+ characters", password.length >= 12],
    ["Uppercase", /[A-Z]/.test(password)],
    ["Lowercase", /[a-z]/.test(password)],
    ["Number", /[0-9]/.test(password)],
  ] as const;
  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    await submit(
      mode,
      id,
      password,
      confirm,
      mode === "create" ? username : undefined,
      shardBytes.current?base64Bytes(shardBytes.current):undefined,
    );
    setPassword("");
    setConfirm("");
  }
  const copy = {
    open: ["Welcome back.", "Unlock your vault to continue."],
    create: ["Create a vault.", multipleVaults?"Keep a separate vault on this phone. Your other vaults stay saved.":"Two secrets that only you know."],
    restore: [
      "Restore your vault.",
      "Bring your encrypted backup to this device.",
    ],
  }[mode as "open" | "create" | "restore"];
  return (
    <main className="vault-gate">
      <header className="gate-topbar">
        <Brand onClick={pickStorage}/>
        <input ref={storagePicker} type="file" accept=".cpvault" className="visually-hidden" tabIndex={-1} aria-label="Select app storage file" onChange={e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';if(file)void selectStorage(file).then(()=>{shardBytes.current?.fill(0);shardBytes.current=null;setShardLoaded(false);setMode('open');}).catch(error=>onError(error.message));}}/>
        <input ref={shardPicker} type="file" className="visually-hidden" tabIndex={-1} aria-label="Select segment 07 file" onChange={async e=>{const file=e.currentTarget.files?.[0];e.currentTarget.value='';if(!file)return;try{const bytes=await readSovereignFile(file,'shard7');shardBytes.current?.fill(0);shardBytes.current=bytes;setShardLoaded(true);}catch(error:any){onError(error.message);}}}/>
        <button
          type="button"
          className="network-chip"
          onClick={() => setNetworkOpen(true)}
        >
          <span className={`relay-dot ${relayUrl ? "configured" : ""}`} />
          {relayUrl ? "Relay saved" : "Set up relay"}
          <Network size={14} />
        </button>
      </header>
      <div className="gate-layout">
        <motion.section
          className="vault-card glass-panel"
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={spring}
        >
          <div className="gate-heading">
            <h2>{copy[0]}</h2>
            <p>{copy[1]}</p>
          </div>
          <div className="gate-tabs" role="tablist" aria-label="Vault action">
            {modes.map(([v, label]) => (
              <button
                type="button"
                role="tab"
                aria-selected={mode === v}
                disabled={busy}
                key={v}
                onClick={() => {setMode(v);setPassword('');setConfirm('');shardBytes.current?.fill(0);shardBytes.current=null;setShardLoaded(false);}}
              >
                {mode === v && (
                  <motion.span
                    layoutId="vault-mode"
                    className="tab-indicator"
                    transition={spring}
                  />
                )}
                <span>{label}</span>
              </button>
            ))}
          </div>
          {pendingCreation&&<div className="stack"><p>Your vault is ready to initialize. Save its separate seventh segment before continuing.</p><button type="button" className="btn-primary" disabled={busy} onClick={()=>void finishCreation()}>Choose 7th Segment File Location</button><p className="field-help">Choose your own folder and filename. You will need this file for every cold unlock.</p></div>}
          {storageSelected&&!pendingCreation&&<p className="field-help" role="status">Storage file selected. Enter its vault credentials and load its seventh segment.</p>}
          <form onSubmit={onSubmit} className="vault-form" autoComplete="off" hidden={pendingCreation}>
            {multipleVaults&&mode==='open'&&<p className="field-help">Enter the Vault ID and master passphrase for the vault you want to open, and load its seventh-segment file.</p>}
            {mode === "create" && (
              <label className="field-label">
                Username
                <input
                  aria-label="Your username"
                  className="glass-input"
                  required
                  minLength={3}
                  maxLength={32}
                  pattern="[a-zA-Z0-9_]+"
                  autoCapitalize="none"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="How contacts will find you"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={busy}
                />
              </label>
            )}
            <label className="field-label">
              Vault ID
              <span className="secret-input">
                <KeyRound size={17} />
                <input
                  aria-label="Vault ID"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  type={visible ? "text" : "password"}
                  required={mode !== "open" || requiresVaultId}
                  minLength={8}
                  maxLength={256}
                  value={id}
                  onChange={(e) => setId(e.target.value)}
                  placeholder="Your private identifier"
                  disabled={busy}
                />
                <button
                  type="button"
                  className="icon-button"
                  aria-label={visible ? "Hide Vault ID" : "Show Vault ID"}
                  aria-pressed={visible}
                  onClick={() => setVisible(!visible)}
                >
                  {visible ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </span>
            </label>
            <label className="field-label">
              Master passphrase
              <span className="secret-input">
                <LockKeyhole size={17} />
                <input
                  aria-label="Master passphrase"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  type="password"
                  required
                  minLength={12}
                  maxLength={1024}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Known only to you"
                  disabled={busy}
                />
              </span>
            </label>
            <motion.div
              className="mode-fields"
              key={mode}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.15 }}
            >
              {mode === "create" ? (
                <>
                  <ul className="password-policy" aria-label="Passphrase rules">
                    {policy.map(([rule, met]) => (
                      <li key={rule} className={met ? "met" : ""}>
                        <Check size={13} /> {rule}
                      </li>
                    ))}
                  </ul>
                  <label className="field-label">
                    Confirm passphrase
                    <input
                      aria-label="Confirm passphrase"
                      type="password"
                      required
                      autoComplete="off"
                      autoCapitalize="none"
                      spellCheck={false}
                      className="glass-input"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      disabled={busy}
                    />
                  </label>
                  <p className="field-help">
                    Write both secrets down somewhere safe. If you lose them,
                    nobody can recover them for you.
                  </p>
                </>
              ) : mode === "restore" ? (
                <>
                  <p className="field-help">
                    Use Restore on a new device, or when Unlock says fragments
                    are missing. It downloads your encrypted backup, so the
                    relay must be reachable. If the relay is down, nothing on
                    this device is lost. Try again later.
                  </p>
                  <label className="transfer-check">
                    <input
                      type="checkbox"
                      required
                      checked={transfer}
                      onChange={(e) => setTransfer(e.target.checked)}
                    />
                    <span>
                      I stopped messaging on my previous device. Move my active
                      vault here.
                    </span>
                  </label>
                </>
              ) : (
                <p className="unlock-note">
                  <Shield size={16} />
                  <span>
                    {requiresVaultId
                      ? "Your Vault ID and passphrase never leave this device. The public UID you share with contacts is separate."
                      : "Older vault: use your existing password."}
                  </span>
                </p>
              )}
            </motion.div>
            {restoreRequired && (
              <p className="inline-warning" role="status">
                Part of your vault on this device is missing or damaged.
                Restore from your encrypted backup to get access back.
              </p>
            )}
            <motion.button
              whileTap={{ scale: 0.98 }}
              transition={spring}
              disabled={busy || (mode === "restore" && !transfer)}
              className="btn-primary gate-submit"
            >
              <span>
                {busy
                  ? mode === "restore"
                    ? "Restoring…"
                    : mode === "create"
                      ? "Creating vault…"
                      : "Unlocking…"
                  : mode === "restore"
                    ? "Restore vault"
                    : mode === "create"
                      ? "Create vault"
                      : "Unlock vault"}
              </span>
              {busy ? (
                <Loader2 className="spin" size={18} />
              ) : (
                <ArrowRight size={18} />
              )}
            </motion.button>
            {busy && (
              <p className="busy-hint" role="status">
                {mode === "restore"
                  ? "Downloading and checking your encrypted backup from the relay."
                  : "Deriving encryption keys from your passphrase. This can take a few seconds."}
              </p>
            )}
          </form>
          <FragmentShield status={status} onPickShard7={mode==='open'&&!pendingCreation?()=>shardPicker.current?.click():undefined} shard7Loaded={shardLoaded}/>
        </motion.section>
      </div>
      <footer className="gate-footer">
        <span>
          <LockKeyhole size={12} /> AES-256-GCM · Your keys stay with you
        </span>
      </footer>
      <Sheet
        open={networkOpen}
        onClose={() => setNetworkOpen(false)}
        title="Relay connection"
        eyebrow="Network"
      >
        <p>
          A relay carries encrypted messages between devices. Your vault
          secrets stay on this device. Saving a route does not test it; the
          app shows whether the relay is reachable after you unlock.
        </p>
        <RelayRoutes current={relayUrl} save={saveRelay} />
        <form
          className="stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setNetworkBusy(true);
            try {
              if (await saveRelay(relay)) setNetworkOpen(false);
            } finally {
              setNetworkBusy(false);
            }
          }}
        >
          <label className="field-label">
            Custom relay URL
            <input
              type="url"
              className="glass-input"
              required
              value={relay}
              onChange={(e) => setRelay(e.target.value)}
              placeholder="https://relay.example.com"
            />
          </label>
          <button className="btn-primary" disabled={networkBusy}>
            {networkBusy ? (
              "Saving…"
            ) : (
              <>
                <Check size={16} /> Save relay
              </>
            )}
          </button>
        </form>
      </Sheet>
    </main>
  );
}
