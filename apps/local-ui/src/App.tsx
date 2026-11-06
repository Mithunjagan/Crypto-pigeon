import { VaultGate, FragmentShield, shardStorageKey } from "./VaultGate";
import {readVaultShards,rememberVaultShard} from './vaultFragments';
import {SovereignStorageSheet,saveSovereignFile,readSovereignFile,base64Bytes,useTapGesture} from './SovereignStorage';
import { UidBadge } from "./UidBadge";
import { RelayRoutes } from "./RelayRoutes";
import { PeerScanner } from "./PeerScanner";
import { MessageBubble } from "./MessageBubble";
import { TransportPrivacy } from "./TransportPrivacy";
import { BackgroundDelivery } from "./BackgroundDelivery";
import React, { useState, useEffect, useRef } from "react";
import {
  Plus,
  ArrowUp,
  Mic,
  Settings,
  Shield,
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  Search,
  ChevronLeft,
  LockKeyhole,
  MessageSquare,
  X,
  Clock3,
  QrCode,
  Inbox,
  ArrowUpRight,
  Check,
  Square,
  ChevronDown,
  Loader2,
  Network,
  KeyRound,
  UserPlus,
  ShieldCheck,
  User,
  HardDriveUpload,
  SlidersHorizontal,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Avatar, Brand, Sheet, PrivacyNote, Waveform, spring, pageTransition } from "./ui";
import {installBackNavigation} from './backNavigation';
import {useBackAction} from './useBackNavigation';

const queuedMessageNotice =
  "Message queued. It will retry while the app is open and your vault is unlocked.";

export default function App() {
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [vaultState, setVaultState] = useState<
    "unconfigured" | "locked" | "unlocked" | "bootstrapping"
  >("bootstrapping");

  const [quickLocked,setQuickLocked]=useState(false);
  const [showPin,setShowPin]=useState(false),[pin,setPin]=useState(""),[pinConfirm,setPinConfirm]=useState("");
  const [profile,setProfile]=useState({displayName:"",statusLine:""});
  const [peerTyping,setPeerTyping]=useState(false);
  const lastTyping=useRef(0),lastRead=useRef(""),incomingSeen=useRef(new Set<string>());
  const haptic=()=>navigator.vibrate?.(8);
  const [busy, setBusy] = useState(false);
  const [showStorage,setShowStorage]=useState(false),[pendingCreation,setPendingCreation]=useState(false),[storageSelected,setStorageSelected]=useState(false);
  const storageLogo=useTapGesture(4,2000,()=>setShowStorage(true));
  const [restoreRequired, setRestoreRequired] = useState(false);
  const [relayUrl, setRelayUrl] = useState("");
  const [showRequests, setShowRequests] = useState(false);
  const [showIdentity, setShowIdentity] = useState(false);
  const [showTimer, setShowTimer] = useState(false);
  const [timerBusy, setTimerBusy] = useState(false);
  const [isMobile, setIsMobile] = useState(
    () => window.matchMedia("(max-width: 767px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 767px)");
    const update = () => setIsMobile(mq.matches);
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  const [recordingSeconds, setRecordingSeconds] = useState(0);
  const recordingStartRef = useRef(0);
  const recordingCancelledRef=useRef(false);
  const messageListRef=useRef<HTMLDivElement>(null),scrolledConversationRef=useRef<string|null>(null);
  const reducedMotion=useReducedMotion();
  const holdRef = useRef<number | undefined>(undefined);
  const heldRecordingRef = useRef(false);
  const recordingHeldActiveRef = useRef(false);
  const [sessionUnavailable, setSessionUnavailable] = useState(false);
  const [sending, setSending] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [contactSearch, setContactSearch] = useState("");
  const sendingRef = useRef(false);
  const optimisticRef = useRef(new Map<string, any>());
  const syncInFlightRef = useRef<Promise<{
    ok: boolean;
    status?: number;
  }> | null>(null);
  const wakeSyncRef = useRef<() => void>(() => {});
  const uploadRef = useRef(false);
  const selectedConversationRef = useRef<string | null>(null);
  const [requiresVaultId, setRequiresVaultId] = useState(true);
  const [multipleVaults,setMultipleVaults]=useState(false);
  const vaultEpochRef=useRef(0);
  const [fragmentStatus, setFragmentStatus] = useState<any>(null);
  const [publicUid, setPublicUid] = useState("");
  const [mobilePane, setMobilePane] = useState("contacts");
  const [showSafety, setShowSafety] = useState(false);
  const [timer, setTimer] = useState(0);
  // Forms
  const [changeVaultId, setChangeVaultId] = useState("");
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  // App State
  const [contacts, setContacts] = useState<any[]>([]);
  const [selectedContact, setSelectedContact] = useState<any | null>(null);
  selectedConversationRef.current = selectedContact?.conversation_id ?? null;
  const [messages, setMessages] = useState<any[]>([]);
  const [inputText, setInputText] = useState("");
  const [newContactUsername, setNewContactUsername] = useState("");
  const [incomingRequests, setIncomingRequests] = useState<any[]>([]);
  const [decidingRequest, setDecidingRequest] = useState<string | null>(null);
  const pendingInvitesRef = useRef(new Set<string>());

  // UI Panels
  const [showSettings, setShowSettings] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);
  const [relayStatus, setRelayStatus] = useState<
    "checking" | "online" | "offline"
  >("checking");
  const [transportInfo,setTransportInfo]=useState<{mode:string;activeTransport:string;serverless:boolean;bootstrapPercent:number}|null>(null);
  useEffect(()=>{setTransportInfo(null);if(vaultState!=="unlocked"||quickLocked)return;let live=true;const load=async()=>{try{const response=await apiFetch('/api/transport/status');if(response.ok){const value=await response.json();if(live)setTransportInfo(value);}}catch{}};void load();const timer=setInterval(()=>void load(),5000);return()=>{live=false;clearInterval(timer);};},[vaultState,quickLocked]);

  // Registration / Activation
  const [registrationState, setRegistrationState] = useState<
    "idle" | "pending" | "success"
  >("idle");
  const [regUsername, setRegUsername] = useState("");

  // Audio Recording
  const [isRecording, setIsRecording] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  // File Upload
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Poll intervals
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const pollFailuresRef = useRef(0);

  useEffect(() => {
    bootstrapSession();
  }, []);
  useEffect(() => {
    if (!isRecording) return;
    const tick = () =>
      setRecordingSeconds(
        Math.floor((Date.now() - recordingStartRef.current) / 1000),
      );
    const interval = window.setInterval(tick, 250);
    return () => clearInterval(interval);
  }, [isRecording]);

  useEffect(() => {
    if (!infoMsg || infoMsg === queuedMessageNotice || uploading) return;
    const timeout = window.setTimeout(() => setInfoMsg(null), 5000);
    return () => window.clearTimeout(timeout);
  }, [infoMsg, uploading]);

  useEffect(() => {
    if (vaultState === "unlocked" && !quickLocked) {
      const epoch=vaultEpochRef.current;
      void apiFetch("/api/profile").then(r=>r.ok?r.json():null).then(p=>{if(p&&epoch===vaultEpochRef.current)setProfile(p);});
      loadContacts();
      loadRegistrationState();
    }
  }, [vaultState, csrfToken, quickLocked]);

  useEffect(()=>{
    if(vaultState!=="unlocked"||quickLocked)return;
    const visible=!!selectedContact?.conversation_id&&(!isMobile||mobilePane==="chat");
    void apiFetch("/api/transport/chat",{method:"POST",body:JSON.stringify({conversationId:visible?selectedContact?.conversation_id:null})}).catch(()=>{});
  },[vaultState,quickLocked,selectedContact?.conversation_id,isMobile,mobilePane]);

  useEffect(() => {
    if (quickLocked || vaultState !== "unlocked" || registrationState !== "success") return;
    let stopped = false,
      running = false,
      again = false;
    let timer: number | undefined;
    const activeChat =
      !!selectedContact?.conversation_id &&
      (!isMobile || mobilePane === "chat");
    const poll = async () => {
      if (stopped) return;
      if (running) {
        again = true;
        return;
      }
      clearTimeout(timer);
      running = true;
      const result = await syncMessages();
      running = false;
      if (stopped) return;
      if (result.status === 401 || result.status === 409) {
        setErrorMsg(
          "Device is not registered or the vault moved. Unlock again to reconnect.",
        );
        return;
      }
      setRelayStatus(result.ok ? "online" : "offline");
      pollFailuresRef.current = result.ok ? 0 : pollFailuresRef.current + 1;
      const delay = again
        ? 0
        : Math.min(
            (activeChat ? 1200 : 3000) * 2 ** pollFailuresRef.current,
            30000,
          );
      again = false;
      timer = window.setTimeout(() => void poll(), delay);
    };
    const wake = () => void poll();
    wakeSyncRef.current = wake;
    const visible = () => {
      if (document.visibilityState === "visible") wake();
    };
    document.addEventListener("visibilitychange", visible);
    pollFailuresRef.current = 0;
    wake();
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visible);
      if (wakeSyncRef.current === wake) wakeSyncRef.current = () => {};
    };
  }, [
    vaultState,
    quickLocked,
    csrfToken,
    registrationState,
    selectedContact?.conversation_id,
    mobilePane,
    isMobile,
  ]);

  useEffect(() => {
    if (quickLocked || vaultState !== "unlocked" || registrationState !== "success") return;
    const abort = new AbortController();
    let cursor = 0;
    const listen = async () => {
      while (!abort.signal.aborted) {
        try {
          const response = await apiFetch("/api/events?after=" + cursor, {
            signal: abort.signal,
          });
          if (!response.ok) {
            if ([400, 401, 409].includes(response.status)) return;
            throw new Error("event_feed_unavailable");
          }
          const event = await response.json();
          if (event.revision > cursor) {
            cursor = event.revision;
            if(event.type==="QUICK_LOCKED")setQuickLocked(true);
            if(event.type==='STORAGE_SAVE_FAILED')setErrorMsg('Your chosen storage file could not be updated. The encrypted working copy is safe; export to a writable location.');
            if(event.type==="ROUTE_CHANGED")void apiFetch("/api/relay/config").then(r=>r.ok?r.json():null).then(c=>{if(c)setRelayUrl(c.relayUrl);});
            if (
              [
                "NEW_ENVELOPE",
                "CONNECTED",
                "ROUTE_CHANGED",
                "MESSAGES_CHANGED",
              ].includes(event.type)
            )
              wakeSyncRef.current();
            if (event.type === "BACKUP_FAILED")
              setErrorMsg(
                "Background backup could not sync. Messages remain on this device; backup will retry while unlocked.",
              );
          }
        } catch {
          if (!abort.signal.aborted)
            await new Promise((resolve) => setTimeout(resolve, 1500));
        }
      }
    };
    void listen();
    return () => abort.abort();
  }, [vaultState, csrfToken, registrationState, quickLocked]);

  useEffect(() => {
    if (quickLocked || vaultState !== "unlocked" || registrationState !== "success") return;
    let stopped = false,
      timer: number | undefined;
    const requests = async () => {
      await loadConversationRequests();
      for (const peer of [...pendingInvitesRef.current]) {
        if (stopped) return;
        try {
          const contact = await establishSession(peer, false);
          setInfoMsg(`${contact?.displayName || contact?.username || peer} accepted. Your conversation is ready.`);
        } catch {
          // Not accepted yet; try again on the next pass.
        }
      }
      if (!stopped) timer = window.setTimeout(() => void requests(), 15000);
    };
    void requests();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [vaultState, csrfToken, registrationState, quickLocked]);

  useEffect(() => {
    if (selectedContact) {
      setMessages([]);
      setInputText("");
      setTimer(selectedContact.disappearing_seconds || 0);
      void loadMessages(selectedContact.conversation_id);
    }
  }, [selectedContact?.conversation_id]);

  const lastMessage=messages[messages.length-1];
  useEffect(()=>{
    if(isMobile&&mobilePane!=='chat'){scrolledConversationRef.current=null;return;}
    const list=messageListRef.current,conversation=selectedContact?.conversation_id;
    if(!list||!conversation||!lastMessage?.message_id)return;
    const first=scrolledConversationRef.current!==conversation;
    const nearEnd=list.scrollHeight-list.scrollTop-list.clientHeight<160;
    if(first||nearEnd||lastMessage.direction==='sent')list.scrollTo({top:list.scrollHeight,behavior:first||reducedMotion?'auto':'smooth'});
    scrolledConversationRef.current=conversation;
  },[lastMessage?.message_id,selectedContact?.conversation_id,mobilePane,isMobile,reducedMotion]);
  useEffect(()=>installBackNavigation(window),[]);

  const bootstrapSession = async (providedSecret?: string) => {
    setSessionUnavailable(false);
    try {
      const hash = providedSecret ?? window.location.hash.slice(1);
      let res;
      if (hash) {
        res = await fetch("/api/bootstrap", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ secret: hash }),
        });
        // Clear fragment
        window.history.replaceState(null, "", window.location.pathname);
      } else {
        res = await fetch("/api/session");
      }

      if (res.ok) {
        const data = await res.json();
        setCsrfToken(data.csrfToken);
        setQuickLocked(data.vaultState === "quick_locked");
        setVaultState(data.vaultState === "quick_locked" ? "unlocked" : data.vaultState);
        const status = await fetch("/api/vault/status").then((r) => r.json());
        setRequiresVaultId(status.requiresVaultId ?? true);
        setMultipleVaults(status.multipleVaults===true);
        const config = await fetch("/api/relay/config").then((r) =>
          r.ok ? r.json() : null,
        );
        if (config?.relayUrl) setRelayUrl(config.relayUrl);
        await loadFragmentStatus();
      } else {
        setVaultState("locked");
        setErrorMsg(
          "Open the single-use bootstrap link from your paired daemon to connect this browser.",
        );
      }
    } catch {
      setSessionUnavailable(true);
      setVaultState("locked");
    }
  };

  const apiFetch = async (path: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {});
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
    if (
      options.body != null &&
      !headers.has("Content-Type") &&
      !(options.body instanceof FormData)
    ) {
      headers.set("Content-Type", "application/json");
    }
    options.headers = headers;
    return fetch(path, options);
  };

  const relayDown =
    "Can't reach the relay. Your vault and messages on this device are safe. Check the relay route in Settings.";
  const errorMessage = (code?: string) => {
    // Raw exception text from vault/network failures: translate the cause, not the symptom.
    if (/unable to authenticate|bad decrypt|invalid_password|wrong final block/i.test(code || ""))
      return "Vault ID or passphrase is incorrect.";
    if (/fetch failed|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|network/i.test(code || ""))
      return relayDown;
    return ({
      RELAY_UNAVAILABLE: relayDown,
      RELAY_SYNC_UNAVAILABLE: relayDown,
      RELAY_BACKUP_UNAVAILABLE: "Can't reach the relay to read your backup. Nothing on this device was changed. Try again when the relay is reachable.",
      BACKUP_NOT_FOUND_OR_INVALID_CREDENTIALS: "No backup matches that Vault ID and passphrase. Check both and try again.",
      INVALID_VAULT_CREDENTIALS: "Vault ID or master passphrase is incorrect.",
      VAULT_ID_ALREADY_ON_DEVICE: "A vault with this ID is already saved on this phone. Use Unlock, or choose a different Vault ID for a new vault.",
      LOCK_BEFORE_VAULT_SWITCH: "Fully lock the current vault before opening or creating another one.",
      BROWSER_VAULT_SHARDS_INVALID: "The saved browser fragments could not be read. Keep your vault and segment files; do not clear app storage.",
      vault_already_exists: "This vault already exists. Use Unlock with its Vault ID and master passphrase.",
      SHARD7_FILE_REQUIRED: "Load your segment file first: tap Segment 07’s top-right corner five times, then select the file.",
      SHARD7_FILE_MISMATCH: "That segment file belongs to another vault. Select this vault’s file and retry.",
      RESTORE_FAILED_CHECK_CREDENTIALS_AND_RELAY: "Restore failed. Check your Vault ID and passphrase, and that the relay is reachable.",
      INVALID_BACKUP_SIGNATURE: "The backup on the relay failed its integrity check, so it was not used.",
      VAULT_ID_ALREADY_EXISTS_USE_RESTORE: "A vault with this ID already exists. Use Restore to bring it to this device.",
      LEGACY_VAULT_USE_EXISTING_PASSWORD: "This is an older vault. Unlock it with your existing password.",
      LOCK_BEFORE_RESTORE: "Fully lock the vault before restoring.",
      LOCK_BEFORE_RELAY_CHANGE: "Fully lock the vault before changing the relay.",
      INVALID_RELAY_URL: "That relay address isn't a valid URL.",
      INVALID_SESSION_PIN: "Incorrect PIN.",
      PIN_RETRY_LATER: "Too many attempts. Try again in 30 seconds.",
      NEW_PASSWORD_MUST_DIFFER: "The new passphrase must be different from the current one.",
      NEW_CREDENTIALS_ALREADY_IN_USE: "Those credentials are already used by another vault.",
      SAFETY_NUMBER_CHANGED: "Their safety number changed. Review it before verifying.",
      IDENTITY_NOT_READY: "Your identity is still being set up. Try again in a moment.",
      INTERNAL_ERROR: "Something went wrong on this device. Try again.",
      REQUEST_ID_REQUIRED: "Missing request ID",
      REQUEST_ID_INVALID: "Missing request ID",
      ACTIVATION_CODE_REQUIRED: "Activation code is required",
      ACTIVATION_CODE_EXPIRED: "Activation code expired",
      ACTIVATION_CODE_INVALID: "Activation code invalid",
      ACTIVATION_ATTEMPTS_EXCEEDED: "Too many invalid activation attempts",
      REQUEST_NOT_APPROVED: "Request not approved",
      REQUEST_NOT_FOUND: "Activation request not found",
      ACTIVATION_ALREADY_COMPLETED:
        "This activation request has already been completed",
      PREKEY_REGISTRATION_FAILED: "Prekey registration failed",
      LOCAL_VAULT_PERSISTENCE_FAILED: "Local vault persistence failed",
      DEVICE_NOT_REGISTERED: "Choose your username in Settings to finish setting up this device.",
      TOR_NOT_READY: "Tor is still connecting. Wait for the connection indicator to reach 100%.",
      RELAY_DISABLED_IN_DIRECT_MODE: "Use a signed invite for direct messaging. Relay usernames need a configured relay route.",
      PINNED_INVITE_CHANGED: "This invite differs from your saved contact. Review their identity before changing the contact.",
      USERNAME_UNAVAILABLE: "Username is unavailable",
    } as Record<string, string>)[code || ""] ||
    code ||
    "Request failed";
  };

  const responseError = async (res: Response, fallback: string) => {
    try {
      const body = (await res.json()) as { error?: string };
      return errorMessage(body.error) || fallback;
    } catch {
      return fallback;
    }
  };

  const loadRegistrationState = async () => {
    const epoch=vaultEpochRef.current;
    try {
      const res = await apiFetch("/api/access/state");
      if (!res.ok) return;
      const data = (await res.json()) as {
        publicUid?: string;
        requestId?: string;
        username?: string;
        status?: "idle" | "pending" | "activated";
      };
      if(epoch!==vaultEpochRef.current)return;
      setPublicUid(data.publicUid||'');
      if (data.status === "pending" && data.requestId) {
        setRegUsername(data.username || "");
        setRegistrationState("pending");
      } else if (data.status === "activated") {
        setRegistrationState("success");
      }else setRegistrationState('idle');
    } catch {
      // The page remains usable; retry happens on the next unlock/session refresh.
    }
  };

  const loadFragmentStatus = async () => {
    const present = !!localStorage.getItem(shardStorageKey);
    try {
      const r = await fetch(
        "/api/vault/horcrux-status?clientPresent=" + present,
      );
      if (r.ok) setFragmentStatus(await r.json());
    } catch {}
  };
  const saveRelay = async (url: string) => {
    try {
      const r = await apiFetch("/api/relay/config", {
        method: "POST",
        body: JSON.stringify({ relayUrl: url }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(errorMessage(data.error || "INVALID_RELAY_URL"));
      setRelayUrl(data.relayUrl);
      setRelayStatus("checking");
      wakeSyncRef.current();
      return true;
    } catch (e: any) {
      setErrorMsg(errorMessage(e.message));
      return false;
    }
  };
  const submitVault = async (
    mode: string,
    vaultId: string,
    password: string,
    confirm: string,
    username?: string,
    shard7Payload?:string,
  ) => {
    if (mode === "create" && password !== confirm) {
      setErrorMsg("Passwords do not match");
      return;
    }
    setBusy(true);
    setErrorMsg(null);
    vaultEpochRef.current++;
    try {
      const r = await apiFetch("/api/vault/" + mode, {
        method: "POST",
        body: JSON.stringify({
          vaultId: vaultId || (!requiresVaultId ? "legacy-local" : ""),
          password,
          username,
          shard7Payload,
          clientShard: localStorage.getItem(shardStorageKey) ?? undefined,
          clientShards: readVaultShards(),
          decoyClientShard: localStorage.getItem("cp-decoy-shard-v1") ?? undefined,
          transferConfirmed: mode === "restore" ? true : undefined,
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Vault operation failed");
      if (!data.decoySession&&(data.clientShard||data.vaultHandle))rememberVaultShard(data);
      if(data.shard7FileBytes){data.shard7FileBytes=null;setPendingCreation(true);setRegUsername(username||'');return;}
      setStorageSelected(false);
      setRestoreRequired(false);
      await bootstrapSession();
      if(data.onboardingPending){setShowSettings(true);setInfoMsg("Your vault is ready. Choose a username to finish setting up.");}
    } catch (e: any) {
      if (e.message === "HORCRUX_INCOMPLETE_RESTORE_REQUIRED")
        setRestoreRequired(true);
      setErrorMsg(
        e.message === "HORCRUX_INCOMPLETE_RESTORE_REQUIRED"
          ? "Part of your vault on this device is missing or damaged. Restore from your encrypted backup to get access back."
          : errorMessage(e.message),
      );
    } finally {
      setBusy(false);
    }
  };

  const handleLockVault = async () => {
    if (busy) return;
    setBusy(true);
    vaultEpochRef.current++;syncInFlightRef.current=null;
    setProfile({displayName:'',statusLine:''});setPeerTyping(false);incomingSeen.current.clear();lastRead.current='';
    setShowStorage(false);window.dispatchEvent(new Event('cp-vault-locked'));
    // Hide decrypted content immediately while the engine seals and syncs.
    setQuickLocked(false);setVaultState("locked");selectedConversationRef.current=null;
    setInputText("");setMessages([]);setContacts([]);setSelectedContact(null);optimisticRef.current.clear();
    setShowSettings(false);setShowSafety(false);setShowAddContact(false);setShowIdentity(false);setShowRequests(false);setShowTimer(false);
    if(mediaRecorderRef.current?.state==="recording")mediaRecorderRef.current.stop();
    try {
      const res = await apiFetch("/api/vault/lock", { method: "POST" });
      if (res.ok) {
        const result = await res.json();
        if(result.localStorageError)setErrorMsg('Vault locked. The chosen storage file could not be updated; the encrypted working copy is preserved.');
        if (!result.backupSynced)
          setErrorMsg(
            "Vault locked, but backup sync failed. The relay may have an older backup.",
          );
        setVaultState("locked");
        setQuickLocked(false);
        setCsrfToken(null);
        selectedConversationRef.current = null;
        if (mediaRecorderRef.current?.state === "recording")
          mediaRecorderRef.current.stop();
        setShowSettings(false);
        setShowSafety(false);
        setShowAddContact(false);
        setShowIdentity(false);
        setShowRequests(false);
        setShowTimer(false);
        setInputText("");
        setSelectedContact(null);
        setMessages([]);
        optimisticRef.current.clear();
        setContacts([]);
        setIncomingRequests([]);
        pendingInvitesRef.current.clear();
        setPublicUid("");
        setRegistrationState("idle");
        await bootstrapSession(result.bootstrapSecret);
      } else {
        setErrorMsg(
          await responseError(res, "Could not sync and lock the vault"),
        );
      }
    } catch {
      setErrorMsg("Failed to lock vault");
    } finally {
      setBusy(false);
    }
  };

  const finishCreation=async()=>{
    setBusy(true);setErrorMsg(null);
    try{
      await saveSovereignFile('shard7');const result=await apiFetch('/api/vault/shard7/saved',{method:'POST'});
      if(!result.ok)throw new Error('Segment saved, but vault initialization could not finish. Retry.');
      setPendingCreation(false);await bootstrapSession();setShowSettings(true);setInfoMsg('Segment saved. Set up your public identity when your relay is available.');
    }catch(error:any){setErrorMsg(error.message);}finally{setBusy(false);}
  };
  const selectStorage=async(file:File)=>{
    const bytes=await readSovereignFile(file,'storage');
    try{
      if(vaultState==='unlocked')await handleLockVault();
      // Lock rotates CSRF; refresh before the import request.
      const session=await fetch('/api/session').then(r=>r.json());
      const storageDocumentUri=(window as any).CryptoPigeonFiles?.storageSelection?.()||undefined;
      const response=await fetch('/api/vault/storage/import',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrfToken||csrfToken||''},body:JSON.stringify({storagePayload:base64Bytes(bytes),storageDocumentUri})});
      if(!response.ok){const result=await response.json();throw new Error(errorMessage(result.error||'Could not select storage file.'));}
      setStorageSelected(true);setShowStorage(false);setVaultState('locked');
    }finally{bytes.fill(0);}
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/api/vault/change-password", {
        method: "POST",
        body: JSON.stringify({
          vaultId: changeVaultId,
          oldPassword,
          newPassword,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        if (result.clientShard)rememberVaultShard(result);
        setChangeVaultId("");
        setInfoMsg(
          "Passphrase changed. Save the new segment file before locking. Existing cloud copies may still use the previous passphrase.",
        );
        setOldPassword("");
        setNewPassword("");
        setShowSettings(false);
        if(result.shard7FileBytes){result.shard7FileBytes=null;setShowStorage(true);}
      } else {
        const data = await res.json();
        setErrorMsg(errorMessage(data.error || "Failed to change passphrase"));
      }
    } catch {
      setErrorMsg("Network error");
    }
  };

  const handleApplyAccess = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/api/access/apply", {
        method: "POST",
        body: JSON.stringify({ username: regUsername }),
      });
      if (res.ok) {
        const data = await res.json();
        if(data.activated){setRegistrationState("success");setShowSettings(false);setErrorMsg(null);await loadRegistrationState();return;}
        if (!data.requestId) {
          setErrorMsg("Relay did not return an activation request ID");
          return;
        }
        setRegUsername(data.username || regUsername);
        setRegistrationState("pending");
        setErrorMsg(null);
      } else {
        setErrorMsg(await responseError(res, "Relay unavailable"));
      }
    } catch {
      setErrorMsg("Network error");
    }
  };

  const loadContacts = async (): Promise<any[] | null> => {
    const epoch=vaultEpochRef.current;
    try {
      const res = await apiFetch("/api/contacts");
      if (res.ok) {
        const data = await res.json();
        if(epoch!==vaultEpochRef.current)return null;
        setContacts(data);
        setSelectedContact((current:any)=>current?data.find((c:any)=>c.contact_id===current.contact_id)||current:current);
        return data;
      }
    } catch {
      console.error("Failed to load contacts");
    }
    return null;
  };

  // Sets up the cryptographic session with a peer who accepted (or sent) a request,
  // then opens the conversation. Users never have to trigger this step themselves.
  const establishSession = async (peer: string, open = true) => {
    const signedInvite=peer.startsWith('pigeon://invite?');
    const res = await apiFetch(signedInvite?"/api/contacts/import":"/api/contacts/add", {
      method: "POST",
      body: JSON.stringify(signedInvite?{uri:peer}:{ username: peer }),
    });
    if (!res.ok) throw new Error(await responseError(res, "Could not set up the secure session"));
    const result=await res.json();pendingInvitesRef.current.delete(peer);
    const list = await loadContacts();
    const key = peer.toLowerCase();
    const contact = list?.find(
      (c: any) => c.conversation_id===result.conversationId || c.publicUid?.toLowerCase() === key || c.username?.toLowerCase() === key,
    );
    if (contact && open) {
      setSelectedContact(contact);
      setMobilePane("chat");
    }
    return contact;
  };

  const handleAddContact = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await establishSession(newContactUsername.trim());
      setNewContactUsername("");
      setShowAddContact(false);
      setErrorMsg(null);
    } catch (error: any) {
      setErrorMsg(
        error.message === "Request failed"
          ? "Couldn't open the conversation. They may not have accepted your request yet."
          : error.message,
      );
    }
  };

  const sendInvitation = async (peer: string) => {
    if(peer.startsWith('pigeon://invite?')){await establishSession(peer);setInfoMsg("Signed invite verified and contact pinned. Share your invite with them too.");setShowAddContact(false);setShowIdentity(false);return;}
    const r = await apiFetch("/api/conversations/requests", {
      method: "POST",
      body: JSON.stringify({ recipientUsername: peer }),
    });
    if (!r.ok) throw new Error(await responseError(r, "Invitation failed"));
    pendingInvitesRef.current.add(peer);
    setInfoMsg(
      "Invitation sent. The conversation opens automatically once they accept.",
    );
    setShowAddContact(false);
    setShowIdentity(false);
  };

  const handleConversationRequest = async () => {
    try {
      await sendInvitation(newContactUsername.trim());
      setNewContactUsername("");
    } catch (error: any) {
      setErrorMsg(error.message || "Failed to send conversation request");
    }
  };

  const loadConversationRequests = async (): Promise<{
    ok: boolean;
    status?: number;
  }> => {
    const epoch=vaultEpochRef.current;
    try {
      const res = await apiFetch("/api/conversations/requests");
      if (res.ok) {
        const requests=await res.json();if(epoch!==vaultEpochRef.current)return {ok:false};
        setIncomingRequests(requests);
        return { ok: true, status: res.status };
      }
      return { ok: false, status: res.status };
    } catch {
      return { ok: false };
    }
  };

  const decideConversationRequest = async (
    item: any,
    decision: "accept" | "reject",
  ) => {
    setDecidingRequest(item.request_id);
    try {
      const res = await apiFetch(
        `/api/conversations/requests/${item.request_id}/${decision}`,
        { method: "POST" },
      );
      if (!res.ok)
        throw new Error(await responseError(res, "Failed to update conversation request"));
      await loadConversationRequests();
      if (decision === "reject") {
        setInfoMsg("Request declined.");
        return;
      }
      const peer = item.requester_public_uid || item.requester_username;
      try {
        await establishSession(peer);
        setShowRequests(false);
        setInfoMsg(`You're connected with ${item.requester_username}.`);
      } catch {
        // Accepted on the relay; keep retrying the session in the background.
        pendingInvitesRef.current.add(peer);
        setInfoMsg(
          "Accepted. Setting up the secure session; this retries automatically.",
        );
      }
    } catch (error: any) {
      setErrorMsg(error.message || "Failed to update conversation request");
    } finally {
      setDecidingRequest(null);
    }
  };

  const loadMessages = async (contactId: string) => {
    const epoch=vaultEpochRef.current;
    try {
      const res = await apiFetch(`/api/messages/${contactId}`);
      if (res.ok) {
        const data = await res.json();
        if (epoch===vaultEpochRef.current&&selectedConversationRef.current === contactId) {
          for (const [key, local] of optimisticRef.current)
            if (data.some((m: any) => m.message_id === local.message_id))
              optimisticRef.current.delete(key);
          setMessages([
            ...data,
            ...[...optimisticRef.current.values()].filter(
              (m) => m.conversation_id === contactId,
            ),
          ]);
        }
      }
    } catch {
      console.error("Failed to load messages");
    }
  };

  const syncMessages = (): Promise<{ ok: boolean; status?: number }> => {
    if (syncInFlightRef.current) return syncInFlightRef.current;
    const epoch=vaultEpochRef.current;
    const operation = (async () => {
      try {
        const requestedConversation = selectedConversationRef.current;
        const res = await apiFetch("/api/fetch-messages", {
          method: "POST",
          body: JSON.stringify({
            conversationId: requestedConversation || undefined,
          }),
        });
        if (!res.ok) return { ok: false, status: res.status };
        const data = await res.json();
        if(epoch!==vaultEpochRef.current)return {ok:false};
        setPeerTyping(!!data.typing);
        const conversation = selectedConversationRef.current;
        if (
          conversation &&
          data.conversationId === conversation &&
          Array.isArray(data.messages)
        ) {
          for (const [key, local] of optimisticRef.current)
            if (
              data.messages.some((m: any) => m.message_id === local.message_id)
            )
              optimisticRef.current.delete(key);
          setMessages([
            ...data.messages,
            ...[...optimisticRef.current.values()].filter(
              (m) => m.conversation_id === conversation,
            ),
          ]);
        } else if (conversation) await loadMessages(conversation);
        if (data.received > 0) void loadContacts();
        if (data.sent > 0)
          setInfoMsg((current) =>
            current === queuedMessageNotice ? null : current,
          );
        return { ok: true, status: res.status };
      } catch {
        return { ok: false };
      }
    })();
    syncInFlightRef.current = operation;
    void operation.finally(() => {
      if (syncInFlightRef.current === operation) syncInFlightRef.current = null;
    });
    return operation;
  };

  const control=async(type:string)=>{
    const conversationId=selectedConversationRef.current;
    if(!conversationId||quickLocked||document.visibilityState!=="visible")return;
    await apiFetch("/api/control",{method:"POST",body:JSON.stringify({conversationId,type})}).catch(()=>{});
  };
  useEffect(()=>{
    if(quickLocked||!selectedContact||document.visibilityState!=="visible"||(isMobile&&mobilePane!=="chat"))return;
    const received=messages.filter(m=>m.direction==="received");
    const fresh=received.filter(m=>!incomingSeen.current.has(m.message_id));
    received.forEach(m=>incomingSeen.current.add(m.message_id));
    if(fresh.length)haptic();
    const latest=received.at(-1)?.message_id;
    if(latest&&latest!==lastRead.current){lastRead.current=latest;void control("read_receipt");}
  },[messages,selectedContact?.conversation_id,mobilePane,quickLocked]);
  useEffect(()=>{if(!peerTyping)return;const t=setTimeout(()=>setPeerTyping(false),5000);return()=>clearTimeout(t);},[peerTyping]);
  const quickLock=async()=>{
    if(mediaRecorderRef.current?.state==="recording"){setErrorMsg("Finish your voice note before locking");return;}
    const r=await apiFetch("/api/session/lock",{method:"POST"});
    if(r.ok){setQuickLocked(true);setInputText("");setPin("");setShowSettings(false);setShowIdentity(false);setShowAddContact(false);setShowSafety(false);setShowRequests(false);setShowTimer(false);}
    else if(r.status===409){setPin("");setPinConfirm("");setShowPin(true);}
    else setErrorMsg("Could not quick lock");
  };
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !selectedContact || sendingRef.current) return;
    haptic();
    sendingRef.current = true;
    setSending(true);
    const conversationId = selectedContact.conversation_id,
      submittedText = inputText;
    const localId = "optimistic-" + crypto.randomUUID();
    const optimistic = {
      message_id: localId,
      conversation_id: conversationId,
      direction: "sent",
      plaintext: submittedText,
      sent_at: Date.now(),
      status: "sending",
    };
    optimisticRef.current.set(localId, optimistic);
    setInputText("");
    setMessages((current) => [...current, optimistic]);
    try {
      const res = await apiFetch("/api/send", {
        method: "POST",
        body: JSON.stringify({
          conversationId,
          plaintext: submittedText,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        if (result.status === "queued") setInfoMsg(queuedMessageNotice);
        if (result.backupSynced === false)
          setErrorMsg(
            "Message saved, but cloud backup did not sync. Retry backup in Settings.",
          );
        const delivered = {
          ...optimistic,
          message_id: result.messageId,
          status: result.status,
        };
        optimisticRef.current.set(localId, delivered);
        if (selectedConversationRef.current === conversationId)
          setMessages((current) =>
            current.map((m) => (m.message_id === localId ? delivered : m)),
          );
        await loadMessages(conversationId);
      } else {
        const data = await res.json();
        optimisticRef.current.delete(localId);
        if (selectedConversationRef.current === conversationId) {
          setMessages((current) =>
            current.filter((m) => m.message_id !== localId),
          );
          setInputText((current) => current || submittedText);
        }
        setErrorMsg(errorMessage(data.error || "Failed to send message"));
      }
    } catch {
      optimisticRef.current.delete(localId);
      if (selectedConversationRef.current === conversationId) {
        setMessages((current) =>
          current.filter((m) => m.message_id !== localId),
        );
        setInputText((current) => current || submittedText);
      }
      setErrorMsg(
        "Send could not be confirmed. Check the conversation before retrying; your draft is restored.",
      );
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  };

  const sendAttachment = async (
    file: Blob,
    filename: string,
    mimeType: string,
    conversationId: string,
  ) => {
    if (uploadRef.current) return;
    if (file.size > 25 * 1024 * 1024) {
      setErrorMsg("Attachments must be 25 MiB or smaller");
      return;
    }
    uploadRef.current = true;
    setUploading(true);
    setErrorMsg(null);
    try {
      setInfoMsg("Encrypting and uploading…");
      const bytes = new Uint8Array(await file.arrayBuffer()),
        parts: string[] = [];
      for (let i = 0; i < bytes.length; i += 32768)
        parts.push(String.fromCharCode(...bytes.subarray(i, i + 32768)));
      const encrypted = await apiFetch("/api/attachments/encrypt", {
        method: "POST",
        body: JSON.stringify({
          filedataB64: btoa(parts.join("")),
          filename,
          mimeType: mimeType || "application/octet-stream",
        }),
      });
      if (!encrypted.ok)
        throw new Error(await responseError(encrypted, "File upload failed"));
      const attachmentManifest = await encrypted.json();
      const sent = await apiFetch("/api/send", {
        method: "POST",
        body: JSON.stringify({
          conversationId,
          plaintext: mimeType.startsWith("audio/")
            ? "Voice note"
            : `Sent an attachment: ${filename}`,
          attachmentManifest,
        }),
      });
      if (!sent.ok)
        throw new Error(
          await responseError(
            sent,
            "File uploaded but message failed. Please retry.",
          ),
        );
      const result = await sent.json();
      setInfoMsg(result.status === "queued" ? queuedMessageNotice : null);
      if (result.backupSynced === false)
        setErrorMsg(
          "File saved, but backup did not sync. Retry backup in Settings.",
        );
      await loadMessages(conversationId);
    } catch (error: any) {
      setErrorMsg(error.message || "Attachment failed. Please retry.");
      setInfoMsg(null);
    } finally {
      uploadRef.current = false;
      setUploading(false);
    }
  };
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (file && selectedContact)
      await sendAttachment(
        file,
        file.name,
        file.type,
        selectedContact.conversation_id,
      );
  };
  const startRecording = async (hold = false) => {
    if (!selectedContact || uploadRef.current || isRecording) return;
    const conversationId = selectedContact.conversation_id;
    recordingCancelledRef.current=false;
    let stream: MediaStream | undefined;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      if (hold && !recordingHeldActiveRef.current) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      const supported=['audio/webm;codecs=opus','audio/webm','audio/ogg;codecs=opus','audio/mp4'].find(type=>MediaRecorder.isTypeSupported(type));
      const recorder = new MediaRecorder(stream,supported?{mimeType:supported}:undefined);
      mediaRecorderRef.current = recorder;
      audioChunksRef.current = [];
      recorder.ondataavailable = (event) => {
        if (event.data.size) audioChunksRef.current.push(event.data);
      };
      recorder.onstop = async () => {
        haptic();
        stream?.getTracks().forEach((track) => track.stop());
        setIsRecording(false);
        const blob = new Blob(audioChunksRef.current, {
          type: recorder.mimeType || "audio/webm",
        });
        if (!recordingCancelledRef.current&&selectedConversationRef.current === conversationId && blob.size)
          await sendAttachment(
            blob,
            blob.type.startsWith('audio/mp4')?'voice-note.m4a':blob.type.startsWith('audio/ogg')?'voice-note.ogg':'voice-note.webm',
            blob.type,
            conversationId,
          );
      };
      recorder.onerror = () => {
        stream?.getTracks().forEach((track) => track.stop());
        setIsRecording(false);
        setErrorMsg("Recording failed. Try again.");
      };
      haptic();
      recorder.start();
      recordingStartRef.current = Date.now();
      setRecordingSeconds(0);
      setIsRecording(true);
    } catch {
      stream?.getTracks().forEach((track) => track.stop());
      setErrorMsg(
        "Microphone unavailable. Allow microphone access in app settings and try again.",
      );
    }
  };
  const stopRecording = () => {
    if (mediaRecorderRef.current?.state === "recording")
      mediaRecorderRef.current.stop();
  };

  const chatOpen = !!selectedContact && (!isMobile || mobilePane === "chat");
  useBackAction(showTimer,()=>setShowTimer(false),50);
  useBackAction(isRecording,()=>{recordingCancelledRef.current=true;recordingHeldActiveRef.current=false;stopRecording();},75);
  useBackAction(isMobile&&chatOpen&&vaultState==='unlocked'&&!quickLocked,()=>{setMobilePane('contacts');setShowTimer(false);},10);
  useBackAction(!!contactSearch&&!chatOpen&&vaultState==='unlocked'&&!quickLocked,()=>setContactSearch(''),5);
  const filteredContacts = contacts.filter(
    (contact) =>
      !contactSearch ||
      [contact.username, contact.displayName, contact.publicUid].some((v) =>
        v?.toLowerCase().includes(contactSearch.toLowerCase()),
      ),
  );
  const timers = [
    [0, "Off"],
    [3600, "1 hour"],
    [86400, "24 hours"],
    [604800, "7 days"],
  ] as const;
  const timerLabel =
    (
      { 0: "Off", 3600: "1h", 86400: "24h", 604800: "7d" } as Record<
        number,
        string
      >
    )[timer] || "Custom";
  const changeTimer = async (seconds: number) => {
    if (!selectedContact || timerBusy) return;
    const conversationId = selectedContact.conversation_id;
    setTimerBusy(true);
    try {
      const r = await apiFetch(
        "/api/conversations/" + conversationId + "/timer",
        { method: "POST", body: JSON.stringify({ seconds }) },
      );
      if (!r.ok) throw new Error("Could not update disappearing timer");
      setContacts((current) =>
        current.map((c) =>
          c.conversation_id === conversationId
            ? { ...c, disappearing_seconds: seconds }
            : c,
        ),
      );
      if (selectedConversationRef.current === conversationId) {
        setTimer(seconds);
        setSelectedContact((c: any) => ({
          ...c,
          disappearing_seconds: seconds,
        }));
      }
      setShowTimer(false);
    } catch (e: any) {
      setErrorMsg(e.message || "Could not update disappearing timer");
    } finally {
      setTimerBusy(false);
    }
  };

  const relayText = !transportInfo?"Checking connection…":transportInfo.mode!=="RELAY_ONLY"?(transportInfo.serverless?"Direct Tor Onion P2P":`Tor connecting ${transportInfo.bootstrapPercent}%`):
    relayStatus === "online"
      ? "Up to date"
      : relayStatus === "offline"
        ? "Relay unreachable · retrying"
        : "Connecting to relay…";
  const contactName = (c: any) => c?.displayName || c?.username || "";

  if (quickLocked)
    return (
      <main className="session-screen">
        <Brand />
        <motion.div
          className="session-card glass-panel"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={spring}
        >
          <span className="lock-emblem">
            <KeyRound size={26} />
          </span>
          <h1>Screen locked</h1>
          <p>Your vault is still open. Enter your 4-digit PIN to continue.</p>
          <form
            className="stack"
            onSubmit={async (e) => {
              e.preventDefault();
              const r = await apiFetch("/api/session/unlock", {
                method: "POST",
                body: JSON.stringify({ pin }),
              });
              setPin("");
              if (r.ok) {
                setQuickLocked(false);
                setErrorMsg(null);
                lastRead.current = "";
                void bootstrapSession();
              } else
                setErrorMsg(
                  r.status === 429
                    ? "Too many attempts. Try again in 30 seconds."
                    : "Incorrect PIN.",
                );
            }}
          >
            <input
              aria-label="Session PIN"
              type="password"
              inputMode="numeric"
              pattern="[0-9]{4}"
              maxLength={4}
              autoComplete="off"
              autoFocus
              className="glass-input pin-input"
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/[^0-9]/g, ""))}
            />
            <button className="btn-primary" disabled={pin.length !== 4}>
              Unlock screen
            </button>
          </form>
          {errorMsg && (
            <p role="alert" className="inline-warning">
              {errorMsg}
            </p>
          )}
          <div className="session-alt">
            <p>Forgot your PIN? Fully lock the vault, then open it with your Vault ID and passphrase.</p>
            <button
              className="btn-secondary danger"
              disabled={busy}
              onClick={handleLockVault}
            >
              <LockKeyhole size={16} /> Fully lock vault
            </button>
          </div>
        </motion.div>
      </main>
    );
  return (
    <div className="app-root">
      <AnimatePresence>
        {(errorMsg || infoMsg) && (
          <motion.div
            key={errorMsg ? "error" : "info"}
            role={errorMsg ? "alert" : "status"}
            className={`app-toast ${errorMsg ? "error-toast" : ""}`}
            initial={{ opacity: 0, y: -16, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -16 }}
            transition={spring}
          >
            {errorMsg ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
            <span>{errorMsg || infoMsg}</span>
            <button
              className="icon-button"
              aria-label="Dismiss notification"
              onClick={() => (errorMsg ? setErrorMsg(null) : setInfoMsg(null))}
            >
              <X size={17} />
            </button>
          </motion.div>
        )}
      </AnimatePresence>
      {vaultState === "bootstrapping" && (
        <div className="session-loader">
          <Brand />
          <Loader2 size={22} className="spin" />
          <p>Opening your private space…</p>
        </div>
      )}
      {sessionUnavailable ? (
        <main className="reconnect">
          <Brand />
          <div className="lock-emblem">
            <Network size={26} />
          </div>
          <h1>Let's reconnect.</h1>
          <p>
            The vault service on this device isn't responding. Reopen the app
            and try again. Your data has not been touched.
          </p>
          <button
            className="btn-primary"
            onClick={() => void bootstrapSession()}
          >
            Try again <ArrowUpRight size={17} />
          </button>
        </main>
      ) : (
        (vaultState === "unconfigured" || vaultState === "locked") && (
          <VaultGate
            state={vaultState}
            status={fragmentStatus}
            requiresVaultId={requiresVaultId}
            multipleVaults={multipleVaults}
            busy={busy}
            submit={submitVault}
            restoreRequired={restoreRequired}
            relayUrl={relayUrl}
            saveRelay={saveRelay}
            pendingCreation={pendingCreation}
            finishCreation={finishCreation}
            selectStorage={selectStorage}
            storageSelected={storageSelected}
            onError={setErrorMsg}
          />
        )
      )}
      {vaultState === "unlocked" && !quickLocked && (
        <main className={`messenger ${chatOpen ? "has-chat" : ""}`}>
          <aside
            className="contact-sidebar"
            aria-label="Inbox"
            aria-hidden={isMobile && chatOpen}
            inert={isMobile && chatOpen}
          >
            <header className="inbox-topbar">
              <Brand onClick={storageLogo}/>
              <div className="header-actions">
                <button
                  type="button"
                  className="icon-button"
                  aria-label="New connection"
                  title="New connection"
                  onClick={() => setShowAddContact(true)}
                >
                  <UserPlus size={19} />
                </button>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Lock screen with PIN"
                  title="Lock screen with PIN (vault stays open)"
                  onClick={quickLock}
                >
                  <KeyRound size={18} />
                </button>
                <button
                  type="button"
                  disabled={busy}
                  className="icon-button danger-icon"
                  aria-label="Fully lock vault"
                  title="Fully lock vault (needs Vault ID and passphrase to reopen)"
                  onClick={handleLockVault}
                >
                  {busy ? (
                    <Loader2 size={18} className="spin" />
                  ) : (
                    <LockKeyhole size={18} />
                  )}
                </button>
              </div>
            </header>
            <div className="inbox-heading">
              <h1>Chats</h1>
              <span
                className={`relay-pill ${relayStatus}`}
                role="status"
                aria-label={`Connection status: ${relayText}`}
              >
                <span className={`relay-dot ${relayStatus}`} />
                {relayText}
              </span>
            </div>
            <label className="conversation-search">
              <Search size={18} />
              <input
                aria-label="Search conversations"
                placeholder="Search by name or UID"
                value={contactSearch}
                onChange={(e) => setContactSearch(e.target.value)}
              />
            </label>
            {registrationState !== "success" && (
              <button
                className="registration-prompt"
                onClick={() => setShowSettings(true)}
              >
                <span className="prompt-icon">
                  <Shield size={18} />
                </span>
                <span>
                  {registrationState === "pending"
                    ? "Finish setting up your identity"
                    : "Choose your username"}
                  <small>So people can find and message you</small>
                </span>
                <ArrowUpRight size={17} />
              </button>
            )}
            <div className="list-label">
              <span>Conversations</span>
              <span className="contact-count">{contacts.length}</span>
            </div>
            <div className="contact-list">
              {filteredContacts.length ? (
                filteredContacts.map((contact) => (
                  <motion.button
                    type="button"
                    key={contact.contact_id}
                    whileTap={{ scale: 0.985 }}
                    transition={spring}
                    className={`contact-row ${selectedContact?.contact_id === contact.contact_id ? "active" : ""}`}
                    onClick={() => {
                      setSelectedContact(contact);
                      setMobilePane("chat");
                      setShowTimer(false);
                    }}
                  >
                    <Avatar name={contactName(contact)} />
                    <span className="contact-copy">
                      <span className="contact-name">
                        <span className="contact-label">
                          {contactName(contact)}
                        </span>
                        {contact.identity_changed === 1 ? (
                          <AlertTriangle
                            size={14}
                            className="danger"
                            aria-label="Safety number changed"
                          />
                        ) : contact.verified ? (
                          <ShieldCheck
                            size={14}
                            className="verified"
                            aria-label="Verified"
                          />
                        ) : null}
                      </span>
                      <span
                        className={`contact-preview ${contact.identity_changed === 1 ? "danger" : ""}`}
                      >
                        {contact.identity_changed === 1
                          ? "Safety number changed · tap to review"
                          : contact.statusLine || `@${contact.username}`}
                      </span>
                    </span>
                    {contact.disappearing_seconds > 0 && (
                      <Clock3
                        size={14}
                        className="row-timer"
                        aria-label="Disappearing messages on"
                      />
                    )}
                  </motion.button>
                ))
              ) : (
                <div className="inbox-empty">
                  <div className="empty-orbit">
                    <MessageSquare size={28} strokeWidth={1.4} />
                  </div>
                  <h3>
                    {contactSearch
                      ? "No conversations found"
                      : "No conversations yet"}
                  </h3>
                  <p>
                    {contactSearch
                      ? "Try another name or public UID."
                      : "Invite someone with their public UID or QR code to start a private conversation."}
                  </p>
                  {!contactSearch && (
                    <button
                      className="btn-primary"
                      onClick={() => setShowAddContact(true)}
                    >
                      <UserPlus size={17} /> New connection
                    </button>
                  )}
                </div>
              )}
            </div>
            <nav className="bottom-dock" aria-label="Main navigation">
              {[
                {
                  name: "Chats",
                  icon: MessageSquare,
                  action: () => {
                    setMobilePane("contacts");
                    setShowIdentity(false);
                    setShowRequests(false);
                    setShowSettings(false);
                  },
                  active: !showIdentity && !showRequests && !showSettings,
                },
                {
                  name: "My QR",
                  icon: QrCode,
                  action: () => setShowIdentity(true),
                  active: showIdentity,
                },
                {
                  name: "Requests",
                  icon: Inbox,
                  action: () => setShowRequests(true),
                  active: showRequests,
                },
                {
                  name: "Settings",
                  icon: Settings,
                  action: () => setShowSettings(true),
                  active: showSettings,
                },
              ].map((item) => (
                <motion.button
                  type="button"
                  key={item.name}
                  whileTap={{ scale: 0.94 }}
                  className={item.active ? "active" : ""}
                  aria-label={
                    item.name === "Requests" && incomingRequests.length
                      ? `Requests, ${incomingRequests.length} new`
                      : item.name
                  }
                  aria-current={item.active ? "page" : undefined}
                  onClick={item.action}
                >
                  {item.active && (
                    <motion.span
                      className="dock-indicator"
                      layoutId="dock-active"
                      transition={spring}
                    />
                  )}
                  <span className="dock-icon">
                    <item.icon size={20} strokeWidth={1.8} />
                    {item.name === "Requests" &&
                      incomingRequests.length > 0 && (
                        <b className="request-badge">
                          {incomingRequests.length}
                        </b>
                      )}
                  </span>
                  <span aria-hidden="true">{item.name}</span>
                </motion.button>
              ))}
            </nav>
          </aside>
          <AnimatePresence initial={false}>
            {(!isMobile || chatOpen) && (
              <motion.section
                key={isMobile ? "mobile-thread" : "desktop-thread"}
                className="chat-thread"
                aria-label="Conversation"
                initial={reducedMotion?false:isMobile ? { x: "100%" } : { opacity: 0 }}
                animate={isMobile ? { x: 0 } : { opacity: 1 }}
                exit={isMobile ? { x: reducedMotion?0:"100%" } : { opacity: 0 }}
                transition={reducedMotion?{duration:0}:pageTransition}
              >
                {selectedContact ? (
                  <>
                    <header className="thread-header">
                      <button
                        type="button"
                        className="icon-button mobile-back"
                        aria-label="Back to conversations"
                        onClick={() => {
                          setMobilePane("contacts");
                          setShowTimer(false);
                        }}
                      >
                        <ChevronLeft size={24} />
                      </button>
                      <Avatar name={contactName(selectedContact)} />
                      <button
                        type="button"
                        className="thread-person"
                        aria-label={`${contactName(selectedContact)}: view safety number`}
                        onClick={() => setShowSafety(true)}
                      >
                        <strong>{contactName(selectedContact)}</strong>
                        <span>
                          {selectedContact.identity_changed === 1 ? (
                            <span className="verify-chip danger">
                              <AlertTriangle size={11} /> Review identity
                            </span>
                          ) : selectedContact.verified ? (
                            <span className="verify-chip verified">
                              <ShieldCheck size={11} /> Verified
                            </span>
                          ) : (
                            <span className="verify-chip">
                              <Shield size={11} /> Not verified
                            </span>
                          )}
                          <code>
                            {selectedContact.publicUid || `@${selectedContact.username}`}
                          </code>
                        </span>
                      </button>
                      <div className="timer-control">
                        <button
                          type="button"
                          className={`timer-pill ${timer ? "enabled" : ""}`}
                          aria-label={`Disappearing message timer: ${timerLabel}`}
                          aria-haspopup="menu"
                          aria-expanded={showTimer}
                          onClick={() => setShowTimer(!showTimer)}
                        >
                          <Clock3 size={15} />
                          <span>{timerLabel}</span>
                          <ChevronDown size={13} />
                        </button>
                        <AnimatePresence>
                          {showTimer && (
                            <>
                              <button
                                tabIndex={-1}
                                className="popover-dismiss"
                                aria-label="Close timer menu"
                                onClick={() => setShowTimer(false)}
                              />
                              <motion.div
                                className="timer-menu"
                                role="menu"
                                aria-label="Disappearing messages"
                                initial={{ opacity: 0, y: -4 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -4 }}
                                transition={reducedMotion?{duration:0}:{duration:0.14}}
                              >
                                <span className="menu-title">
                                  Disappearing messages
                                </span>
                                {timers.map(([seconds, label]) => (
                                  <button
                                    type="button"
                                    role="menuitemradio"
                                    aria-checked={timer === seconds}
                                    disabled={timerBusy}
                                    key={seconds}
                                    onClick={() => void changeTimer(seconds)}
                                  >
                                    <Clock3 size={15} />
                                    <span>{label}</span>
                                    {timer === seconds && <Check size={15} />}
                                  </button>
                                ))}
                                <p>Applies to new messages in this chat.</p>
                              </motion.div>
                            </>
                          )}
                        </AnimatePresence>
                      </div>
                    </header>
                    {selectedContact.identity_changed === 1 && (
                      <div className="identity-warning" role="alert">
                        <AlertTriangle size={20} />
                        <p>
                          <strong>
                            {contactName(selectedContact)}'s safety number
                            changed.
                          </strong>{" "}
                          New messages are blocked until you check it with them.
                        </p>
                        <button
                          className="text-button"
                          onClick={() => setShowSafety(true)}
                        >
                          Review
                        </button>
                      </div>
                    )}
                    <div className="message-list" ref={messageListRef}>
                      <div className="thread-intro">
                        <LockKeyhole size={13} />
                        <span>
                          Messages are end-to-end encrypted. Only you and{" "}
                          {contactName(selectedContact)} can read them.
                        </span>
                      </div>
                      {!messages.length && (
                        <div className="chat-empty">
                          <Avatar name={contactName(selectedContact)} large />
                          <h2>Say hello to {contactName(selectedContact)}</h2>
                          <p>
                            {selectedContact.statusLine ||
                              "Your first message starts the conversation."}
                          </p>
                        </div>
                      )}
                      {messages.map((msg, index) => {
                        const timestamp = msg.sent_at || msg.received_at;
                        const date = timestamp ? new Date(timestamp) : null;
                        const previous = messages[index - 1];
                        const showDate =
                          date &&
                          (!previous ||
                            new Date(
                              previous.sent_at || previous.received_at,
                            ).toDateString() !== date.toDateString());
                        return (
                          <React.Fragment key={msg.message_id}>
                            {showDate && (
                              <div className="date-divider">
                                <span>
                                  {date.toLocaleDateString(undefined, {
                                    weekday: "short",
                                    month: "short",
                                    day: "numeric",
                                  })}
                                </span>
                              </div>
                            )}
                            <MessageBubble msg={msg} enter={index===messages.length-1&&scrolledConversationRef.current===selectedContact?.conversation_id} />
                          </React.Fragment>
                        );
                      })}
                      {peerTyping && <TypingIndicator />}
                      <div ref={messagesEndRef} />
                    </div>
                    <div className="composer-area">
                      <AnimatePresence>
                        {isRecording && (
                          <motion.div
                            role="status"
                            className="recording-overlay"
                            initial={{ opacity: 0, y: 12 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: 12 }}
                            transition={spring}
                          >
                            <span className="record-dot" />
                            <span>Recording</span>
                            <Waveform active />
                            <span className="mono">
                              {Math.floor(recordingSeconds / 60)}:
                              {String(recordingSeconds % 60).padStart(2, "0")}
                            </span>
                            <span className="recording-hint">Tap stop to send</span>
                          </motion.div>
                        )}
                      </AnimatePresence>
                      <form onSubmit={handleSendMessage} className="composer">
                        <button
                          type="button"
                          className="icon-button attach-button"
                          disabled={uploading || isRecording}
                          aria-label="Send attachment"
                          onClick={() => fileInputRef.current?.click()}
                        >
                          {uploading ? (
                            <Loader2 className="spin" size={20} />
                          ) : (
                            <Plus size={22} strokeWidth={1.8} />
                          )}
                        </button>
                        <input
                          type="file"
                          ref={fileInputRef}
                          className="visually-hidden"
                          tabIndex={-1}
                          onChange={handleFileUpload}
                        />
                        <textarea
                          rows={1}
                          aria-label="Message"
                          placeholder={
                            isRecording ? "Recording your voice…" : "Message"
                          }
                          disabled={isRecording}
                          onKeyDown={(e) => {
                            if (
                              e.key === "Enter" &&
                              !e.shiftKey &&
                              !e.nativeEvent.isComposing
                            ) {
                              e.preventDefault();
                              e.currentTarget.form?.requestSubmit();
                            }
                          }}
                          value={inputText}
                          onChange={(e) => {
                            setInputText(e.target.value);
                            if(e.target.value.trim()&&Date.now()-lastTyping.current>2500){lastTyping.current=Date.now();void control("typing");}
                            e.target.style.height = "auto";
                            e.target.style.height =
                              Math.min(e.target.scrollHeight, 140) + "px";
                          }}
                        />
                        <AnimatePresence mode="popLayout" initial={false}>
                          {inputText.trim() && !isRecording ? (
                            <motion.button
                              key="send"
                              type="submit"
                              disabled={sending || uploading}
                              aria-label="Send message"
                              className="send-button"
                              initial={{ opacity: 0, scale: 0.7 }}
                              animate={{ opacity: 1, scale: 1 }}
                              exit={{ opacity: 0, scale: 0.7 }}
                              whileTap={{ scale: 0.9 }}
                              transition={spring}
                            >
                              {sending ? (
                                <Loader2 className="spin" size={18} />
                              ) : (
                                <ArrowUp size={20} strokeWidth={2.6} />
                              )}
                            </motion.button>
                          ) : (
                            <motion.button
                              key="mic"
                              type="button"
                              className={`mic-button ${isRecording ? "recording" : ""}`}
                              aria-label={
                                isRecording
                                  ? "Stop and send voice note"
                                  : "Record voice note"
                              }
                              disabled={uploading}
                              initial={{ opacity: 0, scale: 0.7 }}
                              animate={{ opacity: 1, scale: 1 }}
                              exit={{ opacity: 0, scale: 0.7 }}
                              whileTap={{ scale: 0.9 }}
                              transition={spring}
                              onPointerDown={(e) => {
                                if (e.button !== 0 || isRecording) return;
                                heldRecordingRef.current = false;
                                holdRef.current = window.setTimeout(() => {
                                  heldRecordingRef.current = true;
                                  recordingHeldActiveRef.current = true;
                                  void startRecording(true);
                                }, 300);
                                e.currentTarget.setPointerCapture(e.pointerId);
                              }}
                              onPointerUp={() => {
                                clearTimeout(holdRef.current);
                                recordingHeldActiveRef.current = false;
                                if (heldRecordingRef.current) stopRecording();
                              }}
                              onPointerCancel={() => {
                                clearTimeout(holdRef.current);
                                recordingHeldActiveRef.current = false;
                                if (heldRecordingRef.current) stopRecording();
                              }}
                              onClick={() => {
                                if (heldRecordingRef.current) {
                                  heldRecordingRef.current = false;
                                  return;
                                }
                                void (isRecording
                                  ? stopRecording()
                                  : startRecording());
                              }}
                            >
                              {isRecording ? (
                                <Square size={15} fill="currentColor" />
                              ) : (
                                <Mic size={20} />
                              )}
                            </motion.button>
                          )}
                        </AnimatePresence>
                      </form>
                      <span className="composer-footnote">
                        {uploading
                          ? "Encrypting attachment…"
                          : "Enter to send · Shift+Enter for a new line"}
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="studio-empty">
                    <div className="studio-welcome">
                      <span className="empty-orbit">
                        <MessageSquare size={30} strokeWidth={1.6} />
                      </span>
                      <h2>No conversation selected</h2>
                      <p>
                        Pick a conversation on the left, or invite someone new.
                      </p>
                      <button
                        className="btn-secondary"
                        onClick={() => setShowAddContact(true)}
                      >
                        <UserPlus size={17} /> New connection
                      </button>
                    </div>
                    <PrivacyNote />
                  </div>
                )}
              </motion.section>
            )}
          </AnimatePresence>
        </main>
      )}
      <Sheet
        open={showIdentity && vaultState === "unlocked" && !quickLocked}
        onClose={() => setShowIdentity(false)}
        title="Your identity"
        eyebrow="Share to connect"
      >
        <UidBadge uid={publicUid} api={apiFetch} />
        {!publicUid ? (
          <button
            className="btn-primary"
            onClick={() => {
              setShowIdentity(false);
              setShowSettings(true);
            }}
          >
            Choose your username <ArrowUpRight size={16} />
          </button>
        ) : (
          <div className="sheet-group">
            <h3 className="group-title">Add someone</h3>
            <p className="field-help">
              Scan their signed QR to pin their keys on this device. Exchange
              invites in person or through a channel where you know who sent it.
            </p>
            <PeerScanner onPeer={sendInvitation} />
          </div>
        )}
      </Sheet>
      <Sheet
        open={showRequests && vaultState === "unlocked" && !quickLocked}
        onClose={() => setShowRequests(false)}
        title="Connection requests"
        eyebrow={
          incomingRequests.length
            ? `${incomingRequests.length} waiting`
            : "Requests"
        }
      >
        <p>
          Only accept people you recognize. Accepting opens a private
          conversation with them.
        </p>
        {incomingRequests.length ? (
          incomingRequests.map((item) => (
            <div className="request-card" key={item.request_id}>
              <div className="request-person">
                <Avatar name={item.requester_username} />
                <span>
                  <strong>{item.requester_username}</strong>
                  <code>{item.requester_public_uid}</code>
                </span>
              </div>
              <div className="request-actions">
                <button
                  className="btn-secondary"
                  disabled={!!decidingRequest}
                  onClick={() => void decideConversationRequest(item, "reject")}
                >
                  Decline
                </button>
                <button
                  className="btn-primary"
                  disabled={!!decidingRequest}
                  onClick={() => void decideConversationRequest(item, "accept")}
                >
                  {decidingRequest === item.request_id ? (
                    <>
                      <Loader2 size={16} className="spin" /> Connecting…
                    </>
                  ) : (
                    <>
                      Accept <Check size={16} />
                    </>
                  )}
                </button>
              </div>
            </div>
          ))
        ) : (
          <div className="sheet-empty">
            <span className="empty-orbit">
              <Inbox size={28} strokeWidth={1.4} />
            </span>
            <h3>No requests right now</h3>
            <p>When someone invites you, their request appears here.</p>
          </div>
        )}
      </Sheet>
      <Sheet
        open={showAddContact && vaultState === "unlocked" && !quickLocked}
        onClose={() => setShowAddContact(false)}
        title="New connection"
        eyebrow="Invite someone"
      >
        <form onSubmit={handleAddContact} className="stack">
          <label className="field-label">
            Signed invite link (or relay username)
            <input
              type="text"
              required
              autoCapitalize="none"
              autoComplete="off"
              spellCheck={false}
              placeholder="pigeon://invite?v=2&…"
              className="glass-input"
              value={newContactUsername}
              onChange={(e) => setNewContactUsername(e.target.value)}
            />
          </label>
          <button
            type="button"
            disabled={!newContactUsername.trim()}
            className="btn-primary"
            onClick={handleConversationRequest}
          >
            {newContactUsername.startsWith('pigeon://')?'Import signed invite':'Send relay request'} <ArrowUpRight size={17} />
          </button>
          <p className="field-help">
            For serverless messaging, both people import each other's signed invite.
          </p>
          <details className="settings-subsection">
            <summary>They already accepted?</summary>
            <p>
              Open the conversation now instead of waiting for it to appear.
            </p>
            <button
              type="submit"
              className="btn-secondary"
              disabled={!newContactUsername.trim()}
            >
              Open conversation <MessageSquare size={16} />
            </button>
          </details>
        </form>
        <div className="sheet-group">
          <h3 className="group-title">Or scan their QR code</h3>
          <PeerScanner onPeer={sendInvitation} />
        </div>
      </Sheet>
      <Sheet
        open={showSafety && !!selectedContact && vaultState === "unlocked" && !quickLocked}
        onClose={() => setShowSafety(false)}
        title="Safety number"
        eyebrow={`Verify ${contactName(selectedContact)}`}
      >
        <div className="safety-person">
          <Avatar name={contactName(selectedContact)} />
          <span>
            <strong>{contactName(selectedContact)}</strong>
            <code>{selectedContact?.publicUid || `@${selectedContact?.username}`}</code>
          </span>
          {selectedContact?.identity_changed === 1 ? (
            <span className="verify-chip danger">
              <AlertTriangle size={12} /> Changed
            </span>
          ) : selectedContact?.verified ? (
            <span className="verify-chip verified">
              <ShieldCheck size={12} /> Verified
            </span>
          ) : (
            <span className="verify-chip">Not verified</span>
          )}
        </div>
        {selectedContact?.identity_changed === 1 ? (
          <div className="identity-help">
            <p>
              <strong>Why did this change?</strong> Usually because{" "}
              {contactName(selectedContact)} reinstalled the app or moved to a
              new device. Rarely, it can mean someone is trying to intercept
              your messages.
            </p>
            <p>
              <strong>What to do:</strong> contact them another way (in person
              or a phone call) and ask whether they changed devices. Until this
              is resolved, the old secure session is kept and the new identity
              is blocked.
            </p>
          </div>
        ) : (
          <ol className="safety-steps">
            <li>Meet in person or call {contactName(selectedContact)}.</li>
            <li>Compare the numbers below with the ones on their screen.</li>
            <li>If every block matches, confirm below.</li>
          </ol>
        )}
        <div className="safety-number">
          {selectedContact?.safety_number_hash ? (
            String(selectedContact.safety_number_hash)
              .match(/.{1,4}/g)
              ?.map((block, i) => <code key={i}>{block}</code>)
          ) : (
            <p>Available once your secure session is set up.</p>
          )}
        </div>
        <button
          disabled={
            !selectedContact?.safety_number_hash ||
            selectedContact?.identity_changed === 1
          }
          className="btn-primary"
          onClick={async () => {
            try {
              const r = await apiFetch(
                "/api/contacts/" +
                  encodeURIComponent(selectedContact.contact_id) +
                  "/verify",
                {
                  method: "POST",
                  body: JSON.stringify({
                    safetyNumber: selectedContact.safety_number_hash,
                  }),
                },
              );
              if (r.ok) {
                setSelectedContact((c: any) => ({ ...c, verified: 1 }));
                await loadContacts();
                setShowSafety(false);
              } else setErrorMsg(await responseError(r, "Verification failed"));
            } catch {
              setErrorMsg("Verification unavailable. Try again.");
            }
          }}
        >
          <ShieldCheck size={17} /> I compared them. They match.
        </button>
      </Sheet>
      <SovereignStorageSheet open={showStorage&&vaultState==='unlocked'&&!quickLocked} onClose={()=>setShowStorage(false)} api={apiFetch} onImport={selectStorage} onError={setErrorMsg}/>
      <Sheet open={showPin && !quickLocked} onClose={()=>setShowPin(false)} title="Set a screen-lock PIN" eyebrow="Lock screen">
        <p>The PIN hides this open session from people nearby. It does not close your vault; Fully lock does that.</p>
        <form className="stack" onSubmit={async e=>{e.preventDefault();if(pin!==pinConfirm){setErrorMsg("PINs do not match");return;}const r=await apiFetch("/api/session/pin",{method:"POST",body:JSON.stringify({pin})});if(r.ok){setPin("");setPinConfirm("");setShowPin(false);setInfoMsg("PIN saved. Use the key button to lock the screen.");}else setErrorMsg("Use exactly four digits");}}>
          <label className="field-label">New PIN<input aria-label="New session PIN" type="password" inputMode="numeric" required pattern="[0-9]{4}" maxLength={4} className="glass-input pin-input" value={pin} onChange={e=>setPin(e.target.value.replace(/[^0-9]/g,""))}/></label>
          <label className="field-label">Confirm PIN<input aria-label="Confirm session PIN" type="password" inputMode="numeric" required pattern="[0-9]{4}" maxLength={4} className="glass-input pin-input" value={pinConfirm} onChange={e=>setPinConfirm(e.target.value.replace(/[^0-9]/g,""))}/></label>
          <button className="btn-primary">Save PIN</button>
        </form>
      </Sheet>
      <Sheet
        open={showSettings && vaultState === "unlocked" && !quickLocked}
        onClose={() => setShowSettings(false)}
        title="Settings"
        eyebrow="Your private space"
      >
        {registrationState !== "success" && (
          <section className="settings-card highlight registration-section">
            <h3 className="settings-heading">
              <Shield size={17} /> Choose your username
            </h3>
            <form onSubmit={handleApplyAccess} className="stack">
              <p>
                {registrationState === "pending"
                  ? "Your vault is ready. Finish creating your public identity."
                  : "This is the public name people see. Your private keys are created automatically."}
              </p>
              <label className="field-label">
                Username
                <input
                  type="text"
                  required
                  minLength={3}
                  maxLength={32}
                  autoCapitalize="none"
                  autoComplete="off"
                  className="glass-input"
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                />
              </label>
              <button className="btn-primary">
                Create identity <ArrowUpRight size={16} />
              </button>
            </form>
          </section>
        )}
        <section className="settings-card">
          <h3 className="settings-heading">
            <User size={17} /> Profile
          </h3>
          <form className="stack" onSubmit={async e=>{e.preventDefault();const r=await apiFetch("/api/profile",{method:"POST",body:JSON.stringify(profile)});if(r.ok)setInfoMsg("Profile saved and shared, encrypted, with your contacts.");else setErrorMsg("Could not save profile");}}>
            <label className="field-label">Display name<input aria-label="Display Name" className="glass-input" maxLength={64} value={profile.displayName} onChange={e=>setProfile({...profile,displayName:e.target.value})}/></label>
            <label className="field-label">Status line<input aria-label="Status line" className="glass-input" maxLength={140} placeholder="Visible to your contacts" value={profile.statusLine} onChange={e=>setProfile({...profile,statusLine:e.target.value})}/></label>
            <button className="btn-secondary">Save profile</button>
          </form>
        </section>
        <section className="settings-card">
          <h3 className="settings-heading">
            <LockKeyhole size={17} /> Locking
          </h3>
          <div className="lock-option">
            <span className="lock-icon">
              <KeyRound size={18} />
            </span>
            <span>
              <strong>Lock screen with PIN</strong>
              <small>Hides the app behind a 4-digit PIN. Your vault stays open and messages keep arriving.</small>
            </span>
            <button className="btn-secondary" onClick={()=>{setPin("");setPinConfirm("");setShowPin(true);}}>Set PIN</button>
          </div>
          <div className="lock-option danger">
            <span className="lock-icon">
              <LockKeyhole size={18} />
            </span>
            <span>
              <strong>Fully lock vault</strong>
              <small>Syncs a backup, then closes cryptographic access. Reopening needs your Vault ID and passphrase.</small>
            </span>
            <button className="btn-secondary danger" disabled={busy} onClick={handleLockVault}>
              {busy ? "Locking…" : "Lock"}
            </button>
          </div>
        </section>
        <section className="settings-card">
          <h3 className="settings-heading">
            <HardDriveUpload size={17} /> Backup
          </h3>
          <p>An encrypted copy of your vault is kept on the relay so you can restore it on a new device.</p>
          <FragmentShield status={fragmentStatus} unlocked />
          <button
            className="btn-secondary"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await apiFetch("/api/vault/sync-backup", {
                  method: "POST",
                });
                if (!r.ok) throw new Error(relayDown);
                await loadFragmentStatus();
                setInfoMsg("Encrypted backup is up to date.");
              } catch (e: any) {
                setErrorMsg(e.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            <RefreshCw size={16} /> Back up now
          </button>
        </section>
        <section className="settings-card">
          <h3 className="settings-heading">
            <ShieldCheck size={17} /> Privacy
          </h3>
          <BackgroundDelivery api={apiFetch} open={showSettings} />
          <TransportPrivacy api={apiFetch} open={showSettings} />
        </section>
        <section className="settings-card">
          <h3 className="settings-heading">
            <SlidersHorizontal size={17} /> Advanced
          </h3>
          <details className="settings-section">
            <summary>
              <Network size={17} /> Relay connection
              <span className={`relay-pill ${relayStatus}`}>
                <span className={`relay-dot ${relayStatus}`} />
                {relayStatus === "online"
                  ? "Reachable"
                  : relayStatus === "offline"
                    ? "Unreachable"
                    : "Checking"}
              </span>
              <ChevronDown size={16} />
            </summary>
            <RelayRoutes current={relayUrl} save={saveRelay} />
            <form
              className="stack"
              onSubmit={async (e) => {
                e.preventDefault();
                const form = e.currentTarget;
                const value = String(new FormData(form).get("relayUrl") || "");
                if (await saveRelay(value))
                  setInfoMsg("Relay saved. Checking whether it's reachable…");
              }}
            >
              <label className="field-label">
                Custom relay URL
                <input
                  name="relayUrl"
                  key={relayUrl}
                  type="url"
                  required
                  className="glass-input"
                  defaultValue={relayUrl}
                />
              </label>
              <button className="btn-secondary">Save relay</button>
            </form>
          </details>
          <details className="settings-section">
            <summary>
              <KeyRound size={17} /> Change master passphrase
              <ChevronDown size={16} />
            </summary>
            <form onSubmit={handleChangePassword} className="stack">
              <label className="field-label">
                Vault ID
                <input
                  type="password"
                  required
                  minLength={8}
                  autoComplete="off"
                  className="glass-input"
                  value={changeVaultId}
                  onChange={(e) => setChangeVaultId(e.target.value)}
                />
              </label>
              <label className="field-label">
                Current passphrase
                <input
                  type="password"
                  required
                  autoComplete="off"
                  className="glass-input"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                />
              </label>
              <label className="field-label">
                New passphrase
                <input
                  type="password"
                  required
                  minLength={12}
                  autoComplete="off"
                  className="glass-input"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                />
              </label>
              <button type="submit" className="btn-primary">
                Update passphrase <ArrowUpRight size={16} />
              </button>
            </form>
          </details>
          {registrationState === "success" && (
            <p className="activated-status">
              <CheckCircle size={16} /> This device is registered with the relay.
            </p>
          )}
        </section>
        <PrivacyNote />
      </Sheet>
    </div>
  );
}

function TypingIndicator(){return <span className="typing-indicator" role="status" aria-label="Peer is typing"><i/><i/><i/><small>typing…</small></span>;}
