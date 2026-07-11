import React, { useState, useEffect, useRef } from 'react';
import {
  Lock,
  Unlock,
  UserPlus,
  Send,
  Image,
  Mic,
  Settings,
  Shield,
  AlertTriangle,
  RefreshCw,
  LogOut,
  CheckCircle,
  KeyRound
} from 'lucide-react';

export default function App() {
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [vaultState, setVaultState] = useState<'unconfigured' | 'locked' | 'unlocked' | 'bootstrapping'>('bootstrapping');
  
  // Forms
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  
  // App State
  const [contacts, setContacts] = useState<any[]>([]);
  const [selectedContact, setSelectedContact] = useState<any | null>(null);
  const [messages, setMessages] = useState<any[]>([]);
  const [inputText, setInputText] = useState('');
  const [newContactUsername, setNewContactUsername] = useState('');
  
  // UI Panels
  const [showSettings, setShowSettings] = useState(false);
  const [showAddContact, setShowAddContact] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [infoMsg, setInfoMsg] = useState<string | null>(null);
  
  // Registration / Activation
  const [requestId, setRequestId] = useState('');
  const [activationCode, setActivationCode] = useState('');
  const [registrationState, setRegistrationState] = useState<'idle' | 'pending' | 'success'>('idle');
  const [regUsername, setRegUsername] = useState('');

  // Audio Recording
  const [isRecording, setIsRecording] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);

  // File Upload
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Poll intervals
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    bootstrapSession();
  }, []);

  useEffect(() => {
    if (vaultState === 'unlocked') {
      loadContacts();
      const interval = setInterval(() => {
        syncMessages();
      }, 3000);
      return () => clearInterval(interval);
    }
  }, [vaultState, csrfToken]);

  useEffect(() => {
    if (selectedContact) {
      loadMessages(selectedContact.contact_id);
    }
  }, [selectedContact]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const bootstrapSession = async () => {
    try {
      const hash = window.location.hash.slice(1);
      let res;
      if (hash) {
        res = await fetch('/api/bootstrap', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret: hash })
        });
        // Clear fragment
        window.history.replaceState(null, '', window.location.pathname);
      } else {
        res = await fetch('/api/session');
      }

      if (res.ok) {
        const data = await res.json();
        setCsrfToken(data.csrfToken);
        setVaultState(data.vaultState);
      } else {
        setVaultState('unconfigured');
      }
    } catch {
      setVaultState('unconfigured');
    }
  };

  const apiFetch = async (path: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {});
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }
    options.headers = headers;
    return fetch(path, options);
  };

  const handleCreateVault = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== passwordConfirm) {
      setErrorMsg('Passwords do not match');
      return;
    }
    try {
      const res = await apiFetch('/api/vault/create', {
        method: 'POST',
        body: JSON.stringify({ password })
      });
      if (res.ok) {
        await bootstrapSession();
        setPassword('');
        setPasswordConfirm('');
        setErrorMsg(null);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Failed to create vault');
      }
    } catch {
      setErrorMsg('Network error occurred');
    }
  };

  const handleUnlockVault = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/api/vault/open', {
        method: 'POST',
        body: JSON.stringify({ password })
      });
      if (res.ok) {
        await bootstrapSession();
        setPassword('');
        setErrorMsg(null);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Invalid password');
      }
    } catch {
      setErrorMsg('Network error occurred');
    }
  };

  const handleLockVault = async () => {
    try {
      const res = await apiFetch('/api/vault/lock', { method: 'POST' });
      if (res.ok) {
        setVaultState('locked');
        setCsrfToken(null);
        setSelectedContact(null);
        setMessages([]);
      }
    } catch {
      setErrorMsg('Failed to lock vault');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/api/vault/change-password', {
        method: 'POST',
        body: JSON.stringify({ oldPassword, newPassword })
      });
      if (res.ok) {
        setInfoMsg('Password changed successfully');
        setOldPassword('');
        setNewPassword('');
        setShowSettings(false);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Failed to change password');
      }
    } catch {
      setErrorMsg('Network error');
    }
  };

  const handleApplyAccess = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/api/access/apply', {
        method: 'POST',
        body: JSON.stringify({ username: regUsername })
      });
      if (res.ok) {
        const data = await res.json();
        setRequestId(data.requestId);
        setRegistrationState('pending');
        setErrorMsg(null);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Failed to apply');
      }
    } catch {
      setErrorMsg('Network error');
    }
  };

  const handleActivateAccess = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/api/access/activate', {
        method: 'POST',
        body: JSON.stringify({ requestId, activationCode })
      });
      if (res.ok) {
        setRegistrationState('success');
        setActivationCode('');
        setErrorMsg(null);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Activation failed');
      }
    } catch {
      setErrorMsg('Network error');
    }
  };

  const loadContacts = async () => {
    try {
      const res = await apiFetch('/api/contacts');
      if (res.ok) {
        const data = await res.json();
        setContacts(data);
      }
    } catch {
      console.error('Failed to load contacts');
    }
  };

  const handleAddContact = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/api/contacts/add', {
        method: 'POST',
        body: JSON.stringify({ username: newContactUsername })
      });
      if (res.ok) {
        await loadContacts();
        setNewContactUsername('');
        setShowAddContact(false);
        setErrorMsg(null);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Contact not found or error adding contact');
      }
    } catch {
      setErrorMsg('Network error');
    }
  };

  const loadMessages = async (contactId: string) => {
    try {
      const res = await apiFetch(`/api/messages/${contactId}`);
      if (res.ok) {
        const data = await res.json();
        setMessages(data);
      }
    } catch {
      console.error('Failed to load messages');
    }
  };

  const syncMessages = async () => {
    try {
      const res = await apiFetch('/api/fetch-messages', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        if (data.received > 0 && selectedContact) {
          loadMessages(selectedContact.contact_id);
        }
      }
    } catch {
      // ignore
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !selectedContact) return;

    try {
      const res = await apiFetch('/api/send', {
        method: 'POST',
        body: JSON.stringify({
          conversationId: selectedContact.contact_id,
          plaintext: inputText
        })
      });
      if (res.ok) {
        setInputText('');
        loadMessages(selectedContact.contact_id);
      } else {
        const data = await res.json();
        setErrorMsg(data.error || 'Failed to send message');
      }
    } catch {
      setErrorMsg('Failed to send message');
    }
  };

  // Attachment upload helper
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedContact) return;

    const reader = new FileReader();
    reader.onload = async () => {
      const arrayBuffer = reader.result as ArrayBuffer;
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
      );

      try {
        setInfoMsg('Encrypting and uploading file...');
        // 1. Encrypt and upload attachment chunked
        const encRes = await apiFetch('/api/attachments/encrypt', {
          method: 'POST',
          body: JSON.stringify({
            filedataB64: base64,
            filename: file.name,
            mimeType: file.type
          })
        });

        if (!encRes.ok) throw new Error('Encryption failed');

        const manifest = await encRes.json();

        // 2. Send E2EE message with attachment manifest
        await apiFetch('/api/send', {
          method: 'POST',
          body: JSON.stringify({
            conversationId: selectedContact.contact_id,
            plaintext: `Sent an attachment: ${file.name}`,
            attachmentManifest: manifest
          })
        });

        setInfoMsg(null);
        loadMessages(selectedContact.contact_id);
      } catch (err) {
        setErrorMsg('Failed to upload attachment');
        setInfoMsg(null);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  // Voice Note Recording
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        audioChunksRef.current.push(event.data);
      };

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        const reader = new FileReader();
        reader.onload = async () => {
          const arrayBuffer = reader.result as ArrayBuffer;
          const base64 = btoa(
            new Uint8Array(arrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
          );

          try {
            setInfoMsg('Uploading voice note...');
            const encRes = await apiFetch('/api/attachments/encrypt', {
              method: 'POST',
              body: JSON.stringify({
                filedataB64: base64,
                filename: 'voice-note.webm',
                mimeType: 'audio/webm'
              })
            });

            if (!encRes.ok) throw new Error('Voice note upload failed');
            const manifest = await encRes.json();

            await apiFetch('/api/send', {
              method: 'POST',
              body: JSON.stringify({
                conversationId: selectedContact.contact_id,
                plaintext: '🎤 Voice Note',
                attachmentManifest: manifest
              })
            });

            setInfoMsg(null);
            loadMessages(selectedContact.contact_id);
          } catch {
            setErrorMsg('Failed to upload voice note');
            setInfoMsg(null);
          }
        };
        reader.readAsArrayBuffer(audioBlob);
      };

      mediaRecorder.start();
      setIsRecording(true);
    } catch {
      setErrorMsg('Failed to access microphone');
    }
  };

  const stopRecording = () => {
    mediaRecorderRef.current?.stop();
    setIsRecording(false);
  };

  return (
    <div className="flex flex-col h-full w-full">
      {/* Toast Notification */}
      {errorMsg && (
        <div className="absolute top-4 right-4 z-50 bg-red-900/90 border border-red-500 text-red-200 px-4 py-3 rounded-lg flex items-center gap-2 animate-fade-in">
          <AlertTriangle size={18} />
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="ml-2 font-bold hover:text-white">&times;</button>
        </div>
      )}
      {infoMsg && (
        <div className="absolute top-4 right-4 z-50 bg-indigo-900/90 border border-indigo-500 text-indigo-200 px-4 py-3 rounded-lg flex items-center gap-2 animate-fade-in">
          <RefreshCw size={18} className="animate-spin" />
          <span>{infoMsg}</span>
        </div>
      )}

      {/* Bootstrapping Loader */}
      {vaultState === 'bootstrapping' && (
        <div className="flex flex-col items-center justify-center h-full gap-4">
          <RefreshCw size={48} className="animate-spin text-indigo-500" />
          <h2 className="text-xl font-semibold">Loading Session...</h2>
        </div>
      )}

      {/* Vault Unconfigured (Create Vault) */}
      {vaultState === 'unconfigured' && (
        <div className="flex items-center justify-center h-full p-4">
          <div className="glass-panel w-full max-w-md p-8 flex flex-col gap-6 animate-fade-in">
            <div className="flex flex-col items-center gap-2">
              <div className="p-4 bg-indigo-500/10 rounded-full text-indigo-400">
                <Lock size={40} />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">Create Secure Vault</h1>
              <p className="text-sm text-slate-400 text-center">
                Configure your database vault. Use a strong password to generate your 256-bit local master key.
              </p>
            </div>

            <form onSubmit={handleCreateVault} className="flex flex-col gap-4">
              <input
                type="password"
                placeholder="Vault Password (min. 12 characters)"
                className="glass-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <input
                type="password"
                placeholder="Confirm Vault Password"
                className="glass-input"
                value={passwordConfirm}
                onChange={(e) => setPasswordConfirm(e.target.value)}
              />
              <button type="submit" className="btn-primary flex items-center justify-center gap-2 mt-2">
                <KeyRound size={18} /> Initialize Vault
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Vault Locked (Unlock Vault) */}
      {vaultState === 'locked' && (
        <div className="flex items-center justify-center h-full p-4">
          <div className="glass-panel w-full max-w-md p-8 flex flex-col gap-6 animate-fade-in">
            <div className="flex flex-col items-center gap-2">
              <div className="p-4 bg-indigo-500/10 rounded-full text-indigo-400">
                <Unlock size={40} />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">Vault Locked</h1>
              <p className="text-sm text-slate-400 text-center">
                Enter your vault password to decrypt local keys and authenticate database.
              </p>
            </div>

            <form onSubmit={handleUnlockVault} className="flex flex-col gap-4">
              <input
                type="password"
                placeholder="Vault Password"
                className="glass-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button type="submit" className="btn-primary flex items-center justify-center gap-2 mt-2">
                Unlock Database
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Main Unlocked Chat Client */}
      {vaultState === 'unlocked' && (
        <div className="flex h-full w-full overflow-hidden">
          {/* Sidebar */}
          <div className="w-80 border-r border-slate-800 flex flex-col h-full bg-slate-950/40">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield size={22} className="text-indigo-400" />
                <span className="font-bold tracking-wide">Crypto Pigeon</span>
              </div>
              <div className="flex items-center gap-1">
                <button onClick={() => setShowSettings(true)} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition">
                  <Settings size={18} />
                </button>
                <button onClick={handleLockVault} className="p-2 hover:bg-red-950/20 hover:text-red-400 rounded-lg text-slate-400 transition" title="Lock Database">
                  <LogOut size={18} />
                </button>
              </div>
            </div>

            <div className="p-4 flex flex-col gap-3">
              <button onClick={() => setShowAddContact(true)} className="btn-secondary w-full flex items-center justify-center gap-2 py-2.5">
                <UserPlus size={16} /> New Conversation
              </button>
            </div>

            {/* Contacts list */}
            <div className="flex-1 overflow-y-auto px-2">
              <h3 className="px-3 py-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">Conversations</h3>
              <div className="flex flex-col gap-1">
                {contacts.length === 0 ? (
                  <p className="text-xs text-slate-500 text-center py-8">No contacts added yet.</p>
                ) : (
                  contacts.map(contact => (
                    <button
                      key={contact.contact_id}
                      onClick={() => setSelectedContact(contact)}
                      className={`flex flex-col gap-1 w-full text-left p-3 rounded-lg transition ${selectedContact?.contact_id === contact.contact_id ? 'bg-indigo-600/20 border-l-4 border-indigo-500' : 'hover:bg-slate-900/50'}`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm text-slate-200">{contact.username}</span>
                        {contact.identity_changed === 1 && (
                          <AlertTriangle size={14} className="text-amber-500" />
                        )}
                      </div>
                      <span className="text-xs text-slate-500 truncate">{contact.contact_id}</span>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Chat Window */}
          <div className="flex-1 flex flex-col h-full bg-slate-950/10">
            {selectedContact ? (
              <>
                {/* Header */}
                <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/25">
                  <div className="flex flex-col">
                    <span className="font-bold text-slate-100">{selectedContact.username}</span>
                    <span className="text-xs text-slate-400">Safety Number: {selectedContact.safety_number_hash || 'Calculating...'}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {selectedContact.verified === 1 ? (
                      <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full font-medium">
                        <CheckCircle size={12} /> Verified
                      </span>
                    ) : (
                      <span className="text-xs text-amber-500 bg-amber-500/10 px-2.5 py-1 rounded-full font-medium">
                        Unverified
                      </span>
                    )}
                  </div>
                </div>

                {/* Identity changed warning banner */}
                {selectedContact.identity_changed === 1 && (
                  <div className="bg-amber-950/40 border-b border-amber-500/25 px-4 py-3 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2 text-amber-200 text-sm">
                      <AlertTriangle size={18} className="text-amber-400 shrink-0" />
                      <span>
                        <strong>Security Warning:</strong> This contact's identity key has changed. E2EE session replacement blocked.
                      </span>
                    </div>
                    <button className="btn-secondary py-1.5 px-3 text-xs bg-amber-500/10 border-amber-500/20 hover:bg-amber-500/20 text-amber-200">
                      Approve Change
                    </button>
                  </div>
                )}

                {/* Messages Box */}
                <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
                  {messages.map(msg => (
                    <div
                      key={msg.message_id}
                      className={`flex flex-col max-w-lg rounded-xl p-3.5 shadow-sm animate-fade-in ${msg.direction === 'sent' ? 'self-end bg-indigo-600/30 text-indigo-50 border border-indigo-500/20' : 'self-start bg-slate-900/60 text-slate-100 border border-slate-800'}`}
                    >
                      <span className="text-sm leading-relaxed whitespace-pre-wrap">{msg.plaintext}</span>
                      <div className="flex items-center justify-between mt-1 text-[10px] text-slate-500">
                        <span>{new Date(msg.sent_at || msg.received_at).toLocaleTimeString()}</span>
                        {msg.status === 'sent' && <span className="ml-2">✓</span>}
                      </div>
                    </div>
                  ))}
                  <div ref={messagesEndRef} />
                </div>

                {/* Footer Input */}
                <form onSubmit={handleSendMessage} className="p-4 border-t border-slate-800 flex items-center gap-3 bg-slate-950/25">
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="p-3 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded-xl text-slate-400 hover:text-white transition"
                    title="Send File/Attachment"
                  >
                    <Image size={18} />
                  </button>
                  <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    onChange={handleFileUpload}
                  />

                  <button
                    type="button"
                    onMouseDown={startRecording}
                    onMouseUp={stopRecording}
                    className={`p-3 border rounded-xl transition ${isRecording ? 'bg-red-600 text-white border-red-500 animate-pulse' : 'bg-slate-900 border-slate-800 text-slate-400 hover:bg-slate-800 hover:text-white'}`}
                    title="Hold to Record Voice Note"
                  >
                    <Mic size={18} />
                  </button>

                  <input
                    type="text"
                    placeholder="Type E2EE message..."
                    className="glass-input flex-1 py-3"
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                  />

                  <button type="submit" className="p-3 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-white transition">
                    <Send size={18} />
                  </button>
                </form>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-slate-500">
                <Shield size={48} className="text-slate-700" />
                <h3 className="text-lg">Select a contact to begin messaging securely.</h3>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-md p-6 flex flex-col gap-6 animate-fade-in">
            <h2 className="text-xl font-bold flex items-center gap-2">
              <Settings size={20} className="text-indigo-400" /> Settings
            </h2>

            {/* Change Password Form */}
            <form onSubmit={handleChangePassword} className="flex flex-col gap-4">
              <h3 className="text-sm font-semibold text-slate-300">Change Vault Password</h3>
              <input
                type="password"
                placeholder="Old Password"
                className="glass-input"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
              />
              <input
                type="password"
                placeholder="New Password"
                className="glass-input"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
              <button type="submit" className="btn-primary py-2 text-sm mt-1">
                Update Password
              </button>
            </form>

            {/* Registration setup if needed */}
            <div className="border-t border-slate-800 pt-4 flex flex-col gap-4">
              <h3 className="text-sm font-semibold text-slate-300">Relay Device Registration</h3>
              {registrationState === 'idle' && (
                <form onSubmit={handleApplyAccess} className="flex flex-col gap-3">
                  <input
                    type="text"
                    placeholder="Register Username"
                    className="glass-input"
                    value={regUsername}
                    onChange={(e) => setRegUsername(e.target.value)}
                  />
                  <button type="submit" className="btn-secondary py-2 text-sm">
                    Request Activation
                  </button>
                </form>
              )}

              {registrationState === 'pending' && (
                <form onSubmit={handleActivateAccess} className="flex flex-col gap-3">
                  <p className="text-xs text-amber-400">Request ID: {requestId}</p>
                  <input
                    type="text"
                    placeholder="Enter Activation Code"
                    className="glass-input"
                    value={activationCode}
                    onChange={(e) => setActivationCode(e.target.value)}
                  />
                  <button type="submit" className="btn-primary py-2 text-sm">
                    Submit Activation Code
                  </button>
                </form>
              )}

              {registrationState === 'success' && (
                <p className="text-xs text-emerald-400 flex items-center gap-1">
                  <CheckCircle size={14} /> Device Activated & Keys Synchronized!
                </p>
              )}
            </div>

            <button onClick={() => setShowSettings(false)} className="btn-secondary py-2 text-sm mt-2">
              Close
            </button>
          </div>
        </div>
      )}

      {/* Add Contact Modal */}
      {showAddContact && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-md p-6 flex flex-col gap-6 animate-fade-in">
            <h2 className="text-xl font-bold flex items-center gap-2">
              <UserPlus size={20} className="text-indigo-400" /> Start Conversation
            </h2>

            <form onSubmit={handleAddContact} className="flex flex-col gap-4">
              <p className="text-xs text-slate-400">
                Enter the exact username of the remote contact. The local daemon will fetch their prekey bundle from the relay server and establish a Signal cryptographic session.
              </p>
              <input
                type="text"
                placeholder="Contact Username"
                className="glass-input"
                value={newContactUsername}
                onChange={(e) => setNewContactUsername(e.target.value)}
              />
              <button type="submit" className="btn-primary py-2.5 text-sm mt-2">
                Establish Session
              </button>
            </form>

            <button onClick={() => setShowAddContact(false)} className="btn-secondary py-2 text-sm">
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
