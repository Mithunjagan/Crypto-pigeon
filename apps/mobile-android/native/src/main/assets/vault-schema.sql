
      CREATE TABLE IF NOT EXISTS vault_instance (singleton INTEGER PRIMARY KEY CHECK(singleton=1), token TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS account_public (singleton INTEGER PRIMARY KEY CHECK(singleton=1), public_uid TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS contacts (
        contact_id TEXT PRIMARY KEY, 
        username TEXT NOT NULL,
        public_uid TEXT,
        identity_public_key BLOB NOT NULL, 
        verified INTEGER NOT NULL DEFAULT 0, 
        safety_number_hash TEXT, 
        identity_changed INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS conversations (
        conversation_id TEXT PRIMARY KEY, 
        contact_id TEXT NOT NULL REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        disappearing_seconds INTEGER, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        message_id TEXT PRIMARY KEY, 
        conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE, 
        direction TEXT NOT NULL CHECK(direction IN ('sent','received')), 
        plaintext TEXT NOT NULL, 
        sent_at INTEGER, 
        received_at INTEGER, 
        read_at INTEGER, 
        disappear_at INTEGER, 
        remote_blob_id TEXT, 
        status TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_sessions (
        contact_id TEXT PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        ratchet_state BLOB NOT NULL, 
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS message_outbox (
        envelope_id TEXT PRIMARY KEY,
        message_id TEXT NOT NULL UNIQUE REFERENCES messages(message_id) ON DELETE CASCADE,
        mailbox_id TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS identity_keys (
        device_id TEXT PRIMARY KEY, 
        identity_private_key BLOB NOT NULL, 
        identity_public_key BLOB NOT NULL, 
        signed_prekey_private BLOB NOT NULL, 
        signed_prekey_public BLOB NOT NULL, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS attachments (
        attachment_id TEXT PRIMARY KEY, 
        message_id TEXT NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE, 
        encrypted_local_path TEXT, 
        file_name_encrypted BLOB, 
        file_size INTEGER, 
        file_hash BLOB, 
        file_key BLOB, 
        disappear_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS attachment_downloads (
        attachment_id TEXT PRIMARY KEY REFERENCES attachments(attachment_id) ON DELETE CASCADE,
        manifest TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_account (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), 
        identity_key_pair BLOB NOT NULL, 
        registration_id INTEGER NOT NULL, 
        user_id TEXT, 
        device_id TEXT NOT NULL, 
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_signed_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS signal_kyber_prekeys (
        prekey_id INTEGER PRIMARY KEY, 
        record BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS relay_auth (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), 
        access_token TEXT NOT NULL
      );
      -- Pending activation is vault state, not browser state.  Keeping the
      -- request id here lets a restarted UI safely resume the same request.
      CREATE TABLE IF NOT EXISTS activation_state (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        request_id TEXT NOT NULL,
        username TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending', 'activated')),
        expires_at TEXT,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS remote_contacts (
        contact_id TEXT PRIMARY KEY REFERENCES contacts(contact_id) ON DELETE CASCADE, 
        user_id TEXT NOT NULL, 
        device_id TEXT NOT NULL, 
        signal_device_id INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_auth_key (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen_envelope_ids (
        envelope_id TEXT PRIMARY KEY,
        received_at INTEGER NOT NULL
      );
    