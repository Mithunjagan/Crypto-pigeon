-- Enable uuid-ossp if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

-- 2. Access Requests Table
CREATE TABLE IF NOT EXISTS access_requests (
  request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','activated')) DEFAULT 'pending',
  activation_code_hash TEXT,
  pepper_version INTEGER NOT NULL DEFAULT 1,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  activation_expires_at TIMESTAMPTZ,
  activation_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ
);

-- 3. Connection Requests Table
CREATE TABLE IF NOT EXISTS connection_requests (
  request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  recipient_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected')) DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  decided_at TIMESTAMPTZ
);

-- 4. Conversation Permissions Table
CREATE TABLE IF NOT EXISTS conversation_permissions (
  user_one UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  user_two UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY(user_one, user_two),
  CHECK(user_one < user_two)
);

-- 5. Device Identity Keys Table (v3)
CREATE TABLE IF NOT EXISTS device_identity_keys (
  device_id            UUID PRIMARY KEY,
  user_id              UUID NOT NULL REFERENCES users(user_id),
  identity_public_key  BYTEA NOT NULL,
  auth_public_key      BYTEA NOT NULL,
  registration_id      INTEGER NOT NULL,
  signal_device_id     INTEGER NOT NULL,
  registered_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at           TIMESTAMPTZ,
  UNIQUE(user_id)
);

-- 6. Signed Prekeys Table (v3)
CREATE TABLE IF NOT EXISTS signed_prekeys (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  signal_prekey_id INTEGER NOT NULL,
  public_key       BYTEA NOT NULL,
  signature        BYTEA NOT NULL,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ,
  UNIQUE(device_id, signal_prekey_id)
);

-- 7. Classical One-Time Prekeys Table (v3)
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  signal_prekey_id INTEGER NOT NULL,
  public_key       BYTEA NOT NULL,
  consumed         BOOLEAN NOT NULL DEFAULT false,
  consumed_at      TIMESTAMPTZ,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(device_id, signal_prekey_id)
);

-- 8. Post-Quantum One-Time Prekeys Table (v3)
CREATE TABLE IF NOT EXISTS pq_one_time_prekeys (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id        UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  signal_prekey_id INTEGER NOT NULL,
  public_key       BYTEA NOT NULL,
  signature        BYTEA NOT NULL,
  prekey_type      TEXT NOT NULL CHECK (prekey_type IN ('one_time', 'last_resort')),
  consumed         BOOLEAN NOT NULL DEFAULT false,
  consumed_at      TIMESTAMPTZ,
  uploaded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(device_id, signal_prekey_id)
);

-- 9. Key Version Tracking Table
CREATE TABLE IF NOT EXISTS device_key_versions (
  device_id   UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  key_type    TEXT NOT NULL,
  version     INTEGER NOT NULL,
  fingerprint BYTEA NOT NULL,
  changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(device_id, key_type, version)
);

-- 10. Messages Queue Table (v3)
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY,
  sender_id UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  encrypted_payload BYTEA NOT NULL, -- contains serialized envelope / ciphertext
  type TEXT NOT NULL DEFAULT 'message',
  timestamp BIGINT NOT NULL, -- Unix ms
  delivered BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient_pending ON messages(recipient_id) WHERE delivered = false;

-- 11. Sessions Table (v3)
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL, -- Unix ms
  created_at BIGINT NOT NULL DEFAULT (extract(epoch from now()) * 1000)
);

-- 12. Connection Appeals Table
CREATE TABLE IF NOT EXISTS connection_appeals (
  appeal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  target_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  passkey_hash TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')) DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ,
  UNIQUE(requester_user_id, target_user_id, status)
);

-- 13. Approved Connections Table
CREATE TABLE IF NOT EXISTS approved_connections (
  user_one UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  user_two UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  active BOOLEAN NOT NULL DEFAULT FALSE,
  activated_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  PRIMARY KEY(user_one, user_two),
  CHECK(user_one < user_two)
);

-- 14. Attachment Blobs Table (v3)
CREATE TABLE IF NOT EXISTS attachment_blobs (
  blob_id UUID PRIMARY KEY,
  owner_device_id UUID NOT NULL REFERENCES device_identity_keys(device_id) ON DELETE CASCADE,
  chunk_count INTEGER NOT NULL,
  total_size INTEGER NOT NULL,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 15. Attachment Chunks Table (v3)
CREATE TABLE IF NOT EXISTS attachment_chunks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  blob_id UUID NOT NULL REFERENCES attachment_blobs(blob_id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  nonce BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL,
  UNIQUE(blob_id, chunk_index)
);
