# Architecture

Each user runs a local Node.js daemon bound to `127.0.0.1`. The daemon serves the React UI, keeps private Signal identity material in an encrypted SQLCipher vault, and is the only component that encrypts or decrypts messages. The browser only submits user input to the daemon and displays daemon-provided plaintext.

The relay uses PostgreSQL for account approval state, public device prekeys, recipient-consented conversation permissions, and temporary ciphertext envelopes. It does not store private keys, vault passphrases, plaintext messages, or decrypted attachments.

The administrator uses `apps/admin-cli`, which connects directly to the relay database to approve access requests. Approval generates a random one-use activation code; only an Argon2id hash and expiry are stored.
