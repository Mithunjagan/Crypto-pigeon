# Protocol flow

1. User creates an encrypted local vault and submits a username access request.
2. Administrator runs the CLI, approves the random request ID, and gives the one-use activation code to the user.
3. The daemon activates with the code and uploads public prekeys. Private keys never leave the vault.
4. A user requests a conversation by exact username. The recipient sees and accepts or rejects it.
5. Only an accepted pair may retrieve each other's public prekey bundle, establish a Signal session, and relay ciphertext envelopes.
