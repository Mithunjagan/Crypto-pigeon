# Threat model

## Protected

- A relay database leak does not expose local Signal private keys or local vault passphrases.
- Relay operators cannot read authenticated Signal message payloads.
- Tampered ciphertext is rejected by the Signal protocol adapter.
- Conversation permission requires recipient acceptance; administrator approval alone cannot open a chat.
- Local message records and ratchet state are stored in the encrypted SQLCipher vault.

## Not fully protected

- Malware, browser extensions, and screen capture on an unlocked endpoint can read displayed content.
- The relay, reverse proxies, and hosting provider can observe routing metadata while users connect. This application does not persist IP addresses, but infrastructure outside the application may log them.
- Traffic analysis, modified clients, screenshots, copied text, weak vault passphrases, and denial of service remain possible.
- Disappearing messages are retention control, not protection against screenshots or modified clients.
