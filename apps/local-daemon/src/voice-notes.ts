import type { Vault } from './vault.js';
import type { LocalSignalStore } from './signal-store.js';
import type { RelayClient } from './relay-client.js';
import { encryptAndUploadAttachment, downloadAndDecryptAttachment } from './attachments.js';
import type { AttachmentManifest } from '@crypto-pigeon/shared-types';

export async function uploadVoiceNote(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  audioData: Buffer
): Promise<AttachmentManifest> {
  // Voice notes are uploaded as chunked audio/webm files
  const filename = `voice-note-${Date.now()}.webm`;
  return encryptAndUploadAttachment(vault, store, relayClient, audioData, filename, 'audio/webm');
}

export async function downloadVoiceNote(
  vault: Vault,
  store: LocalSignalStore,
  relayClient: RelayClient,
  manifest: AttachmentManifest,
  messageId: string
): Promise<Buffer> {
  return downloadAndDecryptAttachment(vault, store, relayClient, manifest, messageId);
}
