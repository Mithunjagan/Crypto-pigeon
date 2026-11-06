export interface LocalContact {
  contactId: string;
  username: string;
  verified: boolean;
  identityChanged: boolean;
}

export interface LocalMessage {
  messageId: string;
  conversationId: string;
  direction: 'sent' | 'received';
  plaintext: string;
  sentAt?: number;
  receivedAt?: number;
  readAt?: number;
  disappearAt?: number;
  remoteBlobId?: string;
  status: string;
}

export interface LocalConversation {
  conversationId: string;
  contactId: string;
  disappearingSeconds?: number;
  createdAt: number;
}
