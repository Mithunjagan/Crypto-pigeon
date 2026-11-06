import type { FastifyRequest } from 'fastify';

export interface AuthenticatedUser {
  deviceId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
  }
}
