import type { FastifyReply } from 'fastify';

export function setSecurityHeaders(reply: FastifyReply) {
  reply.header(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; media-src 'self' blob:; font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
  );
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Cache-Control', 'no-store, no-cache, must-revalidate');
  reply.header('Permissions-Policy', 'microphone=(self), camera=(), geolocation=(), payment=()');
  reply.header('Cross-Origin-Opener-Policy', 'same-origin');
  reply.header('Cross-Origin-Resource-Policy', 'same-origin');
}
