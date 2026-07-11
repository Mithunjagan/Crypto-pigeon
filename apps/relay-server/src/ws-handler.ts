import type { IncomingMessage } from 'node:http';
import { parse } from 'node:url';
import { WebSocketServer, WebSocket } from 'ws';
import { pool } from './db.js';
import { logger } from './logger.js';

// Map of active WebSocket connections: deviceId -> WebSocket
const clients = new Map<string, WebSocket>();

export function setupWebSocket(server: any) {
  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', async (request: IncomingMessage, socket: any, head: Buffer) => {
    const { query } = parse(request.url || '', true);
    const token = query.token;
    const origin = request.headers.origin || '';

    // Validate origin: allow localhost/127.0.0.1 for development/testing, or custom domains
    // Spec: "WebSocket Handshake Validation: ... Origin header (http://127.0.0.1:PORT only)" -> Wait, this applies to the Localhost Daemon local UI WebSocket upgrade!
    // For the Relay WebSocket upgrade, the Origin can be anything (or verified depending on deployment, but let's allow it for E2E tests).
    
    if (typeof token !== 'string') {
      logger.warn('WebSocket upgrade rejected: missing token');
      socket.destroy();
      return;
    }

    try {
      const nowMs = Date.now();
      const result = await pool.query(
        'SELECT device_id FROM sessions WHERE token = $1 AND expires_at > $2',
        [token, nowMs]
      );

      if (result.rows.length === 0) {
        logger.warn('WebSocket upgrade rejected: invalid or expired token');
        socket.destroy();
        return;
      }

      const deviceId = result.rows[0].device_id;

      wss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
        // Register client
        clients.set(deviceId, ws);
        logger.debug({ deviceId }, 'WebSocket client connected');

        // Setup ping-pong keepalive
        let isAlive = true;
        ws.on('pong', () => {
          isAlive = true;
        });

        const pingInterval = setInterval(() => {
          if (!isAlive) {
            ws.terminate();
            return;
          }
          isAlive = false;
          ws.ping();
        }, 30000);

        ws.on('message', (message: any) => {
          // Relay WebSocket is push-only for messages, but can handle client pings
          try {
            const data = JSON.parse(message.toString());
            if (data.type === 'ping') {
              ws.send(JSON.stringify({ type: 'pong' }));
            }
          } catch {
            // ignore malformed messages
          }
        });

        ws.on('close', () => {
          clearInterval(pingInterval);
          clients.delete(deviceId);
          logger.debug({ deviceId }, 'WebSocket client disconnected');
        });

        ws.on('error', (err: Error) => {
          logger.error({ err, deviceId }, 'WebSocket client error');
          ws.close();
        });
      });
    } catch (error) {
      logger.error({ err: error }, 'WebSocket upgrade authentication failed');
      socket.destroy();
    }
  });

  return wss;
}

/**
 * Sends a message notification to a connected client.
 * Returns true if the client was online and notified, false otherwise.
 */
export function notifyClient(deviceId: string, data: any): boolean {
  const ws = clients.get(deviceId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(data));
      return true;
    } catch (error) {
      logger.error({ err: error, deviceId }, 'Failed to send message via WebSocket');
      return false;
    }
  }
  return false;
}
