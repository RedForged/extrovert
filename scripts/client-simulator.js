#!/usr/bin/env node
'use strict';

/**
 * client-simulator.js
 *
 * Headless mock native client / bot that connects to Extrovert's Realtime WebSocket Gateway.
 * Useful for interactive development of extrovert_native or other third-party clients.
 *
 * Usage:
 *   node scripts/client-simulator.js [--token=ext_pat_...] [--url=ws://localhost:3000/ws] [--room=1]
 */

const WebSocket = require('ws');

const args = process.argv.slice(2);
const options = {
  url: 'ws://localhost:3000/ws',
  token: 'ext_pat_bob_full_access_token_67890',
  roomId: '1',
};

for (const arg of args) {
  if (arg.startsWith('--url=')) options.url = arg.split('=')[1];
  if (arg.startsWith('--token=')) options.token = arg.split('=')[1];
  if (arg.startsWith('--room=')) options.roomId = arg.split('=')[1];
}

console.log('--- Extrovert Client Gateway Simulator ---');
console.log(`Connecting to: ${options.url}`);
console.log(`Using PAT:     ${options.token}`);
console.log(`Room Topic:    room:${options.roomId}`);

const ws = new WebSocket(options.url);
let lastSeq = 0;

ws.on('open', () => {
  console.log('[ws:connected] Socket opened. Subscribing to topics...');

  // 1. Subscribe to Room events
  ws.send(JSON.stringify({
    action: 'subscribe',
    topic: `room:${options.roomId}`,
    token: options.token,
  }));

  // 2. Subscribe to Home Timeline
  ws.send(JSON.stringify({
    action: 'subscribe',
    topic: 'timeline:home',
    token: options.token,
  }));

  // 3. Subscribe to Notifications
  ws.send(JSON.stringify({
    action: 'subscribe',
    topic: 'notifications',
    token: options.token,
  }));
});

ws.on('message', (raw) => {
  try {
    const msg = JSON.parse(raw);
    if (msg.seq) lastSeq = msg.seq;

    switch (msg.type) {
      case 'subscribed':
        console.log(`[ws:subscribed] Subscribed to topic: ${msg.topic}`);
        break;

      case 'unsubscribed':
        console.log(`[ws:unsubscribed] Unsubscribed from topic: ${msg.topic}`);
        break;

      case 'gateway_event':
        console.log(`\n[EVENT seq=${msg.seq}] Topic: ${msg.topic} | Event: ${msg.event}`);
        console.log(JSON.stringify(msg.data, null, 2));

        // Auto-reply demo if receiving a plaintext room message
        if (msg.event === 'message_create' && msg.data.body && !msg.data.body.startsWith('[Bot]')) {
          console.log(`[bot] Saw message: "${msg.data.body}" from @${msg.data.author ? msg.data.author.username : 'anon'}`);
        }
        break;

      case 'typing':
        console.log(`[ws:typing] User ${msg.userId} in channel ${msg.channel}: typing=${msg.typing}`);
        break;

      case 'resumed':
        console.log(`[ws:resumed] Replayed ${msg.replayed} missed events since seq ${lastSeq}`);
        break;

      case 'error':
        console.error(`[ws:error] ${msg.message}`);
        break;

      default:
        console.log('[ws:msg]', msg);
    }
  } catch (err) {
    console.error('Failed to parse gateway message:', raw.toString());
  }
});

ws.on('close', (code, reason) => {
  console.log(`[ws:closed] Connection closed (${code}): ${reason}`);
});

ws.on('error', (err) => {
  console.error('[ws:error]', err.message);
});

// Periodic ping
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ action: 'ping' }));
  }
}, 30000);
