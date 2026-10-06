'use strict';

// Bot webhook delivery (planned.md F5.3): the server POSTs notification
// events as JSON to the bot's registered URL, signed with
// X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body)). Failures retry
// with exponential backoff, bounded attempts.

const crypto = require('node:crypto');

const MAX_ATTEMPTS = 5;
const MAX_TIMEOUT_MS = 10000;

function sign(secret, body) {
  return crypto.createHmac('sha256', String(secret)).update(body).digest('hex');
}

function deliver(hook, payload, attempt) {
  const signature = sign(hook.secret, payload);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), MAX_TIMEOUT_MS);
  fetch(hook.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Webhook-Signature': signature,
      'User-Agent': 'Extrovert-Bot-Webhook/1.0',
    },
    body: payload,
    signal: controller.signal,
  }).then((res) => {
    if (!res.ok) throw new Error('HTTP ' + res.status);
  }).catch((err) => {
    const next = attempt + 1;
    if (next >= MAX_ATTEMPTS) {
      console.warn('bot webhook delivery failed permanently:', hook.url, err && err.message);
      return;
    }
    setTimeout(() => deliver(hook, payload, next), Math.min(30000, 1000 * 2 ** next));
  }).finally(() => clearTimeout(timer));
}

function dispatchBotWebhook(userId, event) {
  try {
    const db = require('./db');
    const hook = db.getBotWebhook(userId);
    if (!hook || !hook.url) return;
    deliver(hook, JSON.stringify(event), 0);
  } catch (err) {
    console.error('bot webhook dispatch failed:', err && err.message);
  }
}

module.exports = { dispatchBotWebhook, sign };
