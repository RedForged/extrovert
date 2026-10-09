'use strict';

// Bot webhook delivery (planned.md F5.3): the server POSTs notification
// events as JSON to the bot's registered URL, signed with
// X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body)). Failures retry
// with exponential backoff, bounded attempts.
//
// SSRF: the URL is validated (public host only) AND the resolved address is
// pinned for the actual connection, so a hostname cannot answer a public
// address at validation time and a private one at connect time (DNS rebinding).

const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const { validateWebhookUrl, isPrivateAddress } = require('./push');

const MAX_ATTEMPTS = 5;
const MAX_TIMEOUT_MS = 10000;

function sign(secret, body) {
  return crypto.createHmac('sha256', String(secret)).update(body).digest('hex');
}

// A net.connect lookup that always answers with the pre-validated addresses,
// ignoring any later DNS answer for the hostname.
function pinnedLookup(addrs) {
  const entries = addrs.map(a => ({ address: a, family: a.includes(':') ? 6 : 4 }));
  return (host, opts, cb) => {
    if (opts && opts.all) return cb(null, entries);
    const e = entries[0];
    return cb(null, e.address, e.family);
  };
}

function postPinned(url, headers, body, addrs) {
  return new Promise((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(url, {
      method: 'POST',
      headers,
      lookup: pinnedLookup(addrs),
      timeout: MAX_TIMEOUT_MS,
    }, (res) => {
      const status = res.statusCode;
      res.resume();
      res.on('end', () => resolve(status));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

async function deliver(hook, payload, attempt) {
  const check = await validateWebhookUrl(hook.url);
  if (!check.ok) {
    console.warn('bot webhook blocked (not a public host):', hook.url, check.reason);
    return;
  }
  let url;
  let addrs = [];
  try {
    url = new URL(hook.url);
    const resolved = await Promise.race([
      dns.lookup(url.hostname, { all: true, verbatim: true }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('dns timeout')), 4000)),
    ]);
    addrs = resolved.map((r) => r.address).filter((a) => !isPrivateAddress(a));
  } catch {
    addrs = [];
  }
  if (!addrs.length) {
    console.warn('bot webhook blocked (no public address):', hook.url);
    return;
  }

  const signature = sign(hook.secret, payload);
  const headers = {
    'Content-Type': 'application/json',
    'X-Webhook-Signature': signature,
    'User-Agent': 'Extrovert-Bot-Webhook/1.0',
    'Content-Length': Buffer.byteLength(payload),
  };
  try {
    const status = await postPinned(url, headers, payload, addrs);
    if (status >= 400) throw new Error('HTTP ' + status);
  } catch (err) {
    const next = attempt + 1;
    if (next >= MAX_ATTEMPTS) {
      console.warn('bot webhook delivery failed permanently:', hook.url, err && err.message);
      return;
    }
    setTimeout(() => deliver(hook, payload, next), Math.min(30000, 1000 * 2 ** next));
  }
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
