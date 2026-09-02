'use strict';

// Web-push (VAPID) for browser subscriptions only.
//
// The native app does NOT use a third-party push relay: its foreground
// service keeps a WebSocket to the signaling server (push_register) and the
// server delivers call/missed-call payloads over that connection directly.
// See webrtc-signaling.js sendWsPush.

const db = require('./db');
const https = require('node:https');
const dns = require('node:dns');

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@extrovert.local';

let webPush = null;
let webPushConfigured = false;
function loadWebPush() {
  if (webPush) return webPush;
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return null;
  try {
    webPush = require('web-push');
    webPush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
    webPushConfigured = true;
    return webPush;
  } catch (e) {
    console.error('push: web-push not available:', e.message);
    return null;
  }
}

function getVapidPublicKey() {
  return VAPID_PUBLIC_KEY || null;
}

// ---- SSRF guard for push subscription endpoints ----------------------------
//
// A push subscription endpoint is a URL the SERVER will POST to (web-push
// https.request). Accepting arbitrary endpoints lets a client make the server
// issue requests to internal hosts (cloud metadata 169.254.169.254, loopback
// services, RFC1918 ranges). Real browsers only ever produce endpoints at
// public push services, so blocking http://, loopback and private addresses
// costs nothing and closes the vector. Hostnames that are not IP literals are
// assumed public (resolving them would require DNS at subscribe time).

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true;                                      // 0.0.0.0/8
  if (a === 10) return true;                                     // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true;             // 100.64.0.0/10 CGNAT
  if (a === 127) return true;                                    // loopback
  if (a === 169 && b === 254) return true;                       // 169.254.0.0/16 link-local
  if (a === 172 && b >= 16 && b <= 31) return true;              // 172.16.0.0/12
  if (a === 192 && b === 0) return true;                         // 192.0.0.0/24
  if (a === 192 && b === 168) return true;                       // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true;          // 198.18.0.0/15
  if (a >= 224) return true;                                     // multicast + reserved
  return false;
}

// Decode an IPv4-mapped IPv6 tail into a dotted-quad IPv4 string, or null if
// the tail is not a valid 32-bit IPv4 encoding. The WHATWG URL parser
// canonicalizes mapped addresses to two hex groups ('::ffff:7f00:1' ->
// '127.0.0.1'); anything else fails closed (treated as private).
function ipv4FromMappedTail(tail) {
  const groups = String(tail).split(':');
  if (groups.length !== 2 || !groups.every(g => /^[0-9a-f]{1,4}$/.test(g))) return null;
  const value = (parseInt(groups[0], 16) << 16) | parseInt(groups[1], 16);
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

function isPrivateHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === 'localhost') return true;
  if (h.includes(':')) {
    // IPv6 literal. The WHATWG URL parser already canonicalizes the address
    // (compression, lowercase, shorthand IPv4), so prefix checks are reliable.
    let ip = h;
    if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
    const zone = ip.indexOf('%');
    if (zone !== -1) ip = ip.slice(0, zone);
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true;            // fc00::/7 ULA
    if (ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb')) return true; // fe80::/10
    if (ip.startsWith('ff')) return true;                                    // multicast
    if (ip.startsWith('2002:')) return true;                                 // 6to4 (embeds an IPv4 address)
    if (ip.startsWith('64:ff9b:')) return true;                              // NAT64 well-known prefix (embeds IPv4)
    if (ip.startsWith('2001::') || ip.startsWith('2001:0:')) return true;    // Teredo 2001:0000::/32
    // IPv4-mapped IPv6: dotted tail (::ffff:127.0.0.1) or hex groups (::ffff:7f00:1).
    const mapped = ip.match(/^::ffff:(.+)$/);
    if (mapped) {
      const v4 = ipv4FromMappedTail(mapped[1]);
      return v4 ? isPrivateIPv4(v4) : true;
    }
    return false;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return isPrivateIPv4(h);
  return false; // non-literal hostname: resolved separately via DNS
}

// ---- DNS resolution cache (bounds lookups so hostile subscribes cannot
// spam the resolver / block the event loop) ----
const DNS_CACHE_TTL_MS = 10 * 60 * 1000;
const DNS_FAIL_TTL_MS = 60 * 1000;
const DNS_MAX_CACHE = 500;
const dnsCache = new Map(); // hostname -> { addrs: string[], at: number, ok: boolean }

async function lookupHost(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached) {
    const ttl = cached.ok ? DNS_CACHE_TTL_MS : DNS_FAIL_TTL_MS;
    if (now - cached.at < ttl) return cached.addrs;
    dnsCache.delete(hostname);
  }
  if (dnsCache.size >= DNS_MAX_CACHE) {
    const oldest = dnsCache.keys().next().value;
    dnsCache.delete(oldest);
  }
  let addrs = [];
  let ok = true;
  try {
    const res = await Promise.race([
      dns.promises.lookup(hostname, { all: true, verbatim: true }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('dns timeout')), 1000)),
    ]);
    addrs = res.map(r => r.address);
  } catch {
    ok = false; // NXDOMAIN / timeout: nothing to reach right now
  }
  dnsCache.set(hostname, { addrs, at: now, ok });
  return addrs;
}

function isPrivateAddress(address) {
  const a = String(address).toLowerCase();
  if (a.includes(':')) {
    if (a === '::1' || a === '::') return true;
    if (a.startsWith('fc') || a.startsWith('fd') || a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb') || a.startsWith('ff')) return true;
    // 6to4 embeds an IPv4 address in 2002:V4ADDR::/48; NAT64's well-known
    // prefix 64:ff9b::/96 embeds one in the final 32 bits; Teredo is
    // 2001:0000::/32 (canonical forms start '2001::' or '2001:0:').
    if (a.startsWith('2002:')) return true;
    if (a.startsWith('64:ff9b:')) return true;
    if (a.startsWith('2001::') || a.startsWith('2001:0:')) return true;
    const mapped = a.match(/^::ffff:(.+)$/);
    if (mapped) {
      const v4 = ipv4FromMappedTail(mapped[1]);
      return v4 ? isPrivateIPv4(v4) : true;
    }
    return false;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(a)) return isPrivateIPv4(a);
  return false;
}

// Returns Promise<{ ok: true } | { ok: false, reason }>.
// `platform` is the subscription platform ('web' | 'fcm' | 'apns' | 'ws').
// web-push only ever sends to 'web' subscriptions, so bare tokens are only
// meaningful for the device-token platforms — a 'web' subscription must be a
// real https endpoint.
async function validatePushEndpoint(endpoint, platform) {
  if (typeof endpoint !== 'string' || !endpoint) return { ok: false, reason: 'endpoint is required' };
  // Bare device tokens (fcm/apns/ws) are accepted only if they consist purely
  // of URL-safe token characters AND the platform is not 'web'. Anything else
  // — including leading-whitespace, backslash, scheme-less 'host:port/path',
  // or scheme-prefixed forms — must pass strict https-URL validation, because
  // web-push derives the connection target with the lenient legacy url.parse()
  // at send time (which falls back to loopback for hostless inputs).
  const trimmed = endpoint.trim();
  if (/^[A-Za-z0-9._~-]+$/.test(trimmed)) {
    if (platform === 'web') return { ok: false, reason: 'web push subscriptions require an https endpoint URL' };
    return { ok: true };
  }
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: 'endpoint is not a valid URL' };
  }
  if (url.protocol !== 'https:') {
    return { ok: false, reason: 'push endpoints must use https:' };
  }
  const host = url.hostname.toLowerCase();
  if (isPrivateHostname(host)) {
    return { ok: false, reason: 'push endpoints must target public hosts' };
  }
  if (host.includes(':')) return { ok: true }; // non-private IPv6 literal: fine
  // Hostname (or un-canonicalized IP form): resolve and reject if ANY address
  // is loopback/private/link-local. Fail closed: an endpoint whose host cannot
  // be positively resolved to a public address is refused (real push services
  // always resolve). sendWebPush re-validates at send time, which narrows —
  // though cannot fully eliminate — DNS-rebinding between subscribe and send.
  const addrs = await lookupHost(host);
  if (addrs.length === 0) {
    return { ok: false, reason: 'push endpoint host could not be resolved to a public address' };
  }
  for (const addr of addrs) {
    if (isPrivateAddress(addr)) {
      return { ok: false, reason: 'push endpoints must target public hosts' };
    }
  }
  return { ok: true };
}

// Build an https.Agent whose custom lookup pins the endpoint hostname to the
// addresses validated at send time. web-push (and its legacy url.parse) still
// see the real hostname — SNI and certificate validation are unchanged — but
// the actual connection is made to the pinned public IP, so a DNS rebind after
// validation cannot redirect it to a private host.
function pinnedAgentFor(hostname, addrs) {
  const entries = addrs.map(a => ({ address: a, family: a.includes(':') ? 6 : 4 }));
  return new https.Agent({
    lookup(host, opts, cb) {
      // web-push passes the endpoint hostname verbatim (legacy url.parse keeps
      // its case), so compare case-insensitively against the pinned (lowercased)
      // hostname — otherwise the pin silently falls through to real DNS.
      if (String(host).toLowerCase() === hostname) {
        if (opts && opts.all) return cb(null, entries);
        const e = entries[0];
        return cb(null, e.address, e.family);
      }
      dns.lookup(host, opts, cb);
    },
  });
}

async function sendWebPush(sub, payload) {
  const wp = loadWebPush();
  if (!wp) return;
  const endpoint = String(sub.endpoint || '').trim();
  // Re-validate + resolve right before sending: fails closed on anything the
  // subscribe-time guard missed, and the resolved addresses are pinned for the
  // connection itself (see pinnedAgentFor).
  const check = await validatePushEndpoint(endpoint, 'web');
  if (!check.ok) return;

  let sendOptions = { urgency: 'high', TTL: 120, timeout: 10000 };
  try {
    const host = new URL(endpoint).hostname.toLowerCase();
    // Hostnames get a pinned connection; IPv6 literals are already validated
    // and connect directly (no DNS involved).
    if (!host.includes(':')) {
      const addrs = await lookupHost(host);
      const publicAddrs = addrs.filter(a => !isPrivateAddress(a));
      if (publicAddrs.length === 0) return; // fail closed
      sendOptions.agent = pinnedAgentFor(host, publicAddrs);
    }
  } catch {}

  const pushSub = { endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
  try {
    await wp.sendNotification(
      pushSub,
      JSON.stringify(payload),
      sendOptions
    );
  } catch (err) {
    const status = err.statusCode;
    if (status === 410 || status === 404 || status === 400) {
      try { db.deletePushSubscriptionsByEndpoint(endpoint); } catch {}
    } else if (status) {
      console.error('push: web-push send failed:', status, err.message);
    }
  }
}

// The native app's devices are reached via the signaling WS (sendWsPush in
// webrtc-signaling.js), so this only fans out to browser (web) subscriptions.
async function sendCallPush(calleeUser, callerUser, cancelToken) {
  try {
    const subs = db.getPushSubscriptions(calleeUser.id);
    if (!subs || subs.length === 0) return;
    const payload = {
      type: 'call',
      from: callerUser.username,
      from_display: callerUser.display_name || callerUser.username,
      cancel_token: cancelToken || '',
    };
    for (const sub of subs) {
      if (sub.platform === 'web') {
        await sendWebPush(sub, payload);
      }
    }
  } catch (e) {
    console.error('push: sendCallPush error:', e && e.message);
  }
}

// Offline-call timeout: tell the callee's browsers the call was missed.
// (The native app gets this over the signaling WS instead.)
async function sendMissedCallPush(calleeUser, callerUser) {
  try {
    const subs = db.getPushSubscriptions(calleeUser.id);
    if (!subs || subs.length === 0) return;
    const payload = {
      type: 'missed_call',
      from: callerUser.username,
      from_display: callerUser.display_name || callerUser.username,
    };
    for (const sub of subs) {
      if (sub.platform === 'web') {
        await sendWebPush(sub, payload);
      }
    }
  } catch (e) {
    console.error('push: sendMissedCallPush error:', e && e.message);
  }
}

module.exports = { sendCallPush, sendMissedCallPush, getVapidPublicKey, validatePushEndpoint };
