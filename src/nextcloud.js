'use strict';

// WebDAV client for a user's own Nextcloud, used as an alternative Drive
// backend. A user attaches one instance; files they upload afterwards live
// there instead of this server's disk.
//
// Credentials are a Nextcloud *app password* (Settings → Security → Devices &
// sessions), which the user can revoke without touching their login password.
// Nothing here talks to the database — callers pass a resolved config
// { base_url, username, app_password }.

const fs = require('node:fs');

// Folder created inside the user's Nextcloud for Extrovert uploads.
const FOLDER = 'Extrovert';
const DEFAULT_TIMEOUT_MS = 15000;
// "The folder exists" is remembered per instance so an upload doesn't pay for
// a MKCOL every time. Nextcloud answers 405 for an existing collection.
const DIR_CACHE_TTL_MS = 60 * 60 * 1000;
const ensured = new Map();

function timeoutMs() {
  const n = Number(process.env.EXTV_NEXTCLOUD_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_TIMEOUT_MS;
}

// Canonicalize what the user pasted: an instance URL, optionally with a
// trailing slash or a pasted /remote.php/dav/files/<user> suffix.
function normalizeBaseUrl(raw) {
  const input = String(raw || '').trim();
  if (!input) return { ok: false, error: 'Enter the URL of your Nextcloud instance.' };
  if (input.length > 500) return { ok: false, error: 'That URL is too long.' };
  let url;
  try { url = new URL(input); } catch (e) { return { ok: false, error: 'That does not look like a valid URL.' }; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: 'The URL must start with http:// or https://.' };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'Put your username in the field below, not in the URL.' };
  }
  let pathname = url.pathname.replace(/\/+$/, '');
  const davAt = pathname.toLowerCase().indexOf('/remote.php');
  if (davAt !== -1) pathname = pathname.slice(0, davAt);
  // A pasted app URL (…/index.php/apps/files) still means the instance root.
  const indexAt = pathname.toLowerCase().indexOf('/index.php');
  if (indexAt !== -1) pathname = pathname.slice(0, indexAt);
  return { ok: true, baseUrl: url.origin + pathname };
}

function davRoot(cfg) {
  return cfg.base_url + '/remote.php/dav/files/' + encodeURIComponent(cfg.username);
}

function davUrl(cfg, remotePath) {
  const suffix = String(remotePath).split('/').filter(Boolean).map(encodeURIComponent).join('/');
  return davRoot(cfg) + '/' + suffix;
}

function authHeader(cfg) {
  return 'Basic ' + Buffer.from(cfg.username + ':' + cfg.app_password, 'utf8').toString('base64');
}

async function request(cfg, method, url, opts = {}) {
  // Defence-in-depth for the opt-in private-network ban: refuse literal
  // private targets on every request, not just during the connection probe.
  assertHostAllowed(url);
  const init = {
    method,
    headers: Object.assign({ Authorization: authHeader(cfg) }, opts.headers || {}),
    body: opts.body,
    redirect: 'manual',
  };
  // Node's fetch requires this for a streamed body.
  if (init.body && typeof init.body !== 'string') init.duplex = 'half';
  const t = Number(opts.timeout) || 0;
  if (t > 0) init.signal = AbortSignal.timeout(t);
  return fetch(url, init);
}

function assertHostAllowed(url) {
  if (process.env.EXTV_NEXTCLOUD_BLOCK_PRIVATE !== '1') return;
  const { isPrivateHostname } = require('./push');
  if (isPrivateHostname(new URL(url).hostname)) throw new Error('private storage host refused');
}

function sameOrigin(a, b) {
  try { return new URL(a).origin === new URL(b).origin; } catch (e) { return false; }
}

// Unauthenticated request used by the browser login flow. Never attaches the
// Basic credentials and never follows a redirect to another host silently.
async function publicRequest(method, url, opts = {}) {
  assertHostAllowed(url);
  const init = {
    method,
    headers: Object.assign({ Accept: 'application/json' }, opts.headers || {}),
    body: opts.body,
    redirect: 'manual',
  };
  const t = Number(opts.timeout) || 0;
  if (t > 0) init.signal = AbortSignal.timeout(t);
  return fetch(url, init);
}

// Nextcloud Login Flow v2 — the browser approval the official desktop and
// mobile apps use. The user authenticates on their own Nextcloud (including
// 2FA/SSO) and Nextcloud issues a dedicated, revocable app password. Extrovert
// never sees the account password and never stores one.
//   startLoginFlow -> { loginUrl, pollEndpoint, pollToken }
//   pollLoginFlow  -> { status: 'pending' | 'connected' | 'error', ... }
async function startLoginFlow(baseUrl) {
  const allowed = await hostAllowed(baseUrl);
  if (!allowed.ok) return allowed;
  try {
    const res = await publicRequest('POST', baseUrl + '/index.php/login/v2', {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: '',
      timeout: timeoutMs(),
    });
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok || !data) {
      if (res.status === 404) {
        return { ok: false, error: 'That Nextcloud does not offer the browser login flow (HTTP 404). It may be too old or the endpoint is disabled.' };
      }
      return { ok: false, error: 'Nextcloud could not start the login flow (HTTP ' + res.status + ').' };
    }
    const loginUrl = String(data.login || '');
    const pollEndpoint = String(data.poll && data.poll.endpoint || '');
    const pollToken = String(data.poll && data.poll.token || '');
    if (!loginUrl || !pollEndpoint || !pollToken) {
      return { ok: false, error: 'Nextcloud returned an incomplete login-flow response.' };
    }
    // A compromised or misconfigured server must not make us poll or send the
    // user somewhere else (SSRF / open redirect).
    if (!sameOrigin(loginUrl, baseUrl) || !sameOrigin(pollEndpoint, baseUrl)) {
      return { ok: false, error: 'Nextcloud returned a login flow for a different host; refusing it.' };
    }
    return { ok: true, loginUrl, pollEndpoint, pollToken };
  } catch (err) {
    return { ok: false, error: 'Could not reach that Nextcloud: ' + errorMessage(err) + '.' };
  }
}

async function pollLoginFlow(flow) {
  try {
    assertHostAllowed(flow.pollEndpoint);
  } catch (err) {
    return { status: 'error', message: err.message };
  }
  if (!sameOrigin(flow.pollEndpoint, flow.baseUrl)) {
    return { status: 'error', message: 'The login-flow endpoint changed hosts; refusing it.' };
  }
  try {
    const res = await publicRequest('POST', flow.pollEndpoint, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: flow.pollToken }).toString(),
      timeout: timeoutMs(),
    });
    // 404 means "the user has not approved yet" in login flow v2.
    if (res.status === 404) return { status: 'pending' };
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok || !data) {
      return { status: 'error', message: 'Nextcloud answered HTTP ' + res.status + ' while checking the login.' };
    }
    const username = String(data.loginName || '').trim();
    const appPassword = String(data.appPassword || '');
    if (!username || !appPassword) {
      return { status: 'error', message: 'Nextcloud did not return an app password.' };
    }
    // Prefer the canonical server URL, but only if it is the same host we
    // started the flow with.
    let canonical = flow.baseUrl;
    if (data.server) {
      const norm = normalizeBaseUrl(data.server);
      if (norm.ok && sameOrigin(norm.baseUrl, flow.baseUrl)) canonical = norm.baseUrl;
    }
    return { status: 'connected', baseUrl: canonical, username, appPassword };
  } catch (err) {
    return { status: 'error', message: 'Could not reach that Nextcloud: ' + errorMessage(err) + '.' };
  }
}

// Operators who want to forbid server-side requests to private networks can set
// EXTV_NEXTCLOUD_BLOCK_PRIVATE=1. It is off by default because a self-hosted
// Nextcloud on a LAN is the normal case.
async function hostAllowed(baseUrl) {
  if (process.env.EXTV_NEXTCLOUD_BLOCK_PRIVATE !== '1') return { ok: true };
  const { isPrivateHostname, isPrivateAddress } = require('./push');
  const host = new URL(baseUrl).hostname.toLowerCase();
  if (isPrivateHostname(host)) {
    return { ok: false, error: 'That address is private; this server refuses private storage hosts.' };
  }
  if (host.includes(':')) return { ok: true };
  const dns = require('node:dns');
  let addrs = [];
  try {
    addrs = (await dns.promises.lookup(host, { all: true, verbatim: true })).map((r) => r.address);
  } catch (e) { addrs = []; }
  if (!addrs.length) return { ok: false, error: 'That host could not be resolved.' };
  if (addrs.some((a) => isPrivateAddress(a))) {
    return { ok: false, error: 'That address is private; this server refuses private storage hosts.' };
  }
  return { ok: true };
}

function errorMessage(err) {
  if (!err) return 'Unknown error';
  if (err.name === 'TimeoutError') return 'timed out';
  const code = err.cause && err.cause.code;
  return code || err.message || String(err);
}

// Verify the URL + credentials and that the WebDAV root is reachable.
async function probe(cfg) {
  const allowed = await hostAllowed(cfg.base_url);
  if (!allowed.ok) return allowed;
  try {
    const res = await request(cfg, 'PROPFIND', davRoot(cfg), {
      headers: { Depth: '0' },
      timeout: timeoutMs(),
    });
    let error = null;
    if (res.status === 401) {
      error = 'Nextcloud rejected the stored credential. Reconnect in Settings → Drive.';
    } else if (res.status === 404) {
      error = 'That URL does not look like a Nextcloud instance.';
    } else if (res.status < 200 || res.status > 299) {
      error = 'Nextcloud answered with HTTP ' + res.status + '.';
    }
    try { await res.arrayBuffer(); } catch (e) { /* nothing to drain */ }
    return error ? { ok: false, error } : { ok: true };
  } catch (err) {
    return { ok: false, error: 'Could not reach that Nextcloud: ' + errorMessage(err) + '.' };
  }
}

// Create the Extrovert folder if needed. Cached per instance for an hour.
async function ensureDir(cfg) {
  const key = cfg.base_url + '\n' + cfg.username;
  const hit = ensured.get(key);
  if (hit && Date.now() - hit < DIR_CACHE_TTL_MS) return;
  const res = await request(cfg, 'MKCOL', davUrl(cfg, FOLDER), { timeout: timeoutMs() });
  // 201 = created, 405 = already exists.
  if (res.status !== 201 && res.status !== 405) {
    throw new Error('MKCOL ' + FOLDER + ' failed (HTTP ' + res.status + ')');
  }
  ensured.set(key, Date.now());
}

function remotePathFor(name) {
  return FOLDER + '/' + name;
}

// Called when a connection is added, changed or removed so the next upload
// verifies the folder again.
function resetDirCache() {
  ensured.clear();
}

// Upload a staged local file. Content-Length is sent explicitly, which every
// WebDAV server (and reverse proxy in front of one) accepts.
async function uploadFile(cfg, remotePath, localPath) {
  const stat = await fs.promises.stat(localPath);
  const res = await request(cfg, 'PUT', davUrl(cfg, remotePath), {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(stat.size),
    },
    body: fs.createReadStream(localPath),
  });
  // Drain an error body so the socket can be reused.
  if (!res.ok) {
    try { await res.arrayBuffer(); } catch (e) { /* nothing to drain */ }
    throw new Error('PUT failed (HTTP ' + res.status + ')');
  }
  try { await res.arrayBuffer(); } catch (e) { /* empty 201/204 */ }
}

async function deleteFile(cfg, remotePath) {
  const res = await request(cfg, 'DELETE', davUrl(cfg, remotePath), { timeout: timeoutMs() });
  if (!res.ok && res.status !== 404) {
    try { await res.arrayBuffer(); } catch (e) { /* nothing to drain */ }
    throw new Error('DELETE failed (HTTP ' + res.status + ')');
  }
  try { await res.arrayBuffer(); } catch (e) { /* empty 204 */ }
}

// Fetch a stored file. Range is passed through so video/audio seeking works.
async function openFile(cfg, remotePath, opts = {}) {
  const headers = {};
  if (opts.range) headers.Range = String(opts.range);
  return request(cfg, 'GET', davUrl(cfg, remotePath), { headers });
}

module.exports = {
  FOLDER,
  normalizeBaseUrl,
  remotePathFor,
  resetDirCache,
  startLoginFlow,
  pollLoginFlow,
  probe,
  ensureDir,
  uploadFile,
  deleteFile,
  openFile,
  errorMessage,
};
