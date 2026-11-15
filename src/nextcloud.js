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
  if (process.env.EXTV_NEXTCLOUD_BLOCK_PRIVATE === '1') {
    const { isPrivateHostname } = require('./push');
    if (isPrivateHostname(new URL(url).hostname)) throw new Error('private storage host refused');
  }
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
      error = 'Nextcloud rejected those credentials — use an app password, not your login password.';
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
  probe,
  ensureDir,
  uploadFile,
  deleteFile,
  openFile,
  errorMessage,
};
