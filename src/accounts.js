'use strict';

// Multi-account session helpers (planned.md F1).
//
// A session keeps two related pieces of state:
//   - `req.session.accountIds` — the ordered list of accounts signed in on
//     this device (login order).
//   - `req.session.userId`     — the ACTIVE account; every existing
//     `req.session.userId` read site keeps working unchanged (compat shim).
// Login adds to the list + sets active; logout removes from the list; switching
// only swaps `userId`. The session is destroyed only when the last account is
// removed, so switching accounts never invalidates other sessions/tokens.

const { getUserById } = require('./db');

// Ordered list of account ids signed in on this device/session.
// Legacy sessions (pre multi-account) have no `accountIds` — the active
// account is the only signed-in account.
function getAccountIds(req) {
  if (Array.isArray(req.session.accountIds) && req.session.accountIds.length > 0) {
    return req.session.accountIds.slice();
  }
  return req.session.userId ? [req.session.userId] : [];
}

// Full user rows for every signed-in account, in login order (active first is
// NOT guaranteed — consumers compare against req.session.userId). If a listed
// account no longer exists (deleted from this or another device), it is
// dropped from the device list and — when it was the active account — the
// device falls back to the first remaining account (or signs out entirely).
function getSignedInAccounts(req) {
  const ids = getAccountIds(req);
  const accounts = [];
  let ghostFound = false;
  for (const id of ids) {
    const u = getUserById(id);
    if (u) accounts.push(u);
    else ghostFound = true;
  }
  if (ghostFound) {
    req.session.accountIds = accounts.map((a) => a.id);
    if (req.session.userId && !accounts.some((a) => a.id === req.session.userId)) {
      req.session.userId = accounts.length ? accounts[0].id : undefined;
    }
  }
  return accounts;
}

// Add an account to the device list and make it active (login / add-account).
function addAccount(req, userId) {
  const ids = getAccountIds(req);
  if (!ids.includes(userId)) ids.push(userId);
  req.session.accountIds = ids;
  req.session.userId = userId;
  return ids;
}

// Make `userId` the active account. Returns false when it is not signed in on
// this device.
function setActiveAccount(req, userId) {
  const ids = getAccountIds(req);
  if (!ids.includes(userId)) return false;
  req.session.userId = userId;
  req.session.accountIds = ids;
  return true;
}

// Remove one account from the device list. Returns:
//   'destroyed'  — the last account was removed; the caller must destroy the
//                  whole session (no accounts left on this device).
//   'removed'    — the account was removed; if it was active, the first
//                  remaining account becomes active.
//   'not-found'  — the account is not signed in on this device.
function removeAccount(req, userId) {
  const ids = getAccountIds(req);
  if (!ids.includes(userId)) return 'not-found';
  const remaining = ids.filter((id) => id !== userId);
  if (remaining.length === 0) {
    delete req.session.accountIds;
    delete req.session.userId;
    return 'destroyed';
  }
  req.session.accountIds = remaining;
  if (req.session.userId === userId) req.session.userId = remaining[0];
  return 'removed';
}

module.exports = { getAccountIds, getSignedInAccounts, addAccount, setActiveAccount, removeAccount };
