'use strict';

/**
 * Regression test for public/room-e2ee.js message rendering.
 *
 * Room history should decrypt with whatever local group state exists, without
 * waiting for waste-free group reconciliation to finish. A slow or failed
 * reconcile must not hide messages; a decrypt that fails while membership is
 * still pending stays visibly pending.
 */

const assert = require('assert');

global.window = global;

let observerCallback = null;
global.MutationObserver = function (cb) {
  observerCallback = cb;
  this.observe = function () {};
};
global.setTimeout = function () { return 0; };
global.clearTimeout = function () {};
global.fetch = function () { return Promise.resolve({ ok: true, json: function () { return {}; } }); };

function textNode() {
  return {
    textContent: '…',
    classList: { add: function () {}, remove: function () {} },
  };
}

function messageEl(id, ciphertext) {
  const text = textNode();
  return {
    text: text,
    style: {},
    getAttribute: function (name) {
      return {
        'data-msg-id': String(id),
        'data-proto': 'mls',
        'data-sender-id': '2',
        'data-ciphertext': ciphertext,
      }[name] || null;
    },
    querySelector: function (sel) { return sel === '.room-msg-text' ? text : null; },
  };
}

const msgA = messageEl(1, 'ctA');
const msgB = messageEl(2, 'ctB');

const msgArea = {
  getAttribute: function (name) {
    return { 'data-room-id': '7', 'data-user-id': '1', 'data-channel-id': '9' }[name] || null;
  },
};
const membersEl = {
  getAttribute: function (name) {
    return {
      'data-room-id': '7',
      'data-user-id': '1',
      'data-username': 'alice',
      'data-members': JSON.stringify([{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }]),
    }[name] || null;
  },
};
const button = { disabled: false };
const input = { disabled: false };
const form = {
  querySelector: function (sel) {
    if (sel === 'button[type="submit"]') return button;
    if (sel === 'input[name="body"]') return input;
    return null;
  },
};
const statusEl = { textContent: '' };

global.document = {
  readyState: 'complete',
  getElementById: function (id) {
    return {
      'room-messages': msgArea,
      'room-members': membersEl,
      'room-send-form': form,
      'room-e2ee-status': statusEl,
    }[id] || null;
  },
  querySelector: function () { return null; },
  querySelectorAll: function (sel) {
    if (sel === '#room-messages .room-msg[data-proto="mls"]') return [msgA, msgB];
    return [];
  },
  addEventListener: function () {},
};

const decryptCalls = { ctA: 0, ctB: 0 };
let resolveAlpha;
const alpha = new Promise(function (resolve) { resolveAlpha = resolve; });

global.ExtrovertMLS = {
  init: function () { return Promise.resolve(); },
  ready: function () { return true; },
  // Membership never becomes ready: history must still display from local state.
  reconcileRoomGroup: function () {
    const err = new Error('not added yet');
    err.code = 'ROOM_NOT_JOINED';
    return Promise.reject(err);
  },
  pollRoomGroup: function () { return Promise.resolve(null); },
  clearRoomAddBackoff: function () {},
  roomCacheKey: function (id, ct) { return 'k:' + ct; },
  recallPlaintext: function () { return Promise.resolve(null); },
  rememberPlaintext: function () { return Promise.resolve(); },
  decryptRoomMessage: function (roomId, ciphertext) {
    decryptCalls[ciphertext] = (decryptCalls[ciphertext] || 0) + 1;
    if (ciphertext === 'ctA') return alpha.then(function () { return 'alpha'; });
    return Promise.reject(new Error('cannot decrypt'));
  },
};

require('../public/room-e2ee');

function tick() {
  return new Promise(function (resolve) { setImmediate(resolve); });
}

(async function () {
  await tick();
  await tick();
  await tick();

  assert.strictEqual(decryptCalls.ctA, 1, 'message A should be decrypting');
  assert.strictEqual(decryptCalls.ctB, 1, 'message B should have been attempted');

  // A second observer pass while both jobs are in flight must not decrypt again.
  observerCallback();
  observerCallback();
  assert.strictEqual(decryptCalls.ctA, 1, 'message A must only be decrypted once');
  assert.strictEqual(decryptCalls.ctB, 1, 'message B must only be decrypted once');

  resolveAlpha();
  await tick();
  await tick();

  assert.strictEqual(msgA.text.textContent, 'alpha', 'decrypted history must render');
  assert.notStrictEqual(msgA.style.display, 'none', 'decrypted history must stay visible');

  assert.strictEqual(msgB.text.textContent, '…', 'undecrypted history stays visibly pending');
  assert.notStrictEqual(msgB.style.display, 'none', 'pending history must not be hidden');

  console.log('[OK]   room history decrypts without waiting for membership');
  console.log('[OK]   in-flight messages are decrypted once');
  console.log('[OK]   pending messages stay visible instead of disappearing');
  process.exit(0);
})().catch(function (err) {
  console.error(err);
  process.exit(1);
});
