'use strict';

const express = require('express');
const { getUserPresence, sendDmEvent } = require('../webrtc-signaling');
const {
  db, getUserByUsername, getUserById, areMutualFollowers,
  sendMessage, getConversations, getMessages, markConversationRead,
  createNotification, setPublicKey, getPublicKey, getEncryptedPrivateKey,
  editMessage, deleteMessage, getEditHistory,
  setDmSecurity, getDmSecurity, ackMessagesReceived,
  setOlmIdentity, getOlmIdentity, addOlmPrekeys, countAvailablePrekeys, claimOlmPrekey, setOlmBackup, requestDmRekey, dmRekeyNeeded, clearDmRekey,
  registerUserDevice, getUserDevices, getUserDevice, touchUserDevice, deleteUserDevice, addDevicePrekeys, countAvailableDevicePrekeys, claimDevicePrekey, claimAllDevicePrekeysForUser, setUserHistoryBackup, getUserHistoryBackup,
} = require('../db');

const router = express.Router();

// Native clients (OAuth Bearer) use the same E2EE routes as the web app.
const { bearerOrSession } = require('../bearer-auth');
router.use(bearerOrSession);

function back(req, fallback = '/') {
  const ref = req.get('referer');
  if (ref && ref.startsWith('/') && !ref.startsWith('//')) return ref;
  return fallback;
}

// Conversation list.
router.get('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const conversations = getConversations(user.id);
  conversations.forEach(function(c) {
    const p = getUserPresence(c.username);
    c.online = p.online;
    const id = getOlmIdentity(c.id);
    c.sender_curve = id ? id.identity_key : null;
    c.security_active = getDmSecurity(user.id, c.id).active;
  });
  res.render('chats', { conversations });
});

// Download encrypted private key for the current user.
router.get('/keys', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).send('Unauthorized');
  const publicKey = getPublicKey(user.id);
  const encryptedPrivateKey = getEncryptedPrivateKey(user.id);
  if (!publicKey) return res.json({ publicKey: null, encryptedPrivateKey: null });
  res.json({ publicKey, encryptedPrivateKey });
});

// Upload public key and optionally an encrypted private key.
router.post('/pubkey', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).send('Unauthorized');
  const pem = String(req.body.publicKey || '');
  const encPriv = String(req.body.encryptedPrivateKey || '').trim() || null;
  if (!pem || pem.length > 5000) return res.status(400).send('Invalid key');
  setPublicKey(user.id, pem, encPriv);
  res.json({ ok: true });
});

// Publish / refresh Olm identity + prekey bundle (supports per-device multi-ID).
router.post('/prekeys', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const deviceId = String(req.body.device_id || '').trim();
  const identityKey = String(req.body.identity_key || '').trim();
  const ed25519Key = String(req.body.ed25519_key || '').trim();
  const fallbackKey = String(req.body.fallback_key || '').trim() || null;
  const deviceName = String(req.body.device_name || '').trim() || null;
  const oneTimeKeys = Array.isArray(req.body.one_time_keys) ? req.body.one_time_keys : [];
  const backup = String(req.body.backup || '').trim().slice(0, 200000) || null;

  if (deviceId && identityKey && ed25519Key) {
    registerUserDevice(user.id, deviceId, identityKey, ed25519Key, fallbackKey, deviceName);
    if (oneTimeKeys.length) {
      const clean = oneTimeKeys
        .filter(k => k && k.id && k.public_key && String(k.public_key).length <= 5000)
        .map(k => ({ id: String(k.id), public_key: String(k.public_key) }));
      if (clean.length) addDevicePrekeys(user.id, deviceId, clean);
    }
  } else if (identityKey) {
    if (!ed25519Key || identityKey.length > 5000 || ed25519Key.length > 5000) {
      return res.status(400).json({ error: 'invalid identity' });
    }
    setOlmIdentity(user.id, identityKey, ed25519Key, fallbackKey);
    if (oneTimeKeys.length) {
      const clean = oneTimeKeys
        .filter(k => k && k.id && k.public_key && String(k.public_key).length <= 5000)
        .map(k => ({ id: String(k.id), public_key: String(k.public_key) }));
      if (clean.length) addOlmPrekeys(user.id, clean);
    }
  }

  if (backup) {
    const backupIdentity = String(req.body.backup_identity || '').trim() || null;
    setOlmBackup(user.id, backup, backupIdentity);
  }
  const avail = deviceId ? countAvailableDevicePrekeys(user.id, deviceId) : countAvailablePrekeys(user.id);
  res.json({ ok: true, available: avail });
});

// Explicit device registration endpoint
router.post('/devices/register', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const deviceId = String(req.body.device_id || '').trim();
  const identityKey = String(req.body.identity_key || '').trim();
  const ed25519Key = String(req.body.ed25519_key || '').trim();
  const fallbackKey = String(req.body.fallback_key || '').trim() || null;
  const deviceName = String(req.body.device_name || '').trim() || null;
  const oneTimeKeys = Array.isArray(req.body.one_time_keys) ? req.body.one_time_keys : [];
  if (!deviceId || !identityKey || !ed25519Key) {
    return res.status(400).json({ error: 'device_id, identity_key, and ed25519_key required' });
  }
  registerUserDevice(user.id, deviceId, identityKey, ed25519Key, fallbackKey, deviceName);
  if (oneTimeKeys.length) {
    const clean = oneTimeKeys
      .filter(k => k && k.id && k.public_key && String(k.public_key).length <= 5000)
      .map(k => ({ id: String(k.id), public_key: String(k.public_key) }));
    if (clean.length) addDevicePrekeys(user.id, deviceId, clean);
  }
  res.json({ ok: true, device_id: deviceId, available: countAvailableDevicePrekeys(user.id, deviceId) });
});

// List all active devices for the current user
router.get('/devices', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  res.json({ devices: getUserDevices(user.id) });
});

// Revoke a device
router.delete('/devices/:deviceId', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  deleteUserDevice(user.id, req.params.deviceId);
  res.json({ ok: true });
});

// Upload password-encrypted history backup
router.post('/history/backup', express.json({ limit: '10mb' }), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const backupData = String(req.body.backup_data || '').trim();
  if (!backupData) return res.status(400).json({ error: 'backup_data required' });
  setUserHistoryBackup(user.id, backupData);
  res.json({ ok: true });
});

// Download password-encrypted history backup
router.get('/history/backup', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const backup = getUserHistoryBackup(user.id);
  res.json({ backup_data: backup ? backup.backup_data : null, updated_at: backup ? backup.updated_at : null });
});

// Download legacy password-encrypted Olm account backup
router.get('/prekeys/backup', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const id = getOlmIdentity(user.id);
  res.json({ backup: id ? id.backup : null, has_identity: !!(id && id.identity_key) });
});

// How many unused one-time prekeys the current user still has published.
router.get('/prekeys/count', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const deviceId = String(req.query.device_id || '').trim();
  const available = deviceId ? countAvailableDevicePrekeys(user.id, deviceId) : countAvailablePrekeys(user.id);
  res.json({ available });
});

// The current user's own published identity
router.get('/prekeys/identity', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const id = getOlmIdentity(user.id);
  res.json({ identity_key: id ? id.identity_key : null, ed25519_key: id ? id.ed25519_key : null });
});

// Fetch a recipient's Olm bundle (all active devices of recipient + sender's other devices).
router.get('/:username/bundle', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const other = getUserByUsername(req.params.username);
  if (!other) return res.status(404).json({ error: 'not found' });
  if (!areMutualFollowers(user.id, other.id)) return res.status(403).json({ error: 'not mutual followers' });

  const recipientDevices = claimAllDevicePrekeysForUser(other.id);
  const senderDevices = claimAllDevicePrekeysForUser(user.id);
  const primaryRecipient = recipientDevices[0] || null;

  res.json({
    devices: recipientDevices,
    sender_devices: senderDevices,
    identity_key: primaryRecipient ? primaryRecipient.identity_key : null,
    ed25519_key: primaryRecipient ? primaryRecipient.ed25519_key : null,
    one_time_key: primaryRecipient ? primaryRecipient.one_time_key : null,
    fallback_key: primaryRecipient ? primaryRecipient.fallback_key : null,
  });
});

// Ratchet-reset protocol: a recipient who could not decrypt an incoming DM
// asks the sender to rebuild the Olm session. The sender checks for pending
// requests before reusing an existing session and acks after rebuilding.
router.post('/rekey/request', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const otherId = Number(req.body && req.body.other_id);
  if (!otherId) return res.status(400).json({ error: 'missing other_id' });
  requestDmRekey(user.id, otherId);
  res.json({ ok: true });
});
router.get('/rekey/needed', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const requesterId = Number(req.query.requester_id);
  if (!requesterId) return res.status(400).json({ error: 'missing requester_id' });
  res.json({ needed: dmRekeyNeeded(user.id, requesterId) });
});
router.post('/rekey/ack', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const requesterId = Number(req.body && req.body.requester_id);
  if (!requesterId) return res.status(400).json({ error: 'missing requester_id' });
  clearDmRekey(requesterId, user.id);
  res.json({ ok: true });
});

// Recipient's ed25519 identity key for safety-number verification.
router.get('/:username/safety', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const other = getUserByUsername(req.params.username);
  if (!other) return res.status(404).json({ error: 'not found' });
  if (!areMutualFollowers(user.id, other.id)) return res.status(403).json({ error: 'not mutual followers' });
  const mine = getOlmIdentity(user.id);
  const theirs = getOlmIdentity(other.id);
  res.json({
    my_ed25519: mine ? mine.ed25519_key : null,
    their_ed25519: theirs ? theirs.ed25519_key : null,
    my_curve25519: mine ? mine.identity_key : null,
    their_curve25519: theirs ? theirs.identity_key : null,
  });
});

// Conversation with a specific user.
router.get('/:username', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.redirect('/login');
  const other = getUserByUsername(req.params.username);
  if (!other) return res.status(404).render('404', { thing: 'user' });
  if (!areMutualFollowers(user.id, other.id)) {
    return res.status(403).send('You can only message mutual followers.');
  }
  const messages = getMessages(user.id, other.id);
  const recipientPubKey = getPublicKey(other.id);
  const recipientCurve = getOlmIdentity(other.id);
  const security = getDmSecurity(user.id, other.id);
  markConversationRead(user.id, other.id);
  res.render('chat', { other, messages, recipientPubKey, recipientCurve, security, wrapClass: 'chat-wrap' });
});

// Send a message.
router.post('/:username/send', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const other = getUserByUsername(req.params.username);
  if (!other || !areMutualFollowers(user.id, other.id)) {
    return req.xhr ? res.json({ error: 'cannot message' }) : res.redirect(back(req, '/chats'));
  }
  const body = String(req.body.body || '').trim().slice(0, 65536);
  const keyForSender = String(req.body.key_for_sender || '').trim() || null;
  const keyForRecipient = String(req.body.key_for_recipient || '').trim() || null;
  const proto = String(req.body.proto || 'rsa').trim() === 'olm' ? 'olm' : 'rsa';
  const senderCiphertext = String(req.body.sender_ciphertext || '').trim().slice(0, 65536) || null;
  const isSticker = body.startsWith('/uploads/stickers/');
  if (body && !isSticker) {
    if (proto !== 'olm' || !senderCiphertext) {
      return req.xhr ? res.json({ error: 'End-to-end encryption required. All messages must be Olm-encrypted.' }) : res.status(400).send('E2EE required');
    }
  }
  if (body) {
    const secure = getDmSecurity(user.id, other.id).active ? 1 : 0;
    const msgId = sendMessage(user.id, other.id, body, keyForSender, keyForRecipient, proto, senderCiphertext, secure);
    createNotification({ userId: other.id, type: 'message', actorId: user.id });
    const msg = db.prepare(`SELECT id, from_id, body, created_at, key_for_sender, key_for_recipient, proto, sender_ciphertext, secure FROM messages WHERE id = ?`).get(msgId);
    // Live-deliver the ciphertext to the recipient's open tab(s) and sender's other devices.
    const senderId = getOlmIdentity(user.id);
    sendDmEvent(other.username, {
      message: msg,
      sender_curve: senderId ? senderId.identity_key : null,
      from_username: user.username,
      from_display: user.display_name,
      to_username: other.username,
    });
    if (user.username !== other.username) {
      sendDmEvent(user.username, {
        message: msg,
        sender_curve: senderId ? senderId.identity_key : null,
        from_username: user.username,
        from_display: user.display_name,
        to_username: other.username,
      });
    }
    if (req.xhr) {
      return res.json({ message: msg });
    }
  }
  res.redirect('/chats/' + other.username);
});

// Toggle "Additional Security" for this conversation (per-user opt-in; the mode
// only becomes active once BOTH users have enabled it).
router.post('/:username/security', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const other = getUserByUsername(req.params.username);
  if (!other || !areMutualFollowers(user.id, other.id)) {
    return res.status(403).json({ error: 'cannot message' });
  }
  const enabled = !!req.body.enabled;
  setDmSecurity(user.id, other.id, enabled);
  res.json({ ok: true, enabled, security: getDmSecurity(user.id, other.id) });
});

// Acknowledge receipt of secure messages. Once the sender AND the recipient have
// both acknowledged, the server deletes the message — it then exists only on the
// participants' devices.
router.post('/:username/received', express.json(), (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'not logged in' });
  const other = getUserByUsername(req.params.username);
  if (!other || !areMutualFollowers(user.id, other.id)) {
    return res.status(403).json({ error: 'cannot message' });
  }
  const ids = Array.isArray(req.body.message_ids)
    ? req.body.message_ids
    : (Array.isArray(req.body.ids) ? req.body.ids : []);
  const result = ackMessagesReceived(user.id, other.id, ids);
  res.json({ ok: true, ...result });
});

// Edit a message.
router.post('/:username/edit/:mid', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const body = String(req.body.body || '').trim().slice(0, 65536);
  if (!body) return req.xhr ? res.json({ error: 'body required' }) : res.redirect(back(req, '/chats'));
  const keyForSender = String(req.body.key_for_sender || '').trim() || null;
  const keyForRecipient = String(req.body.key_for_recipient || '').trim() || null;
  const proto = String(req.body.proto || 'rsa').trim() === 'olm' ? 'olm' : 'rsa';
  const senderCiphertext = String(req.body.sender_ciphertext || '').trim().slice(0, 65536) || null;
  if (!body.startsWith('/uploads/stickers/') && (proto !== 'olm' || !senderCiphertext)) {
    return req.xhr ? res.json({ error: 'End-to-end encryption required. All messages must be Olm-encrypted.' }) : res.status(400).send('E2EE required');
  }
  const ok = editMessage(Number(req.params.mid), user.id, body, keyForSender, keyForRecipient, proto, senderCiphertext);
  if (!ok) return req.xhr ? res.json({ error: 'not found or not yours' }) : res.status(404).send('Message not found or not yours.');
  if (req.xhr) {
    const msg = db.prepare(`SELECT id, from_id, body, created_at, edited_at, key_for_sender, key_for_recipient, proto, sender_ciphertext, secure FROM messages WHERE id = ?`).get(Number(req.params.mid));
    return res.json({ message: msg });
  }
  res.redirect('/chats/' + req.params.username);
});

// Delete a message.
router.post('/:username/delete/:mid', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return req.xhr ? res.json({ error: 'not logged in' }) : res.redirect('/login');
  const other = getUserByUsername(req.params.username);
  if (!other || !areMutualFollowers(user.id, other.id)) {
    return req.xhr ? res.json({ error: 'cannot message' }) : res.redirect(back(req, '/chats'));
  }
  const msgId = Number(req.params.mid);
  const msg = deleteMessage(msgId, user.id);
  if (!msg) return req.xhr ? res.json({ error: 'not found or not yours' }) : res.status(404).send('Message not found or not yours.');

  // Live-notify both the recipient and sender's other tabs
  sendDmEvent(other.username, {
    type: 'delete_dm',
    message_id: msgId,
    from_username: user.username,
  });
  sendDmEvent(user.username, {
    type: 'delete_dm',
    message_id: msgId,
    from_username: user.username,
  });

  if (req.xhr) {
    return res.json({ ok: true, deleted: msgId });
  }
  res.redirect('/chats/' + req.params.username);
});

router.post('/:username/messages/:mid/delete', (req, res) => {
  req.url = `/${encodeURIComponent(req.params.username)}/delete/${encodeURIComponent(req.params.mid)}`;
  router.handle(req, res);
});

module.exports = router;
