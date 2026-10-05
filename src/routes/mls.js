'use strict';

const express = require('express');
const {
  getUserById,
  registerMlsDevice,
  getMlsDevices,
  getMlsDevice,
  revokeMlsDevice,
  saveMlsKeyPackages,
  getMlsKeyPackagesForUser,
  consumeSpecificMlsKeyPackages,
  claimUserMlsKeyPackages,
  getMlsKeyPackageStatus,
  addMlsGroupMember,
  removeMlsGroupMember,
  getMlsGroupMembers,
  isMlsGroupMember,
  getUserMlsGroups,
  saveMlsProposal,
  getPendingMlsProposals,
  consumeMlsProposals,
  getMlsGroup,
  initMlsGroup,
  commitMlsGroup,
  getMlsCommits,
  getMlsWelcomes,
  ackMlsWelcome,
  saveMlsBackup,
  getMlsBackup,
  isRoomMember,
  getHistoricalDmMessagesForMigration,
  getHistoricalRoomMessagesForMigration,
} = require('../db');
const { bearerOrSession } = require('../bearer-auth');

const router = express.Router();
router.use(bearerOrSession);

// Rate limiting map for KeyPackage queries (max 30 per min per IP/user)
const kpRateLimit = new Map();
const KP_RATE_LIMIT_WINDOW = 60000;
const KP_RATE_LIMIT_MAX = 30;

function checkKpRateLimit(identifier) {
  const now = Date.now();
  const entry = kpRateLimit.get(identifier);
  if (!entry || now - entry.start > KP_RATE_LIMIT_WINDOW) {
    kpRateLimit.set(identifier, { start: now, count: 1 });
    return true;
  }
  if (entry.count >= KP_RATE_LIMIT_MAX) return false;
  entry.count++;
  return true;
}

// Clean up stale rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of kpRateLimit.entries()) {
    if (now - v.start > KP_RATE_LIMIT_WINDOW * 2) kpRateLimit.delete(k);
  }
}, 120000).unref();

function requireAuth(req, res, next) {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// 1. Device Registration (Authentication Service attestation)
router.post('/device/register', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const { device_id, device_name, signing_key_pub } = req.body || {};
  if (!device_id || !signing_key_pub) {
    return res.status(400).json({ error: 'device_id and signing_key_pub are required' });
  }

  try {
    const dev = registerMlsDevice(user.id, device_id, device_name, signing_key_pub);
    res.status(201).json({ ok: true, device: dev });
  } catch (err) {
    if (err.code === 'QUOTA_EXCEEDED') {
      return res.status(429).json({ error: err.message, code: 'QUOTA_EXCEEDED' });
    }
    console.error('Error registering MLS device:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. List Active Devices for Current User (or target user)
router.get('/devices', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const targetUserId = req.query.user_id ? parseInt(req.query.user_id, 10) : user.id;
  const devices = getMlsDevices(targetUserId);
  res.json({ ok: true, devices });
});

// 3. Revoke a Device
router.delete('/devices/:deviceId', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const deviceId = req.params.deviceId;
  revokeMlsDevice(user.id, deviceId);
  res.json({ ok: true });
});

const crypto = require('crypto');
const MLS_KEY_PACKAGE_LABEL = Buffer.from('MLS 1.0 KeyPackage Reference', 'utf8');

function computeMlsKeyPackageRef(wireBytes) {
  if (!Buffer.isBuffer(wireBytes) || wireBytes.length < 5) {
    const err = new Error('MalformedKeyPackageWire: payload too short');
    err.code = 'MalformedKeyPackageWire';
    throw err;
  }
  // Validate RFC 9420 MLSMessage framing: protocol_version = 0x0001 (mls10), wireformat = 0x0005 (mls_key_package)
  if (wireBytes[0] !== 0x00 || wireBytes[1] !== 0x01 || wireBytes[2] !== 0x00 || wireBytes[3] !== 0x05) {
    const err = new Error('MalformedKeyPackageWire: header must have protocol mls10 (0x0001) and wireformat mls_key_package (0x0005)');
    err.code = 'MalformedKeyPackageWire';
    throw err;
  }
  const innerKpBytes = wireBytes.slice(4);
  const lenBuf = innerKpBytes.length < 64
    ? Buffer.from([innerKpBytes.length])
    : (innerKpBytes.length < 16384
        ? Buffer.from([((innerKpBytes.length >> 8) & 0x3f) | 0x40, innerKpBytes.length & 0xff])
        : Buffer.from([((innerKpBytes.length >> 24) & 0x3f) | 0x80, (innerKpBytes.length >> 16) & 0xff, (innerKpBytes.length >> 8) & 0xff, innerKpBytes.length & 0xff]));

  return crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from([MLS_KEY_PACKAGE_LABEL.length]), MLS_KEY_PACKAGE_LABEL, lenBuf, innerKpBytes]))
    .digest('hex');
}

// 4. Upload Batch of KeyPackages
router.post('/keypackages', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const { device_id, keypackages } = req.body || {};
  if (!device_id || !Array.isArray(keypackages) || !keypackages.length) {
    return res.status(400).json({ error: 'device_id and non-empty keypackages array required' });
  }

  const dev = getMlsDevice(user.id, device_id);
  if (!dev || dev.revoked_at) {
    return res.status(403).json({ error: 'Device not registered or revoked' });
  }

  for (let i = 0; i < keypackages.length; i++) {
    const p = keypackages[i];
    const dataStr = typeof p === 'string' ? p : (p && (p.data || p.keypackage_data));
    const ref = p && (p.keypackage_ref || p.ref);
    if (!ref || typeof ref !== 'string' || !/^[0-9a-fA-F]{64}$/.test(ref)) {
      return res.status(400).json({
        error: 'Each keypackage must include a valid 64-character hex keypackage_ref',
        index: i
      });
    }
    if (!dataStr) {
      return res.status(400).json({ error: 'Missing keypackage data', index: i });
    }

    let wireBytes;
    try {
      wireBytes = Buffer.from(dataStr, 'base64');
    } catch {
      return res.status(400).json({ error: 'Invalid base64 keypackage data', index: i });
    }

    let expectedRef;
    try {
      expectedRef = computeMlsKeyPackageRef(wireBytes);
    } catch (wireErr) {
      return res.status(400).json({
        error: wireErr.message || 'MalformedKeyPackageWire',
        code: wireErr.code || 'MalformedKeyPackageWire',
        index: i
      });
    }

    if (expectedRef !== ref.toLowerCase()) {
      return res.status(400).json({
        error: 'KeyPackageRefMismatch: provided keypackage_ref does not match RFC 9420 RefHash of wire bytes',
        code: 'KeyPackageRefMismatch',
        expected: expectedRef,
        received: ref,
        index: i
      });
    }
  }

  try {
    const count = saveMlsKeyPackages(user.id, device_id, keypackages);
    res.json({ ok: true, saved: count });
  } catch (err) {
    console.error('Error saving MLS keypackages:', err);
    res.status(500).json({ error: 'Failed to save keypackages' });
  }
});

// 5. Check KeyPackage Pool Status
router.get('/keypackages/status', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const deviceId = req.query.device_id;
  if (!deviceId) return res.status(400).json({ error: 'device_id is required' });

  const available = getMlsKeyPackageStatus(user.id, deviceId);
  res.json({ ok: true, available });
});

// 6. Two-Phase KeyPackage Claiming
// Phase 1: Query available packages without consuming (default), or consume immediately if query ?consume=1
router.get('/keypackages/:userId', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const targetUserId = parseInt(req.params.userId, 10);
  if (!targetUserId || isNaN(targetUserId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  const rateLimitKey = `${user.id}:${req.ip}`;
  if (!checkKpRateLimit(rateLimitKey)) {
    return res.status(429).json({ error: 'Too many KeyPackage requests. Please wait a minute.' });
  }

  const target = getUserById(targetUserId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const isPeek = req.query.peek === '1' || req.query.consume === '0' || req.query.consume === 'false';
  if (isPeek) {
    const available = getMlsKeyPackagesForUser(targetUserId);
    return res.json({ ok: true, user_id: targetUserId, keypackages: available });
  }

  const claimed = claimUserMlsKeyPackages(targetUserId);
  res.json({ ok: true, user_id: targetUserId, keypackages: claimed });
});

// Phase 2: Consume specific packages after commit incorporates them
router.post('/keypackages/consume', requireAuth, (req, res) => {
  const { keypackage_ids } = req.body || {};
  if (!Array.isArray(keypackage_ids) || !keypackage_ids.length) {
    return res.status(400).json({ error: 'keypackage_ids array required' });
  }
  const consumed = consumeSpecificMlsKeyPackages(keypackage_ids);
  res.json({ ok: true, consumed_count: consumed.length, consumed_ids: consumed.map(c => c.id) });
});

// 7. Fetch Pending Welcomes for Device
router.get('/welcomes', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const deviceId = req.query.device_id;
  if (!deviceId) return res.status(400).json({ error: 'device_id is required' });

  const welcomes = getMlsWelcomes(user.id, deviceId);
  res.json({ ok: true, welcomes });
});

// 8. Acknowledge Welcome
router.post('/welcomes/ack', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const { welcome_id, device_id } = req.body || {};
  if (!welcome_id || !device_id) {
    return res.status(400).json({ error: 'welcome_id and device_id are required' });
  }

  const r = ackMlsWelcome(welcome_id, user.id, device_id);
  res.json({ ok: true, changes: r.changes });
});

// 9. Standalone Proposals Management
router.post('/groups/:groupId/proposals', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const groupId = req.params.groupId;
  const { epoch, proposal_ref, sender_leaf, proposal_type, proposal_data, device_id } = req.body || {};

  if (!groupId || epoch === undefined || !proposal_data) {
    return res.status(400).json({ error: 'Missing required proposal fields' });
  }

  // Authorization check
  if (groupId.startsWith('dm:')) {
    const parts = groupId.slice(3).split('_').map(Number);
    if (!parts.includes(user.id)) return res.status(403).json({ error: 'Not authorized' });
  } else if (groupId.startsWith('room:')) {
    const roomId = parseInt(groupId.slice(5), 10);
    if (!isRoomMember(roomId, user.id)) return res.status(403).json({ error: 'Not a room member' });
  }

  const pRef = proposal_ref || require('crypto').createHash('sha256').update(String(proposal_data)).digest('hex');
  const pType = typeof proposal_type === 'number' ? proposal_type : (proposal_type === 'remove' ? 3 : (proposal_type === 'update' ? 2 : 1));
  const sLeaf = Number(sender_leaf) || 0;

  saveMlsProposal(groupId, epoch, pRef, sLeaf, pType, proposal_data);
  res.status(201).json({ ok: true, proposal_ref: pRef });
});

router.get('/groups/:groupId/proposals', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const groupId = req.params.groupId;
  const epoch = parseInt(req.query.epoch, 10);
  if (isNaN(epoch)) return res.status(400).json({ error: 'epoch query parameter required' });

  if (groupId.startsWith('dm:')) {
    const parts = groupId.slice(3).split('_').map(Number);
    if (!parts.includes(user.id)) return res.status(403).json({ error: 'Not authorized' });
  }

  const proposals = getPendingMlsProposals(groupId, epoch);
  res.json({ ok: true, proposals });
});

// 10. Atomic Group Initialization
router.post('/groups/init', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const { group_id, initial_commit, welcomes, members, device_id, idempotency_key } = req.body || {};
  if (!group_id) return res.status(400).json({ error: 'group_id is required' });

  // Authorization: for DMs (dm:uid1_uid2), caller must be one of the participants
  if (group_id.startsWith('dm:')) {
    const parts = group_id.slice(3).split('_').map(Number);
    if (!parts.includes(user.id)) {
      return res.status(403).json({ error: 'Not authorized for this DM group' });
    }
  } else if (group_id.startsWith('room:')) {
    const roomId = parseInt(group_id.slice(5), 10);
    if (!isRoomMember(roomId, user.id)) {
      return res.status(403).json({ error: 'Not a member of this room' });
    }
  }

  const initialMembers = Array.isArray(members) && members.length ? members : (device_id ? [{ user_id: user.id, device_id, leaf_index: 0, role: 'creator' }] : []);

  try {
    const response = initMlsGroup(group_id, 0, initialMembers, initial_commit || null, welcomes || [], idempotency_key || null);
    res.status(201).json(response);
  } catch (err) {
    if (err.code === 'GROUP_EXISTS') {
      return res.status(409).json({ error: 'GroupExists', epoch: err.epoch });
    }
    console.error('Error initializing MLS group:', err);
    res.status(500).json({ error: 'Failed to initialize group' });
  }
});

// 11. Atomic Commit Submission with CAS Epoch Check
router.post('/groups/:groupId/commit', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const groupId = req.params.groupId;
  const { current_epoch, commit_message, welcomes, proposals_consumed, members_added, members_removed, device_id, idempotency_key } = req.body || {};

  if (current_epoch === undefined || !commit_message) {
    return res.status(400).json({ error: 'current_epoch and commit_message are required' });
  }

  // Authorization check
  if (groupId.startsWith('dm:')) {
    const parts = groupId.slice(3).split('_').map(Number);
    if (!parts.includes(user.id)) {
      return res.status(403).json({ error: 'Not a member of this conversation' });
    }
  } else if (groupId.startsWith('room:')) {
    const roomId = parseInt(groupId.slice(5), 10);
    if (!isRoomMember(roomId, user.id)) {
      return res.status(403).json({ error: 'Not a member of this room' });
    }
  }

  try {
    const result = commitMlsGroup(
      groupId,
      current_epoch,
      commit_message,
      welcomes || [],
      proposals_consumed || [],
      members_added || [],
      members_removed || [],
      idempotency_key || null
    );
    res.json(result);
  } catch (err) {
    if (err.code === 'EPOCH_CONFLICT') {
      return res.status(409).json({
        error: 'EpochConflict',
        expected_epoch: current_epoch,
        server_epoch: err.server_epoch,
      });
    }
    if (err.code === 'GROUP_NOT_FOUND') {
      return res.status(404).json({ error: 'GroupNotFound' });
    }
    console.error('Error committing to MLS group:', err);
    res.status(500).json({ error: 'Failed to advance group epoch' });
  }
});

// 12. Query Catch-Up Commits (for offline sync & Welcome catch-up)
router.get('/groups/:groupId/commits', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const groupId = req.params.groupId;
  const since = parseInt(req.query.since || '-1', 10);

  if (groupId.startsWith('dm:')) {
    const parts = groupId.slice(3).split('_').map(Number);
    if (!parts.includes(user.id)) {
      return res.status(403).json({ error: 'Not a member of this conversation' });
    }
  } else if (groupId.startsWith('room:')) {
    const roomId = parseInt(groupId.slice(5), 10);
    if (!isRoomMember(roomId, user.id)) {
      return res.status(403).json({ error: 'Not a member of this room' });
    }
  }

  const commits = getMlsCommits(groupId, since);
  res.json({ ok: true, group_id: groupId, commits });
});

// 13. Encrypted Credential Backup
router.get('/backup', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const backup = getMlsBackup(user.id);
  res.json({ ok: true, backup });
});

router.post('/backup', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const { backup_data, salt } = req.body || {};
  if (!backup_data || !salt) {
    return res.status(400).json({ error: 'backup_data and salt are required' });
  }

  saveMlsBackup(user.id, backup_data, salt);
  res.json({ ok: true });
});

// 14. Historical Messages for Pre-Decryption Migration Worker
router.get('/migration/messages', requireAuth, (req, res) => {
  const user = res.locals.currentUser;
  const dmCursor = parseInt(req.query.dm_cursor, 10) || 0;
  const roomCursor = parseInt(req.query.room_cursor, 10) || 0;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);

  const dmMessages = getHistoricalDmMessagesForMigration(user.id, dmCursor, limit);
  const remainingLimit = limit - dmMessages.length;
  const roomMessages = remainingLimit > 0
    ? getHistoricalRoomMessagesForMigration(user.id, roomCursor, remainingLimit)
    : [];

  const nextDmCursor = dmMessages.length ? dmMessages[dmMessages.length - 1].id : dmCursor;
  const nextRoomCursor = roomMessages.length ? roomMessages[roomMessages.length - 1].id : roomCursor;
  const hasMore = dmMessages.length === limit || (remainingLimit > 0 && roomMessages.length === remainingLimit);

  res.json({
    ok: true,
    dm_messages: dmMessages,
    room_messages: roomMessages,
    next_dm_cursor: nextDmCursor,
    next_room_cursor: nextRoomCursor,
    has_more: hasMore
  });
});

module.exports = router;
