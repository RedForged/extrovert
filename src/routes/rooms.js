'use strict';

const express = require('express');
const { sanitizeProfileHTML, sanitizeCSS } = require('../sanitize');

const {
  createRoom, getRoom, getRoomsForUser, getAvailableRooms, updateRoom, deleteRoom,   deleteRoomMessage, editRoomMessage, getEditHistory,
  isRoomMember, addRoomMember, removeRoomMember, getRoomMember, getRoomMembers, getUserRoomRole, countRoomMembers,
  createRoomRole, getRoomRole, getRoomRoles, updateRoomRole, deleteRoomRole, transferFounder,
  createRoomChannel, getRoomChannel, getRoomChannels, updateRoomChannel, deleteRoomChannel,
  getRoomMessages, sendRoomMessage, joinDefaultRole, hasRoomPermission, roomPermissionsFor, canViewRoom, canViewRoomChannel, getUserById, getUserByUsername, db,
  createContentReport,
  createJoinRequest, getJoinRequests, getJoinRequestById, approveJoinRequest, rejectJoinRequest, hasPendingRequest,
  publishRoomGroupSession, getRoomGroupSession, isRoomGroupSessionUsable, saveRoomSessionKeys, ensureRoomSessionRecipient, getPendingRoomSessionKeys, getRoomSessionKeyById, markRoomSessionKeyDelivered, getRoomSessionRecipients, getRoomSessionEmptyKeyRecipients,
  getOlmIdentity, getAllDeviceBundlesForUser, claimAllDevicePrekeysForUser,
} = require('../db');

// Room ciphertext cap — oversize payloads are rejected, never truncated.
const ROOM_CT_MAX = 20000;
const ROOM_BODY_MAX = 20000;

const router = express.Router();

// Native clients (OAuth Bearer) use the same routes as the web app. Scopes are
// route-specific: room administration needs `write`, encrypted message/key
// operations need `write:direct`, and reads need `read:direct`.
const { bearerOrSession, requireBearerScope } = require('../bearer-auth');
const { broadcastGatewayEvent } = require('../webrtc-signaling');
router.use(bearerOrSession);

const readScope = requireBearerScope('read');
const readDirect = requireBearerScope('read:direct');
const writeDirect = requireBearerScope('write:direct');
const writeScope = requireBearerScope('write');

const { getVoiceChannelMembers, pushRoomSessionKeyToRecipient, updateUserRoomSubscriptions, removeFromVoiceChannels } = require('../webrtc-signaling');

const PERM = { VIEW: 1, WRITE: 2, MANAGE_CHANNELS: 4, MANAGE_ROLES: 8, MANAGE_MESSAGES: 16, MANAGE_MEMBERS: 32, MANAGE_ROOM: 64 };

function checkPerm(roomId, userId, perm) {
  return hasRoomPermission(roomId, userId, perm);
}

// List rooms
router.get('/', readScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const myRooms = getRoomsForUser(res.locals.currentUser.id)
    .filter(room => canViewRoom(room.id, res.locals.currentUser.id));
  const available = getAvailableRooms(res.locals.currentUser.id);
  res.render('rooms/index', { myRooms, available });
});

// Create room form
router.get('/create', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  res.render('rooms/create');
});

// Create room
router.post('/create', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(res.locals.currentUser)) return res.status(403).send('Your email address must be verified before you can create rooms.');
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const isPublic = req.body.is_public !== '0';
  if (!name) return res.redirect('/rooms/create');
  const roomId = createRoom(name, description, res.locals.currentUser.id, isPublic);
  res.redirect('/rooms/' + roomId);
});

// View room
router.get('/:id', readScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).render('404', { thing: 'room' });
  const userId = res.locals.currentUser.id;
  const isAdmin = res.locals.currentUser.is_admin;
  const isMember = isRoomMember(room.id, userId);
  if (!isMember) {
    // Private rooms are invisible to non-members (matching the API), so their
    // name/description/custom HTML are not disclosed by enumerating room ids.
    if (!room.is_public && !isAdmin) return res.status(404).render('404', { thing: 'room' });
    const members = getRoomMembers(room.id);
    const roles = getRoomRoles(room.id);
    const channels = getRoomChannels(room.id);
    const pending = hasPendingRequest(room.id, userId);
    return res.render('rooms/room-info', { room, members, roles, channels, isAdmin, pending });
  }
  if (!canViewRoom(room.id, userId)) return res.status(403).send('No permission to view this room');

  let role, channels;
  if (isMember) {
    role = getUserRoomRole(room.id, userId);
    channels = getRoomChannels(room.id).filter(ch => canViewRoomChannel(ch.id, userId));
  } else {
    role = null;
    channels = getRoomChannels(room.id);
  }
  const members = getRoomMembers(room.id);
  const roles = getRoomRoles(room.id);
  const myMembership = getRoomMember(room.id, userId);
  const joinedAt = myMembership ? Number(myMembership.joined_at) : 0;

  const firstChannel = channels[0];
  let messages = [];
  const directReadAllowed = res.locals.bearerScopes === undefined
    || String(res.locals.bearerScopes).split(/\s+/).includes('read:direct');
  if (firstChannel && directReadAllowed) messages = getRoomMessages(firstChannel.id, null, joinedAt);

  const voiceChannelMembers = {};
  channels.forEach(ch => {
    if (ch.type === 'voice') voiceChannelMembers[ch.id] = getVoiceChannelMembers(ch.id);
  });

  res.render('rooms/room', { room, channels, members, roles, role, messages, firstChannel, voiceChannelMembers });
});

// Join room
router.post('/:id/join', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  const userId = res.locals.currentUser.id;
  if (isRoomMember(room.id, userId)) return res.redirect('/rooms/' + room.id);
  if (!room.is_public && !res.locals.currentUser.is_admin) return res.status(403).send('This room is private');
  const defaultRole = joinDefaultRole(room.id);
  if (defaultRole) addRoomMember(room.id, userId, defaultRole.id);
  updateUserRoomSubscriptions(userId, room.id, 'join');
  broadcastGatewayEvent('room:' + room.id, 'member_join', {
    room_id: String(room.id),
    user_id: String(userId),
    username: res.locals.currentUser.username,
    display_name: res.locals.currentUser.display_name,
  });
  res.redirect('/rooms/' + room.id);
});

// Announce that this device has registered its MLS keys, so members currently
// viewing the room can fold it into the encryption group.
router.post('/:id/mls-ready', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json({ error: 'Not logged in' });
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const user = res.locals.currentUser;
  if (!isRoomMember(room.id, user.id)) return res.status(403).json({ error: 'Not a member' });
  broadcastGatewayEvent('room:' + room.id, 'member_join', {
    room_id: String(room.id),
    user_id: String(user.id),
    username: user.username,
    display_name: user.display_name,
  });
  res.json({ ok: true });
});

// Leave room
router.post('/:id/leave', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  const userId = res.locals.currentUser.id;
  const role = getUserRoomRole(room.id, userId);
  if (role && role.is_founder) {
    const members = getRoomMembers(room.id);
    const others = members.filter(m => m.user_id !== userId);
    if (others.length === 0) { deleteRoom(room.id); return res.redirect('/rooms'); }
    return res.status(400).send('Transfer founder before leaving');
  }
  removeRoomMember(room.id, userId);
  // Revoke realtime access on this socket immediately (matches the kick path):
  // otherwise a left member keeps receiving the room's live events.
  updateUserRoomSubscriptions(userId, room.id, 'leave');
  removeFromVoiceChannels(userId);
  broadcastGatewayEvent('room:' + room.id, 'member_leave', {
    room_id: String(room.id),
    user_id: String(userId),
    username: res.locals.currentUser.username,
  });
  res.redirect('/rooms');
});

// --- Settings ---

router.get('/:id/settings', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).render('404', { thing: 'room' });
  const isAdmin = res.locals.currentUser.is_admin;
  if (!isAdmin && !checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROOM)) return res.status(403).send('No permission');
  res.render('rooms/settings', { room });
});

router.post('/:id/settings', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  const isAdmin = res.locals.currentUser.is_admin;
  if (!isAdmin && !checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROOM)) return res.status(403).send('No permission');
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const html = sanitizeProfileHTML(req.body.html || '');
  const css = sanitizeCSS(req.body.css || '');
  if (!name) return res.redirect('/rooms/' + room.id + '/settings');
  const isPublic = req.body.is_public !== '0';
  updateRoom(room.id, name, description, html, css, isPublic);
  res.redirect('/rooms/' + room.id);
});

router.post('/:id/delete', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  const isAdmin = res.locals.currentUser.is_admin;
  const role = getUserRoomRole(room.id, res.locals.currentUser.id);
  if (!isAdmin && (!role || !role.is_founder)) return res.status(403).send('Only founder can delete');
  if (!isAdmin) {
    if (String(req.body.confirm_delete) !== 'DELETE') return res.status(400).send('Please type DELETE to confirm');
    if (String(req.body.confirm_name) !== room.name) return res.status(400).send('Room name does not match');
  }
  deleteRoom(room.id);
  res.redirect('/rooms');
});

// --- Channels ---

router.get('/:id/channels', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).render('404', { thing: 'room' });
  if (!canViewRoom(room.id, res.locals.currentUser.id)) return res.status(403).send('No permission');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_CHANNELS)) return res.status(403).send('No permission');
  const channels = getRoomChannels(room.id);
  const roles = getRoomRoles(room.id);
  res.render('rooms/channels', { room, channels, roles });
});

router.post('/:id/channels/create', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_CHANNELS)) return res.status(403).send('No permission');
  const name = String(req.body.name || '').trim();
  if (!name) return res.redirect('/rooms/' + room.id + '/channels');
  function rolesToJson(val) {
    if (!val) return null;
    const arr = Array.isArray(val) ? val : [val];
    return JSON.stringify(arr.map(Number));
  }
  const viewRoles = rolesToJson(req.body.view_roles);
  const writeRoles = rolesToJson(req.body.write_roles);
  const channelType = String(req.body.type || 'text').trim();
  createRoomChannel(room.id, name, viewRoles, writeRoles, channelType);
  res.redirect('/rooms/' + room.id + '/channels');
});

router.post('/:id/channels/:cid/delete', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_CHANNELS)) return res.status(403).send('No permission');
  // The channel must belong to THIS room — otherwise a manager of one room
  // could delete another room's channel (and all its messages) by id.
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.status(404).send('Channel not found');
  deleteRoomChannel(channel.id);
  res.redirect('/rooms/' + room.id + '/channels');
});

// --- Roles ---

router.get('/:id/roles', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).render('404', { thing: 'room' });
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROLES)) return res.status(403).send('No permission');
  const roles = getRoomRoles(room.id);
  res.render('rooms/roles', { room, roles });
});

router.post('/:id/roles/create', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROLES)) return res.status(403).send('No permission');
  const name = String(req.body.name || '').trim();
  if (!name) return res.redirect('/rooms/' + room.id + '/roles');
  const color = /^#[0-9a-fA-F]{6}$/.test(String(req.body.color || '').trim()) ? String(req.body.color).trim() : '#cccccc';
  let permissions = 0;
  if (req.body.can_view) permissions |= PERM.VIEW;
  if (req.body.can_write) permissions |= PERM.WRITE;
  if (req.body.can_manage_channels) permissions |= PERM.MANAGE_CHANNELS;
  if (req.body.can_manage_roles) permissions |= PERM.MANAGE_ROLES;
  if (req.body.can_manage_messages) permissions |= PERM.MANAGE_MESSAGES;
  if (req.body.can_manage_members) permissions |= PERM.MANAGE_MEMBERS;
  if (req.body.can_manage_room) permissions |= PERM.MANAGE_ROOM;
  // A role may not carry permissions its creator does not hold.
  if (permissions & ~roomPermissionsFor(room.id, res.locals.currentUser.id)) return res.status(403).send('Cannot grant permissions you do not hold');
  createRoomRole(room.id, name, color, permissions, 0);
  res.redirect('/rooms/' + room.id + '/roles');
});

router.post('/:id/roles/:rid/update', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROLES)) return res.status(403).send('No permission');
  const role = getRoomRole(Number(req.params.rid));
  if (!role || role.room_id !== room.id) return res.status(404).send('Role not found');
  if (role.is_founder) return res.status(400).send('Cannot edit founder role');
  const name = String(req.body.name || '').trim();
  const color = /^#[0-9a-fA-F]{6}$/.test(String(req.body.color || '').trim()) ? String(req.body.color).trim() : '#cccccc';
  let permissions = 0;
  if (req.body.can_view) permissions |= PERM.VIEW;
  if (req.body.can_write) permissions |= PERM.WRITE;
  if (req.body.can_manage_channels) permissions |= PERM.MANAGE_CHANNELS;
  if (req.body.can_manage_roles) permissions |= PERM.MANAGE_ROLES;
  if (req.body.can_manage_messages) permissions |= PERM.MANAGE_MESSAGES;
  if (req.body.can_manage_members) permissions |= PERM.MANAGE_MEMBERS;
  if (req.body.can_manage_room) permissions |= PERM.MANAGE_ROOM;
  if (permissions & ~roomPermissionsFor(room.id, res.locals.currentUser.id)) return res.status(403).send('Cannot grant permissions you do not hold');
  updateRoomRole(role.id, name || role.name, color, permissions || 0);
  res.redirect('/rooms/' + room.id + '/roles');
});

router.post('/:id/roles/:rid/delete', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_ROLES)) return res.status(403).send('No permission');
  // The role must belong to THIS room.
  const role = getRoomRole(Number(req.params.rid));
  if (!role || role.room_id !== room.id) return res.status(404).send('Role not found');
  if (!deleteRoomRole(role.id)) {
    return res.status(400).send('Cannot delete the founder/default role, or a role still assigned to members');
  }
  res.redirect('/rooms/' + room.id + '/roles');
});

// --- Members ---

router.get('/:id/members', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).render('404', { thing: 'room' });
  if (!canViewRoom(room.id, res.locals.currentUser.id)) return res.status(403).send('No permission');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const members = getRoomMembers(room.id);
  const roles = getRoomRoles(room.id);
  const requests = getJoinRequests(room.id);
  res.render('rooms/members', { room, members, roles, requests });
});

router.post('/:id/members/:uid/setrole', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const roleId = Number(req.body.role_id);
  const targetUser = getUserById(Number(req.params.uid));
  if (!targetUser) return res.status(404).send('User not found');
  const targetRole = getRoomRole(roleId);
  if (!targetRole || targetRole.room_id !== room.id) return res.status(404).send('Role not found');
  if (targetRole.is_founder) return res.status(400).send('Cannot assign founder role');
  if (targetRole.permissions & ~roomPermissionsFor(room.id, res.locals.currentUser.id)) return res.status(403).send('Cannot assign a role with permissions you do not hold');
  const currentMemberRole = getUserRoomRole(room.id, targetUser.id);
  if (currentMemberRole && currentMemberRole.is_founder) return res.status(400).send('Cannot change founder role');
  db.prepare(`UPDATE room_members SET role_id = ? WHERE room_id = ? AND user_id = ?`).run(roleId, room.id, targetUser.id);
  res.redirect('/rooms/' + room.id + '/members');
});

router.post('/:id/members/:uid/kick', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const targetUser = getUserById(Number(req.params.uid));
  if (!targetUser) return res.status(404).send('User not found');
  const currentMemberRole = getUserRoomRole(room.id, targetUser.id);
  if (currentMemberRole && currentMemberRole.is_founder) return res.status(400).send('Cannot kick founder');
  removeRoomMember(room.id, targetUser.id);
  // Revoke realtime access on the kicked member's live socket right away.
  updateUserRoomSubscriptions(targetUser.id, room.id, 'leave');
  removeFromVoiceChannels(targetUser.id);
  broadcastGatewayEvent('room:' + room.id, 'member_leave', {
    room_id: String(room.id),
    user_id: String(targetUser.id),
    username: targetUser.username,
  });
  res.redirect('/rooms/' + room.id + '/members');
});

// Transfer founder
router.post('/:id/transfer', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  const userId = res.locals.currentUser.id;
  const myRole = getUserRoomRole(room.id, userId);
  if (!myRole || !myRole.is_founder) return res.status(403).send('Only founder can transfer');
  const newOwnerId = Number(req.body.user_id);
  if (!newOwnerId) return res.status(400).send('No user specified');
  if (!isRoomMember(room.id, newOwnerId)) return res.status(400).send('User is not a member');
  transferFounder(room.id, newOwnerId);
  const defaultRole = joinDefaultRole(room.id);
  if (defaultRole) db.prepare(`UPDATE room_members SET role_id = ? WHERE room_id = ? AND user_id = ?`).run(defaultRole.id, room.id, userId);
  res.redirect('/rooms/' + room.id + '/members');
});

// --- Messages (AJAX) ---

router.get('/:id/channels/:cid/messages', readDirect, (req, res) => {
  if (!res.locals.currentUser) return res.json([]);
  const room = getRoom(Number(req.params.id));
  if (!room) return res.json([]);
  if (!canViewRoom(room.id, res.locals.currentUser.id)) return res.json([]);
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.json([]);
  if (!canViewRoomChannel(channel.id, res.locals.currentUser.id)) return res.json([]);
  const role = getUserRoomRole(room.id, res.locals.currentUser.id);
  const before = req.query.before ? Number(req.query.before) : null;
  const myMembership = getRoomMember(room.id, res.locals.currentUser.id);
  const joinedAt = myMembership ? Number(myMembership.joined_at) : 0;
  const messages = getRoomMessages(channel.id, before, joinedAt);
  const roles = getRoomRoles(room.id);
  const members = getRoomMembers(room.id);
  const roleMap = {};
  members.forEach(function(m) {
    var r = roles.find(function(rr) { return rr.id === m.role_id; });
    if (r) roleMap[m.user_id] = r.color;
  });
  const canDelete = !!(role && role.permissions & PERM.MANAGE_MESSAGES) || res.locals.currentUser.is_admin;
  res.json({
    messages,
    roles,
    roleMap,
    canDelete,
    members: members.map(m => ({ user_id: m.user_id, username: m.username, display_name: m.display_name, avatar: m.avatar, role_id: m.role_id })),
  });
});

router.post('/:id/channels/:cid/send', writeDirect, (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json({ error: 'Not logged in' });
  const { requireVerifiedEmail: gate } = require('../db');
  if (gate(res.locals.currentUser)) return res.status(403).json({ error: 'email_unverified' });
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (!isRoomMember(room.id, res.locals.currentUser.id)) return res.status(403).json({ error: 'Not a member' });
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.status(404).json({ error: 'Channel not found' });
  if (!res.locals.currentUser.is_admin && !canViewRoomChannel(channel.id, res.locals.currentUser.id)) return res.status(403).json({ error: 'No view permission' });
  const role = getUserRoomRole(room.id, res.locals.currentUser.id);
  if (channel.write_role_ids) {
    try {
      const writeRoles = JSON.parse(channel.write_role_ids);
      if (Array.isArray(writeRoles) && !writeRoles.includes(role.id)) return res.status(403).json({ error: 'No write permission' });
    } catch {}
  }
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.WRITE)) return res.status(403).json({ error: 'No write permission' });
  const body = String(req.body.body || '').trim();
  const rawProto = String(req.body.proto || '').trim();
  const ciphertextRaw = String(req.body.ciphertext || '').trim();
  const isSticker = body.startsWith('/uploads/stickers/');
  if (!isSticker) {
    if (!ciphertextRaw) return res.status(400).json({ error: 'Message is empty' });
    if (ciphertextRaw.length > ROOM_CT_MAX) {
      return res.status(400).json({ error: 'Message is too long.' });
    }
    if (rawProto !== 'mls') {
      return res.status(426).json({
        error: 'LegacyProtocolRetired',
        message: 'Extrovert now uses pure MLS encryption (RFC 9420). Please refresh your browser tab to continue messaging.'
      });
    }
  }
  const ciphertext = ciphertextRaw || null;
  const user = res.locals.currentUser;
  const clientMsgId = String(req.body.client_msg_id || '').trim().slice(0, 64) || null;
  const msgId = sendRoomMessage(channel.id, user.id, isSticker ? body : '', 'mls', ciphertext, null);
  broadcastGatewayEvent('room:' + room.id, 'message_create', {
    id: String(msgId),
    room_id: String(room.id),
    channel_id: String(channel.id),
    user_id: String(user.id),
    author: { id: String(user.id), username: user.username, display_name: user.display_name },
    proto: isSticker ? 'plain' : 'mls',
    body: isSticker ? body : '',
    ciphertext: isSticker ? null : ciphertext,
    client_msg_id: clientMsgId,
    created_at: new Date().toISOString(),
  });
  res.json({ id: msgId, client_msg_id: clientMsgId });
});

// Delete a message
router.post('/:id/channels/:cid/messages/:mid/delete', writeDirect, (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json({ error: 'Not logged in' });
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const userId = res.locals.currentUser.id;
  if (!isRoomMember(room.id, userId) && !res.locals.currentUser.is_admin) return res.status(403).json({ error: 'Not a member' });
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.status(404).json({ error: 'Channel not found' });
  if (!res.locals.currentUser.is_admin && !canViewRoomChannel(channel.id, userId)) return res.status(403).json({ error: 'No view permission' });
  const msgId = Number(req.params.mid);
  const msgs = getRoomMessages(channel.id);
  const msg = msgs.find(m => m.id === msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const canDeleteOwn = msg.user_id === userId;
  const canModerate = checkPerm(room.id, userId, PERM.MANAGE_MESSAGES);
  if (!canDeleteOwn && !canModerate && !res.locals.currentUser.is_admin) return res.status(403).json({ error: 'No permission' });
  deleteRoomMessage(msgId);
  broadcastGatewayEvent('room:' + room.id, 'message_delete', {
    id: String(msgId),
    room_id: String(room.id),
    channel_id: String(channel.id),
  });
  res.json({ ok: true });
});

// Edit a message
router.post('/:id/channels/:cid/messages/:mid/edit', writeDirect, (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json({ error: 'Not logged in' });
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const userId = res.locals.currentUser.id;
  if (!isRoomMember(room.id, userId) && !res.locals.currentUser.is_admin) return res.status(403).json({ error: 'Not a member' });
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.status(404).json({ error: 'Channel not found' });
  if (!res.locals.currentUser.is_admin && !canViewRoomChannel(channel.id, userId)) return res.status(403).json({ error: 'No view permission' });
  const body = String(req.body.body || '').trim();
  const rawProto = String(req.body.proto || '').trim();
  const ciphertextRaw = String(req.body.ciphertext || '').trim();
  const isSticker = body.startsWith('/uploads/stickers/');
  if (!isSticker) {
    if (!ciphertextRaw) return res.status(400).json({ error: 'Message is empty' });
    if (ciphertextRaw.length > ROOM_CT_MAX) {
      return res.status(400).json({ error: 'Message is too long.' });
    }
    if (rawProto !== 'mls') {
      return res.status(426).json({
        error: 'LegacyProtocolRetired',
        message: 'Extrovert now uses pure MLS encryption (RFC 9420). Please refresh your browser tab to continue messaging.'
      });
    }
  }
  const ciphertext = ciphertextRaw || null;
  const ok = editRoomMessage(Number(req.params.mid), userId, isSticker ? body : '', 'mls', ciphertext, null);
  if (!ok) return res.status(403).json({ error: 'Not your message' });
  broadcastGatewayEvent('room:' + room.id, 'message_update', {
    id: String(req.params.mid),
    room_id: String(room.id),
    channel_id: String(channel.id),
    proto: isSticker ? 'plain' : 'mls',
    body: isSticker ? body : '',
    ciphertext: isSticker ? null : ciphertext,
    edited_at: new Date().toISOString(),
  });
  res.json({ ok: true });
});

// Report a message
router.post('/:id/channels/:cid/report', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.status(401).json({ error: 'Not logged in' });
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (!isRoomMember(room.id, res.locals.currentUser.id) && !res.locals.currentUser.is_admin) return res.status(403).json({ error: 'Not a member' });
  const channel = getRoomChannel(Number(req.params.cid));
  if (!channel || channel.room_id !== room.id) return res.status(404).json({ error: 'Channel not found' });
  if (!res.locals.currentUser.is_admin && !canViewRoomChannel(channel.id, res.locals.currentUser.id)) return res.status(403).json({ error: 'No view permission' });
  const messageId = Number(req.body.message_id);
  const reason = String(req.body.reason || '').trim();
  if (!messageId || !reason) return res.status(400).json({ error: 'Missing message ID or reason' });
  const msgs = getRoomMessages(channel.id);
  const msg = msgs.find(m => m.id === messageId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  // Reports go through the shared queue (the legacy reports table is no longer read).
  createContentReport({
    reporterId: res.locals.currentUser.id,
    targetUserId: msg.user_id,
    targetType: 'room_message',
    targetId: msg.id,
    context: 'room "' + room.name + '"',
    snapshot: msg.body || '',
    reason,
  });
  res.json({ ok: true });
});

// Request to join private room
router.post('/:id/request', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room || room.is_public) return res.status(404).send('Room not found');
  const userId = res.locals.currentUser.id;
  if (isRoomMember(room.id, userId)) return res.redirect('/rooms/' + room.id);
  createJoinRequest(room.id, userId);
  res.redirect('/rooms/' + room.id);
});

// Approve join request
router.post('/:id/requests/:rid/approve', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const jreq = getJoinRequestById(Number(req.params.rid));
  if (!jreq || jreq.room_id !== room.id) return res.status(404).send('Request not found');
  approveJoinRequest(Number(req.params.rid));
  const approvedUser = getUserById(jreq.user_id);
  if (approvedUser) {
    updateUserRoomSubscriptions(approvedUser.id, room.id, 'join');
    broadcastGatewayEvent('room:' + room.id, 'member_join', {
      room_id: String(room.id),
      user_id: String(approvedUser.id),
      username: approvedUser.username,
      display_name: approvedUser.display_name,
    });
  }
  res.redirect('/rooms/' + room.id + '/members');
});

// Reject join request
router.post('/:id/requests/:rid/reject', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const jreq = getJoinRequestById(Number(req.params.rid));
  if (!jreq || jreq.room_id !== room.id) return res.status(404).send('Request not found');
  rejectJoinRequest(Number(req.params.rid));
  res.redirect('/rooms/' + room.id + '/members');
});

// Invite user to private room
router.post('/:id/invite', writeScope, (req, res) => {
  if (!res.locals.currentUser) return res.redirect('/login');
  const room = getRoom(Number(req.params.id));
  if (!room) return res.status(404).send('Room not found');
  if (!checkPerm(room.id, res.locals.currentUser.id, PERM.MANAGE_MEMBERS)) return res.status(403).send('No permission');
  const username = String(req.body.username || '').trim().toLowerCase();
  if (!username) return res.redirect('/rooms/' + room.id + '/members');
  const target = getUserByUsername(username);
  if (!target) return res.status(404).send('User not found');
  if (isRoomMember(room.id, target.id)) return res.status(400).send('Already a member');
  const defaultRole = joinDefaultRole(room.id);
  if (defaultRole) addRoomMember(room.id, target.id, defaultRole.id);
  updateUserRoomSubscriptions(target.id, room.id, 'join');
  broadcastGatewayEvent('room:' + room.id, 'member_join', {
    room_id: String(room.id),
    user_id: String(target.id),
    username: target.username,
    display_name: target.display_name,
  });
  res.redirect('/rooms/' + room.id + '/members');
});

module.exports = router;
