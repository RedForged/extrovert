'use strict';

// One report endpoint for everything reportable. Each target type is validated
// against what the reporter is allowed to see, so a report can't be used to
// probe for content someone shouldn't know about.
//
// For end-to-end encrypted content (room and DM messages) the server holds only
// ciphertext, so the reporter's client sends the text it can see — that is the
// only copy a moderator ever gets.

const express = require('express');
const db = require('../db');
const { canView } = require('../network');

const router = express.Router();

const MAX_REASON = 500;
const MAX_SNAPSHOT = 2000;

router.post('/', (req, res) => {
  const user = res.locals.currentUser;
  if (!user) return res.status(401).json({ error: 'Not logged in' });

  const type = String(req.body.target_type || '').trim();
  const targetId = Number(req.body.target_id);
  const reason = String(req.body.reason || '').trim().slice(0, MAX_REASON);
  let snapshot = String(req.body.snapshot || '').slice(0, MAX_SNAPSHOT);

  if (!db.REPORT_TARGET_TYPES.has(type) || !targetId) return res.status(400).json({ error: 'Bad target.' });
  if (!reason) return res.status(400).json({ error: 'A reason is required.' });

  let targetUserId = null;
  let context = '';

  if (type === 'post') {
    const post = db.getPostById(targetId);
    if (!post || !canView(user.id, post.user_id)) return res.status(404).json({ error: 'Post not found.' });
    targetUserId = post.user_id;
    context = '#' + post.id;
    snapshot = String(post.body || '').slice(0, MAX_SNAPSHOT);
  } else if (type === 'comment') {
    const comment = db.getCommentById(targetId);
    if (!comment) return res.status(404).json({ error: 'Comment not found.' });
    const post = db.getPostById(comment.post_id);
    if (!post || !canView(user.id, post.user_id)) return res.status(404).json({ error: 'Comment not found.' });
    targetUserId = comment.user_id;
    context = 'on post #' + comment.post_id;
    snapshot = String(comment.body || '').slice(0, MAX_SNAPSHOT);
  } else if (type === 'user') {
    const target = db.getUserById(targetId);
    if (!target) return res.status(404).json({ error: 'User not found.' });
    if (target.id === user.id) return res.status(400).json({ error: 'You cannot report yourself.' });
    targetUserId = target.id;
    context = '@' + target.username;
  } else if (type === 'room_message') {
    // The room and channel come from the message itself, so the client only
    // needs to send the message id.
    const message = db.getRoomMessageById(targetId);
    if (!message) return res.status(404).json({ error: 'Message not found.' });
    const channel = db.getRoomChannel(message.channel_id);
    const room = channel ? db.getRoom(channel.room_id) : null;
    if (!room) return res.status(404).json({ error: 'Message not found.' });
    if (!db.isRoomMember(room.id, user.id) && !user.is_admin) return res.status(403).json({ error: 'Not a member.' });
    targetUserId = message.user_id;
    context = 'room "' + room.name + '"';
  } else if (type === 'dm_message') {
    const message = db.db.prepare(`SELECT * FROM messages WHERE id = ?`).get(targetId);
    if (!message || (message.from_id !== user.id && message.to_id !== user.id)) {
      return res.status(404).json({ error: 'Message not found.' });
    }
    targetUserId = message.from_id === user.id ? message.to_id : message.from_id;
    context = 'direct message';
  }

  const id = db.createContentReport({
    reporterId: user.id,
    targetUserId,
    targetType: type,
    targetId,
    context,
    snapshot,
    reason,
  });
  if (!id) return res.status(400).json({ error: 'Bad target.' });
  res.json({ ok: true });
});

module.exports = router;
