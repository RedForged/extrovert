'use strict';

const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const { getUserById, getUserByUsername, areMutualFollowers, getRoomChannel, isRoomMember, getRoomsForUser, getOAuthToken, getPersonalAccessTokenByHash, hashOAuthToken, createNotification, getPendingRoomSessionKeyForUserAndSession, countAvailablePrekeys } = require('./db');
const { sendCallPush, sendMissedCallPush } = require('./push');
const { canView } = require('./network');

const SESSION_DB_PATH = process.env.EXTV_SESSION_DB_PATH || path.join(__dirname, '..', 'data', 'sessions.db');
const SESSION_SECRET = process.env.SESSION_SECRET;

const clients = new Map();
// Every WS connection per user (multiple tabs) for live DM delivery. Unlike
// `clients` (one signaling connection per user, last-wins), this tracks ALL of
// a user's open connections so pushes reach every tab.
const dmClients = new Map(); // userId -> Set<{ ws, username, displayName }>
// Push-channel connections: the native app's foreground service keeps a WS
// open so calls reach the phone even when the app UI is closed. The service
// sends {type:'push_register'} after connecting; it is NOT a signaling client
// (the user stays "offline" for calls, so the pending-call flow still runs and
// the ring is delivered here as a push).
const pushClients = new Map(); // userId -> Set<ws>
const voiceChannels = new Map();
const topicSubscriptions = new Map(); // topic -> Set<{ ws, userId }>
const recentGatewayEvents = [];
let globalSeq = 1;

const { onNotification } = require('./notif-broadcaster');

function subscribeClient(ws, userId, topic) {
  if (!topicSubscriptions.has(topic)) topicSubscriptions.set(topic, new Set());
  topicSubscriptions.get(topic).add({ ws, userId });
  if (!ws.subscribedTopics) ws.subscribedTopics = new Set();
  ws.subscribedTopics.add(topic);
}

function unsubscribeClient(ws, topic) {
  const set = topicSubscriptions.get(topic);
  if (set) {
    for (const item of set) {
      if (item.ws === ws) { set.delete(item); break; }
    }
    if (set.size === 0) topicSubscriptions.delete(topic);
  }
  if (ws.subscribedTopics) ws.subscribedTopics.delete(topic);
}

function cleanupClientSubscriptions(ws) {
  if (ws.subscribedTopics) {
    for (const topic of ws.subscribedTopics) {
      unsubscribeClient(ws, topic);
    }
  }
}

function performAutoSubscribe(ws, user) {
  if (!ws || !user) return;
  ws.autoSubscribe = true;
  subscribeClient(ws, user.id, 'timeline:home');
  subscribeClient(ws, user.id, 'notifications');
  subscribeClient(ws, user.id, 'presence');
  try {
    const userRooms = getRoomsForUser(user.id);
    if (Array.isArray(userRooms)) {
      for (const r of userRooms) {
        subscribeClient(ws, user.id, 'room:' + r.id);
      }
    }
  } catch {}
  try {
    ws.send(JSON.stringify({
      type: 'subscribed',
      auto_subscribed: true,
      channels: [...(ws.subscribedTopics || [])],
    }));
  } catch {}
  try {
    const prekeyCount = countAvailablePrekeys(user.id);
    if (prekeyCount < 10) {
      ws.send(JSON.stringify({
        seq: globalSeq++,
        type: 'gateway_event',
        topic: 'presence',
        event: 'otk_low',
        data: {
          count: prekeyCount,
          threshold: 10,
          message: 'Remaining one-time prekeys are low. Upload fresh prekeys to prevent incoming message failures.',
        },
      }));
    }
  } catch {}
}

function updateUserRoomSubscriptions(userId, roomId, action) {
  const topic = 'room:' + roomId;
  const uid = Number(userId);
  const userDmConns = dmClients.get(uid);
  if (userDmConns) {
    for (const item of userDmConns) {
      if (item && item.ws && item.ws.autoSubscribe) {
        if (action === 'join') subscribeClient(item.ws, uid, topic);
        else if (action === 'leave') unsubscribeClient(item.ws, topic);
      }
    }
  }
  const client = clients.get(uid);
  if (client && client.ws && client.ws.autoSubscribe) {
    if (action === 'join') subscribeClient(client.ws, uid, topic);
    else if (action === 'leave') unsubscribeClient(client.ws, topic);
  }
}

function getGatewayLatestSeq() {
  return Math.max(0, globalSeq - 1);
}

function broadcastGatewayEvent(topic, eventName, data) {
  const frame = {
    seq: globalSeq++,
    type: 'gateway_event',
    topic,
    event: eventName,
    data,
  };

  recentGatewayEvents.push(frame);
  if (recentGatewayEvents.length > 500) recentGatewayEvents.shift();

  const subscribers = topicSubscriptions.get(topic);
  if (!subscribers) return;

  const isRoomMsg = topic.startsWith('room:') && eventName === 'message_create' && data && data.group_session_id;

  const json = JSON.stringify(frame);
  for (const item of subscribers) {
    if (item.ws && item.ws.readyState === 1) {
      try {
        if (isRoomMsg && item.userId && Number(item.userId) !== Number(data.user_id)) {
          const pendingKey = getPendingRoomSessionKeyForUserAndSession(item.userId, data.group_session_id);
          if (pendingKey) {
            const customizedData = Object.assign({}, data, {
              session_key: {
                key_id: pendingKey.key_id,
                encrypted_key: pendingKey.encrypted_key,
                sender_id: String(pendingKey.sender_id),
              },
            });
            item.ws.send(JSON.stringify(Object.assign({}, frame, { data: customizedData })));
            continue;
          }
        }
        item.ws.send(json);
      } catch {}
    }
  }
}

// Timeline events (post/comment create, edit, delete) are authored by a single
// user, and content visibility is network-bound via canView(). The shared
// 'timeline:home' topic therefore cannot be broadcast verbatim to every
// subscriber — doing so leaked every API-authored post to every connected user,
// bypassing canView. Fan the frame out per subscriber, filtered by canView, and
// keep the topic name so clients and the resume protocol are unchanged. The
// author id rides on the stored frame (stripped before delivery) so replay on
// resume applies the same filter.
function broadcastTimelineEvent(topic, eventName, data, authorId) {
  const frame = {
    seq: globalSeq++,
    type: 'gateway_event',
    topic,
    event: eventName,
    data,
    _authorId: Number(authorId),
  };

  recentGatewayEvents.push(frame);
  if (recentGatewayEvents.length > 500) recentGatewayEvents.shift();

  const subscribers = topicSubscriptions.get(topic);
  if (!subscribers) return;

  const out = JSON.stringify({ seq: frame.seq, type: frame.type, topic: frame.topic, event: frame.event, data: frame.data });
  for (const item of subscribers) {
    if (!item.ws || item.ws.readyState !== 1) continue;
    if (item.userId == null || !canView(Number(item.userId), frame._authorId)) continue;
    try { item.ws.send(out); } catch {}
  }
}

// Pending calls to offline users: calleeUserId -> pending record.
// Lets a caller "ring" an offline peer: the callee gets a missed_call
// notification (persisted + pushed via SSE) and a real WebRTC offer the moment
// they reconnect (their WS connect handler checks pendingCalls). If they never
// come back, the caller is told after PENDING_TTL and the attempt ends.
const PENDING_TTL = 120000;
const pendingCalls = new Map();
// calleeUserId -> { callerId, callerUsername, callerDisplayName, cancelToken,
//                   createdAt, expiresAt, timer }

let sessionDb;
try {
  sessionDb = new DatabaseSync(SESSION_DB_PATH);
  sessionDb.exec('PRAGMA busy_timeout = 5000;');
} catch (e) {
  console.error('Signaling: failed to open session DB', e);
}

function parseCookies(cookieHeader) {
  const result = {};
  if (!cookieHeader) return result;
  cookieHeader.split(';').forEach(pair => {
    const i = pair.indexOf('=');
    if (i === -1) return;
    const key = pair.slice(0, i).trim();
    const val = pair.slice(i + 1).trim();
    if (key) result[key] = val;
  });
  return result;
}

function unsignSessionId(signedValue, secret) {
  if (typeof signedValue !== 'string') return null;
  const match = signedValue.match(/^s:(.+)\.(.+)$/);
  if (!match) return null;
  const sid = match[1];
  const sig = match[2];
  const expected = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '');
  try {
    if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      return sid;
    }
  } catch {}
  return null;
}

function getSession(sid) {
  if (!sessionDb) return null;
  try {
    const row = sessionDb.prepare(`SELECT data, expires_at FROM sessions WHERE sid = ?`).get(sid);
    if (!row) return null;
    if (row.expires_at <= Date.now()) {
      sessionDb.prepare(`DELETE FROM sessions WHERE sid = ?`).run(sid);
      return null;
    }
    return JSON.parse(row.data);
  } catch { return null; }
}

function lookupTokenUser(token) {
  if (!token || typeof token !== 'string') return null;
  const trimmed = token.trim();
  const tokenRecord = getOAuthToken(trimmed);
  if (tokenRecord && (!tokenRecord.expires_at || tokenRecord.expires_at > Date.now())) {
    const user = getUserById(tokenRecord.user_id);
    if (user && !user.banned) return user;
  }
  const patHash = hashOAuthToken(trimmed);
  const pat = getPersonalAccessTokenByHash(patHash);
  if (pat && (!pat.expires_at || pat.expires_at > Date.now())) {
    const user = getUserById(pat.user_id);
    if (user && !user.banned) return user;
  }
  return null;
}

function lookupUserFromRequest(req) {
  // 1. Session cookie (browser clients)
  if (SESSION_SECRET && sessionDb) {
    const cookies = parseCookies(req.headers.cookie);
    const rawSid = cookies['connect.sid'];
    if (rawSid) {
      const signedSid = decodeURIComponent(rawSid);
      const sid = unsignSessionId(signedSid, SESSION_SECRET);
      if (sid) {
        const session = getSession(sid);
        if (session && session.userId) {
          const user = getUserById(session.userId);
          if (user && !user.banned) return user;
        }
      }
    }
  }
  // 2. Bearer token via Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const user = lookupTokenUser(req.headers.authorization.slice(7));
    if (user) return user;
  }
  // 3. Bearer token via ?token= query param (native/mobile clients)
  try {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token');
    if (token) {
      const user = lookupTokenUser(token);
      if (user) return user;
    }
  } catch {}
  return null;
}

function isMutualFollowerOnline(aId, bId) {
  return areMutualFollowers(aId, bId);
}

function broadcastPresence(userId, type) {
  const user = getUserById(userId);
  if (!user) return;
  for (const [otherId, client] of clients) {
    if (otherId === userId) continue;
    if (areMutualFollowers(userId, otherId)) {
      try {
        client.ws.send(JSON.stringify({
          type,
          username: user.username,
          display_name: user.display_name,
        }));
      } catch {}
    }
  }
}

function sendToUser(toUsername, message) {
  for (const [id, client] of clients) {
    if (client.username === toUsername) {
      try {
        client.ws.send(JSON.stringify(message));
        return true;
      } catch { return false; }
    }
  }
  return false;
}

function getVoiceChannelMembers(channelId) {
  const members = voiceChannels.get(channelId);
  if (!members) return [];
  const result = [];
  for (const userId of members) {
    const client = clients.get(userId);
    if (client) result.push({ id: userId, username: client.username, display_name: client.displayName });
  }
  return result;
}

function removeFromVoiceChannels(userId) {
  for (const [channelId, members] of voiceChannels) {
    if (members.has(userId)) {
      members.delete(userId);
      const client = clients.get(userId);
      const username = client ? client.username : 'unknown';
      broadcastToRoomMembers(channelId, userId, {
        type: 'user_left_channel',
        channel_id: channelId,
        username,
      });
      if (members.size === 0) voiceChannels.delete(channelId);
    }
  }
  const client = clients.get(userId);
  if (client) client.inCall = false;
}

function broadcastToRoomMembers(channelId, excludeUserId, msg) {
  const ch = getRoomChannel(channelId);
  if (!ch) return;
  for (const [otherId, other] of clients) {
    if (otherId === excludeUserId) continue;
    if (isRoomMember(ch.room_id, otherId)) {
      try { other.ws.send(JSON.stringify(msg)); } catch {}
    }
  }
}

function routeToChannelMember(msg, user, forwardType) {
  const members = voiceChannels.get(msg.channel_id);
  if (!members) return;
  // Only a participant in the voice channel may drive its call signalling.
  if (!members.has(user.id)) return;
  for (const otherId of members) {
    if (otherId === user.id) continue;
    if (msg.to) {
      const target = clients.get(otherId);
      if (target && target.username === msg.to) {
        try {
          target.ws.send(JSON.stringify({
            type: forwardType,
            from: user.username,
            from_display: user.display_name,
            sdp: msg.sdp,
            candidate: msg.candidate,
            channel_id: msg.channel_id,
          }));
        } catch {}
      }
    }
  }
}

function cancelPendingCall(calleeId, reason) {
  const p = pendingCalls.get(calleeId);
  if (!p) return false;
  pendingCalls.delete(calleeId);
  clearTimeout(p.timer);
  const caller = clients.get(p.callerId);
  if (caller) {
    caller.inCall = false;
    const callee = getUserById(calleeId);
    const calleeUsername = callee ? callee.username : '';
    try {
      caller.ws.send(JSON.stringify({
        type: reason === 'timeout' ? 'call_unanswered' : 'call_declined',
        from: calleeUsername,
        to: calleeUsername,
      }));
    } catch {}
  }
  // The call was never answered: tell the callee's devices with a normal
  // (non-full-screen) missed-call push notification.
  if (reason === 'timeout') {
    try {
      const callee = getUserById(calleeId);
      const callerUser = getUserById(p.callerId);
      if (callee) {
        if (callerUser) sendMissedCallPush(callee, callerUser);
        sendWsPush(calleeId, {
          type: 'missed_call',
          from: callerUser ? callerUser.username : '',
          from_display: callerUser ? (callerUser.display_name || callerUser.username) : 'Someone',
        });
      }
    } catch (e) { console.error('missed-call push:', e && e.message); }
  }
  return true;
}

function cancelPendingCallByToken(cancelToken) {
  for (const [calleeId, p] of pendingCalls) {
    if (p.cancelToken === cancelToken) {
      return cancelPendingCall(calleeId, 'declined');
    }
  }
  return false;
}

// Cancel any pending call this user (as caller) is waiting on.
function cancelOutgoingPending(callerId, reason) {
  for (const [calleeId, p] of pendingCalls) {
    if (p.callerId === callerId) {
      cancelPendingCall(calleeId, reason);
    }
  }
}

function initSignaling(wss) {
  wss.on('connection', (ws, req) => {
    let user = lookupUserFromRequest(req);
    let registered = false;
    let clientData = null;

    let autoSubFromUrl = false;
    try {
      const url = new URL(req.url, 'http://localhost');
      const asVal = url.searchParams.get('auto_subscribe');
      if (asVal === '1' || asVal === 'true') {
        autoSubFromUrl = true;
      }
    } catch {}

    function registerSignalingClient() {
      if (registered || !user) return;
      registered = true;

      if (autoSubFromUrl || ws.autoSubscribe) {
        performAutoSubscribe(ws, user);
      }

      clientData = {
        ws,
        username: user.username,
        displayName: user.display_name,
        userId: user.id,
        inCall: false,
      };
      clients.set(user.id, clientData);

      // Track this connection for live DM pushes (all tabs).
      if (!dmClients.has(user.id)) dmClients.set(user.id, new Set());
      dmClients.get(user.id).add({ ws, username: user.username, displayName: user.display_name });

      broadcastPresence(user.id, 'user_online');

      // Listen to notification broadcasts and push to this socket
      const stopNotif = onNotification(user.id, (notif) => {
        if (ws.readyState === 1) {
          try {
            ws.send(JSON.stringify({
              seq: globalSeq++,
              type: 'gateway_event',
              topic: 'notifications',
              event: 'notification_new',
              data: notif,
            }));
          } catch {}
        }
      });
      ws.on('close', stopNotif);

      for (const [otherId, client] of clients) {
        if (otherId === user.id) continue;
        if (areMutualFollowers(user.id, otherId)) {
          try {
            ws.send(JSON.stringify({
              type: 'user_online',
              username: client.username,
              display_name: client.displayName,
            }));
          } catch {}
        }
      }

      // If this user just came back online and someone is waiting to call them
      // (offline call), ring them now and tell the caller to produce the offer.
      const pending = pendingCalls.get(user.id);
      if (pending && clients.has(pending.callerId)) {
        pendingCalls.delete(user.id);
        clearTimeout(pending.timer);
        try {
          ws.send(JSON.stringify({
            type: 'incoming_call',
            from: pending.callerUsername,
            from_display: pending.callerDisplayName,
          }));
        } catch {}
        const caller = clients.get(pending.callerId);
        if (caller) {
          try {
            caller.ws.send(JSON.stringify({ type: 'callee_ringing', to: user.username }));
          } catch {}
        }
      } else if (pending) {
        // Caller is gone — drop the pending call silently.
        pendingCalls.delete(user.id);
        clearTimeout(pending.timer);
      }
    }

    if (user && autoSubFromUrl) {
      registerSignalingClient();
    }

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }
      // A valid-JSON primitive ("null", "42", "\"x\"") parses to a non-object;
      // touching msg.token below would throw and (via the process-level
      // uncaughtException handler) exit the server. Reject anything that is not
      // a plain object before it is dereferenced.
      if (!msg || typeof msg !== 'object') return;

      // Authenticate dynamically if message carries a token
      if (!user && (msg.token || msg.action === 'auth' || msg.action === 'subscribe' || msg.action === 'resume')) {
        const tokenUser = lookupTokenUser(msg.token);
        if (tokenUser) {
          user = tokenUser;
          if (msg.auto_subscribe) ws.autoSubscribe = true;
          registerSignalingClient();
        }
      }

      // First message decides the connection's role if authenticated
      if (user && !registered) {
        if (msg.type === 'push_register') {
          registered = true;
          if (!pushClients.has(user.id)) pushClients.set(user.id, new Set());
          pushClients.get(user.id).add(ws);
          try { ws.send(JSON.stringify({ type: 'push_registered' })); } catch {}
          return;
        }
        registerSignalingClient();
      }

      const actionType = msg.action || msg.type;

      // Every signaling action below dereferences `user`. An unauthenticated
      // frame (e.g. {"type":"call_offer","to":"x"}) must never reach them: a
      // null deref here throws out of this listener, and the process-level
      // uncaughtException handler exits the server — an anonymous remote DoS.
      // Only 'ping' is answered before authentication.
      if (!user && actionType !== 'ping') {
        try { ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' })); } catch {}
        return;
      }

      // A `push_register` socket is push-only: it sets `registered` WITHOUT
      // building `clientData` (only registerSignalingClient does that). Every
      // call/channel action below dereferences `clientData` (e.g.
      // `clientData.inCall`), so processing one here would throw and exit the
      // process. Answer only 'ping' on such a socket.
      if (registered && !clientData && actionType !== 'ping') {
        return;
      }

      switch (actionType) {
        case 'ping':
          try { ws.send(JSON.stringify({ type: 'pong' })); } catch {}
          break;

        case 'auto_subscribe':
        case 'subscribe_all': {
          if (!user) {
            try { ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' })); } catch {}
            break;
          }
          performAutoSubscribe(ws, user);
          break;
        }

        case 'subscribe': {
          if (!user) {
            try { ws.send(JSON.stringify({ type: 'error', message: 'Unauthorized' })); } catch {}
            break;
          }
          if (msg.auto_subscribe) {
            performAutoSubscribe(ws, user);
          }
          const channels = Array.isArray(msg.channels)
            ? msg.channels
            : (msg.channel ? [msg.channel] : (msg.topic ? [msg.topic] : []));
          for (const ch of channels) {
            const topic = String(ch || '').trim();
            if (!topic) continue;
            if (topic.startsWith('room:')) {
              const roomId = parseInt(topic.split(':')[1], 10);
              if (roomId && !isRoomMember(roomId, user.id) && !user.is_admin) continue;
            }
            subscribeClient(ws, user.id, topic);
          }
          try {
            ws.send(JSON.stringify({
              type: 'subscribed',
              topic: msg.topic || (channels.length === 1 ? channels[0] : undefined),
              channels: [...(ws.subscribedTopics || [])],
            }));
          } catch {}
          break;
        }

        case 'unsubscribe': {
          const channels = Array.isArray(msg.channels)
            ? msg.channels
            : (msg.channel ? [msg.channel] : (msg.topic ? [msg.topic] : []));
          for (const ch of channels) {
            unsubscribeClient(ws, String(ch || '').trim());
          }
          try {
            ws.send(JSON.stringify({
              type: 'unsubscribed',
              topic: msg.topic || (channels.length === 1 ? channels[0] : undefined),
              channels: [...(ws.subscribedTopics || [])],
            }));
          } catch {}
          break;
        }

        case 'resume': {
          if (msg.auto_subscribe && user && !ws.autoSubscribe) {
            performAutoSubscribe(ws, user);
          }
          const clientSeq = Number(msg.seq) || 0;
          const missed = recentGatewayEvents.filter(e => e.seq > clientSeq
            && ws.subscribedTopics && ws.subscribedTopics.has(e.topic)
            // Timeline frames carry the author id; replay only what this viewer
            // may see (the live path applies the same canView filter).
            && (!e._authorId || (user && canView(Number(user.id), e._authorId))));
          for (const ev of missed) {
            try {
              ws.send(JSON.stringify({ seq: ev.seq, type: ev.type, topic: ev.topic, event: ev.event, data: ev.data }));
            } catch {}
          }
          try {
            ws.send(JSON.stringify({
              type: 'resumed',
              replayed: missed.length,
              last_seq: globalSeq - 1,
            }));
          } catch {}
          break;
        }

        case 'typing': {
          if (!user) break;
          const ch = msg.channel || (msg.room_id ? `room:${msg.room_id}` : null);
          if (ch) {
            // Echo back to the sender (harmless, no other recipient), but only
            // BROADCAST into a room topic the sender actually belongs to. This
            // mirrors the read-side ('subscribe') authorization and stops any
            // user from injecting spoofed typing events into other rooms or
            // global topics (timeline:home, notifications, …).
            try {
              ws.send(JSON.stringify({
                type: 'typing',
                channel: ch,
                userId: user.id,
                username: user.username,
                typing: !!msg.typing,
              }));
            } catch {}
            if (ch.startsWith('room:')) {
              const roomId = parseInt(ch.slice(5), 10);
              if (roomId && (isRoomMember(roomId, user.id) || user.is_admin)) {
                broadcastGatewayEvent(ch, 'typing', {
                  channel: ch,
                  user_id: user.id,
                  username: user.username,
                  display_name: user.display_name,
                  typing: !!msg.typing,
                });
              }
            }
          } else if (msg.scope === 'room' && msg.room_id) {
            const roomId = parseInt(msg.room_id, 10);
            if (isRoomMember(roomId, user.id) || user.is_admin) {
              broadcastGatewayEvent(`room:${roomId}`, 'typing', {
                room_id: roomId,
                channel_id: msg.channel_id,
                user_id: user.id,
                username: user.username,
                display_name: user.display_name,
              });
            }
          } else if (msg.scope === 'dm' && msg.to) {
            const target = getUserByUsername(msg.to);
            if (target && areMutualFollowers(user.id, target.id)) {
              sendDmEvent(target.username, {
                type: 'dm_typing',
                from_username: user.username,
                from_display: user.display_name,
              });
            }
          }
          break;
        }

        // First step of a 1:1 call: ask the server whether the callee is
        // reachable. Server replies callee_available (proceed with offer),
        // user_busy, or calling_offline (callee is offline but has been
        // queued for ring-on-reconnect + notified of a missed call).
        case 'call_request': {
          if (msg.channel_id) break; // room voice channels use call_offer directly
          // Resolve the callee and require a mutual-follow relationship BEFORE
          // revealing any online/busy state — otherwise this is a presence
          // oracle for any account by username.
          const callee = getUserByUsername(msg.to);
          if (!callee || !areMutualFollowers(user.id, callee.id)) {
            try { ws.send(JSON.stringify({ type: 'user_offline', from: msg.to })); } catch {}
            break;
          }
          const target = findUserByUsername(msg.to);
          if (target) {
            try {
              ws.send(JSON.stringify(target.inCall
                ? { type: 'user_busy', from: msg.to }
                : { type: 'callee_available', to: msg.to }));
            } catch {}
            break;
          }
          if (pendingCalls.has(callee.id)) {
            console.log('  -> callee already has a pending call');
            try { ws.send(JSON.stringify({ type: 'user_busy', from: msg.to })); } catch {}
            break;
          }
          const cancelToken = crypto.randomUUID();
          const createdAt = Date.now();
          const expiresAt = createdAt + PENDING_TTL;
          const timer = setTimeout(() => {
            cancelPendingCall(callee.id, 'timeout');
          }, PENDING_TTL);
          pendingCalls.set(callee.id, {
            callerId: user.id,
            callerUsername: user.username,
            callerDisplayName: user.display_name,
            cancelToken,
            createdAt,
            expiresAt,
            timer,
          });
          clientData.inCall = true;
          try {
            createNotification({ userId: callee.id, type: 'missed_call', actorId: user.id });
          } catch (e) { console.error('createNotification missed_call:', e); }
          // Ring the phone: browser subscriptions via web-push, the native
          // app's push service via its always-on WS connection.
          try { sendCallPush(callee, user, cancelToken); } catch {}
          try {
            sendWsPush(callee.id, {
              type: 'call',
              from: user.username,
              from_display: user.display_name,
              cancel_token: cancelToken,
            });
          } catch {}
          console.log('  -> callee offline, queued pending call');
          try {
            ws.send(JSON.stringify({ type: 'calling_offline', to: msg.to, expires_at: expiresAt }));
          } catch {}
          break;
        }

        // Caller aborts an offline-call wait (or cancels before the callee
        // reconnects). Clears the pending call and frees the caller.
        case 'call_cancel': {
          if (msg.channel_id) break;
          cancelOutgoingPending(user.id, 'declined');
          clientData.inCall = false;
          break;
        }

        case 'call_offer':
          console.log('WS msg call_offer from', user.username, 'to', msg.to, 'channel:', msg.channel_id);
          if (msg.channel_id) {
            const members = voiceChannels.get(msg.channel_id);
            // Sender must actually be in the voice channel to ring its members.
            if (members && !members.has(user.id)) break;
            if (members) {
              for (const otherId of members) {
                if (otherId === user.id) continue;
                if (msg.to) {
                  const target = clients.get(otherId);
                  if (target && target.username === msg.to) {
                    console.log('  -> forwarding incoming_call to', target.username);
                    try {
                      target.ws.send(JSON.stringify({
                        type: 'incoming_call',
                        from: user.username,
                        from_display: user.display_name,
                        sdp: msg.sdp,
                        channel_id: msg.channel_id,
                      }));
                    } catch {}
                  }
                }
              }
            }
          } else {
            const target = findUserByUsername(msg.to);
            if (!target) {
              console.log('  -> target not found (offline?)');
              try { ws.send(JSON.stringify({ type: 'user_offline', from: msg.to })); } catch {}
              break;
            }
            if (!areMutualFollowers(user.id, target.userId)) {
              console.log('  -> call_offer blocked: not mutual followers');
              try { ws.send(JSON.stringify({ type: 'error', error: 'not_allowed' })); } catch {}
              break;
            }
            if (target.inCall) {
              console.log('  -> target busy');
              try {
                ws.send(JSON.stringify({ type: 'user_busy', from: msg.to }));
              } catch {}
              break;
            }
            console.log('  -> forwarding incoming_call to', target.username);
            try {
              target.ws.send(JSON.stringify({
                type: 'incoming_call',
                from: user.username,
                from_display: user.display_name,
                sdp: msg.sdp,
              }));
            } catch {}
            clientData.inCall = true;
          }
          break;

        case 'call_answer':
          console.log('WS msg call_answer from', user.username, 'to', msg.to);
          if (msg.channel_id) {
            routeToChannelMember(msg, user, 'call_answered');
          } else {
            const target = findUserByUsername(msg.to);
            if (!target || !areMutualFollowers(user.id, target.userId)) {
              console.log('  -> call_answer blocked: target offline or not mutual followers');
              break;
            }
            console.log('  -> forwarding call_answered to', target.username);
            try {
              target.ws.send(JSON.stringify({
                type: 'call_answered',
                from: user.username,
                from_display: user.display_name,
                sdp: msg.sdp,
              }));
            } catch {}
            clientData.inCall = true;
          }
          break;

        case 'ice_candidate':
          console.log('WS msg ice_candidate from', user.username, 'to', msg.to);
          if (msg.channel_id) {
            routeToChannelMember(msg, user, 'ice_candidate');
          } else {
            const target = findUserByUsername(msg.to);
            if (!target || !areMutualFollowers(user.id, target.userId)) break;
            if (target) {
              try {
                target.ws.send(JSON.stringify({
                  type: 'ice_candidate',
                  from: user.username,
                  candidate: msg.candidate,
                }));
              } catch {}
            }
          }
          break;

        case 'call_end':
          console.log('WS msg call_end from', user.username);
          if (msg.channel_id) {
            routeToChannelMember(msg, user, 'call_ended');
          } else {
            const target = findUserByUsername(msg.to);
            if (!target || !areMutualFollowers(user.id, target.userId)) break;
            if (target) {
              console.log('  -> forwarding call_ended to', target.username);
              try {
                target.ws.send(JSON.stringify({
                  type: 'call_ended',
                  from: user.username,
                }));
              } catch {}
              clientData.inCall = false;
            }
          }
          break;

        case 'call_decline':
          console.log('WS msg call_decline from', user.username);
          if (msg.channel_id) {
            routeToChannelMember(msg, user, 'call_declined');
          } else {
            const target = findUserByUsername(msg.to);
            if (!target || !areMutualFollowers(user.id, target.userId)) break;
            if (target) {
              try {
                target.ws.send(JSON.stringify({
                  type: 'call_declined',
                  from: user.username,
                }));
              } catch {}
              clientData.inCall = false;
            }
          }
          break;

        case 'join_channel': {
          const channelId = msg.channel_id;
          if (!channelId) return;

          // Only room members may join a channel: prevents roster leaks of
          // private rooms via channel_joined and ring-spam by non-members.
          const channel = getRoomChannel(Number(channelId));
          if (!channel || !isRoomMember(channel.room_id, user.id)) {
            try { ws.send(JSON.stringify({ type: 'error', error: 'not_a_member' })); } catch {}
            break;
          }

          let members = voiceChannels.get(channelId);
          if (!members) {
            members = new Set();
            voiceChannels.set(channelId, members);
          }

          if (members.has(user.id)) return;
          members.add(user.id);


          clientData.inCall = true;

          ws.send(JSON.stringify({
            type: 'channel_joined',
            channel_id: channelId,
            self: { id: user.id, username: user.username, display_name: user.display_name },
            members: getVoiceChannelMembers(channelId).filter(m => m.id !== user.id),
          }));

          broadcastToRoomMembers(channelId, user.id, {
            type: 'user_joined_channel',
            channel_id: channelId,
            username: user.username,
            display_name: user.display_name,
          });
          break;
        }

        case 'leave_channel': {
          const channelId = msg.channel_id;
          if (!channelId) return;
          // Only a member of the channel's room may emit presence events into it
          // (mirrors join_channel); otherwise a non-member could spoof
          // user_left_channel into any room.
          const channel = getRoomChannel(Number(channelId));
          if (!channel || !isRoomMember(channel.room_id, user.id)) break;
          const members = voiceChannels.get(channelId);
          if (!members) return;
          members.delete(user.id);
          if (clientData) clientData.inCall = false;
          if (members.size === 0) {
            voiceChannels.delete(channelId);
          }
          broadcastToRoomMembers(channelId, user.id, {
            type: 'user_left_channel',
            channel_id: channelId,
            username: user.username,
          });
          break;
        }
      }
    });

    ws.on('close', () => {
      cleanupClientSubscriptions(ws);
      if (!user) return;
      removeFromVoiceChannels(user.id);
      cancelOutgoingPending(user.id, 'declined');
      const dmSet = dmClients.get(user.id);
      if (dmSet) {
        for (const c of dmSet) {
          if (c.ws === ws) { dmSet.delete(c); break; }
        }
        if (dmSet.size === 0) dmClients.delete(user.id);
      }
      const pushSet = pushClients.get(user.id);
      if (pushSet) {
        pushSet.delete(ws);
        if (pushSet.size === 0) pushClients.delete(user.id);
      }
      const c = clients.get(user.id);
      if (c && c.ws === ws) {
        clients.delete(user.id);
        for (const [otherId, other] of clients) {
          if (other.inCall) {
            try {
              other.ws.send(JSON.stringify({
                type: 'call_ended', from: user.username,
              }));
            } catch {}
          }
        }
        broadcastPresence(user.id, 'user_offline');
      }
    });

    ws.on('error', () => {});
  });
}

function findUserByUsername(username) {
  for (const [id, client] of clients) {
    if (client.username === username) {
      client.userId = id;
      return client;
    }
  }
  return null;
}

function getOnlineUsers(userId) {
  const result = [];
  for (const [id, client] of clients) {
    if (id === userId) continue;
    if (areMutualFollowers(userId, id)) {
      result.push({
        id,
        username: client.username,
        display_name: client.displayName,
        in_call: !!client.inCall,
      });
    }
  }
  return result;
}

function getUserPresence(username) {
  for (const [id, client] of clients) {
    if (client.username === username) {
      return { online: true, in_call: !!client.inCall };
    }
  }
  return { online: false, in_call: false };
}

// Push a new DM or delete event to EVERY open tab and client of the recipient.
function sendDmEvent(toUsername, payload) {
  const message = Object.assign({ type: 'new_dm' }, payload);
  let delivered = false;
  const sentWs = new Set();
  const targetLower = String(toUsername || '').trim().toLowerCase();
  if (!targetLower) return false;

  for (const [userId, conns] of dmClients) {
    for (const c of conns) {
      if (c && String(c.username || '').trim().toLowerCase() === targetLower) {
        if (c.ws && !sentWs.has(c.ws) && c.ws.readyState === 1) {
          try { c.ws.send(JSON.stringify(message)); delivered = true; sentWs.add(c.ws); } catch {}
        }
      }
    }
  }

  for (const [userId, client] of clients) {
    if (client && String(client.username || '').trim().toLowerCase() === targetLower) {
      if (client.ws && !sentWs.has(client.ws) && client.ws.readyState === 1) {
        try { client.ws.send(JSON.stringify(message)); delivered = true; sentWs.add(client.ws); } catch {}
      }
    }
  }

  return delivered;
}

// Deliver a push payload to every push-channel connection (the native app's
// foreground service) of a user. Returns true if at least one was delivered.
function sendWsPush(userId, payload) {
  const conns = pushClients.get(userId);
  if (!conns) return false;
  let delivered = false;
  for (const ws of conns) {
    try { ws.send(JSON.stringify(payload)); delivered = true; } catch {}
  }
  return delivered;
}

// Deliver an arbitrary message to all open WebSockets for a given userId
function sendToUserSockets(userId, messageObj) {
  const uid = Number(userId);
  if (!uid) return false;
  let delivered = false;
  const sentWs = new Set();
  const conns = dmClients.get(uid);
  const json = typeof messageObj === 'string' ? messageObj : JSON.stringify(messageObj);

  if (conns) {
    for (const c of conns) {
      if (c && c.ws && c.ws.readyState === 1 && !sentWs.has(c.ws)) {
        try { c.ws.send(json); delivered = true; sentWs.add(c.ws); } catch {}
      }
    }
  }

  const client = clients.get(uid);
  if (client && client.ws && client.ws.readyState === 1 && !sentWs.has(client.ws)) {
    try { client.ws.send(json); delivered = true; sentWs.add(client.ws); } catch {}
  }

  return delivered;
}

// Push a newly shared Megolm room session key directly to a recipient in realtime
function pushRoomSessionKeyToRecipient(recipientId, keyPayload) {
  const uid = Number(recipientId);
  if (!uid) return false;
  const frame = {
    seq: globalSeq++,
    type: 'gateway_event',
    topic: 'room:' + keyPayload.room_id,
    event: 'room_session_key',
    data: keyPayload,
  };
  // Do NOT add this to recentGatewayEvents: it is addressed to ONE recipient,
  // and the shared replay buffer is replayed on `resume` by topic alone, which
  // would deliver it to every other room member who reconnects. Offline
  // recipients get it via the pending-session-key mechanism instead.
  return sendToUserSockets(uid, frame);
}

module.exports = {
  initSignaling,
  getOnlineUsers,
  getUserPresence,
  getVoiceChannelMembers,
  sendDmEvent,
  sendToUserSockets,
  pushRoomSessionKeyToRecipient,
  cancelPendingCallByToken,
  broadcastGatewayEvent,
  broadcastTimelineEvent,
  removeFromVoiceChannels,
  getGatewayLatestSeq,
  updateUserRoomSubscriptions,
};
