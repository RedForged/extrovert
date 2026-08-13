'use strict';

const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const { getUserById, getUserByUsername, areMutualFollowers, getRoomChannel, isRoomMember, getOAuthToken, createNotification } = require('./db');
const { sendCallPush, sendMissedCallPush } = require('./push');

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
          if (user) return user;
        }
      }
    }
  }
  // 2. Bearer token via ?token= query param (native/mobile clients)
  try {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token');
    if (token) {
      const tokenRecord = getOAuthToken(token);
      if (tokenRecord && (!tokenRecord.expires_at || tokenRecord.expires_at > Date.now())) {
        const user = getUserById(tokenRecord.user_id);
        if (user) return user;
      }
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
    const user = lookupUserFromRequest(req);
    if (!user) {
      console.log('WS auth failed: no user from request', req.headers.cookie ? 'cookie present' : 'no cookie');
      ws.close(4001, 'Unauthorized');
      return;
    }
    console.log('WS connected:', user.username, '(id:', user.id + ')');

    // A connection is only a signaling client once it proves it isn't a push
    // channel: the first message is either {type:'push_register'} (native push
    // service — never appears online, calls are pushed to it) or anything else
    // (the web/native UI client, which sends {type:'ping'} on open).
    let registered = false;
    let clientData = null;

    function registerSignalingClient() {
      if (registered) return;
      registered = true;

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

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }

      // First message decides the connection's role.
      if (!registered) {
        if (msg.type === 'push_register') {
          registered = true;
          if (!pushClients.has(user.id)) pushClients.set(user.id, new Set());
          pushClients.get(user.id).add(ws);
          console.log('push channel registered:', user.username, '(id:', user.id + ')');
          try { ws.send(JSON.stringify({ type: 'push_registered' })); } catch {}
          return;
        }
        registerSignalingClient();
      }

      switch (msg.type) {
        case 'ping':
          try { ws.send(JSON.stringify({ type: 'pong' })); } catch {}
          break;

        // First step of a 1:1 call: ask the server whether the callee is
        // reachable. Server replies callee_available (proceed with offer),
        // user_busy, or calling_offline (callee is offline but has been
        // queued for ring-on-reconnect + notified of a missed call).
        case 'call_request': {
          if (msg.channel_id) break; // room voice channels use call_offer directly
          console.log('WS msg call_request from', user.username, 'to', msg.to);
          const target = findUserByUsername(msg.to);
          if (target) {
            if (target.inCall) {
              console.log('  -> target busy');
              try { ws.send(JSON.stringify({ type: 'user_busy', from: msg.to })); } catch {}
            } else {
              console.log('  -> target online, callee_available');
              try { ws.send(JSON.stringify({ type: 'callee_available', to: msg.to })); } catch {}
            }
            break;
          }
          // Target offline: resolve via DB and queue a pending call.
          const callee = getUserByUsername(msg.to);
          if (!callee) {
            console.log('  -> callee not found');
            try { ws.send(JSON.stringify({ type: 'user_offline', from: msg.to })); } catch {}
            break;
          }
          if (!areMutualFollowers(user.id, callee.id)) {
            console.log('  -> not mutual followers');
            try { ws.send(JSON.stringify({ type: 'user_offline', from: msg.to })); } catch {}
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
            if (target) {
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
            } else {
              console.log('  -> target not found');
            }
          }
          break;

        case 'ice_candidate':
          console.log('WS msg ice_candidate from', user.username, 'to', msg.to);
          if (msg.channel_id) {
            routeToChannelMember(msg, user, 'ice_candidate');
          } else {
            const target = findUserByUsername(msg.to);
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
          const members = voiceChannels.get(channelId);
          if (!members) return;
          members.delete(user.id);
          clientData.inCall = false;
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
    if (client.username === username) return client;
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
module.exports = { initSignaling, getOnlineUsers, getUserPresence, getVoiceChannelMembers, sendDmEvent, cancelPendingCallByToken };
