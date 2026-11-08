'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

function intEnv(name, fallback) {
  const raw = process.env[name];
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function strEnv(name) {
  const raw = process.env[name];
  return typeof raw === 'string' && raw.trim() !== '' ? raw.trim() : '';
}

const PORT = (() => {
  const raw = process.env.PORT;
  if (raw === undefined || raw === '') return 8080;
  const value = Number.parseInt(raw, 10);

  return Number.isFinite(value) && value >= 0 ? value : 8080;
})();
const HOST = process.env.HOST || '0.0.0.0';
const ACCESS_FILE = process.env.ACCESS_FILE || path.join(__dirname, 'access.json');
const DEV_TOKEN_FILE = process.env.DEV_TOKEN_FILE || path.join(__dirname, 'devToken.txt');
const DEV_TOKEN_MIN_LENGTH = intEnv('DEV_TOKEN_MIN_LENGTH', 16);
const DEV_TOKEN_FAIL_LIMIT = intEnv('DEV_TOKEN_FAIL_LIMIT', 20);
const DEV_TOKEN_FAIL_WINDOW_MS = intEnv('DEV_TOKEN_FAIL_WINDOW_MS', 300000);
const HEARTBEAT_INTERVAL_MS = intEnv('HEARTBEAT_INTERVAL_MS', 30000);
const HEARTBEAT_TIMEOUT_MS = intEnv('HEARTBEAT_TIMEOUT_MS', 90000);
const MAX_MESSAGE_BYTES = intEnv('MAX_MESSAGE_BYTES', 64 * 1024);
const RATE_WINDOW_MS = intEnv('RATE_WINDOW_MS', 10000);
const RATE_MAX_MESSAGES = intEnv('RATE_MAX_MESSAGES', 60);
const RATE_MAX_COMMANDS = intEnv('RATE_MAX_COMMANDS', 15);
const MAX_SESSIONS = intEnv('MAX_SESSIONS', 500);
const ACK_TIMEOUT_MS = intEnv('ACK_TIMEOUT_MS', 15000);
const ACCESS_WATCH_INTERVAL_MS = intEnv('ACCESS_WATCH_INTERVAL_MS', 3000);
const START_TIME = Date.now();

function log(level, message, extra) {
  const line = `[${new Date().toISOString()}] [${level}] ${message}`;
  if (extra !== undefined) {
    console.log(line, extra);
  } else {
    console.log(line);
  }
}

const access = {
  userids: new Set(),
  raw: [],
};

function parseAccessData(data) {
  let list = data;
  if (data && !Array.isArray(data) && Array.isArray(data.userids)) {
    list = data.userids;
  }
  if (!Array.isArray(list)) return null;
  const ids = [];
  for (const entry of list) {
    const id = typeof entry === 'string' ? Number.parseInt(entry, 10) : entry;
    if (Number.isSafeInteger(id) && id > 0) ids.push(id);
  }
  return ids;
}

function loadAccess(reason) {
  try {
    const text = fs.readFileSync(ACCESS_FILE, 'utf8');
    const ids = parseAccessData(JSON.parse(text));
    if (ids === null) {
      log('warn', `Access file ${ACCESS_FILE} has an unexpected shape (expected { "userids": [ ... ] })`);
      return false;
    }
    const before = access.raw.slice().sort().join(',');
    access.userids = new Set(ids);
    access.raw = ids;
    const after = ids.slice().sort().join(',');
    if (before !== after) {
      log('info', `Access list ${reason || 'loaded'}: ${ids.length} developer id(s)`);
      return true;
    }
    return false;
  } catch (error) {
    log('warn', `Could not read access file ${ACCESS_FILE}: ${error.message}`);
    return false;
  }
}

loadAccess('loaded');

function watchAccessFile() {
  try {
    fs.watch(ACCESS_FILE, { persistent: false }, () => {
      if (loadAccess('reloaded (fs.watch)')) {
        revalidateRoles();
      }
    });
  } catch (error) {
    log('warn', `fs.watch unavailable for access file (${error.message}); using polling`);
  }
  try {
    fs.watchFile(ACCESS_FILE, { interval: ACCESS_WATCH_INTERVAL_MS, persistent: false }, (current, previous) => {
      if (current.mtimeMs !== previous.mtimeMs && loadAccess('reloaded (fs.watchFile)')) {
        revalidateRoles();
      }
    });
  } catch (error) {
    log('warn', `fs.watchFile unavailable for access file (${error.message})`);
  }
}

watchAccessFile();

function isDeveloperId(userId) {
  return access.userids.has(userId);
}

function loadDevToken() {
  const fromEnv = strEnv('CPANEL_DEV_TOKEN');
  if (fromEnv !== '') {
    if (fromEnv.length < DEV_TOKEN_MIN_LENGTH) {
      log('warn', `CPANEL_DEV_TOKEN is shorter than ${DEV_TOKEN_MIN_LENGTH} characters; refusing to load it`);
      return '';
    }
    return fromEnv;
  }
  try {
    const fromFile = fs.readFileSync(DEV_TOKEN_FILE, 'utf8').trim();
    if (fromFile === '') return '';
    if (fromFile.length < DEV_TOKEN_MIN_LENGTH) {
      log('warn', `${DEV_TOKEN_FILE} holds a token shorter than ${DEV_TOKEN_MIN_LENGTH} characters; refusing to load it`);
      return '';
    }
    return fromFile;
  } catch (error) {
    return '';
  }
}

function verifyDevToken(candidate) {
  if (DEV_TOKEN === '') return false;
  if (typeof candidate !== 'string') return false;
  const value = candidate.trim();
  if (value.length !== DEV_TOKEN.length) return false;
  const provided = Buffer.from(value, 'utf8');
  const expected = Buffer.from(DEV_TOKEN, 'utf8');
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

function devTokenLocked(remote) {
  const entry = devTokenFailures.get(remote);
  if (!entry) return false;
  if (Date.now() - entry.windowStart > DEV_TOKEN_FAIL_WINDOW_MS) {
    devTokenFailures.delete(remote);
    return false;
  }
  return entry.count >= DEV_TOKEN_FAIL_LIMIT;
}

function noteDevTokenFailure(remote) {
  const now = Date.now();
  let entry = devTokenFailures.get(remote);
  if (!entry || now - entry.windowStart > DEV_TOKEN_FAIL_WINDOW_MS) {
    entry = { windowStart: now, count: 0 };
    devTokenFailures.set(remote, entry);
  }
  entry.count += 1;
  if (entry.count === DEV_TOKEN_FAIL_LIMIT) {
    log('warn', `${entry.count} invalid developer tokens from ${remote} within ${DEV_TOKEN_FAIL_WINDOW_MS}ms`);
  }
}

const devTokenFailures = new Map();
const DEV_TOKEN = loadDevToken();

function cleanString(value, maxLength, fallback) {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (trimmed.length === 0) return fallback;
  return trimmed.slice(0, maxLength);
}

function cleanInt(value, fallback) {
  const num = typeof value === 'number' ? value : Number.parseInt(value, 10);
  return Number.isSafeInteger(num) ? num : fallback;
}

function safeSend(socket, payload) {
  if (socket.readyState !== socket.OPEN) return false;
  try {
    socket.send(JSON.stringify(payload));
    return true;
  } catch (error) {
    log('warn', `send failed: ${error.message}`);
    return false;
  }
}

function sendError(socket, code, message) {
  return safeSend(socket, { type: 'error', code, message });
}

const sessions = new Map();

const sessionKeys = new Map();

const pendingCommands = new Map();

function publicSession(session) {
  return {
    sessionId: session.id,
    userId: session.userId,
    username: session.username,
    displayName: session.displayName,
    placeId: session.placeId,
    jobId: session.jobId,
    role: session.role,
    connectedAt: session.connectedAt,
  };
}

function countByRole(role) {
  let count = 0;
  for (const session of sessions.values()) {
    if (session.role === role) count += 1;
  }
  return count;
}

function broadcastToDevelopers(payload, onlySessionId) {
  for (const session of sessions.values()) {
    if (session.role !== 'developer') continue;
    if (onlySessionId && session.id !== onlySessionId) continue;
    safeSend(session.socket, payload);
  }
}

function broadcastToAll(payload) {
  for (const session of sessions.values()) {
    safeSend(session.socket, payload);
  }
}

function revalidateRoles() {
  for (const session of Array.from(sessions.values())) {
    if (!session.registered) continue;
    const wanted = isDeveloperId(session.userId) && session.devTokenOk === true ? 'developer' : 'participant';
    if (wanted === session.role) continue;
    session.role = wanted;
    log('info', `role re-evaluated for ${session.id} user=${session.userId} -> ${wanted}`);
    if (wanted === 'participant') {
      try {
        session.socket.close(4403, 'developer access revoked');
      } catch (error) {}
    }
  }
  broadcastParticipantList();
}

function broadcastParticipantList() {
  const list = [];
  for (const session of sessions.values()) list.push(publicSession(session));
  broadcastToDevelopers({ type: 'participants', list });
}

function removeSession(session, reason) {
  if (!session || session.removed) return;
  session.removed = true;
  sessions.delete(session.id);
  if (sessionKeys.get(session.key) === session.id) {
    sessionKeys.delete(session.key);
  }

  for (const [requestId, pending] of Array.from(pendingCommands.entries())) {
    if (pending.targetId === session.id) {
      clearTimeout(pending.timer);
      pendingCommands.delete(requestId);
      const origin = sessions.get(pending.originId);
      if (origin) {
        safeSend(origin.socket, {
          type: 'ack',
          requestId,
          ok: false,
          message: 'target disconnected before responding',
        });
      }
    } else if (pending.originId === session.id) {
      clearTimeout(pending.timer);
      pendingCommands.delete(requestId);
    }
  }

  log('info', `session closed (${reason}): ${session.id} user=${session.userId} role=${session.role}`);
  broadcastToDevelopers({
    type: 'participant_left',
    sessionId: session.id,
    userId: session.userId,
    username: session.username,
    reason,
  });
}

function handleRegister(session, message) {
  if (session.registered) {
    return sendError(session.socket, 'already_registered', 'session is already registered');
  }

  const userId = cleanInt(message.userId, 0);
  if (userId <= 0) {
    return sendError(session.socket, 'invalid_register', 'register requires a valid numeric userId');
  }
  if (sessions.size >= MAX_SESSIONS) {
    return sendError(session.socket, 'server_full', 'session limit reached, try again later');
  }

  const jobId = cleanString(message.jobId, 64, 'unknown');
  const key = `${userId}#${jobId}`;

  const existingId = sessionKeys.get(key);
  if (existingId) {
    const existing = sessions.get(existingId);
    if (existing && existing.socket !== session.socket) {
      log('info', `duplicate session replaced: ${existingId} (user ${userId})`);
      safeSend(existing.socket, { type: 'error', code: 'duplicate_session', message: 'replaced by a newer session' });
      removeSession(existing, 'duplicate');
      try {
        existing.socket.close(4400, 'duplicate session');
      } catch (error) {  }
    }
  }

  session.registered = true;
  session.userId = userId;
  session.username = cleanString(message.username, 64, `User_${userId}`);
  session.displayName = cleanString(message.displayName, 64, session.username);
  session.placeId = cleanInt(message.placeId, 0);
  session.jobId = jobId;
  session.key = key;
  session.connectedAt = Date.now();

  const listed = isDeveloperId(userId);
  const lockedOut = devTokenLocked(session.remote);
  const tokenTrusted = !lockedOut && verifyDevToken(message.devToken);
  session.devTokenOk = tokenTrusted;
  session.role = listed && tokenTrusted ? 'developer' : 'participant';

  if (listed && session.role !== 'developer') {
    noteDevTokenFailure(session.remote);
    log('warn', `developer id ${userId} from ${session.remote} failed token verification${lockedOut ? ' (temporarily locked out)' : ''}; registered as participant`);
  }

  sessions.set(session.id, session);
  sessionKeys.set(key, session.id);

  log('info', `session registered: ${session.id} user=${userId} (@${session.username}) role=${session.role} place=${session.placeId} job=${jobId}`);

  safeSend(session.socket, {
    type: 'welcome',
    sessionId: session.id,
    role: session.role,
    serverTime: Date.now(),
    heartbeat: { intervalMs: HEARTBEAT_INTERVAL_MS, timeoutMs: HEARTBEAT_TIMEOUT_MS },
  });

  broadcastToDevelopers({
    type: 'participant_joined',
    participant: publicSession(session),
  });
}

function handleCommand(session, message) {
  if (!session.registered) {
    return sendError(session.socket, 'not_registered', 'register before sending commands');
  }
  if (session.role !== 'developer') {
    return sendError(session.socket, 'forbidden', 'developer access required to send commands');
  }

  const requestId = cleanString(message.requestId, 64, '');
  const targetId = cleanString(message.target, 64, '');
  const action = cleanString(message.action, 48, '');

  if (!requestId || !targetId || !action) {
    return sendError(session.socket, 'invalid_command', 'command requires requestId, target and action');
  }
  if (!/^[a-z0-9_]+$/.test(action)) {
    return sendError(session.socket, 'invalid_command', 'action names must match [a-z0-9_]+');
  }
  if (pendingCommands.has(requestId)) {
    return sendError(session.socket, 'duplicate_request', 'a command with this requestId is already in flight');
  }

  session.rate.commands += 1;
  if (session.rate.commands > RATE_MAX_COMMANDS) {
    return sendError(session.socket, 'rate_limited', 'too many commands, slow down');
  }

  const args = message.args && typeof message.args === 'object' ? message.args : {};
  const target = sessions.get(targetId);

  if (!target) {
    return safeSend(session.socket, {
      type: 'ack',
      requestId,
      ok: false,
      message: 'target unavailable (not connected)',
    });
  }
  if (target.role === 'developer') {
    return safeSend(session.socket, {
      type: 'ack',
      requestId,
      ok: false,
      message: 'developer sessions cannot be targeted',
    });
  }

  const timer = setTimeout(() => {
    pendingCommands.delete(requestId);
    const origin = sessions.get(session.id);
    if (origin) {
      safeSend(origin.socket, {
        type: 'ack',
        requestId,
        ok: false,
        message: 'no response (ack timeout)',
      });
    }
  }, ACK_TIMEOUT_MS);

  pendingCommands.set(requestId, { originId: session.id, targetId, timer });

  const delivered = safeSend(target.socket, {
    type: 'command',
    action,
    args,
    requestId,
    from: {
      sessionId: session.id,
      userId: session.userId,
      username: session.username,
    },
  });

  if (!delivered) {
    clearTimeout(pendingCommands.get(requestId).timer);
    pendingCommands.delete(requestId);
    safeSend(session.socket, {
      type: 'ack',
      requestId,
      ok: false,
      message: 'target unavailable (send failed)',
    });
  }
}

function handleAck(session, message) {
  if (!session.registered) {
    return sendError(session.socket, 'not_registered', 'register before sending acks');
  }
  const requestId = cleanString(message.requestId, 64, '');
  const pending = pendingCommands.get(requestId);

  if (!pending || pending.targetId !== session.id) {
    return sendError(session.socket, 'unknown_ack', 'no matching command for this requestId');
  }

  clearTimeout(pending.timer);
  pendingCommands.delete(requestId);

  const origin = sessions.get(pending.originId);
  if (!origin) return;

  safeSend(origin.socket, {
    type: 'ack',
    requestId,
    ok: message.ok === true,
    message: cleanString(message.message, 240, message.ok === true ? 'ok' : 'failed'),
  });
}

function dispatch(session, message) {
  if (!message || typeof message !== 'object') {
    return sendError(session.socket, 'bad_message', 'expected a JSON object');
  }
  const type = cleanString(message.type, 32, '');
  switch (type) {
    case 'register':
      return handleRegister(session, message);
    case 'participants': {
      if (!session.registered) {
        return sendError(session.socket, 'not_registered', 'register before requesting the participant list');
      }
      if (session.role !== 'developer') {
        return sendError(session.socket, 'forbidden', 'developer access required for the participant list');
      }
      const list = [];
      for (const entry of sessions.values()) list.push(publicSession(entry));
      return safeSend(session.socket, { type: 'participants', list });
    }
    case 'command':
      return handleCommand(session, message);
    case 'ack':
      return handleAck(session, message);
    case 'ping':
      return safeSend(session.socket, { type: 'pong', serverTime: Date.now() });
    case 'pong':
      return;
    default:
      return sendError(session.socket, 'unknown_type', `unknown message type: ${type || '(empty)'}`);
  }
}

const httpServer = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];

  if (url === '/health') {
    const body = JSON.stringify({
      ok: true,
      service: 'cpanel-websocket',
      uptimeMs: Date.now() - START_TIME,
      sessions: sessions.size,
      developers: countByRole('developer'),
      participants: countByRole('participant'),
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(body);
    return;
  }

  if (url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(
      'CPanel WebSocket backend\n' +
      '========================\n' +
      'Point your loader at: wss://<this-host>/\n' +
      'Health check: /health\n'
    );
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found\n');
});

const wss = new WebSocketServer({ server: httpServer, maxPayload: MAX_MESSAGE_BYTES });

wss.on('connection', (socket, req) => {
  const session = {
    id: crypto.randomUUID(),
    socket,
    registered: false,
    removed: false,
    userId: 0,
    username: '',
    displayName: '',
    placeId: 0,
    jobId: 'unknown',
    role: 'participant',
    devTokenOk: false,
    key: '',
    connectedAt: Date.now(),
    lastSeen: Date.now(),
    rate: { windowStart: Date.now(), count: 0, commands: 0 },
    remote: req.socket.remoteAddress || 'unknown',
  };

  log('info', `connection open: ${session.id} from ${session.remote}`);

  socket.on('message', (data, isBinary) => {
    session.lastSeen = Date.now();

    const now = Date.now();
    if (now - session.rate.windowStart > RATE_WINDOW_MS) {
      session.rate.windowStart = now;
      session.rate.count = 0;
      session.rate.commands = 0;
    }
    session.rate.count += 1;
    if (session.rate.count > RATE_MAX_MESSAGES) {
      sendError(socket, 'rate_limited', 'too many messages');
      return;
    }

    if (isBinary) {
      sendError(socket, 'bad_message', 'binary frames are not supported');
      return;
    }

    let message;
    try {
      message = JSON.parse(data.toString('utf8'));
    } catch (error) {
      sendError(socket, 'bad_json', 'message is not valid JSON');
      return;
    }

    try {
      dispatch(session, message);
    } catch (error) {
      log('error', `dispatch failed for ${session.id}: ${error.stack || error.message}`);
      sendError(socket, 'internal_error', 'server failed to handle the message');
    }
  });

  socket.on('close', () => {
    removeSession(session, 'closed');
  });

  socket.on('error', (error) => {
    log('warn', `socket error ${session.id}: ${error.message}`);
    removeSession(session, 'error');
  });
});

const sweepIntervalMs = Math.max(50, Math.min(HEARTBEAT_INTERVAL_MS, 30000));

setInterval(() => {
  const now = Date.now();
  for (const session of Array.from(sessions.values())) {
    if (now - session.lastSeen > HEARTBEAT_TIMEOUT_MS) {
      log('info', `session expired (no heartbeat): ${session.id} user=${session.userId}`);
      try {
        session.socket.close(4001, 'heartbeat timeout');
      } catch (error) {  }
      removeSession(session, 'expired');
      continue;
    }
  }
}, sweepIntervalMs);

setInterval(() => {
  broadcastToAll({ type: 'ping', serverTime: Date.now() });
}, HEARTBEAT_INTERVAL_MS);

httpServer.listen(PORT, HOST, () => {
  const actualPort = httpServer.address().port;
  log('info', `CPanel WebSocket backend listening on http://${HOST}:${actualPort}`);
  log('info', `access file: ${ACCESS_FILE} (${access.raw.length} developer id(s))`);
  log('info', DEV_TOKEN === '' ? 'developer token: NOT CONFIGURED - developer role will never be granted (set CPANEL_DEV_TOKEN or create devToken.txt)' : `developer token: loaded (${DEV_TOKEN.length} chars, source: ${strEnv('CPANEL_DEV_TOKEN') !== '' ? 'env' : 'file'})`);
  log('info', `heartbeat: interval=${HEARTBEAT_INTERVAL_MS}ms timeout=${HEARTBEAT_TIMEOUT_MS}ms`);

  console.log(`LISTENING port=${actualPort}`);
});

function shutdown(signal) {
  log('info', `received ${signal}, shutting down`);
  for (const [, pending] of pendingCommands.entries()) clearTimeout(pending.timer);
  pendingCommands.clear();
  try {
    wss.close();
  } catch (error) {  }
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));