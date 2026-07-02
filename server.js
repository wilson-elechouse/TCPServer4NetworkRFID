#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const net = require('net');
const path = require('path');
const { URL } = require('url');

const HTTP_HOST = process.env.HTTP_HOST || '127.0.0.1';
const HTTP_PORT = Number(process.env.HTTP_PORT || 19090);
const TCP_HOST = process.env.TCP_HOST || '0.0.0.0';
const TCP_PORT = Number(process.env.TCP_PORT || 9000);
const PUBLIC_TCP_HOST = process.env.PUBLIC_TCP_HOST || 'www.elechouse.com';
const PUBLIC_BASE_PATH = normalizeBasePath(process.env.PUBLIC_BASE_PATH || '/rfid-tcp-broker');
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 30 * 60 * 1000);
const HELLO_TIMEOUT_MS = Number(process.env.HELLO_TIMEOUT_MS || 10 * 1000);
const MAX_HELLO_BYTES = Number(process.env.MAX_HELLO_BYTES || 512);
const MAX_WS_PAYLOAD_BYTES = Number(process.env.MAX_WS_PAYLOAD_BYTES || 64 * 1024);
const MAX_DEVICE_CHUNK_BYTES = Number(process.env.MAX_DEVICE_CHUNK_BYTES || 64 * 1024);
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS || 200);
const MAX_WEB_CLIENTS_PER_SESSION = Number(process.env.MAX_WEB_CLIENTS_PER_SESSION || 8);
const SESSION_CODE_LENGTH = Number(process.env.SESSION_CODE_LENGTH || 8);
const SESSION_CODE_ALPHABET = process.env.SESSION_CODE_ALPHABET || 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CREATE_RATE_LIMIT_PER_MIN = Number(process.env.CREATE_RATE_LIMIT_PER_MIN || 30);
// Optional WordPress login gate. Keep disabled by default for the open-source/demo package.
// Set REQUIRE_WEB_AUTH=1 to require a valid WordPress login cookie for the browser UI/API.
const REQUIRE_WEB_AUTH = process.env.REQUIRE_WEB_AUTH === '1';
const WORDPRESS_AUTH_CHECK_URL = process.env.WORDPRESS_AUTH_CHECK_URL || 'http://127.0.0.1/wp-json/elechouse-rfid/v1/auth-check';
const WORDPRESS_AUTH_HOST = process.env.WORDPRESS_AUTH_HOST || 'www.elechouse.com';
const AUTH_CACHE_MS = Number(process.env.AUTH_CACHE_MS || 15 * 1000);
const MAX_TCP_CONNECTIONS_PER_IP = Number(process.env.MAX_TCP_CONNECTIONS_PER_IP || 5);
const MAX_TCP_AUTH_FAILURES_PER_IP = Number(process.env.MAX_TCP_AUTH_FAILURES_PER_IP || 300);
const TCP_AUTH_FAILURE_WINDOW_MS = Number(process.env.TCP_AUTH_FAILURE_WINDOW_MS || 10 * 60 * 1000);
const TCP_AUTH_BLOCK_MS = Number(process.env.TCP_AUTH_BLOCK_MS || 10 * 60 * 1000);
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'elechouse_rfid_session_code';

const sessions = new Map();
const rateBuckets = new Map();
const authCache = new Map();
const tcpIpStates = new Map();

function normalizeBasePath(path) {
  let value = String(path || '').trim();
  if (!value.startsWith('/')) value = `/${value}`;
  return value.replace(/\/+$/, '');
}

function nowIso() {
  return new Date().toISOString();
}

function log(level, message, meta = {}) {
  const line = JSON.stringify({ at: nowIso(), level, message, ...meta });
  if (level === 'error' || level === 'warn') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function json(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function text(res, status, body, contentType = 'text/plain; charset=utf-8', extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(body);
}

function clientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}

function rateLimitCreate(ip) {
  const minute = Math.floor(Date.now() / 60000);
  const current = rateBuckets.get(ip);
  if (!current || current.minute !== minute) {
    rateBuckets.set(ip, { minute, count: 1 });
    return true;
  }
  current.count += 1;
  return current.count <= CREATE_RATE_LIMIT_PER_MIN;
}

function getCookieHeader(req) {
  return String(req.headers.cookie || '').trim();
}

function parseCookies(cookieHeader) {
  const cookies = {};
  for (const part of String(cookieHeader || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const name = part.slice(0, idx).trim();
    const rawValue = part.slice(idx + 1).trim();
    if (!name) continue;
    try {
      cookies[name] = decodeURIComponent(rawValue);
    } catch (_error) {
      cookies[name] = rawValue;
    }
  }
  return cookies;
}

function isSecureRequest(req) {
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return proto === 'https' || Boolean(req.socket.encrypted);
}

function sessionCookieHeader(session, req) {
  const maxAge = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
  const secure = isSecureRequest(req) ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(session.code)}; Path=${PUBLIC_BASE_PATH}; Max-Age=${maxAge}; SameSite=Lax; HttpOnly${secure}`;
}

function clearSessionCookieHeader(req) {
  const secure = isSecureRequest(req) ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=; Path=${PUBLIC_BASE_PATH}; Max-Age=0; SameSite=Lax; HttpOnly${secure}`;
}

function looksLikeWordPressLoginCookie(cookie) {
  return /(?:^|;\s*)wordpress_logged_in_[^=]+=/.test(cookie) || /(?:^|;\s*)wordpress_sec_[^=]+=/.test(cookie);
}

function authCacheKey(cookie) {
  return crypto.createHash('sha256').update(cookie).digest('hex');
}

function isAdminUser(user) {
  const roles = Array.isArray(user?.roles) ? user.roles : [];
  return roles.includes('administrator');
}

async function checkWebAuth(req) {
  if (!REQUIRE_WEB_AUTH) {
    return { ok: true, user: { id: 0, login: 'local-dev', display_name: 'Local Dev', roles: [] } };
  }

  const cookie = getCookieHeader(req);
  if (!cookie || !looksLikeWordPressLoginCookie(cookie)) {
    return { ok: false, status: 401, error: 'login_required' };
  }

  const key = authCacheKey(cookie);
  const cached = authCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.result;
  }

  try {
    const response = await requestWordPressAuthCheck(cookie);
    let body = {};
    try {
      body = JSON.parse(response.bodyText || '{}');
    } catch (_error) {
      body = {};
    }
    const result = response.statusCode >= 200 && response.statusCode < 300 && body && body.ok
      ? { ok: true, user: body.user || null }
      : { ok: false, status: response.statusCode || 401, error: body.error || 'login_required' };
    authCache.set(key, { result, expiresAt: Date.now() + AUTH_CACHE_MS });
    return result;
  } catch (error) {
    log('warn', 'auth_check_failed', { error: error.message });
    return { ok: false, status: 503, error: 'auth_check_failed' };
  }
}

function requestWordPressAuthCheck(cookie) {
  return new Promise((resolve, reject) => {
    const url = new URL(WORDPRESS_AUTH_CHECK_URL);
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers: {
        Cookie: cookie,
        Host: WORDPRESS_AUTH_HOST,
        'X-Forwarded-Proto': 'https',
        'User-Agent': 'elechouse-rfid-tcp-broker/0.1',
        Accept: 'application/json',
      },
      timeout: 2500,
    }, (response) => {
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total <= 64 * 1024) chunks.push(chunk);
      });
      response.on('end', () => {
        resolve({
          statusCode: response.statusCode || 0,
          bodyText: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    request.on('timeout', () => request.destroy(new Error('auth_check_timeout')));
    request.on('error', reject);
    request.end();
  });
}

function renderLoginRequiredPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login required - RFID TCP Broker</title>
  <style>
    body { margin:0; background:#f8fafc; color:#111827; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { max-width:720px; margin:0 auto; padding:56px 18px; }
    .card { background:white; border:1px solid #e5e7eb; border-radius:18px; padding:28px; box-shadow:0 12px 34px rgba(15,23,42,.06); }
    h1 { margin:0 0 10px; font-size:26px; }
    p { line-height:1.65; color:#4b5563; }
    a.button { display:inline-block; margin-top:12px; padding:11px 16px; background:#0f766e; color:white; border-radius:10px; text-decoration:none; font-weight:700; }
    a.link { color:#0f766e; font-weight:650; text-decoration:none; }
  </style>
</head>
<body>
  <main>
    <div class="card">
      <h1>请先登录 ELECHOUSE 账号</h1>
      <p>RFID TCP Broker 是在线调试工具。为了防止公开 TCP 服务被滥用，测试页面和 session 创建现在需要登录后使用。</p>
      <p>设备端不需要登录；设备只需要使用登录网页上生成的测试码连接 TCP Broker。</p>
      <a class="button" href="/my-account/">登录 / My Account</a>
      <p><a class="link" href="${PUBLIC_BASE_PATH}/firmware">查看固件接入说明</a></p>
    </div>
  </main>
</body>
</html>`;
}

function randomCode() {
  let code = '';
  for (let i = 0; i < SESSION_CODE_LENGTH; i += 1) {
    const idx = crypto.randomInt(0, SESSION_CODE_ALPHABET.length);
    code += SESSION_CODE_ALPHABET[idx];
  }
  return code;
}

function createSession(owner = null) {
  cleanupExpiredSessions();
  if (sessions.size >= MAX_SESSIONS) {
    throw new Error('too_many_sessions');
  }

  let code = randomCode();
  for (let i = 0; i < 20 && sessions.has(code); i += 1) {
    code = randomCode();
  }
  if (sessions.has(code)) {
    throw new Error('code_collision');
  }

  const now = Date.now();
  const session = {
    code,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    webClients: new Set(),
    device: null,
    eventSeq: 0,
    lastActivityAt: now,
    owner,
  };
  sessions.set(code, session);
  log('info', 'session_created', { code, expiresAt: new Date(session.expiresAt).toISOString(), userId: owner?.id || null });
  return session;
}

function sessionPublicInfo(session) {
  return {
    code: session.code,
    expiresAt: new Date(session.expiresAt).toISOString(),
    ttlSeconds: Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000)),
    tcpHost: PUBLIC_TCP_HOST,
    tcpPort: TCP_PORT,
    helloText: `HELLO ${session.code}\\n`,
    wsPath: `${PUBLIC_BASE_PATH}/ws`,
  };
}

function sessionBelongsToUser(session, user) {
  if (!REQUIRE_WEB_AUTH) return true;
  const sessionUserId = Number(session?.owner?.id || 0);
  const requestUserId = Number(user?.id || 0);
  return Boolean(sessionUserId && requestUserId && sessionUserId === requestUserId);
}

function getRequestedSessionCode(req, reqUrl) {
  const urlCode = normalizeCode(reqUrl.searchParams.get('code'));
  if (urlCode) return urlCode;
  const cookies = parseCookies(getCookieHeader(req));
  return normalizeCode(cookies[SESSION_COOKIE_NAME]);
}

function getReusableSession(req, reqUrl, user) {
  const code = getRequestedSessionCode(req, reqUrl);
  if (!code) return null;
  const session = getLiveSession(code);
  if (!session || !sessionBelongsToUser(session, user)) return null;
  session.lastActivityAt = Date.now();
  return session;
}

function isExpired(session) {
  return !session || Date.now() >= session.expiresAt;
}

function getLiveSession(code) {
  const normalized = normalizeCode(code);
  const session = sessions.get(normalized);
  if (!session || isExpired(session)) {
    if (session) expireSession(session, 'expired');
    return null;
  }
  return session;
}

function normalizeCode(code) {
  return String(code || '').trim().toUpperCase();
}

function expireSession(session, reason = 'expired') {
  if (!session || !sessions.has(session.code)) return;
  broadcast(session, { type: 'session_expired', reason });
  if (session.device && !session.device.socket.destroyed) {
    safeWrite(session.device.socket, `ERR session_${reason}\n`);
    session.device.socket.destroy();
  }
  for (const client of [...session.webClients]) {
    wsClose(client, 1000, `session_${reason}`);
  }
  sessions.delete(session.code);
  log('info', 'session_removed', { code: session.code, reason });
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const session of [...sessions.values()]) {
    if (now >= session.expiresAt) expireSession(session, 'expired');
  }
  const currentMinute = Math.floor(now / 60000);
  for (const [ip, bucket] of [...rateBuckets.entries()]) {
    if (bucket.minute < currentMinute - 5) rateBuckets.delete(ip);
  }
  for (const [key, cached] of [...authCache.entries()]) {
    if (cached.expiresAt <= now) authCache.delete(key);
  }
  for (const [ip, state] of [...tcpIpStates.entries()]) {
    const noConnections = (state.connections || 0) <= 0;
    const oldFailures = !state.firstFailureAt || now - state.firstFailureAt > TCP_AUTH_FAILURE_WINDOW_MS;
    const unblocked = !state.blockedUntil || state.blockedUntil <= now;
    if (noConnections && oldFailures && unblocked) tcpIpStates.delete(ip);
  }
}

async function handleHttp(req, res) {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = reqUrl.pathname.replace(/\/+$/, '') || '/';

  if (path === '/' && req.method === 'GET') {
    const auth = await checkWebAuth(req);
    if (!auth.ok) {
      return text(res, auth.status === 503 ? 503 : 401, renderLoginRequiredPage(), 'text/html; charset=utf-8');
    }
    try {
      const session = getReusableSession(req, reqUrl, auth.user) || createSession(auth.user || null);
      return text(
        res,
        200,
        renderPage(sessionPublicInfo(session)),
        'text/html; charset=utf-8',
        { 'Set-Cookie': sessionCookieHeader(session, req) }
      );
    } catch (error) {
      log('warn', 'initial_session_create_failed', { error: error.message });
      return text(res, 503, renderPage(null, error.message), 'text/html; charset=utf-8');
    }
  }

  if (path === '/firmware' && req.method === 'GET') {
    return text(res, 200, renderFirmwareDocHtml(), 'text/html; charset=utf-8');
  }

  if (path === '/firmware.md' && req.method === 'GET') {
    return text(res, 200, readFirmwareDoc(), 'text/markdown; charset=utf-8');
  }

  if (path === '/health' && req.method === 'GET') {
    return json(res, 200, {
      ok: true,
      service: 'elechouse-rfid-tcp-broker',
      time: nowIso(),
      sessions: sessions.size,
      tcpPort: TCP_PORT,
      httpPort: HTTP_PORT,
    });
  }

  if (path === '/api/session' && (req.method === 'POST' || req.method === 'GET')) {
    const auth = await checkWebAuth(req);
    if (!auth.ok) {
      return json(res, auth.status === 503 ? 503 : 401, { ok: false, error: auth.error || 'login_required' });
    }

    const ip = clientIp(req);
    if (!rateLimitCreate(ip)) {
      return json(res, 429, { ok: false, error: 'rate_limited' });
    }
    try {
      const oldSession = getReusableSession(req, reqUrl, auth.user);
      if (oldSession) expireSession(oldSession, 'replaced_by_new_session');
      const session = createSession(auth.user || null);
      return json(res, 200, { ok: true, session: sessionPublicInfo(session) }, { 'Set-Cookie': sessionCookieHeader(session, req) });
    } catch (error) {
      log('warn', 'create_session_failed', { error: error.message });
      return json(res, 503, { ok: false, error: error.message });
    }
  }

  if (path === '/api/session/close' && (req.method === 'POST' || req.method === 'DELETE')) {
    const auth = await checkWebAuth(req);
    if (!auth.ok) {
      return json(res, auth.status === 503 ? 503 : 401, { ok: false, error: auth.error || 'login_required' });
    }

    const session = getReusableSession(req, reqUrl, auth.user);
    if (!session) {
      return json(res, 200, { ok: true, closed: false, reason: 'no_live_session' }, { 'Set-Cookie': clearSessionCookieHeader(req) });
    }

    const code = session.code;
    expireSession(session, 'closed_by_user');
    return json(res, 200, { ok: true, closed: true, code }, { 'Set-Cookie': clearSessionCookieHeader(req) });
  }

  if (path === '/api/stats' && req.method === 'GET') {
    const auth = await checkWebAuth(req);
    if (!auth.ok) {
      return json(res, auth.status === 503 ? 503 : 401, { ok: false, error: auth.error || 'login_required' });
    }
    if (REQUIRE_WEB_AUTH && !isAdminUser(auth.user)) {
      return json(res, 403, { ok: false, error: 'admin_required' });
    }

    return json(res, 200, {
      ok: true,
      sessions: [...sessions.values()].map((session) => ({
        code: session.code,
        expiresAt: new Date(session.expiresAt).toISOString(),
        webClients: session.webClients.size,
        deviceConnected: Boolean(session.device && !session.device.socket.destroyed),
        deviceId: session.device?.deviceId || null,
        remoteAddress: session.device?.remoteAddress || null,
        userId: session.owner?.id || null,
      })),
    });
  }

  return json(res, 404, { ok: false, error: 'not_found' });
}

const httpServer = http.createServer((req, res) => {
  handleHttp(req, res).catch((error) => {
    log('error', 'http_handler_failed', { error: error.stack || error.message });
    if (!res.headersSent) json(res, 500, { ok: false, error: 'internal_error' });
  });
});

httpServer.on('upgrade', (req, socket) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (reqUrl.pathname !== '/ws') {
    socket.end('HTTP/1.1 404 Not Found\r\n\r\n');
    return;
  }

  const code = normalizeCode(reqUrl.searchParams.get('code'));
  const session = getLiveSession(code);
  if (!session) {
    socket.end('HTTP/1.1 404 Not Found\r\n\r\nInvalid or expired code');
    return;
  }
  if (session.webClients.size >= MAX_WEB_CLIENTS_PER_SESSION) {
    socket.end('HTTP/1.1 429 Too Many Requests\r\n\r\nToo many web clients for this code');
    return;
  }

  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\nMissing Sec-WebSocket-Key');
    return;
  }

  const accept = crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');

  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '\r\n',
  ].join('\r\n'));

  const client = {
    id: crypto.randomUUID(),
    socket,
    session,
    buffer: Buffer.alloc(0),
    connectedAt: Date.now(),
  };
  session.webClients.add(client);
  log('info', 'web_connected', { code: session.code, clients: session.webClients.size, ip: clientIp(req) });

  wsSend(client, {
    type: 'ready',
    session: sessionPublicInfo(session),
    deviceConnected: Boolean(session.device && !session.device.socket.destroyed),
    deviceId: session.device?.deviceId || null,
    remoteAddress: session.device?.remoteAddress || null,
  });
  broadcast(session, { type: 'web_client_count', count: session.webClients.size });

  socket.on('data', (chunk) => handleWsData(client, chunk));
  socket.on('close', () => removeWebClient(client));
  socket.on('error', (error) => {
    if (error && (error.code === 'EPIPE' || error.code === 'ERR_STREAM_WRITE_AFTER_END')) {
      removeWebClient(client);
      return;
    }
    log('warn', 'web_socket_error', { code: session.code, error: error.message, errorCode: error.code || null });
    removeWebClient(client);
  });
});

function removeWebClient(client) {
  if (!client || !client.session) return;
  const session = client.session;
  if (session.webClients.delete(client)) {
    log('info', 'web_disconnected', { code: session.code, clients: session.webClients.size });
    broadcast(session, { type: 'web_client_count', count: session.webClients.size });
  }
}

function wsSend(client, obj) {
  if (!client || client.socket.destroyed || client.socket.writableEnded || !client.socket.writable) return;
  const payload = Buffer.from(JSON.stringify({ at: nowIso(), ...obj }), 'utf8');
  const header = createWsHeader(0x1, payload.length);
  client.socket.write(Buffer.concat([header, payload]));
}

function wsClose(client, code = 1000, reason = '') {
  if (!client || client.socket.destroyed || client.socket.writableEnded || !client.socket.writable) return;
  const reasonBuffer = Buffer.from(String(reason).slice(0, 120), 'utf8');
  const payload = Buffer.alloc(2 + reasonBuffer.length);
  payload.writeUInt16BE(code, 0);
  reasonBuffer.copy(payload, 2);
  client.socket.write(Buffer.concat([createWsHeader(0x8, payload.length), payload]));
  client.socket.end();
}

function createWsHeader(opcode, length) {
  if (length < 126) {
    return Buffer.from([0x80 | opcode, length]);
  }
  if (length < 65536) {
    const header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
    return header;
  }
  const header = Buffer.alloc(10);
  header[0] = 0x80 | opcode;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(length), 2);
  return header;
}

function handleWsData(client, chunk) {
  client.buffer = Buffer.concat([client.buffer, chunk]);
  while (client.buffer.length >= 2) {
    const first = client.buffer[0];
    const second = client.buffer[1];
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let length = second & 0x7f;
    let offset = 2;

    if (length === 126) {
      if (client.buffer.length < offset + 2) return;
      length = client.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (length === 127) {
      if (client.buffer.length < offset + 8) return;
      const bigLength = client.buffer.readBigUInt64BE(offset);
      if (bigLength > BigInt(MAX_WS_PAYLOAD_BYTES)) {
        wsClose(client, 1009, 'payload_too_large');
        return;
      }
      length = Number(bigLength);
      offset += 8;
    }

    if (length > MAX_WS_PAYLOAD_BYTES) {
      wsClose(client, 1009, 'payload_too_large');
      return;
    }

    let mask;
    if (masked) {
      if (client.buffer.length < offset + 4) return;
      mask = client.buffer.subarray(offset, offset + 4);
      offset += 4;
    }

    if (client.buffer.length < offset + length) return;

    let payload = Buffer.from(client.buffer.subarray(offset, offset + length));
    client.buffer = client.buffer.subarray(offset + length);

    if (masked && mask) {
      for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
    }

    if (opcode === 0x8) {
      client.socket.end();
      return;
    }
    if (opcode === 0x9) {
      client.socket.write(Buffer.concat([createWsHeader(0xA, payload.length), payload]));
      continue;
    }
    if (opcode !== 0x1) {
      continue;
    }

    let msg;
    try {
      msg = JSON.parse(payload.toString('utf8'));
    } catch (_error) {
      wsSend(client, { type: 'error', error: 'invalid_json' });
      continue;
    }
    handleWebMessage(client, msg);
  }
}

function handleWebMessage(client, msg) {
  const session = client.session;
  if (!getLiveSession(session.code)) {
    wsClose(client, 1000, 'session_expired');
    return;
  }

  if (msg.type === 'ping') {
    wsSend(client, { type: 'pong' });
    return;
  }

  if (msg.type === 'send') {
    const device = session.device;
    if (!device || device.socket.destroyed) {
      wsSend(client, { type: 'error', error: 'device_not_connected' });
      return;
    }
    let payload = String(msg.payload ?? '');
    if (msg.appendNewline !== false && !payload.endsWith('\n')) payload += '\n';
    const data = Buffer.from(payload, 'utf8');
    if (data.length > MAX_WS_PAYLOAD_BYTES) {
      wsSend(client, { type: 'error', error: 'payload_too_large' });
      return;
    }
    device.socket.write(data);
    session.lastActivityAt = Date.now();
    broadcast(session, {
      type: 'web_to_device',
      text: payload,
      hex: data.toString('hex'),
      bytes: data.length,
    });
    return;
  }

  wsSend(client, { type: 'error', error: 'unknown_message_type' });
}

function broadcast(session, obj) {
  session.eventSeq += 1;
  const message = { seq: session.eventSeq, ...obj };
  for (const client of [...session.webClients]) {
    wsSend(client, message);
  }
}

function normalizeRemoteIp(address) {
  return String(address || 'unknown').replace(/^::ffff:/, '');
}

function getTcpIpState(ip) {
  let state = tcpIpStates.get(ip);
  if (!state) {
    state = { connections: 0, failures: 0, firstFailureAt: 0, blockedUntil: 0 };
    tcpIpStates.set(ip, state);
  }
  return state;
}

function incrementTcpConnection(ip) {
  const state = getTcpIpState(ip);
  state.connections += 1;
  return state;
}

function decrementTcpConnection(ip) {
  const state = tcpIpStates.get(ip);
  if (!state) return;
  state.connections = Math.max(0, state.connections - 1);
}

function recordTcpAuthFailure(ip, reason) {
  const now = Date.now();
  const state = getTcpIpState(ip);
  if (!state.firstFailureAt || now - state.firstFailureAt > TCP_AUTH_FAILURE_WINDOW_MS) {
    state.firstFailureAt = now;
    state.failures = 0;
  }
  state.failures += 1;
  if (state.failures >= MAX_TCP_AUTH_FAILURES_PER_IP) {
    state.blockedUntil = now + TCP_AUTH_BLOCK_MS;
    log('warn', 'tcp_ip_temporarily_blocked', {
      ip,
      reason,
      failures: state.failures,
      blockedUntil: new Date(state.blockedUntil).toISOString(),
    });
  }
}

function clearTcpAuthFailures(ip) {
  const state = tcpIpStates.get(ip);
  if (!state) return;
  state.failures = 0;
  state.firstFailureAt = 0;
  state.blockedUntil = 0;
}

const tcpServer = net.createServer((socket) => {
  socket.setKeepAlive(true, 30000);
  socket.setNoDelay(true);

  const remoteIp = normalizeRemoteIp(socket.remoteAddress);
  const remoteAddress = `${remoteIp}:${socket.remotePort || ''}`;
  const ipState = incrementTcpConnection(remoteIp);
  let helloBuffer = Buffer.alloc(0);
  let session = null;
  let authed = false;

  socket.once('close', () => decrementTcpConnection(remoteIp));

  if (ipState.blockedUntil && ipState.blockedUntil > Date.now()) {
    rejectTcp(socket, 'ip_temporarily_blocked', remoteIp);
    return;
  }

  if (ipState.connections > MAX_TCP_CONNECTIONS_PER_IP) {
    rejectTcp(socket, 'too_many_connections_from_ip', remoteIp);
    return;
  }

  const helloTimer = setTimeout(() => {
    if (!authed) rejectTcp(socket, 'hello_timeout', remoteIp);
  }, HELLO_TIMEOUT_MS);

  socket.on('data', (chunk) => {
    if (chunk.length > MAX_DEVICE_CHUNK_BYTES) {
      rejectTcp(socket, 'chunk_too_large', remoteIp);
      return;
    }

    if (!authed) {
      helloBuffer = Buffer.concat([helloBuffer, chunk]);
      if (helloBuffer.length > MAX_HELLO_BYTES) {
        rejectTcp(socket, 'hello_too_large', remoteIp);
        return;
      }
      const newline = findNewline(helloBuffer);
      if (newline < 0) return;

      const lineBuffer = helloBuffer.subarray(0, newline);
      const leftover = helloBuffer.subarray(skipLineEnding(helloBuffer, newline));
      const hello = parseHello(lineBuffer.toString('utf8'));
      if (!hello.ok) {
        rejectTcp(socket, hello.error || 'invalid_hello', remoteIp);
        return;
      }

      session = getLiveSession(hello.code);
      if (!session) {
        rejectTcp(socket, 'unknown_or_expired_code', remoteIp);
        return;
      }
      if (session.device && !session.device.socket.destroyed) {
        rejectTcp(socket, 'code_already_has_device', remoteIp);
        return;
      }

      authed = true;
      clearTcpAuthFailures(remoteIp);
      clearTimeout(helloTimer);
      session.device = {
        socket,
        deviceId: hello.deviceId || null,
        remoteAddress,
        connectedAt: Date.now(),
      };
      session.lastActivityAt = Date.now();
      safeWrite(socket, `OK ${session.code}\n`);
      log('info', 'device_connected', { code: session.code, deviceId: hello.deviceId || null, remoteAddress });
      broadcast(session, {
        type: 'device_connected',
        code: session.code,
        deviceId: hello.deviceId || null,
        remoteAddress,
      });

      if (leftover.length > 0) handleDevicePayload(session, socket, leftover);
      return;
    }

    handleDevicePayload(session, socket, chunk);
  });

  socket.on('close', () => {
    clearTimeout(helloTimer);
    if (session && session.device && session.device.socket === socket) {
      const deviceId = session.device.deviceId;
      session.device = null;
      log('info', 'device_disconnected', { code: session.code, deviceId, remoteAddress });
      broadcast(session, { type: 'device_disconnected', deviceId, remoteAddress });
    }
  });

  socket.on('error', (error) => {
    log('warn', 'device_socket_error', { remoteAddress, error: error.message, code: session?.code || null });
  });
});

function findNewline(buffer) {
  const lf = buffer.indexOf(0x0a);
  const cr = buffer.indexOf(0x0d);
  if (lf < 0) return cr;
  if (cr < 0) return lf;
  return Math.min(lf, cr);
}

function skipLineEnding(buffer, newlineIndex) {
  let idx = newlineIndex + 1;
  if (buffer[newlineIndex] === 0x0d && buffer[idx] === 0x0a) idx += 1;
  return idx;
}

function parseHello(line) {
  const trimmed = String(line || '').trim();
  if (!trimmed) return { ok: false, error: 'empty_hello' };

  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed);
      const type = String(obj.type || '').toLowerCase();
      if (type !== 'hello') return { ok: false, error: 'json_type_must_be_hello' };
      const code = normalizeCode(obj.code);
      if (!isValidCode(code)) return { ok: false, error: 'invalid_code' };
      return { ok: true, code, deviceId: sanitizeDeviceId(obj.device_id || obj.deviceId || '') };
    } catch (_error) {
      return { ok: false, error: 'invalid_hello_json' };
    }
  }

  const match = trimmed.match(/^HELLO\s+([A-Za-z0-9]{4,16})(?:\s+(.{1,80}))?$/i);
  if (!match) return { ok: false, error: 'hello_format_must_be_HELLO_CODE' };
  const code = normalizeCode(match[1]);
  if (!isValidCode(code)) return { ok: false, error: 'invalid_code' };
  return { ok: true, code, deviceId: sanitizeDeviceId(match[2] || '') };
}

function isValidCode(code) {
  return /^[A-Z0-9]{4,16}$/.test(code);
}

function sanitizeDeviceId(value) {
  return String(value || '').trim().replace(/[^A-Za-z0-9_.:-]/g, '').slice(0, 64) || null;
}

function rejectTcp(socket, reason, remoteIp = null) {
  const ip = remoteIp || normalizeRemoteIp(socket.remoteAddress);
  if (!['ip_temporarily_blocked', 'too_many_connections_from_ip'].includes(reason)) {
    recordTcpAuthFailure(ip, reason);
  }
  safeWrite(socket, `ERR ${reason}\n`);
  log('warn', 'device_rejected', { reason, remoteAddress: `${ip}:${socket.remotePort || ''}` });
  socket.destroy();
}

function safeWrite(socket, data) {
  if (socket && !socket.destroyed) socket.write(data);
}

function handleDevicePayload(session, socket, chunk) {
  if (!session || !getLiveSession(session.code)) {
    socket.destroy();
    return;
  }
  session.lastActivityAt = Date.now();
  const textValue = chunk.toString('utf8');
  if (textValue.trim().toUpperCase() === 'PING') {
    safeWrite(socket, 'PONG\n');
    broadcast(session, { type: 'device_ping' });
    return;
  }
  broadcast(session, {
    type: 'device_data',
    text: textValue,
    hex: chunk.toString('hex'),
    bytes: chunk.length,
  });
}

function readFirmwareDoc() {
  const docPath = path.join(__dirname, 'docs', 'FIRMWARE_INTEGRATION.md');
  try {
    return fs.readFileSync(docPath, 'utf8');
  } catch (error) {
    log('warn', 'firmware_doc_read_failed', { error: error.message, docPath });
    return '# Firmware integration guide\n\nDocument is temporarily unavailable.';
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[char]));
}

function renderFirmwareDocHtml() {
  const markdown = readFirmwareDoc();
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RFID TCP Broker Firmware Guide</title>
  <style>
    body { margin:0; background:#f8fafc; color:#111827; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { max-width:960px; margin:0 auto; padding:28px 18px 48px; }
    a { color:#0f766e; font-weight:650; text-decoration:none; }
    pre { white-space:pre-wrap; word-wrap:break-word; background:white; border:1px solid #e5e7eb; border-radius:16px; padding:20px; line-height:1.55; box-shadow:0 8px 24px rgba(15,23,42,.04); }
  </style>
</head>
<body>
  <main>
    <p><a href="${PUBLIC_BASE_PATH}/">← Back to RFID TCP Broker Test</a> · <a href="${PUBLIC_BASE_PATH}/firmware.md">Raw Markdown</a></p>
    <pre>${escapeHtml(markdown)}</pre>
  </main>
</body>
</html>`;
}

function renderPage(initialSession = null, initialError = '') {
  const basePath = PUBLIC_BASE_PATH;
  const initialCode = initialSession?.code || '------';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ELECHOUSE RFID TCP Broker Test</title>
  <style>
    :root { color-scheme: light; --brand:#0f766e; --dark:#111827; --muted:#6b7280; --line:#e5e7eb; --bg:#f8fafc; --ok:#16a34a; --bad:#dc2626; --warn:#d97706; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--dark); }
    .wrap { max-width: 1120px; margin:0 auto; padding:28px 18px 48px; }
    .hero { background:linear-gradient(135deg,#0f766e,#0e7490); color:white; border-radius:18px; padding:26px; box-shadow:0 18px 50px rgba(15,118,110,.22); }
    h1 { margin:0 0 8px; font-size:28px; }
    h2 { margin:0 0 14px; font-size:18px; }
    p { line-height:1.55; }
    .muted { color:var(--muted); }
    .hero .muted { color:rgba(255,255,255,.82); }
    .grid { display:grid; grid-template-columns: minmax(0,1fr) minmax(320px,.8fr); gap:18px; margin-top:18px; }
    .card { background:white; border:1px solid var(--line); border-radius:16px; padding:18px; box-shadow:0 8px 24px rgba(15,23,42,.04); }
    .code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:44px; font-weight:800; letter-spacing:.12em; color:var(--brand); }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .pill { display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px; background:#eef2ff; color:#3730a3; font-size:13px; }
    .pill.ok { background:#dcfce7; color:#166534; }
    .pill.bad { background:#fee2e2; color:#991b1b; }
    .pill.warn { background:#fef3c7; color:#92400e; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    pre { background:#0f172a; color:#e2e8f0; padding:12px; border-radius:12px; overflow:auto; line-height:1.5; }
    button { appearance:none; border:0; border-radius:10px; padding:10px 14px; font-weight:650; cursor:pointer; background:var(--brand); color:white; }
    button.secondary { background:#e5e7eb; color:#111827; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    input, textarea { width:100%; border:1px solid #d1d5db; border-radius:10px; padding:10px 12px; font:inherit; }
    textarea { min-height:86px; resize:vertical; }
    .kv { display:grid; grid-template-columns:130px 1fr; gap:8px 12px; font-size:14px; }
    .kv b { color:#374151; }
    .log { height:360px; overflow:auto; background:#020617; color:#dbeafe; border-radius:12px; padding:12px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; line-height:1.45; }
    .log .time { color:#94a3b8; }
    .log .rx { color:#86efac; }
    .log .tx { color:#fcd34d; }
    .log .sys { color:#93c5fd; }
    .log .err { color:#fca5a5; }
    .small { font-size:13px; }
    label.inline { display:flex; align-items:center; gap:8px; font-size:14px; color:#374151; }
    label.inline input { width:auto; }
    @media (max-width: 860px) { .grid { grid-template-columns:1fr; } .code { font-size:36px; } }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>ELECHOUSE RFID TCP Broker Test</h1>
      <p class="muted">Open this page, copy the test code into your device firmware/test app, then watch TCP data from the RFID reader appear here in real time.</p>
      <div class="row"><span id="wsStatus" class="pill warn">Web: starting</span><span id="deviceStatus" class="pill bad">Device: not connected</span><span id="timer" class="pill">Session: --</span></div>
    </section>

    <div class="grid">
      <main class="card">
        <h2>1. Test session</h2>
        <div id="code" class="code">${escapeHtml(initialCode)}</div>
        <p class="muted small">This code expires automatically. Refreshing this page keeps the same live session; click New session only when you want a new code.</p>
        <div class="row">
          <button id="newSessionBtn">New session</button>
          <button class="secondary" id="endSessionBtn">End session</button>
          <button class="secondary" id="copyHelloBtn">Copy HELLO</button>
          <button class="secondary" id="copyConfigBtn">Copy device config</button>
          <a href="${basePath}/firmware" target="_blank" rel="noopener" style="color:#0f766e;font-weight:650;text-decoration:none;">Firmware guide</a>
        </div>

        <h2 style="margin-top:24px;">2. Device connection settings</h2>
        <div class="kv">
          <b>TCP host</b><span><code id="tcpHost">--</code></span>
          <b>TCP port</b><span><code id="tcpPort">--</code></span>
          <b>First packet</b><span><code id="helloText">--</code></span>
        </div>
        <pre id="exampleBlock">Waiting for session...</pre>

        <h2 style="margin-top:24px;">3. Send data back to device</h2>
        <textarea id="sendText" placeholder="Example: LED ON"></textarea>
        <div class="row" style="margin-top:10px; justify-content:space-between;">
          <label class="inline"><input id="appendNewline" type="checkbox" checked> append LF (\\n)</label>
          <button id="sendBtn" disabled>Send to device</button>
        </div>
      </main>

      <aside class="card">
        <div class="row" style="justify-content:space-between; margin-bottom:14px;">
          <h2 style="margin:0;">Live data</h2>
          <div class="row">
            <label class="inline"><input id="showHex" type="checkbox"> show hex</label>
            <button class="secondary" id="clearLogBtn" type="button">Clear data</button>
          </div>
        </div>
        <div class="log" id="log"></div>
      </aside>
    </div>
  </div>

<script>
(() => {
  const API_BASE = ${JSON.stringify(basePath)};
  const INITIAL_SESSION = ${JSON.stringify(initialSession || null)};
  const INITIAL_ERROR = ${JSON.stringify(initialError || '')};
  let session = null;
  let ws = null;
  let timer = null;
  let showHex = false;

  const $ = (id) => document.getElementById(id);
  const logBox = $('log');

  function setPill(el, text, cls) {
    el.className = 'pill ' + (cls || '');
    el.textContent = text;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function addLog(kind, text) {
    const at = new Date().toLocaleTimeString();
    const div = document.createElement('div');
    div.innerHTML = '<span class="time">[' + escapeHtml(at) + ']</span> <span class="' + kind + '">' + escapeHtml(text) + '</span>';
    logBox.appendChild(div);
    logBox.scrollTop = logBox.scrollHeight;
  }

  function clearLog() {
    logBox.innerHTML = '';
  }

  function printableText(value) {
    const slashR = String.fromCharCode(92, 114);
    const slashN = String.fromCharCode(92, 110);
    return String(value || '')
      .split(String.fromCharCode(13)).join(slashR)
      .split(String.fromCharCode(10)).join(slashN);
  }

  function wsUrl(path, code) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return proto + '//' + location.host + path + '?code=' + encodeURIComponent(code);
  }

  function updateSessionView() {
    if (!session) return;
    $('code').textContent = session.code;
    $('tcpHost').textContent = session.tcpHost;
    $('tcpPort').textContent = session.tcpPort;
    $('helloText').textContent = session.helloText.replace('\\n', '\\n');
    $('exampleBlock').textContent = [
      'TCP connect: ' + session.tcpHost + ':' + session.tcpPort,
      'First packet: ' + session.helloText,
      'Then send card data, for example:',
      'CARD 04AABBCCDD\\n'
    ].join('\\n');
    updateTimer();
  }

  function updateTimer() {
    if (!session) return;
    const left = Math.max(0, Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000));
    const m = Math.floor(left / 60);
    const s = String(left % 60).padStart(2, '0');
    setPill($('timer'), 'Session: ' + m + ':' + s, left > 60 ? '' : 'warn');
    if (left <= 0) {
      setPill($('timer'), 'Session expired', 'bad');
      $('sendBtn').disabled = true;
      if (ws) ws.close();
      clearInterval(timer);
    }
  }

  async function newSession() {
    $('newSessionBtn').disabled = true;
    $('sendBtn').disabled = true;
    logBox.innerHTML = '';
    setPill($('wsStatus'), 'Web: creating session', 'warn');
    setPill($('deviceStatus'), 'Device: waiting', 'bad');
    if (ws) ws.close();
    try {
      const res = await fetch(API_BASE + '/api/session', { method: 'POST', cache: 'no-store', credentials: 'same-origin' });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || ('HTTP ' + res.status));
      session = data.session;
      startSession(session, 'Session created: ' + session.code);
    } catch (err) {
      setPill($('wsStatus'), 'Web: error', 'bad');
      addLog('err', 'Failed to create session: ' + err.message);
    } finally {
      $('newSessionBtn').disabled = false;
    }
  }

  async function endSession() {
    if (!session) return;
    $('endSessionBtn').disabled = true;
    addLog('sys', 'Closing session: ' + session.code);
    try {
      await fetch(API_BASE + '/api/session/close?code=' + encodeURIComponent(session.code), {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin'
      });
    } catch (err) {
      addLog('err', 'Failed to close session: ' + err.message);
    }
    if (ws) ws.close();
    session = null;
    clearInterval(timer);
    $('code').textContent = '------';
    $('tcpHost').textContent = '--';
    $('tcpPort').textContent = '--';
    $('helloText').textContent = '--';
    $('exampleBlock').textContent = 'Session closed. Click New session to start again.';
    setPill($('timer'), 'Session: closed', 'bad');
    setPill($('deviceStatus'), 'Device: disconnected', 'bad');
    setPill($('wsStatus'), 'Web: disconnected', 'bad');
    $('sendBtn').disabled = true;
    $('endSessionBtn').disabled = false;
    addLog('sys', 'Session closed and cleaned up');
  }

  function startSession(nextSession, message) {
    session = nextSession;
    updateSessionView();
    clearInterval(timer);
    timer = setInterval(updateTimer, 1000);
    connectWs();
    if (message) addLog('sys', message);
  }

  function connectWs() {
    if (!session) return;
    setPill($('wsStatus'), 'Web: connecting', 'warn');
    ws = new WebSocket(wsUrl(session.wsPath, session.code));
    ws.onopen = () => setPill($('wsStatus'), 'Web: connected', 'ok');
    ws.onclose = () => {
      setPill($('wsStatus'), 'Web: disconnected', 'bad');
      $('sendBtn').disabled = true;
    };
    ws.onerror = () => addLog('err', 'WebSocket error');
    ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.type === 'ready') {
        setPill($('deviceStatus'), msg.deviceConnected ? 'Device: connected' : 'Device: waiting', msg.deviceConnected ? 'ok' : 'bad');
        $('sendBtn').disabled = !msg.deviceConnected;
      } else if (msg.type === 'device_connected') {
        setPill($('deviceStatus'), 'Device: connected', 'ok');
        $('sendBtn').disabled = false;
        addLog('sys', 'Device connected: ' + (msg.deviceId || msg.remoteAddress || 'unknown'));
      } else if (msg.type === 'device_disconnected') {
        setPill($('deviceStatus'), 'Device: disconnected', 'bad');
        $('sendBtn').disabled = true;
        addLog('sys', 'Device disconnected');
      } else if (msg.type === 'device_data') {
        const clean = printableText(msg.text || '');
        addLog('rx', 'RX ' + msg.bytes + 'B: ' + clean + (showHex && msg.hex ? '  [hex ' + msg.hex + ']' : ''));
      } else if (msg.type === 'web_to_device') {
        const clean = printableText(msg.text || '');
        addLog('tx', 'TX ' + msg.bytes + 'B: ' + clean);
      } else if (msg.type === 'device_ping') {
        addLog('sys', 'Device PING → PONG');
      } else if (msg.type === 'session_expired') {
        setPill($('timer'), 'Session expired', 'bad');
        addLog('err', 'Session expired');
      } else if (msg.type === 'error') {
        addLog('err', msg.error || 'error');
      }
    };
  }

  $('sendBtn').addEventListener('click', () => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ type: 'send', payload: $('sendText').value, appendNewline: $('appendNewline').checked }));
  });
  $('clearLogBtn').addEventListener('click', clearLog);
  $('showHex').addEventListener('change', () => {
    showHex = $('showHex').checked;
    addLog('sys', showHex ? 'Hex display enabled' : 'Hex display hidden');
  });
  $('newSessionBtn').addEventListener('click', newSession);
  $('endSessionBtn').addEventListener('click', endSession);
  $('copyHelloBtn').addEventListener('click', async () => {
    if (!session) return;
    await navigator.clipboard.writeText(session.helloText.replace(String.fromCharCode(92, 110), String.fromCharCode(10)));
    addLog('sys', 'HELLO copied');
  });
  $('copyConfigBtn').addEventListener('click', async () => {
    if (!session) return;
    await navigator.clipboard.writeText([
      'Host: ' + session.tcpHost,
      'Port: ' + session.tcpPort,
      'First packet: ' + session.helloText
    ].join(String.fromCharCode(10)));
    addLog('sys', 'Device config copied');
  });

  if (INITIAL_SESSION) {
    startSession(INITIAL_SESSION, 'Session ready: ' + INITIAL_SESSION.code);
  } else {
    if (INITIAL_ERROR) addLog('err', 'Failed to create initial session: ' + INITIAL_ERROR);
    newSession();
  }
})();
</script>
</body>
</html>`;
}

function start() {
  httpServer.listen(HTTP_PORT, HTTP_HOST, () => {
    log('info', 'http_listening', { host: HTTP_HOST, port: HTTP_PORT, publicBasePath: PUBLIC_BASE_PATH });
  });
  tcpServer.listen(TCP_PORT, TCP_HOST, () => {
    log('info', 'tcp_listening', { host: TCP_HOST, port: TCP_PORT, publicTcpHost: PUBLIC_TCP_HOST });
  });
  setInterval(cleanupExpiredSessions, 30 * 1000).unref();
}

function shutdown(signal) {
  log('info', 'shutdown', { signal });
  for (const session of [...sessions.values()]) expireSession(session, 'server_shutdown');
  tcpServer.close();
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (error) => {
  log('error', 'uncaught_exception', { error: error.stack || error.message });
  shutdown('uncaughtException');
});
process.on('unhandledRejection', (error) => {
  log('error', 'unhandled_rejection', { error: error?.stack || String(error) });
});

start();
