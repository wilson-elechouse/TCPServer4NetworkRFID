#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

async function main() {
  const apiBase = process.env.API || 'http://127.0.0.1:19190';
  const apiUrl = new URL(apiBase);
  const apiOrigin = `${apiUrl.protocol}//${apiUrl.host}`;
  const apiPathPrefix = apiUrl.pathname.replace(/\/+$/, '');
  const sessionEndpoint = `${apiOrigin}${apiPathPrefix}/api/session`;
  const authCookie = process.env.AUTH_COOKIE || '';

  const sessionResp = await fetch(sessionEndpoint, {
    method: 'POST',
    headers: authCookie ? { Cookie: authCookie } : undefined,
  });
  const sessionJson = await sessionResp.json();
  if (!sessionJson.ok) throw new Error(`session create failed: ${JSON.stringify(sessionJson)}`);
  const session = sessionJson.session;
  const { code } = session;
  console.log('code', code);

  const wsTls = apiUrl.protocol === 'https:';
  const wsHost = process.env.WS_HOST || apiUrl.hostname;
  const wsPort = Number(process.env.WS_PORT || apiUrl.port || (wsTls ? 443 : 80));
  const wsPath = process.env.WS_PATH || (apiPathPrefix ? session.wsPath : '/ws');

  const events = [];
  const ws = await connectRawWebSocket({ host: wsHost, port: wsPort, path: `${wsPath}?code=${encodeURIComponent(code)}`, tls: wsTls, servername: apiUrl.hostname });
  ws.onMessage = (payload) => {
    const msg = JSON.parse(payload);
    events.push(msg);
    console.log('ws', msg.type, msg.text || msg.error || msg.deviceId || '');
  };

  const deviceHost = process.env.DEVICE_HOST || session.tcpHost;
  const devicePort = Number(process.env.DEVICE_PORT || session.tcpPort || process.env.TCP_PORT || 19191);
  const device = net.createConnection({ host: deviceHost, port: devicePort });
  let deviceRx = '';
  device.on('data', (chunk) => {
    deviceRx += chunk.toString('utf8');
    console.log('device-rx', JSON.stringify(chunk.toString('utf8')));
  });
  await new Promise((resolve, reject) => {
    device.once('connect', resolve);
    device.once('error', reject);
    setTimeout(() => reject(new Error(`device connect timeout: ${deviceHost}:${devicePort}`)), 8000).unref();
  });
  device.write(`HELLO ${code} DEV-SMOKE\n`);

  await waitFor(() => deviceRx.includes(`OK ${code}`), 'device OK');
  device.write('CARD 04AABBCCDD\n');
  await waitFor(() => events.some((e) => e.type === 'device_data' && String(e.text || '').includes('04AABBCCDD')), 'card event');

  ws.send(JSON.stringify({ type: 'send', payload: 'LED ON', appendNewline: true }));
  await waitFor(() => deviceRx.includes('LED ON\n'), 'web command reaches device');

  device.write('PING\n');
  await waitFor(() => deviceRx.includes('PONG\n'), 'PONG');

  ws.close();
  device.destroy();
  console.log('SMOKE_OK');
}

async function connectRawWebSocket({ host, port, path, tls: useTls = false, servername }) {
  const socket = useTls
    ? tls.connect({ host, port, servername: servername || host })
    : net.createConnection({ host, port });

  await new Promise((resolve, reject) => {
    socket.once(useTls ? 'secureConnect' : 'connect', resolve);
    socket.once('error', reject);
    setTimeout(() => reject(new Error(`websocket connect timeout: ${host}:${port}`)), 8000).unref();
  });

  const key = crypto.randomBytes(16).toString('base64');
  socket.write([
    `GET ${path} HTTP/1.1`,
    `Host: ${host}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    '\r\n',
  ].join('\r\n'));

  let buffer = Buffer.alloc(0);
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('websocket upgrade timeout')), 8000);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const idx = buffer.indexOf('\r\n\r\n');
      if (idx < 0) return;
      clearTimeout(timer);
      socket.off('data', onData);
      const head = buffer.subarray(0, idx).toString('utf8');
      buffer = buffer.subarray(idx + 4);
      if (!/^HTTP\/1\.1 101\b/.test(head)) {
        reject(new Error(`websocket upgrade failed: ${head}`));
      } else {
        resolve();
      }
    };
    socket.on('data', onData);
    socket.once('error', reject);
  });

  const client = {
    socket,
    onMessage: null,
    send(text) {
      const payload = Buffer.from(text, 'utf8');
      const header = createMaskedHeader(0x1, payload.length);
      const mask = header.subarray(header.length - 4);
      const maskedPayload = Buffer.from(payload);
      for (let i = 0; i < maskedPayload.length; i += 1) maskedPayload[i] ^= mask[i % 4];
      socket.write(Buffer.concat([header, maskedPayload]));
    },
    close() {
      if (!socket.destroyed) {
        socket.end();
        socket.destroy();
      }
    },
  };

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 2) {
      const first = buffer[0];
      const second = buffer[1];
      const opcode = first & 0x0f;
      let length = second & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (buffer.length < offset + 2) return;
        length = buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (buffer.length < offset + 8) return;
        length = Number(buffer.readBigUInt64BE(offset));
        offset += 8;
      }
      const masked = Boolean(second & 0x80);
      let mask;
      if (masked) {
        if (buffer.length < offset + 4) return;
        mask = buffer.subarray(offset, offset + 4);
        offset += 4;
      }
      if (buffer.length < offset + length) return;
      let payload = Buffer.from(buffer.subarray(offset, offset + length));
      buffer = buffer.subarray(offset + length);
      if (masked && mask) {
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
      }
      if (opcode === 0x1 && client.onMessage) client.onMessage(payload.toString('utf8'));
      if (opcode === 0x8) socket.end();
    }
  });

  if (buffer.length > 0) socket.emit('data', Buffer.alloc(0));
  return client;
}

function createMaskedHeader(opcode, length) {
  const mask = crypto.randomBytes(4);
  if (length < 126) {
    return Buffer.concat([Buffer.from([0x80 | opcode, 0x80 | length]), mask]);
  }
  if (length < 65536) {
    const header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(length, 2);
    return Buffer.concat([header, mask]);
  }
  const header = Buffer.alloc(10);
  header[0] = 0x80 | opcode;
  header[1] = 0x80 | 127;
  header.writeBigUInt64BE(BigInt(length), 2);
  return Buffer.concat([header, mask]);
}

async function waitFor(fn, label, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (fn()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timeout waiting for ${label}`);
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
