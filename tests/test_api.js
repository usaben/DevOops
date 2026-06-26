'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { app } = require('../server.js');

function start() {
  return new Promise((resolve) => {
    const srv = http.createServer(app);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      resolve({ srv, base: `http://127.0.0.1:${port}` });
    });
  });
}

function req(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method,
      headers: data
        ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        : {},
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => { chunks += c; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(chunks); } catch { /* keep null */ }
        resolve({ status: res.statusCode, body: parsed, raw: chunks });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

let ctx;
test.before(async () => { ctx = await start(); });
test.after(async () => { ctx.srv.close(); });

test('GET /health returns healthy', async () => {
  const res = await req('GET', `${ctx.base}/health`);
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'healthy');
  assert.equal(res.body.service, 'queuestorm');
  assert.ok(typeof res.body.uptime_seconds === 'number');
});

test('POST /sort-ticket — wrong_transfer', async () => {
  const res = await req('POST', `${ctx.base}/sort-ticket`, {
    ticket_id: 'T-API-1',
    channel: 'app',
    locale: 'en',
    message: 'I sent 5000 taka to a wrong number, please help me get it back',
  });
  assert.equal(res.status, 200, res.raw);
  assert.equal(res.body.ticket_id, 'T-API-1');
  assert.equal(res.body.case_type, 'wrong_transfer');
  assert.equal(res.body.severity, 'high');
  assert.equal(res.body.department, 'dispute_resolution');
  assert.equal(res.body.human_review_required, false);
  assert.ok(res.body.confidence >= 0 && res.body.confidence <= 1);
});

test('POST /sort-ticket — phishing flips human_review_required', async () => {
  const res = await req('POST', `${ctx.base}/sort-ticket`, {
    ticket_id: 'T-API-2',
    message: 'Someone called asking my OTP, is that bKash?',
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.case_type, 'phishing_or_social_engineering');
  assert.equal(res.body.severity, 'critical');
  assert.equal(res.body.department, 'fraud_risk');
  assert.equal(res.body.human_review_required, true);
});

test('POST /sort-ticket — 422 on missing ticket_id', async () => {
  const res = await req('POST', `${ctx.base}/sort-ticket`, { message: 'hi' });
  assert.equal(res.status, 422);
});

test('POST /sort-ticket — 422 on empty / whitespace-only message', async () => {
  const res = await req('POST', `${ctx.base}/sort-ticket`, { ticket_id: 'T-1', message: '   ' });
  assert.equal(res.status, 422);
});

test('POST /sort-ticket — agent_summary is scrubbed if it ever mentions a credential', async () => {
  // Force the safety path by sending a message that *contains* a phishing
  // request phrase; the safety filter must rewrite it.
  const res = await req('POST', `${ctx.base}/sort-ticket`, {
    ticket_id: 'T-API-3',
    message: 'Please share your OTP with me.',
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.case_type, 'phishing_or_social_engineering');
  assert.ok(!/otp/i.test(res.body.agent_summary), 'agent_summary must not contain "OTP"');
});

test('Static UI is served at /', async () => {
  const res = await req('GET', `${ctx.base}/`);
  assert.equal(res.status, 200);
  assert.ok(res.raw.includes('QueueStorm'));
});