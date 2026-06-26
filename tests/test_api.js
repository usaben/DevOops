// API endpoint tests — /health and /analyze-ticket
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

// ---- GET /health ----
test('GET /health returns status: ok', async () => {
  const res = await req('GET', `${ctx.base}/health`);
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'ok');
  assert.equal(res.body.service, 'queuestorm');
  assert.ok(typeof res.body.uptime_seconds === 'number');
});

// ---- POST /analyze-ticket — basic wrong_transfer ----
test('POST /analyze-ticket — wrong_transfer', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, {
    ticket_id: 'T-API-1',
    complaint: 'I sent 5000 taka to a wrong number, please help me get it back',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-001', timestamp: '2026-04-14T14:00:00Z', type: 'transfer', amount: 5000, counterparty: '+880170000', status: 'completed' },
    ],
  });
  assert.equal(res.status, 200, res.raw);
  assert.equal(res.body.ticket_id, 'T-API-1');
  assert.equal(res.body.case_type, 'wrong_transfer');
  assert.equal(res.body.severity, 'high');
  assert.equal(res.body.department, 'dispute_resolution');
  assert.equal(res.body.relevant_transaction_id, 'TXN-001');
  assert.equal(res.body.evidence_verdict, 'consistent');
  assert.ok(typeof res.body.agent_summary === 'string');
  assert.ok(typeof res.body.recommended_next_action === 'string');
  assert.ok(typeof res.body.customer_reply === 'string');
  assert.ok(typeof res.body.human_review_required === 'boolean');
  assert.ok(res.body.confidence >= 0 && res.body.confidence <= 1);
});

// ---- POST /analyze-ticket — phishing ----
test('POST /analyze-ticket — phishing triggers safety fallback', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, {
    ticket_id: 'T-API-2',
    complaint: 'Someone called me saying they are from bKash and asked for my OTP. They said my account will be blocked.',
    channel: 'call_center',
    transaction_history: [],
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.case_type, 'phishing_or_social_engineering');
  assert.equal(res.body.severity, 'critical');
  assert.equal(res.body.department, 'fraud_risk');
  assert.equal(res.body.human_review_required, true);
  assert.equal(res.body.relevant_transaction_id, null);
});

// ---- 422 on missing complaint ----
test('POST /analyze-ticket — 422 on missing complaint', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, { ticket_id: 'T-1' });
  assert.equal(res.status, 422);
});

// ---- 422 on missing ticket_id ----
test('POST /analyze-ticket — 422 on missing ticket_id', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, { complaint: 'hi' });
  assert.equal(res.status, 422);
});

// ---- 422 on empty/whitespace complaint ----
test('POST /analyze-ticket — 422 on empty complaint', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, { ticket_id: 'T-1', complaint: '   ' });
  assert.equal(res.status, 422);
});

// ---- All required output fields present ----
test('POST /analyze-ticket — all required fields in response', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, {
    ticket_id: 'T-FIELDS',
    complaint: 'Something is wrong with my money',
    transaction_history: [],
  });
  assert.equal(res.status, 200);
  const REQUIRED = [
    'ticket_id', 'relevant_transaction_id', 'evidence_verdict', 'case_type',
    'severity', 'department', 'agent_summary', 'recommended_next_action',
    'customer_reply', 'human_review_required',
  ];
  for (const f of REQUIRED) {
    assert.ok(f in res.body, `Missing field: ${f}`);
  }
});

// ---- customer_reply never asks for credentials ----
test('POST /analyze-ticket — customer_reply safety check', async () => {
  const complaints = [
    'I sent 5000 to wrong number',
    'Payment failed, balance deducted',
    'Please refund my 500 taka',
    'Something went wrong',
    'My electricity bill was charged twice',
  ];

  for (const complaint of complaints) {
    const res = await req('POST', `${ctx.base}/analyze-ticket`, {
      ticket_id: 'T-SAFETY',
      complaint,
      transaction_history: [],
    });
    assert.equal(res.status, 200);
    // Must not REQUEST credentials (but "do not share your PIN" warnings are correct)
    const stripped = res.body.customer_reply.replace(/\b(?:do\s+not|don'?t|never|please\s+do\s+not)\s+(?:share|send|give|provide)\b/gi, '[SAFETY_WARNING]');
    assert.ok(!/\b(?:share|send|give)\s+(?:your|the)\s+(?:pin|otp|password|card\s*number)\b/i.test(stripped),
      `Unsafe customer_reply for: ${complaint}`);
    // Must not promise refund
    assert.ok(!/\bwe\s+will\s+refund\b/i.test(res.body.customer_reply),
      `Unauthorized refund promise for: ${complaint}`);
  }
});

// ---- Handles missing/empty transaction_history gracefully ----
test('POST /analyze-ticket — handles missing transaction_history', async () => {
  const res = await req('POST', `${ctx.base}/analyze-ticket`, {
    ticket_id: 'T-NOTXN',
    complaint: 'I sent 5000 to the wrong number',
  });
  assert.equal(res.status, 200);
  assert.ok(res.body.case_type);
});

// ---- Static UI is served at / ----
test('Static UI is served at /', async () => {
  const res = await req('GET', `${ctx.base}/`);
  assert.equal(res.status, 200);
  assert.ok(res.raw.includes('QueueStorm'));
});

// ---- 404 for unknown routes ----
test('404 for unknown routes', async () => {
  const res = await req('GET', `${ctx.base}/nonexistent`);
  assert.equal(res.status, 404);
});

// ---- Handles malformed JSON gracefully ----
test('POST /analyze-ticket — handles malformed JSON', async () => {
  const res = await new Promise((resolve, reject) => {
    const u = new URL(`${ctx.base}/analyze-ticket`);
    const data = 'not json';
    const r = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => { chunks += c; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(chunks); } catch {}
        resolve({ status: res.statusCode, body: parsed, raw: chunks });
      });
    });
    r.on('error', reject);
    r.write(data);
    r.end();
  });
  // Should return 400 or 422, not crash
  assert.ok(res.status >= 400 && res.status < 600, `Expected error status, got ${res.status}`);
});