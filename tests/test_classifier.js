'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { classify } = require('../server.js');

test('classifier: wrong_transfer', () => {
  const r = classify('I sent 5000 taka to a wrong number this morning, please help me get it back');
  assert.equal(r.case_type, 'wrong_transfer');
  assert.equal(r.severity, 'high');
  assert.equal(r.department, 'dispute_resolution');
  assert.equal(r.human_review_required, false);
});

test('classifier: payment_failed', () => {
  const r = classify('Payment failed but balance deducted. Please check.');
  assert.equal(r.case_type, 'payment_failed');
  assert.equal(r.severity, 'high');
  assert.equal(r.department, 'payments_ops');
});

test('classifier: phishing_or_social_engineering', () => {
  const r = classify('Someone called asking my OTP, is that bKash?');
  assert.equal(r.case_type, 'phishing_or_social_engineering');
  assert.equal(r.severity, 'critical');
  assert.equal(r.department, 'fraud_risk');
  assert.equal(r.human_review_required, true);
});

test('classifier: refund_request (low - changed my mind)', () => {
  const r = classify('Please refund my last transaction, I changed my mind.');
  assert.equal(r.case_type, 'refund_request');
  assert.equal(r.severity, 'low');
  assert.equal(r.department, 'dispute_resolution');
});

test('classifier: refund_request (medium - generic refund)', () => {
  const r = classify('Please refund my last transaction, the merchant refused to take it back.');
  assert.equal(r.case_type, 'refund_request');
  assert.equal(r.severity, 'medium');
});

test('classifier: other', () => {
  const r = classify('App crashed when I opened it.');
  assert.equal(r.case_type, 'other');
  assert.equal(r.department, 'customer_support');
});

test('classifier: phishing overrides even with refund keywords present', () => {
  const r = classify('Please refund me, but first share your OTP with us.');
  assert.equal(r.case_type, 'phishing_or_social_engineering');
  assert.equal(r.human_review_required, true);
});

test('classifier: human_review_required flips on critical severity', () => {
  const r = classify('Someone saying they are bKash officer is asking for my PIN to verify account.');
  assert.equal(r.severity, 'critical');
  assert.equal(r.human_review_required, true);
});

test('classifier: confidence is in [0, 1]', () => {
  const samples = [
    'I sent 5000 taka to a wrong number',
    'Payment failed but balance deducted',
    'Someone called asking my OTP',
    'Please refund my last transaction, I changed my mind.',
    'App crashed when I opened it.',
  ];
  for (const m of samples) {
    const r = classify(m);
    assert.ok(r.confidence >= 0 && r.confidence <= 1, `confidence ${r.confidence} out of range`);
  }
});

test('classifier: every response has all required fields', () => {
  const r = classify('I sent 5000 taka to a wrong number');
  for (const k of ['case_type','severity','department','agent_summary','human_review_required','confidence','signals']) {
    assert.ok(k in r, `missing field ${k}`);
  }
});