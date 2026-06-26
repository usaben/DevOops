'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scrubSummary } = require('../server.js');

function isSafe(text) {
  return !/(?:pin|otp|password|code|cvv|card)/i.test(text);
}

test('safety: pin request is scrubbed', () => {
  const r = scrubSummary('Please share your PIN with us.');
  assert.equal(r.safe, false, 'phishing request should be blocked');
  assert.equal(r.fallback.case_type, 'phishing_or_social_engineering');
});

test('safety: otp request is scrubbed', () => {
  const r = scrubSummary('Send me your OTP code.');
  assert.equal(r.safe, false, 'otp request should be blocked');
  assert.equal(r.fallback.severity, 'critical');
});

test('safety: password request is scrubbed', () => {
  const r = scrubSummary('Reply with your password.');
  assert.equal(r.safe, false, 'password request should be blocked');
  assert.equal(r.fallback.department, 'fraud_risk');
});

test('safety: card number request is scrubbed', () => {
  const r = scrubSummary('My card number is 4111 1111 1111 1111, please verify.');
  // No phishing request phrase, but a 16-digit card number triggers the denylist.
  assert.ok(!/\b4111\s?1111\s?1111\s?1111\b/.test(r.text || ''),
    'card number must be redacted from the surviving text');
});

test('safety: safe summary is untouched', () => {
  const clean = 'Customer reports sending 5000 to the wrong recipient and requests recovery of the funds.';
  const r = scrubSummary(clean);
  assert.equal(r.safe, true);
  assert.equal(r.text, clean);
});

test('safety: hard fallback kicks in if scrubber somehow leaks a token', () => {
  // "OTP request. OTP." is itself a phishing request phrase - falls back.
  const r = scrubSummary('OTP request. OTP.');
  assert.equal(r.safe, false);
  assert.equal(r.fallback.case_type, 'phishing_or_social_engineering');
  assert.equal(r.fallback.human_review_required, true);
});