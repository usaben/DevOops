// Test all 10 sample cases from SUST_Preli_Sample_Cases.json
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzeTicket } = require('../server.js');

// ---- SAMPLE-01: Wrong transfer with matching evidence ----
test('SAMPLE-01: Wrong transfer with matching evidence', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-001',
    complaint: 'I sent 5000 taka to a wrong number around 2pm today. The number was supposed to be 01712345678 but I think I typed it wrong. The person isn\'t responding to my call. Please help me get my money back.',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    campaign_context: 'boishakh_bonanza_day_1',
    transaction_history: [
      { transaction_id: 'TXN-9101', timestamp: '2026-04-14T14:08:22Z', type: 'transfer', amount: 5000, counterparty: '+8801719876543', status: 'completed' },
      { transaction_id: 'TXN-9087', timestamp: '2026-04-13T18:12:00Z', type: 'cash_in', amount: 10000, counterparty: 'AGENT-512', status: 'completed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-001');
  assert.equal(result.relevant_transaction_id, 'TXN-9101');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'wrong_transfer');
  assert.equal(result.severity, 'high');
  assert.equal(result.department, 'dispute_resolution');
  assert.equal(result.human_review_required, true);
  assert.ok(result.agent_summary.length > 0);
  assert.ok(result.recommended_next_action.length > 0);
  assert.ok(result.customer_reply.length > 0);
  assert.ok(result.confidence >= 0 && result.confidence <= 1);
  // Safety: customer_reply must not REQUEST credentials (but "do not share your PIN" is a valid safety warning)
  const stripped = result.customer_reply.replace(/\b(?:do\s+not|don'?t|never|please\s+do\s+not)\s+(?:share|send|give|provide)\b/gi, '[SAFETY_WARNING]');
  assert.ok(!/\b(?:share|send|give)\s+(?:your|the)\s+(?:pin|otp|password)\b/i.test(stripped), 'customer_reply must not request credentials');
});

// ---- SAMPLE-02: Wrong transfer with inconsistent evidence ----
test('SAMPLE-02: Wrong transfer claim with inconsistent evidence', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-002',
    complaint: 'I sent 2000 to the wrong person by mistake. Please reverse it.',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9202', timestamp: '2026-04-14T11:30:00Z', type: 'transfer', amount: 2000, counterparty: '+8801812345678', status: 'completed' },
      { transaction_id: 'TXN-9180', timestamp: '2026-04-10T09:15:00Z', type: 'transfer', amount: 2500, counterparty: '+8801812345678', status: 'completed' },
      { transaction_id: 'TXN-9145', timestamp: '2026-04-05T17:45:00Z', type: 'transfer', amount: 1500, counterparty: '+8801812345678', status: 'completed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-002');
  assert.equal(result.relevant_transaction_id, 'TXN-9202');
  assert.equal(result.evidence_verdict, 'inconsistent');
  assert.equal(result.case_type, 'wrong_transfer');
  assert.equal(result.severity, 'medium');
  assert.equal(result.department, 'dispute_resolution');
  assert.equal(result.human_review_required, true);
});

// ---- SAMPLE-03: Failed payment with balance deducted ----
test('SAMPLE-03: Failed payment with balance deducted', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-003',
    complaint: 'I tried to pay 1200 taka for my mobile recharge but the app showed failed. But my balance was deducted! Please refund my money.',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9301', timestamp: '2026-04-14T16:00:00Z', type: 'payment', amount: 1200, counterparty: 'MERCHANT-MOBILE-OP', status: 'failed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-003');
  assert.equal(result.relevant_transaction_id, 'TXN-9301');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'payment_failed');
  assert.equal(result.severity, 'high');
  assert.equal(result.department, 'payments_ops');
  // Safe reply — must NOT promise refund
  assert.ok(!/\bwe\s+will\s+refund\b/i.test(result.customer_reply));
  assert.ok(result.customer_reply.includes('PIN') || result.customer_reply.includes('OTP') || result.customer_reply.toLowerCase().includes('pin'));
});

// ---- SAMPLE-04: Refund request — change of mind ----
test('SAMPLE-04: Refund request requiring safe handling', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-004',
    complaint: "I paid 500 to a merchant for a product but I changed my mind and don't want it anymore. Please refund my 500 taka.",
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9401', timestamp: '2026-04-14T13:00:00Z', type: 'payment', amount: 500, counterparty: 'MERCHANT-7821', status: 'completed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-004');
  assert.equal(result.relevant_transaction_id, 'TXN-9401');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'refund_request');
  assert.equal(result.severity, 'low');
  assert.equal(result.department, 'customer_support');
  assert.equal(result.human_review_required, false);
  // Must NOT promise refund
  assert.ok(!/\bwe\s+will\s+refund\b/i.test(result.customer_reply));
});

// ---- SAMPLE-05: Phishing / social engineering ----
test('SAMPLE-05: Phishing or social engineering report', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-005',
    complaint: "Someone called me saying they are from bKash and asked for my OTP. They said my account will be blocked if I don't share it. Is this real? I haven't shared anything yet.",
    language: 'en',
    channel: 'call_center',
    user_type: 'customer',
    transaction_history: [],
  });

  assert.equal(result.ticket_id, 'TKT-005');
  assert.equal(result.relevant_transaction_id, null);
  assert.equal(result.evidence_verdict, 'insufficient_data');
  assert.equal(result.case_type, 'phishing_or_social_engineering');
  assert.equal(result.severity, 'critical');
  assert.equal(result.department, 'fraud_risk');
  assert.equal(result.human_review_required, true);
  // customer_reply must reinforce safety
  assert.ok(result.customer_reply.toLowerCase().includes('never'));
});

// ---- SAMPLE-06: Vague complaint ----
test('SAMPLE-06: Vague complaint, insufficient evidence', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-006',
    complaint: 'Something is wrong with my money. Please check.',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9601', timestamp: '2026-04-13T10:00:00Z', type: 'cash_in', amount: 3000, counterparty: 'AGENT-220', status: 'completed' },
      { transaction_id: 'TXN-9602', timestamp: '2026-04-12T15:30:00Z', type: 'transfer', amount: 800, counterparty: '+8801911223344', status: 'completed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-006');
  assert.equal(result.relevant_transaction_id, null);
  assert.equal(result.evidence_verdict, 'insufficient_data');
  assert.equal(result.case_type, 'other');
  assert.equal(result.severity, 'low');
  assert.equal(result.department, 'customer_support');
  assert.equal(result.human_review_required, false);
});

// ---- SAMPLE-07: Agent cash-in issue, Bangla ----
test('SAMPLE-07: Agent cash-in issue, Bangla complaint', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-007',
    complaint: 'আমি আজ সকালে এজেন্টের কাছে ২০০০ টাকা ক্যাশ ইন করেছি কিন্তু আমার ব্যালেন্সে টাকা আসেনি। এজেন্ট বলছে টাকা পাঠিয়েছে কিন্তু আমি দেখছি না।',
    language: 'bn',
    channel: 'call_center',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9701', timestamp: '2026-04-14T09:30:00Z', type: 'cash_in', amount: 2000, counterparty: 'AGENT-318', status: 'pending' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-007');
  assert.equal(result.relevant_transaction_id, 'TXN-9701');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'agent_cash_in_issue');
  assert.equal(result.severity, 'high');
  assert.equal(result.department, 'agent_operations');
  assert.equal(result.human_review_required, true);
});

// ---- SAMPLE-08: Ambiguous match, multiple transactions ----
test('SAMPLE-08: Multiple plausible transactions, ambiguous match', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-008',
    complaint: "I sent 1000 to my brother yesterday but he says he didn't get it. Please check.",
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-9801', timestamp: '2026-04-13T11:20:00Z', type: 'transfer', amount: 1000, counterparty: '+8801712001122', status: 'completed' },
      { transaction_id: 'TXN-9802', timestamp: '2026-04-13T19:45:00Z', type: 'transfer', amount: 1000, counterparty: '+8801812334455', status: 'completed' },
      { transaction_id: 'TXN-9803', timestamp: '2026-04-13T20:10:00Z', type: 'transfer', amount: 1000, counterparty: '+8801712001122', status: 'failed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-008');
  // Should be null due to ambiguity
  assert.equal(result.relevant_transaction_id, null);
  assert.equal(result.evidence_verdict, 'insufficient_data');
  assert.equal(result.case_type, 'wrong_transfer');
  assert.equal(result.severity, 'medium');
  assert.equal(result.department, 'dispute_resolution');
  assert.equal(result.human_review_required, false, 'Should not need human review when asking for clarification');
});

// ---- SAMPLE-09: Merchant settlement delay ----
test('SAMPLE-09: Merchant settlement delay', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-009',
    complaint: "I am a merchant. My yesterday's sales of 15000 taka have not been settled to my account. Settlement usually happens by 11am next day. Please check.",
    language: 'en',
    channel: 'merchant_portal',
    user_type: 'merchant',
    transaction_history: [
      { transaction_id: 'TXN-9901', timestamp: '2026-04-13T18:00:00Z', type: 'settlement', amount: 15000, counterparty: 'MERCHANT-SELF', status: 'pending' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-009');
  assert.equal(result.relevant_transaction_id, 'TXN-9901');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'merchant_settlement_delay');
  assert.equal(result.severity, 'medium');
  assert.equal(result.department, 'merchant_operations');
  assert.equal(result.human_review_required, false);
});

// ---- SAMPLE-10: Duplicate payment ----
test('SAMPLE-10: Duplicate payment claim', () => {
  const result = analyzeTicket({
    ticket_id: 'TKT-010',
    complaint: 'I paid my electricity bill 850 taka but it deducted twice from my account. Please check, I only paid once.',
    language: 'en',
    channel: 'in_app_chat',
    user_type: 'customer',
    transaction_history: [
      { transaction_id: 'TXN-10001', timestamp: '2026-04-14T08:15:30Z', type: 'payment', amount: 850, counterparty: 'BILLER-DESCO', status: 'completed' },
      { transaction_id: 'TXN-10002', timestamp: '2026-04-14T08:15:42Z', type: 'payment', amount: 850, counterparty: 'BILLER-DESCO', status: 'completed' },
    ],
  });

  assert.equal(result.ticket_id, 'TKT-010');
  assert.equal(result.relevant_transaction_id, 'TXN-10002');
  assert.equal(result.evidence_verdict, 'consistent');
  assert.equal(result.case_type, 'duplicate_payment');
  assert.equal(result.severity, 'high');
  assert.equal(result.department, 'payments_ops');
  assert.equal(result.human_review_required, true);
  // Safety: must not promise refund
  assert.ok(!/\bwe\s+will\s+refund\b/i.test(result.customer_reply));
});

// ---- Schema validation: all required fields present ----
test('Schema: all required response fields present in every case', () => {
  const REQUIRED_FIELDS = [
    'ticket_id', 'relevant_transaction_id', 'evidence_verdict', 'case_type',
    'severity', 'department', 'agent_summary', 'recommended_next_action',
    'customer_reply', 'human_review_required',
  ];

  const input = {
    ticket_id: 'TKT-SCHEMA',
    complaint: 'I sent 5000 taka to a wrong number',
    transaction_history: [
      { transaction_id: 'TXN-0001', timestamp: '2026-04-14T14:00:00Z', type: 'transfer', amount: 5000, counterparty: '+880100000', status: 'completed' },
    ],
  };

  const result = analyzeTicket(input);
  for (const field of REQUIRED_FIELDS) {
    assert.ok(field in result, `Missing required field: ${field}`);
  }
  // Optional fields
  assert.ok('confidence' in result);
  assert.ok('reason_codes' in result);
});

// ---- Enum validation ----
test('Enum validation: all outputs use valid enums', () => {
  const VALID_CASE_TYPES = ['wrong_transfer', 'payment_failed', 'refund_request', 'duplicate_payment', 'merchant_settlement_delay', 'agent_cash_in_issue', 'phishing_or_social_engineering', 'other'];
  const VALID_SEVERITIES = ['low', 'medium', 'high', 'critical'];
  const VALID_DEPARTMENTS = ['customer_support', 'dispute_resolution', 'payments_ops', 'merchant_operations', 'agent_operations', 'fraud_risk'];
  const VALID_VERDICTS = ['consistent', 'inconsistent', 'insufficient_data'];

  const cases = [
    { ticket_id: 'E-1', complaint: 'I sent 5000 to wrong number', transaction_history: [] },
    { ticket_id: 'E-2', complaint: 'Payment failed but balance deducted', transaction_history: [] },
    { ticket_id: 'E-3', complaint: 'Someone asked my OTP claiming to be bKash', transaction_history: [] },
    { ticket_id: 'E-4', complaint: 'Please refund I changed my mind', transaction_history: [] },
    { ticket_id: 'E-5', complaint: 'App crashed', transaction_history: [] },
  ];

  for (const c of cases) {
    const r = analyzeTicket(c);
    assert.ok(VALID_CASE_TYPES.includes(r.case_type), `Invalid case_type: ${r.case_type}`);
    assert.ok(VALID_SEVERITIES.includes(r.severity), `Invalid severity: ${r.severity}`);
    assert.ok(VALID_DEPARTMENTS.includes(r.department), `Invalid department: ${r.department}`);
    assert.ok(VALID_VERDICTS.includes(r.evidence_verdict), `Invalid evidence_verdict: ${r.evidence_verdict}`);
    assert.ok(r.confidence >= 0 && r.confidence <= 1, `confidence out of range: ${r.confidence}`);
  }
});