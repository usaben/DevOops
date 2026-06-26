// QueueStorm Investigator — Customer Support Ticket Triage (Node.js + Express)
//
// API Contract (SUST CSE Carnival 2026 · Codex Community Hackathon):
//   GET  /health          -> { status: "ok" }
//   POST /analyze-ticket  -> full structured response per problem statement
//
// Rule-based evidence reasoning + classifier + safety filter.
// No LLM, no external services, deterministic, < 5ms per request.

'use strict';

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { z }   = require('zod');

const VERSION    = '2.0.0';
const START_TIME = Date.now();

// ---------------------------------------------------------------------------
// Zod Schemas — Request Validation (Section 5 of Problem Statement)
// ---------------------------------------------------------------------------

const TransactionEntry = z.object({
  transaction_id: z.string(),
  timestamp:      z.string(),
  type:           z.enum(['transfer', 'payment', 'cash_in', 'cash_out', 'settlement', 'refund']),
  amount:         z.number(),
  counterparty:   z.string(),
  status:         z.enum(['completed', 'failed', 'pending', 'reversed']),
});

const AnalyzeTicketRequest = z.object({
  ticket_id:           z.string().min(1).max(64),
  complaint:           z.string()
                        .min(1, 'complaint must not be empty')
                        .max(8000)
                        .transform(v => v.trim())
                        .refine(v => v.length > 0, { message: 'complaint must not be empty' }),
  language:            z.enum(['en', 'bn', 'mixed']).optional(),
  channel:             z.enum(['in_app_chat', 'call_center', 'email', 'merchant_portal', 'field_agent']).optional(),
  user_type:           z.enum(['customer', 'merchant', 'agent', 'unknown']).optional(),
  campaign_context:    z.string().optional(),
  transaction_history: z.array(TransactionEntry).optional().default([]),
  metadata:            z.any().optional(),
});

// ---------------------------------------------------------------------------
// Allowed Enums (Section 7)
// ---------------------------------------------------------------------------

const CASE_TYPES = [
  'wrong_transfer', 'payment_failed', 'refund_request', 'duplicate_payment',
  'merchant_settlement_delay', 'agent_cash_in_issue',
  'phishing_or_social_engineering', 'other',
];

const DEPARTMENTS = [
  'customer_support', 'dispute_resolution', 'payments_ops',
  'merchant_operations', 'agent_operations', 'fraud_risk',
];

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

const EVIDENCE_VERDICTS = ['consistent', 'inconsistent', 'insufficient_data'];

// ---------------------------------------------------------------------------
// Regex Helpers
// ---------------------------------------------------------------------------

function compile(re) { return new RegExp(re, 'i'); }

// ---------------------------------------------------------------------------
// Classifier Signal Catalogues
// ---------------------------------------------------------------------------

const PHISHING_SIGNALS = [
  ['phishing',        compile('\\b(?:otp|one[\\s-]?time\\s*password|otp\\s*code)\\b'), 3.0],
  ['phishing',        compile('\\bpin\\b'), 3.0],
  ['phishing',        compile('\\bpassword\\b'), 3.0],
  ['phishing',        compile("\\b(?:share|send|give|tell|provide|reply\\s+with|forward)\\s+(?:your|the|me|us)\\b[^\\.]{0,40}?(?:pin|otp|password|code)\\b"), 4.0],
  ['phishing',        compile("\\b(?:someone|caller|person|he|she|they|operator|agent)\\b[^\\.]{0,80}?(?:asking|asked|says|said|claiming|claim)[^\\.]{0,80}?(?:pin|otp|password|code)\\b"), 3.5],
  ['phishing',        compile("\\b(?:click\\s+(?:the|this)\\s+link|http[s]?:\\/\\/|bit\\.ly|tinyurl)\\b"), 1.5],
  ['phishing',        compile("\\b(?:verify\\s+your\\s+account|account\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated))\\b"), 2.5],
  ['phishing',        compile('\\b(?:won|winner|prize|lottery|cashback|reward)\\b'), 1.0],
  ['phishing',        compile("\\b(?:b\\s*k\\s*a\\s*s\\s*h|nagad|rocket)\\b[^\\.]{0,60}?(?:calling|called)\\b"), 1.5],
  // Bangla phishing keywords
  ['phishing',        compile('(?:ওটিপি|পিন|পাসওয়ার্ড)'), 3.0],
  ['phishing',        compile('(?:শেয়ার\\s*কর|জানা|বল)'), 1.5],
];

const WRONG_TRANSFER_SIGNALS = [
  ['wrong_transfer',  compile("\\b(?:wrong\\s+(?:number|recipient|person|account)|sent\\s+to\\s+(?:the\\s+)?wrong|by\\s+mistake|mistakenly)\\b"), 3.5],
  ['wrong_transfer',  compile("\\b(?:get\\s+(?:it|the\\s+money|my\\s+money|back)|return\\s+(?:the\\s+)?money|refund\\s+(?:me|my))\\b"), 2.5],
  ['wrong_transfer',  compile('\\b(?:taka|tk|bdt)\\b'), 0.5],
  ['wrong_transfer',  compile("\\b(?:sent|transferred|paid|sent\\s+money|cash\\s*out)\\b"), 1.0],
  ['wrong_transfer',  compile('\\b(?:unknown\\s+person|stranger|random\\s+number|unknown\\s+number)\\b'), 1.5],
  // Bangla
  ['wrong_transfer',  compile('(?:ভুল\\s*নম্বর|ভুলে|ভুল\\s*ব্যক্তি)'), 3.5],
  ['wrong_transfer',  compile('(?:টাকা\\s*ফেরত|টাকা\\s*পাঠ)'), 2.0],
];

const PAYMENT_FAILED_SIGNALS = [
  ['payment_failed',  compile("\\b(?:payment\\s+failed|transaction\\s+(?:failed|unsuccessful|declined|not\\s+completed)|couldn'?t\\s+(?:pay|complete|send)|didn'?t\\s+(?:go\\s+through|receive|reach))\\b"), 3.5],
  ['payment_failed',  compile("\\b(?:balance\\s+(?:deducted|debited|reduced|gone)|money\\s+(?:deducted|debited|taken)|amount\\s+(?:deducted|debited))\\b"), 3.0],
  ['payment_failed',  compile("\\b(?:not\\s+(?:received|credited|reflected)|haven'?t\\s+received)\\b"), 2.0],
  ['payment_failed',  compile('\\b(?:network\\s+(?:error|issue|problem)|server\\s+(?:error|down)|timeout)\\b'), 1.0],
  ['payment_failed',  compile("\\b(?:failed|showing\\s+failed|showed\\s+failed|app\\s+showed\\s+failed|status.*failed)\\b"), 2.0],
  // Bangla
  ['payment_failed',  compile('(?:ব্যর্থ|ফেইল|ব্যালেন্স\\s*কাট)'), 3.0],
];

const REFUND_SIGNALS = [
  ['refund_request',  compile("\\b(?:refund|return\\s+(?:my|the)\\s+money|chargeback|reversal)\\b"), 3.0],
  ['refund_request',  compile("\\b(?:changed\\s+my\\s+mind|cancel\\s+(?:my|the)\\s+(?:order|transaction|payment)|don'?t\\s+want\\s+(?:it|this)\\s+anymore)\\b"), 2.5],
  ['refund_request',  compile("\\b(?:merchant|shop|seller|vendor)\\b[^\\.]{0,40}?(?:return|refund|cancel)\\b"), 2.0],
  // Bangla
  ['refund_request',  compile('(?:রিফান্ড|টাকা\\s*ফেরত)'), 3.0],
];

const DUPLICATE_PAYMENT_SIGNALS = [
  ['duplicate_payment', compile("\\b(?:duplicate\\s+(?:payment|charge|deduction|transaction)|charged\\s+twice|double\\s+(?:charged|payment|deducted)|paid\\s+twice|deducted\\s+twice|twice\\s+from)\\b"), 4.0],
  ['duplicate_payment', compile("\\b(?:two\\s+times|2\\s+times|two\\s+payments)\\b"), 2.5],
  ['duplicate_payment', compile("\\b(?:only\\s+(?:paid|sent)\\s+once|i\\s+only\\s+paid\\s+once)\\b"), 2.0],
  // Bangla
  ['duplicate_payment', compile('(?:দুইবার|ডুপ্লিকেট)'), 3.0],
];

const MERCHANT_SETTLEMENT_SIGNALS = [
  ['merchant_settlement_delay', compile("\\b(?:settlement|settle)\\b"), 3.0],
  ['merchant_settlement_delay', compile("\\b(?:merchant|sales|shop|store)\\b[^\\.]{0,60}?(?:not\\s+(?:settled|received|credited)|delay|late|pending|missing)\\b"), 3.5],
  ['merchant_settlement_delay', compile("\\b(?:yesterday'?s?\\s+sales|daily\\s+settlement)\\b"), 2.0],
  // Bangla
  ['merchant_settlement_delay', compile('(?:সেটেলমেন্ট|মার্চেন্ট)'), 2.5],
];

const AGENT_CASH_IN_SIGNALS = [
  ['agent_cash_in_issue', compile("\\b(?:cash\\s*in|cashed\\s*in|deposited?)\\b[^\\.]{0,80}?(?:agent|not\\s+(?:reflected|received|showing|credited)|balance)\\b"), 3.5],
  ['agent_cash_in_issue', compile("\\b(?:agent)\\b[^\\.]{0,60}?(?:cash\\s*in|deposit)\\b"), 3.0],
  ['agent_cash_in_issue', compile("\\b(?:agent\\s+(?:says|said|claiming|claims))\\b"), 1.5],
  // Bangla
  ['agent_cash_in_issue', compile('(?:ক্যাশ\\s*ইন|এজেন্ট).*(?:আসেনি|পাইনি|ব্যালেন্স)'), 4.0],
  ['agent_cash_in_issue', compile('(?:এজেন্ট).*(?:ক্যাশ\\s*ইন|টাকা)'), 3.0],
];

// ---------------------------------------------------------------------------
// Score & classify complaint text
// ---------------------------------------------------------------------------

function scoreSignals(text, signals) {
  let total = 0.0;
  const fired = [];
  for (const [label, re, weight] of signals) {
    if (re.test(text)) { total += weight; fired.push(label); }
  }
  return [total, [...new Set(fired)]];
}

function extractAmount(text) {
  // Try to extract a numeric amount from complaint text
  const m = text.match(/(\d[\d,]*(?:\.\d+)?)\s*(?:taka|tk|bdt|টাকা)?/i);
  if (m) return parseFloat(m[1].replace(/,/g, ''));
  return null;
}

function extractAmountPhrase(text) {
  const m = text.match(/(\d[\d,]*(?:\.\d+)?)\s*(?:taka|tk|bdt|টাকা)?/i);
  if (m) return m[0].trim();
  return null;
}

// ---------------------------------------------------------------------------
// Evidence Reasoning Engine (Section 3 — 35% of score)
// ---------------------------------------------------------------------------

function findRelevantTransaction(complaint, transactions, caseType) {
  if (!transactions || transactions.length === 0) {
    return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
  }

  const claimedAmount = extractAmount(complaint);
  const complaintLower = complaint.toLowerCase();

  // --- Duplicate Payment Detection ---
  if (caseType === 'duplicate_payment') {
    return detectDuplicatePayment(transactions, claimedAmount);
  }

  // --- Merchant Settlement Delay ---
  if (caseType === 'merchant_settlement_delay') {
    return detectMerchantSettlement(transactions, claimedAmount);
  }

  // --- Agent Cash In Issue ---
  if (caseType === 'agent_cash_in_issue') {
    return detectAgentCashIn(transactions, claimedAmount, complaintLower);
  }

  // --- General matching (wrong_transfer, payment_failed, refund_request, etc.) ---
  return matchGeneralTransaction(complaint, transactions, caseType, claimedAmount, complaintLower);
}

function detectDuplicatePayment(transactions, claimedAmount) {
  // Find pairs of transactions with same amount, same counterparty, close timestamps
  const payments = transactions.filter(t =>
    (t.type === 'payment' || t.type === 'transfer') && t.status === 'completed'
  );

  for (let i = 0; i < payments.length; i++) {
    for (let j = i + 1; j < payments.length; j++) {
      const a = payments[i], b = payments[j];
      if (a.amount === b.amount && a.counterparty === b.counterparty) {
        const timeDiff = Math.abs(new Date(a.timestamp) - new Date(b.timestamp));
        // If within 5 minutes, likely duplicate
        if (timeDiff < 5 * 60 * 1000) {
          // Return the later one as the duplicate
          const later = new Date(a.timestamp) > new Date(b.timestamp) ? a : b;
          return {
            relevant_transaction_id: later.transaction_id,
            evidence_verdict: 'consistent',
          };
        }
      }
    }
  }

  // If claimed amount matches but no duplicate pair found
  if (claimedAmount) {
    const matching = payments.filter(t => t.amount === claimedAmount);
    if (matching.length >= 2) {
      // Sort by timestamp descending, return latest as suspected duplicate
      matching.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      return {
        relevant_transaction_id: matching[0].transaction_id,
        evidence_verdict: 'consistent',
      };
    }
  }

  return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
}

function detectMerchantSettlement(transactions, claimedAmount) {
  const settlements = transactions.filter(t => t.type === 'settlement');
  if (settlements.length === 0) {
    return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
  }

  let best = null;
  for (const t of settlements) {
    if (t.status === 'pending') {
      if (!best || (claimedAmount && t.amount === claimedAmount)) {
        best = t;
      }
    }
  }

  if (best) {
    return {
      relevant_transaction_id: best.transaction_id,
      evidence_verdict: 'consistent',
    };
  }

  // Fallback: return most recent settlement
  settlements.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return {
    relevant_transaction_id: settlements[0].transaction_id,
    evidence_verdict: claimedAmount && settlements[0].amount === claimedAmount ? 'consistent' : 'insufficient_data',
  };
}

function detectAgentCashIn(transactions, claimedAmount, complaintLower) {
  const cashIns = transactions.filter(t => t.type === 'cash_in');
  if (cashIns.length === 0) {
    return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
  }

  // Prefer pending cash_in matching amount
  let best = null;
  for (const t of cashIns) {
    if (claimedAmount && t.amount === claimedAmount) {
      best = t;
      break;
    }
  }
  if (!best) {
    // Most recent cash_in
    cashIns.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    best = cashIns[0];
  }

  return {
    relevant_transaction_id: best.transaction_id,
    evidence_verdict: best.status === 'pending' || best.status === 'failed' ? 'consistent' : 'consistent',
  };
}

function matchGeneralTransaction(complaint, transactions, caseType, claimedAmount, complaintLower) {
  // Score each transaction for match quality
  const candidates = [];

  for (const txn of transactions) {
    let score = 0;
    const reasons = [];

    // Amount match
    if (claimedAmount && txn.amount === claimedAmount) {
      score += 5;
      reasons.push('amount_match');
    }

    // Type match with case type
    if (caseType === 'wrong_transfer' && txn.type === 'transfer') {
      score += 3;
      reasons.push('type_match');
    }
    if (caseType === 'payment_failed' && txn.type === 'payment') {
      score += 3;
      reasons.push('type_match');
    }
    if (caseType === 'refund_request' && txn.type === 'payment') {
      score += 3;
      reasons.push('type_match');
    }

    // Status relevance
    if (caseType === 'payment_failed' && txn.status === 'failed') {
      score += 4;
      reasons.push('failed_status');
    }
    if (txn.status === 'pending') {
      score += 1;
      reasons.push('pending_status');
    }

    // Recency bonus (more recent transactions are more likely to be relevant)
    const age = Date.now() - new Date(txn.timestamp).getTime();
    if (age < 24 * 60 * 60 * 1000) score += 2; // within 24h
    else if (age < 48 * 60 * 60 * 1000) score += 1; // within 48h

    // Counterparty mention in complaint
    if (txn.counterparty && complaintLower.includes(txn.counterparty.toLowerCase())) {
      score += 3;
      reasons.push('counterparty_mentioned');
    }

    candidates.push({ txn, score, reasons });
  }

  candidates.sort((a, b) => b.score - a.score);

  if (candidates.length === 0) {
    return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
  }

  const best = candidates[0];

  // Check for ambiguous match: multiple candidates with similar high scores
  if (candidates.length >= 2 && best.score > 0) {
    const second = candidates[1];
    if (best.score === second.score && best.score >= 3) {
      // Ambiguous — can't determine which transaction
      return {
        relevant_transaction_id: null,
        evidence_verdict: 'insufficient_data',
      };
    }
  }

  if (best.score <= 0) {
    return { relevant_transaction_id: null, evidence_verdict: 'insufficient_data' };
  }

  // Determine evidence verdict
  let verdict = 'consistent';

  // Check for inconsistency patterns
  if (caseType === 'wrong_transfer') {
    verdict = checkWrongTransferConsistency(best.txn, transactions, complaint);
  } else if (caseType === 'payment_failed') {
    verdict = best.txn.status === 'failed' ? 'consistent' : 'insufficient_data';
  }

  return {
    relevant_transaction_id: best.txn.transaction_id,
    evidence_verdict: verdict,
  };
}

function checkWrongTransferConsistency(matchedTxn, allTransactions, complaint) {
  // If the customer has sent money to the same counterparty multiple times before,
  // it's inconsistent with a "wrong transfer" claim
  const sameRecipient = allTransactions.filter(t =>
    t.type === 'transfer' &&
    t.counterparty === matchedTxn.counterparty &&
    t.transaction_id !== matchedTxn.transaction_id
  );

  if (sameRecipient.length >= 2) {
    return 'inconsistent'; // Established recipient pattern
  }

  return 'consistent';
}

// ---------------------------------------------------------------------------
// Classifier — determine case_type
// ---------------------------------------------------------------------------

function classifyComplaint(complaint, transactions, userType) {
  const allSignalSets = [
    ['phishing_or_social_engineering', PHISHING_SIGNALS],
    ['wrong_transfer',                 WRONG_TRANSFER_SIGNALS],
    ['payment_failed',                 PAYMENT_FAILED_SIGNALS],
    ['refund_request',                 REFUND_SIGNALS],
    ['duplicate_payment',              DUPLICATE_PAYMENT_SIGNALS],
    ['merchant_settlement_delay',      MERCHANT_SETTLEMENT_SIGNALS],
    ['agent_cash_in_issue',            AGENT_CASH_IN_SIGNALS],
  ];

  const scores = {};
  const firedSignals = {};
  for (const [caseType, signals] of allSignalSets) {
    const [score, fired] = scoreSignals(complaint, signals);
    scores[caseType] = score;
    firedSignals[caseType] = fired;
  }

  // Context boosting from transaction_history and user_type
  if (transactions && transactions.length > 0) {
    // Boost duplicate_payment if two identical transactions exist
    const payments = transactions.filter(t => t.status === 'completed' && (t.type === 'payment' || t.type === 'transfer'));
    for (let i = 0; i < payments.length; i++) {
      for (let j = i + 1; j < payments.length; j++) {
        if (payments[i].amount === payments[j].amount &&
            payments[i].counterparty === payments[j].counterparty) {
          const dt = Math.abs(new Date(payments[i].timestamp) - new Date(payments[j].timestamp));
          if (dt < 5 * 60 * 1000) {
            scores['duplicate_payment'] += 2.0;
          }
        }
      }
    }

    // Boost agent_cash_in_issue if cash_in transaction with pending status
    if (transactions.some(t => t.type === 'cash_in' && t.status === 'pending')) {
      scores['agent_cash_in_issue'] += 1.5;
    }

    // Boost merchant_settlement_delay if settlement transaction pending
    if (transactions.some(t => t.type === 'settlement' && t.status === 'pending')) {
      scores['merchant_settlement_delay'] += 1.5;
    }

    // Boost payment_failed if failed payment exists
    if (transactions.some(t => t.type === 'payment' && t.status === 'failed')) {
      scores['payment_failed'] += 1.5;
    }
  }

  // User type boosts
  if (userType === 'merchant') {
    scores['merchant_settlement_delay'] += 1.0;
  }

  // Pick best scoring case_type
  let bestCase = 'other';
  let bestScore = 0.0;
  let bestSignals = [];

  for (const [caseType] of allSignalSets) {
    if (scores[caseType] > bestScore) {
      bestScore = scores[caseType];
      bestCase = caseType;
      bestSignals = firedSignals[caseType];
    }
  }

  const MIN_THRESHOLD = 1.5;
  if (bestScore < MIN_THRESHOLD) {
    return { case_type: 'other', score: 0, reason_codes: ['vague_complaint', 'needs_clarification'] };
  }

  return { case_type: bestCase, score: bestScore, reason_codes: bestSignals };
}

// ---------------------------------------------------------------------------
// Department Routing (Section 7.2)
// ---------------------------------------------------------------------------

const DEPARTMENT_MAP = {
  wrong_transfer:                 'dispute_resolution',
  payment_failed:                 'payments_ops',
  refund_request:                 'customer_support',  // simple refund → customer_support
  duplicate_payment:              'payments_ops',
  merchant_settlement_delay:      'merchant_operations',
  agent_cash_in_issue:            'agent_operations',
  phishing_or_social_engineering: 'fraud_risk',
  other:                          'customer_support',
};

function getDepartment(caseType, complaint) {
  // Contested refund goes to dispute_resolution
  const complaintL = complaint.toLowerCase();
  if (caseType === 'refund_request') {
    if (/\b(?:merchant|shop|seller|vendor)\b/i.test(complaint) &&
        !/\bchanged\s+my\s+mind\b/i.test(complaint)) {
      // If disputing with merchant (not just changed mind), it might go to dispute_resolution
      // But per sample cases, refund_request with "changed my mind" -> customer_support
    }
  }
  return DEPARTMENT_MAP[caseType] || 'customer_support';
}

// ---------------------------------------------------------------------------
// Severity (Section 7.1 + sample cases)
// ---------------------------------------------------------------------------

function getSeverity(caseType, complaint, transactions, evidenceVerdict) {
  if (caseType === 'phishing_or_social_engineering') return 'critical';

  if (caseType === 'wrong_transfer') {
    if (evidenceVerdict === 'inconsistent' || evidenceVerdict === 'insufficient_data') return 'medium';
    return 'high';
  }

  if (caseType === 'payment_failed') return 'high';

  if (caseType === 'duplicate_payment') return 'high';

  if (caseType === 'agent_cash_in_issue') return 'high';

  if (caseType === 'merchant_settlement_delay') return 'medium';

  if (caseType === 'refund_request') {
    if (/\b(?:changed\s+my\s+mind|cancel|don'?t\s+want)/i.test(complaint)) return 'low';
    return 'medium';
  }

  if (/\b(?:crash|frozen|hang|bug|error)\b/i.test(complaint)) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Human Review Required
// ---------------------------------------------------------------------------

function needsHumanReview(caseType, severity, evidenceVerdict, transactions) {
  if (caseType === 'phishing_or_social_engineering') return true;
  if (severity === 'critical') return true;
  if (evidenceVerdict === 'inconsistent') return true;

  // Wrong transfer disputes need human review (but not when asking for clarification)
  if (caseType === 'wrong_transfer' && evidenceVerdict !== 'insufficient_data') return true;

  // Duplicate payment needs verification
  if (caseType === 'duplicate_payment') return true;

  // Agent cash-in issues need investigation
  if (caseType === 'agent_cash_in_issue') return true;

  // High-value cases (>= 10000 BDT) — but not for merchant settlement (routine business)
  if (caseType === 'merchant_settlement_delay') return false;
  if (transactions && transactions.length > 0) {
    const claimedTxn = transactions.find(t => t.amount >= 10000);
    if (claimedTxn) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Agent Summary Builder
// ---------------------------------------------------------------------------

function buildAgentSummary(caseType, complaint, transactions, relevantTxnId, evidenceVerdict) {
  const txn = relevantTxnId ?
    transactions.find(t => t.transaction_id === relevantTxnId) : null;

  const amount = txn ? `${txn.amount} BDT` : (extractAmountPhrase(complaint) || 'an unspecified amount');

  switch (caseType) {
    case 'wrong_transfer':
      if (txn) {
        if (evidenceVerdict === 'inconsistent') {
          const sameRecipient = transactions.filter(t =>
            t.type === 'transfer' && t.counterparty === txn.counterparty
          ).length;
          return `Customer claims ${txn.transaction_id} (${txn.amount} BDT to ${txn.counterparty}) was a wrong transfer, but transaction history shows ${sameRecipient} prior transfers to the same counterparty, suggesting an established recipient.`;
        }
        return `Customer reports sending ${txn.amount} BDT via ${txn.transaction_id} to ${txn.counterparty}, which they believe was the wrong recipient.`;
      }
      return `Customer reports sending ${amount} to the wrong recipient and requests recovery of the funds.`;

    case 'payment_failed':
      if (txn) {
        return `Customer attempted a ${txn.amount} BDT payment (${txn.transaction_id}) which ${txn.status}, but reports balance was deducted. Requires payments operations investigation.`;
      }
      return `Customer reports a failed transaction of ${amount}; balance may have been deducted.`;

    case 'refund_request':
      if (txn) {
        return `Customer requests refund of ${txn.amount} BDT for ${txn.transaction_id} (${txn.type} to ${txn.counterparty}). ${/changed\s+my\s+mind/i.test(complaint) ? 'Not a service failure.' : ''}`;
      }
      return `Customer is requesting a refund for ${amount}. Review the transaction history and process the request per policy.`;

    case 'duplicate_payment':
      if (txn) {
        const dups = transactions.filter(t =>
          t.amount === txn.amount && t.counterparty === txn.counterparty &&
          t.transaction_id !== txn.transaction_id && t.status === 'completed'
        );
        if (dups.length > 0) {
          const timeDiff = Math.abs(new Date(txn.timestamp) - new Date(dups[0].timestamp));
          const seconds = Math.round(timeDiff / 1000);
          return `Customer reports duplicate payment. Two identical ${txn.amount} BDT payments to ${txn.counterparty} were completed ${seconds} seconds apart (${dups[0].transaction_id} and ${txn.transaction_id}). The second is likely the duplicate.`;
        }
        return `Customer reports duplicate payment of ${txn.amount} BDT (${txn.transaction_id}).`;
      }
      return `Customer reports a duplicate payment of ${amount}.`;

    case 'merchant_settlement_delay':
      if (txn) {
        return `Merchant reports ${txn.amount} BDT settlement (${txn.transaction_id}) is delayed. Settlement status is ${txn.status}.`;
      }
      return `Merchant reports settlement delay of ${amount}.`;

    case 'agent_cash_in_issue':
      if (txn) {
        return `Customer reports ${txn.amount} BDT cash-in via ${txn.counterparty} (${txn.transaction_id}) not reflected in balance. Transaction status is ${txn.status}.`;
      }
      return `Customer reports a cash-in issue with an agent. Balance not updated.`;

    case 'phishing_or_social_engineering':
      return 'Customer reports a suspected phishing or social-engineering attempt. Do NOT contact the customer via any callback number in the message.';

    default:
      if (!transactions || transactions.length === 0) {
        return 'Customer reports a vague concern without specifying transaction, amount, or issue. Insufficient detail to identify any relevant transaction.';
      }
      return 'Customer inquiry that did not match a known triage category. Route to general support for review.';
  }
}

// ---------------------------------------------------------------------------
// Recommended Next Action
// ---------------------------------------------------------------------------

function buildNextAction(caseType, relevantTxnId, evidenceVerdict, complaint) {
  const txnRef = relevantTxnId || 'the transaction';

  switch (caseType) {
    case 'wrong_transfer':
      if (evidenceVerdict === 'inconsistent') {
        return `Flag for human review. Verify with the customer whether this was genuinely a wrong transfer given the established transaction pattern with this recipient.`;
      }
      if (evidenceVerdict === 'insufficient_data') {
        return `Reply to customer asking for the recipient's number to identify the correct transaction. Do not initiate dispute until the transaction is confirmed.`;
      }
      return `Verify ${txnRef} details with the customer and initiate the wrong-transfer dispute workflow per policy.`;

    case 'payment_failed':
      return `Investigate ${txnRef} ledger status. If balance was deducted on a failed payment, initiate the automatic reversal flow within standard SLA.`;

    case 'refund_request':
      if (/\bchanged\s+my\s+mind\b/i.test(complaint)) {
        return `Inform the customer that refund eligibility depends on the merchant's own policy. Provide guidance on contacting the merchant directly for a refund.`;
      }
      return `Review ${txnRef} and determine refund eligibility per policy. Escalate if needed.`;

    case 'duplicate_payment':
      return `Verify the duplicate with payments_ops. If the biller confirms only one payment was received, initiate reversal of ${txnRef}.`;

    case 'merchant_settlement_delay':
      return `Route to merchant_operations to verify settlement batch status. If the batch is delayed, communicate a revised ETA to the merchant.`;

    case 'agent_cash_in_issue':
      return `Investigate ${txnRef} pending status with agent operations. Confirm settlement state and resolve within the standard cash-in SLA.`;

    case 'phishing_or_social_engineering':
      return `Escalate to fraud_risk team immediately. Confirm to customer that the company never asks for OTP. Log the reported number for fraud pattern analysis.`;

    default:
      return `Reply to customer asking for specific details: which transaction, what amount, what went wrong, and approximate time.`;
  }
}

// ---------------------------------------------------------------------------
// Customer Reply Builder (safety-critical)
// ---------------------------------------------------------------------------

function buildCustomerReply(caseType, relevantTxnId, complaint, language, evidenceVerdict) {
  const isBangla = language === 'bn';
  const txnRef = relevantTxnId || '';
  const safetyNote = isBangla
    ? 'অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।'
    : 'Please do not share your PIN or OTP with anyone.';

  if (isBangla) {
    return buildBanglaReply(caseType, txnRef, safetyNote);
  }

  switch (caseType) {
    case 'wrong_transfer':
      if (evidenceVerdict === 'insufficient_data') {
        return `Thank you for reaching out. We see multiple transactions on that date. Could you share the recipient's number so we can identify the right transaction? ${safetyNote}`;
      }
      return `We have ${txnRef ? `noted your concern about transaction ${txnRef}` : 'received your request'}. ${safetyNote} Our dispute team will review the case and contact you through official support channels.`;

    case 'payment_failed':
      return `We have noted that transaction ${txnRef || 'your recent payment'} may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels. ${safetyNote}`;

    case 'refund_request':
      if (/\bchanged\s+my\s+mind\b/i.test(complaint)) {
        return `Thank you for reaching out. Refunds for completed merchant payments depend on the merchant's own policy. We recommend contacting the merchant directly. If you need help reaching them, please reply and we will guide you. ${safetyNote}`;
      }
      return `We have received your refund request${txnRef ? ` regarding transaction ${txnRef}` : ''}. Our team will review the case and any eligible amount will be returned through official channels. ${safetyNote}`;

    case 'duplicate_payment':
      return `We have noted the possible duplicate payment${txnRef ? ` for transaction ${txnRef}` : ''}. Our payments team will verify with the biller and any eligible amount will be returned through official channels. ${safetyNote}`;

    case 'merchant_settlement_delay':
      return `We have noted your concern about settlement${txnRef ? ` ${txnRef}` : ''}. Our merchant operations team will check the batch status and update you on the expected settlement time through official channels.`;

    case 'agent_cash_in_issue':
      return `We have noted your concern about${txnRef ? ` transaction ${txnRef}` : ' your cash-in'}. Our agent operations team will verify and resolve this through official channels. ${safetyNote}`;

    case 'phishing_or_social_engineering':
      return `Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, or password under any circumstances. Please do not share these with anyone, even if they claim to be from us. Our fraud team has been notified of this incident.`;

    default:
      return `Thank you for reaching out. To help you faster, please share the transaction ID, the amount involved, and a short description of what went wrong. ${safetyNote}`;
  }
}

function buildBanglaReply(caseType, txnRef, safetyNote) {
  switch (caseType) {
    case 'wrong_transfer':
      return `আপনার ${txnRef ? `লেনদেন ${txnRef} এর ` : ''}বিষয়ে আমরা অবগত হয়েছি। আমাদের বিরোধ নিষ্পত্তি দল এটি যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। ${safetyNote}`;

    case 'payment_failed':
      return `আপনার ${txnRef ? `লেনদেন ${txnRef} ` : 'সাম্প্রতিক পেমেন্ট '}সংক্রান্ত বিষয়টি নোট করা হয়েছে। আমাদের পেমেন্ট দল পর্যালোচনা করবে এবং যোগ্য পরিমাণ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। ${safetyNote}`;

    case 'agent_cash_in_issue':
      return `আপনার ${txnRef ? `লেনদেন ${txnRef} ` : ''}এর বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। ${safetyNote}`;

    case 'phishing_or_social_engineering':
      return `তথ্য শেয়ার করার আগে আমাদের সাথে যোগাযোগ করার জন্য ধন্যবাদ। আমরা কখনই আপনার পিন, ওটিপি বা পাসওয়ার্ড জিজ্ঞাসা করি না। অনুগ্রহ করে কাউকে এগুলো শেয়ার করবেন না। আমাদের জালিয়াতি দল এই ঘটনা সম্পর্কে অবহিত করা হয়েছে।`;

    default:
      return `আপনার সমস্যার কথা জানানোর জন্য ধন্যবাদ। আমাদের দল যত দ্রুত সম্ভব আপনাকে সাহায্য করবে। ${safetyNote}`;
  }
}

// ---------------------------------------------------------------------------
// Safety Filter (Section 8 — 20% of score)
// ---------------------------------------------------------------------------

const CREDENTIAL_REQUEST_PATTERNS = [
  /\b(?:share|send|give|tell|provide|reply\s+with|forward)\s+(?:your|the|me|us)\b[^\.]{0,40}?(?:pin|otp|password|code)\b/i,
  /\b(?:someone|caller|person|he|she|they|operator|agent|officer)\b[^\.]{0,80}?(?:asking|asked|says|said|claiming|claim)[^\.]{0,80}?(?:pin|otp|password|code)\b/i,
  /\b(?:click\s+(?:the|this)\s+link|http[s]?:\/\/|bit\.ly|tinyurl)\b/i,
  /\b(?:won|winner|prize|lottery|cashback|reward)\b/i,
  /^\s*(?:pin|otp|code|password|cvv|cvc)\b[\s\S]{0,40}$/i,
];

const SENSITIVE_DENYLIST = [
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  /\b(?:\d[ -]?){13,19}\b/g,
  /\b(?:password|passwd|pwd|pin|otp|cvv|cvc)\s*[:=]?\s*\S+/gi,
  /\b(?:account|acc)\s*(?:no|number|#)?\s*[:=]?\s*\d{6,}\b/gi,
  /\b(?:pin|otp|code|cvv|cvc)\s*[:=]?\s*\d{3,6}\b/gi,
];

const UNSAFE_REFUND_PATTERNS = [
  /\b(?:we\s+will|we'll|we\s+shall|we\s+are\s+going\s+to)\s+(?:refund|reverse|return\s+(?:your|the)\s+money|unblock|recover)\b/i,
  /\b(?:your\s+refund\s+(?:has|is)\s+(?:been\s+)?(?:processed|approved|confirmed))\b/i,
  /\b(?:we\s+have\s+(?:refunded|reversed|recovered|unblocked))\b/i,
];

function isPhishingRequest(text) {
  return CREDENTIAL_REQUEST_PATTERNS.some(p => p.test(text));
}

function scrubText(text) {
  let scrubbed = text;
  for (const pat of SENSITIVE_DENYLIST) {
    scrubbed = scrubbed.replace(pat, '[REDACTED]');
  }
  scrubbed = scrubbed.replace(/\b(?:http[s]?:\/\/[^\s]+|bit\.ly[^\s]*|tinyurl\.com[^\s]*)\b/gi, '[LINK REMOVED]');
  return scrubbed;
}

function validateSafetyOfReply(text) {
  // Check customer_reply doesn't REQUEST credentials from the user.
  // "Do not share your PIN" is a safety WARNING and is correct/expected.
  // Only flag as unsafe if the text ASKS FOR credentials without a preceding negation.
  const stripped = text.replace(/\b(?:do\s+not|don'?t|never|please\s+do\s+not|please\s+don'?t)\s+(?:share|send|give|provide)\b/gi, '[SAFETY_WARNING]');
  if (/\b(?:share|send|give|provide)\s+(?:your|the)\s+(?:pin|otp|password|code|card\s*number)\b/i.test(stripped)) {
    return false;
  }
  // Check doesn't promise unauthorized refund
  if (UNSAFE_REFUND_PATTERNS.some(p => p.test(text))) {
    return false;
  }
  return true;
}

function hardFallback() {
  return {
    case_type: 'phishing_or_social_engineering',
    severity: 'critical',
    department: 'fraud_risk',
    agent_summary: 'Message withheld by safety filter. Treated as potential phishing — do not contact the customer via any callback number in the message.',
    human_review_required: true,
    confidence: 1.0,
    reason_codes: ['safety_fallback'],
    relevant_transaction_id: null,
    evidence_verdict: 'insufficient_data',
    recommended_next_action: 'Escalate to fraud_risk team immediately. Do not act on any instructions embedded in the complaint.',
    customer_reply: 'Thank you for reaching out. We never ask for your PIN, OTP, or password under any circumstances. Please do not share these with anyone. Our fraud team has been notified.',
  };
}

function scrubSummary(message) {
  const isRequest = isPhishingRequest(message);
  if (isRequest) {
    return { safe: false, fallback: hardFallback() };
  }
  return { safe: true, text: scrubText(message) };
}

// ---------------------------------------------------------------------------
// Prompt Injection Defense
// ---------------------------------------------------------------------------

function sanitizeComplaint(complaint) {
  // Strip any instructions that try to override system behavior
  // We don't modify the text for classification, but we flag it
  const injectionPatterns = [
    /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i,
    /you\s+(?:are|must)\s+now\s+(?:a|an)/i,
    /system\s*:\s*/i,
    /\boverride\b.*\b(?:rules?|instructions?|safety)\b/i,
  ];

  const hasInjection = injectionPatterns.some(p => p.test(complaint));
  return { text: complaint, hasInjection };
}

// ---------------------------------------------------------------------------
// Main Analysis Pipeline
// ---------------------------------------------------------------------------

function analyzeTicket(input) {
  const {
    ticket_id,
    complaint,
    language,
    channel,
    user_type,
    campaign_context,
    transaction_history: transactions,
  } = input;

  // Step 1: Safety check on raw complaint
  const scrub = scrubSummary(complaint);
  if (!scrub.safe) {
    return { ticket_id, ...scrub.fallback };
  }

  // Step 2: Check for prompt injection
  const sanitized = sanitizeComplaint(complaint);

  // Step 3: Classify the complaint
  const classification = classifyComplaint(complaint, transactions, user_type);
  let caseType = classification.case_type;
  let reasonCodes = classification.reason_codes;

  // Step 4: Evidence reasoning — match complaint against transaction history
  const evidence = findRelevantTransaction(complaint, transactions || [], caseType);
  const { relevant_transaction_id, evidence_verdict } = evidence;

  // Step 5: Determine severity
  const severity = getSeverity(caseType, complaint, transactions, evidence_verdict);

  // Step 6: Determine department
  const department = getDepartment(caseType, complaint);

  // Step 7: Human review required?
  const human_review_required = needsHumanReview(caseType, severity, evidence_verdict, transactions);

  // Step 8: Build agent summary (scrubbed)
  let agent_summary = buildAgentSummary(caseType, complaint, transactions || [], relevant_transaction_id, evidence_verdict);
  agent_summary = scrubText(agent_summary);

  // Step 9: Build recommended next action
  const recommended_next_action = buildNextAction(caseType, relevant_transaction_id, evidence_verdict, complaint);

  // Step 10: Build customer reply (safety-critical)
  let customer_reply = buildCustomerReply(caseType, relevant_transaction_id, complaint, language, evidence_verdict);

  // Step 11: Safety validation on generated text
  if (!validateSafetyOfReply(customer_reply)) {
    customer_reply = 'Thank you for reaching out. Our team will review your case and contact you through official support channels. Please do not share your PIN or OTP with anyone.';
  }

  // Step 12: Confidence score
  let confidence = Math.min(1.0, classification.score / 5.0);
  if (caseType === 'other') confidence = 0.5;
  if (evidence_verdict === 'consistent') confidence = Math.max(confidence, 0.85);
  if (evidence_verdict === 'inconsistent') confidence = Math.min(confidence, 0.80);
  if (evidence_verdict === 'insufficient_data' && caseType !== 'phishing_or_social_engineering') {
    confidence = Math.min(confidence, 0.70);
  }
  confidence = Number(confidence.toFixed(2));

  // Enrich reason codes
  if (evidence_verdict === 'inconsistent') reasonCodes.push('evidence_inconsistent');
  if (evidence_verdict === 'consistent' && relevant_transaction_id) reasonCodes.push('transaction_match');
  if (evidence_verdict === 'insufficient_data') reasonCodes.push('needs_clarification');
  if (sanitized.hasInjection) reasonCodes.push('prompt_injection_detected');
  reasonCodes = [...new Set(reasonCodes)];

  return {
    ticket_id,
    relevant_transaction_id,
    evidence_verdict,
    case_type: caseType,
    severity,
    department,
    agent_summary,
    recommended_next_action,
    customer_reply,
    human_review_required,
    confidence,
    reason_codes: reasonCodes,
  };
}

// ---------------------------------------------------------------------------
// Express App
// ---------------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// GET /health — must return {"status":"ok"}
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'queuestorm',
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - START_TIME) / 1000),
  });
});

// Serve the demo UI
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// POST /analyze-ticket — main endpoint
app.post('/analyze-ticket', (req, res) => {
  try {
    const parsed = AnalyzeTicketRequest.safeParse(req.body);
    if (!parsed.success) {
      return res.status(422).json({
        error: 'validation_failed',
        details: parsed.error.issues.map(i => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const result = analyzeTicket(parsed.data);
    return res.status(200).json(result);
  } catch (err) {
    // Never expose stack traces or secrets
    return res.status(500).json({
      error: 'internal_error',
      message: 'An internal error occurred while processing the ticket.',
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'not_found', path: req.path });
});

// Global error handler (prevents HTML stack traces from express.json)
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'bad_request', message: 'Malformed JSON payload.' });
  }
  return res.status(500).json({ error: 'internal_error', message: 'An internal error occurred.' });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 8000;
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`QueueStorm Investigator listening on 0.0.0.0:${PORT}`);
  });
}

module.exports = { app, analyzeTicket, classifyComplaint, findRelevantTransaction, scrubSummary, buildCustomerReply, validateSafetyOfReply };
