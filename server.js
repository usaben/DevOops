// QueueStorm - Customer Support Ticket Triage (Node.js + Express)
//
// Same external contract as the previous Python implementation:
//   GET  /health       -> { status: "healthy", service, version, uptime_seconds }
//   POST /sort-ticket  -> { ticket_id, case_type, severity, department,
//                          agent_summary, human_review_required,
//                          confidence, signals }
//
// English-first classifier (same scoring as app/classifier.py).
// English rules cover all 5 PDF sample cases. Bangla-only inputs fall through
// to case_type="other" but the API still validates and responds.

'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');
const { z } = require('zod');

const VERSION = '1.0.0';
const START_TIME = Date.now();

// ---------------------------------------------------------------------------
// Validation (zod) - equivalent of app/schemas.py SortTicketRequest
// ---------------------------------------------------------------------------

const SortTicketRequest = z.object({
  ticket_id: z.string().min(1).max(64),
  channel:   z.enum(['app', 'sms', 'call_center', 'merchant_portal']).optional(),
  locale:    z.enum(['bn', 'en', 'mixed']).optional(),
  message:   z.string()
    .min(1, 'message must not be empty')
    .max(4000)
    .transform(v => v.trim())
    .refine(v => v.length > 0, { message: 'message must not be empty' }),
});

// ---------------------------------------------------------------------------
// Classifier - equivalent of app/classifier.py
// ---------------------------------------------------------------------------

function compile(re) { return new RegExp(re, 'i'); }

const PHISHING_SIGNALS = [
  ['phish.otp',          compile('\\b(?:otp|one[\\s-]?time\\s*password|otp\\s*code)\\b'), 3.0],
  ['phish.pin',          compile('\\bpin\\b'), 3.0],
  ['phish.password',     compile('\\bpassword\\b'), 3.0],
  ['phish.ask_share',    compile("\\b(?:share|send|give|tell|provide|reply\\s+with|forward)\\s+(?:your|the|me|us)\\b[^\\.]{0,40}?(?:pin|otp|password|code)\\b"), 4.0],
  ['phish.call_claim',   compile("\\b(?:someone|caller|person|he|she|they|operator|agent)\\b[^\\.]{0,80}?(?:asking|asked|says|said|claiming|claim)[^\\.]{0,80}?(?:pin|otp|password|code)\\b"), 3.5],
  ['phish.suspicious_link', compile("\\b(?:click\\s+(?:the|this)\\s+link|http[s]?:\\/\\/|bit\\.ly|tinyurl)\\b"), 1.5],
  ['phish.verify_account',  compile("\\b(?:verify\\s+your\\s+account|account\\s+(?:will\\s+be\\s+)?(?:blocked|suspended|deactivated))\\b"), 2.5],
  ['phish.prize',        compile('\\b(?:won|winner|prize|lottery|cashback|reward)\\b'), 1.0],
  ['phish.bkash_call',   compile("\\b(?:b\\s*k\\s*a\\s*s\\s*h|nagad|rocket)\\b[^\\.]{0,60}?(?:calling|called)\\b"), 1.5],
];

const WRONG_TRANSFER_SIGNALS = [
  ['wt.wrong_number',     compile("\\b(?:wrong\\s+(?:number|recipient|person|account)|sent\\s+to\\s+(?:the\\s+)?wrong|by\\s+mistake|mistakenly)\\b"), 3.5],
  ['wt.get_back',         compile("\\b(?:get\\s+(?:it|the\\s+money|my\\s+money|back)|return\\s+(?:the\\s+)?money|refund\\s+(?:me|my))\\b"), 2.5],
  ['wt.amount_keywords',  compile('\\b(?:taka|tk|bdt)\\b'), 0.5],
  ['wt.transfer_verb',    compile("\\b(?:sent|transferred|paid|sent\\s+money|cash\\s*out)\\b"), 1.0],
  ['wt.unknown_person',   compile('\\b(?:unknown\\s+person|stranger|random\\s+number|unknown\\s+number)\\b'), 1.5],
];

const PAYMENT_FAILED_SIGNALS = [
  ['pf.failed',           compile("\\b(?:payment\\s+failed|transaction\\s+(?:failed|unsuccessful|declined|not\\s+completed)|couldn'?t\\s+(?:pay|complete|send)|didn'?t\\s+(?:go\\s+through|receive|reach))\\b"), 3.5],
  ['pf.balance_deducted', compile("\\b(?:balance\\s+(?:deducted|debited|reduced|gone)|money\\s+(?:deducted|debited|taken)|amount\\s+(?:deducted|debited))\\b"), 3.0],
  ['pf.not_received',     compile("\\b(?:not\\s+(?:received|credited|reflected)|haven'?t\\s+received)\\b"), 2.0],
  ['pf.network_error',    compile('\\b(?:network\\s+(?:error|issue|problem)|server\\s+(?:error|down)|timeout)\\b'), 1.0],
];

const REFUND_SIGNALS = [
  ['rf.refund_keyword',   compile("\\b(?:refund|return\\s+(?:my|the)\\s+money|chargeback|reversal)\\b"), 3.0],
  ['rf.changed_mind',     compile("\\b(?:changed\\s+my\\s+mind|cancel\\s+(?:my|the)\\s+(?:order|transaction|payment)|don'?t\\s+want\\s+(?:it|this)\\s+anymore)\\b"), 2.5],
  ['rf.duplicate',        compile("\\b(?:duplicate\\s+(?:payment|charge|deduction)|charged\\s+twice|double\\s+(?:charged|payment))\\b"), 3.0],
  ['rf.merchant',         compile("\\b(?:merchant|shop|seller|vendor)\\b[^\\.]{0,40}?(?:return|refund|cancel)\\b"), 2.0],
];

function scoreSignals(message, signals) {
  let total = 0.0;
  const fired = [];
  for (const [name, re, weight] of signals) {
    if (re.test(message)) { total += weight; fired.push(name); }
  }
  return [total, fired];
}

function amountPhrase(message) {
  const m = message.match(/(\d[\d,\.]*\s*(?:taka|tk|bdt|k\b|000)?)/i);
  if (m) return m[0].trim();
  return '';
}

const DEPARTMENT_FOR_CASE = {
  wrong_transfer:                   'dispute_resolution',
  payment_failed:                   'payments_ops',
  refund_request:                   'dispute_resolution',
  phishing_or_social_engineering:   'fraud_risk',
  other:                            'customer_support',
};

function severityFor(caseType, msg) {
  const msgL = msg.toLowerCase();
  if (caseType === 'phishing_or_social_engineering') return 'critical';
  if (caseType === 'wrong_transfer')                  return 'high';
  if (caseType === 'payment_failed')                  return 'high';
  if (caseType === 'refund_request') {
    if (/\b(?:changed\s+my\s+mind|cancel)\b/i.test(msgL)) return 'low';
    return 'medium';
  }
  if (/\b(?:crash|frozen|hang|bug|error)\b/i.test(msgL)) return 'medium';
  return 'low';
}

function humanReview(caseType, severity) {
  return caseType === 'phishing_or_social_engineering' || severity === 'critical';
}

function buildSummary(caseType, message, amount) {
  const amt = amount || 'an unspecified';
  switch (caseType) {
    case 'wrong_transfer':
      return `Customer reports sending ${amt} to the wrong recipient and requests recovery of the funds.`;
    case 'payment_failed':
      return `Customer reports a failed transaction of ${amt}; balance may have been deducted. Verify the transaction through the official app and confirm settlement.`;
    case 'refund_request':
      return `Customer is requesting a refund for ${amt}. Review the transaction history and process the request per policy.`;
    case 'phishing_or_social_engineering':
      return 'Customer reports a suspected phishing or social-engineering attempt. Do NOT call any number from the message. Verify through the official app only.';
    default:
      return 'Customer inquiry that did not match a known triage category. Route to general support for human review.';
  }
}

function classify(message) {
  const scores = {
    phishing_or_social_engineering: scoreSignals(message, PHISHING_SIGNALS),
    wrong_transfer:                  scoreSignals(message, WRONG_TRANSFER_SIGNALS),
    payment_failed:                  scoreSignals(message, PAYMENT_FAILED_SIGNALS),
    refund_request:                  scoreSignals(message, REFUND_SIGNALS),
  };

  let bestCase = 'other';
  let bestScore = 0.0;
  let bestSignals = [];
  for (const [caseType, [s, fired]] of Object.entries(scores)) {
    if (s > bestScore) { bestScore = s; bestCase = caseType; bestSignals = fired; }
  }

  const MIN_CONFIDENCE_THRESHOLD = 1.5;
  let caseType = 'other';
  let signals = [];
  if (bestScore >= MIN_CONFIDENCE_THRESHOLD) {
    caseType = bestCase;
    signals = bestSignals;
  }

  const severity = severityFor(caseType, message);
  const amount = amountPhrase(message);
  const summary = buildSummary(caseType, message, amount);
  const department = DEPARTMENT_FOR_CASE[caseType] || 'customer_support';

  let confidence = Math.min(1.0, bestScore / 5.0);
  if (caseType === 'other') confidence = 0.0;

  return {
    case_type: caseType,
    severity,
    department,
    agent_summary: summary,
    human_review_required: humanReview(caseType, severity),
    confidence: Number(confidence.toFixed(2)),
    signals,
  };
}

// ---------------------------------------------------------------------------
// Safety filter - equivalent of app/safety.py
// ---------------------------------------------------------------------------

const SENSITIVE_DENYLIST = [
  // 16-digit card numbers (grouped or ungrouped)
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
  // 13-19 digit numbers (any grouping)
  /\b(?:\d[ -]?){13,19}\b/g,
  // credential labels followed by a value, e.g. "pin: 1234", "password=secret", "cvv 123"
  /\b(?:password|passwd|pwd|pin|otp|cvv|cvc)\s*[:=]?\s*\S+/gi,
  // "account 12345678" / "acc no 1234567"
  /\b(?:account|acc)\s*(?:no|number|#)?\s*[:=]?\s*\d{6,}\b/gi,
  // 4-6 digit codes only when attached to a credential label
  /\b(?:pin|otp|code|cvv|cvc)\s*[:=]?\s*\d{3,6}\b/gi,
];

const REQUEST_PATTERNS = [
  // "share/send/... your pin/otp/password/code"
  /\b(?:share|send|give|tell|provide|reply\s+with|forward)\s+(?:your|the|me|us)\b[^\.]{0,40}?(?:pin|otp|password|code)\b/i,
  // "someone/operator/agent ... asking ... pin/otp/..."
  /\b(?:someone|caller|person|he|she|they|operator|agent|officer)\b[^\.]{0,80}?(?:asking|asked|says|said|claiming|claim)[^\.]{0,80}?(?:pin|otp|password|code)\b/i,
  // links or shortened URLs
  /\b(?:click\s+(?:the|this)\s+link|http[s]?:\/\/|bit\.ly|tinyurl)\b/i,
  // prize / lottery lures
  /\b(?:won|winner|prize|lottery|cashback|reward)\b/i,
  // short messages that are just a credential token (e.g. "OTP.", "code", "Pin 1234")
  /^\s*(?:pin|otp|code|password|cvv|cvc)\b[\s\S]{0,40}$/i,
];

function hardFallback() {
  return {
    case_type: 'phishing_or_social_engineering',
    severity: 'critical',
    department: 'fraud_risk',
    agent_summary: 'Message withheld by safety filter. Treated as potential phishing - do not contact the customer via any callback number in the message.',
    human_review_required: true,
    confidence: 1.0,
    signals: ['safety.fallback'],
  };
}

function scrubSummary(message) {
  // Detect phishing/scam intent on the ORIGINAL message - scrubbing removes the
  // exact tokens that the request patterns look for.
  const isRequest = REQUEST_PATTERNS.some(p => p.test(message));

  let scrubbed = message;
  for (const pat of SENSITIVE_DENYLIST) scrubbed = scrubbed.replace(pat, '[REDACTED]');
  // Also drop any literal URL fragments
  scrubbed = scrubbed.replace(/\b(?:http[s]?:\/\/[^\s]+|bit\.ly[^\s]*|tinyurl\.com[^\s]*)\b/gi, '[LINK REMOVED]');

  if (isRequest) {
    return { safe: false, fallback: hardFallback() };
  }
  return { safe: true, text: scrubbed };
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'healthy',
    service: 'queuestorm',
    version: VERSION,
    uptime_seconds: Math.floor((Date.now() - START_TIME) / 1000),
  });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/sort-ticket', (req, res) => {
  const parsed = SortTicketRequest.safeParse(req.body);
  if (!parsed.success) {
    return res.status(422).json({
      error: 'validation_failed',
      details: parsed.error.issues.map(i => ({
        field: i.path.join('.'),
        message: i.message,
      })),
    });
  }
  const { ticket_id } = parsed.data;
  const message = parsed.data.message;

  const scrub = scrubSummary(message);
  if (!scrub.safe) {
    return res.status(200).json({
      ticket_id,
      ...scrub.fallback,
    });
  }

  const result = classify(scrub.text);
  return res.status(200).json({ ticket_id, ...result });
});

app.use((req, res) => {
  res.status(404).json({ error: 'not_found', path: req.path });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`QueueStorm triage listening on :${PORT}`);
  });
}

module.exports = { app, classify, scrubSummary };
