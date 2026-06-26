# QueueStorm Investigator — Customer Support Ticket Triage

> **SUST CSE Carnival 2026 — Codex Community Hackathon**
> Online Preliminary Round Submission

An AI/API service that reads a customer support complaint along with the customer's recent transaction history, investigates the evidence, classifies the issue, routes it to the right department, and drafts a safe reply — all without requesting any sensitive credentials.

**Key capabilities:**
- 🔍 **Evidence reasoning** — matches complaint against transaction history, detects inconsistencies
- 🏷️ **8 case types** — wrong_transfer, payment_failed, refund_request, duplicate_payment, merchant_settlement_delay, agent_cash_in_issue, phishing_or_social_engineering, other
- 🛡️ **Safety-first** — never asks for PIN/OTP/password, never promises unauthorized refunds
- 🌐 **Bangla support** — handles Bangla (bn) and mixed (Banglish) complaints with Bangla replies
- ⚡ **Sub-5ms response** — pure rule-based, no LLM, no external API calls

Backend: **Node.js 20 + Express + Zod**. No LLM, no external services, fully deterministic.

---

## Live Demo

🚀 **Deployed on Render:** <https://devoops.onrender.com/>

| Endpoint           | Method | Purpose                                       |
|--------------------|--------|-----------------------------------------------|
| `/`                | GET    | Interactive API tester UI                     |
| `/health`          | GET    | Liveness probe — returns `{"status":"ok"}`    |
| `/analyze-ticket`  | POST   | Analyze one ticket — the main API endpoint    |

---

## Quick Start (Local)

```bash
# 1. Clone
git clone https://github.com/usaben/DevOops
cd DevOops

# 2. Install
npm install

# 3. Run
npm start
# Server starts on http://localhost:8000
```

The server listens on `process.env.PORT` (defaults to `8000`) and binds to `0.0.0.0`.

### Smoke Test

```bash
# Health check
curl -s http://localhost:8000/health
# → {"status":"ok","service":"queuestorm","version":"2.0.0","uptime_seconds":5}

# Analyze a ticket
curl -s -X POST http://localhost:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "TKT-001",
    "complaint": "I sent 5000 taka to a wrong number around 2pm today.",
    "language": "en",
    "channel": "in_app_chat",
    "user_type": "customer",
    "transaction_history": [
      {
        "transaction_id": "TXN-9101",
        "timestamp": "2026-04-14T14:08:22Z",
        "type": "transfer",
        "amount": 5000,
        "counterparty": "+8801719876543",
        "status": "completed"
      }
    ]
  }'
```

### Sample Output (SAMPLE-01)

```json
{
  "ticket_id": "TKT-001",
  "relevant_transaction_id": "TXN-9101",
  "evidence_verdict": "consistent",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT via TXN-9101 to +8801719876543, which they believe was the wrong recipient.",
  "recommended_next_action": "Verify TXN-9101 details with the customer and initiate the wrong-transfer dispute workflow per policy.",
  "customer_reply": "We have noted your concern about transaction TXN-9101. Please do not share your PIN or OTP with anyone. Our dispute team will review the case and contact you through official support channels.",
  "human_review_required": true,
  "confidence": 1,
  "reason_codes": ["wrong_transfer", "transaction_match"]
}
```

---

## API Reference

### `GET /health`

Returns `{"status":"ok"}` to confirm the service is alive.

```json
{
  "status": "ok",
  "service": "queuestorm",
  "version": "2.0.0",
  "uptime_seconds": 12
}
```

### `POST /analyze-ticket`

**Request body** — JSON:

| Field                | Type   | Required | Notes                                                              |
|----------------------|--------|----------|--------------------------------------------------------------------|
| `ticket_id`          | string | yes      | Echoed back in the response.                                       |
| `complaint`          | string | yes      | Customer complaint text (1–8000 chars, trimmed).                   |
| `language`           | string | optional | One of: `en`, `bn`, `mixed`.                                      |
| `channel`            | string | optional | One of: `in_app_chat`, `call_center`, `email`, `merchant_portal`, `field_agent`. |
| `user_type`          | string | optional | One of: `customer`, `merchant`, `agent`, `unknown`.                |
| `campaign_context`   | string | optional | Campaign identifier from the harness.                              |
| `transaction_history`| array  | optional | Array of transaction objects (see below). May be empty.            |
| `metadata`           | object | optional | Additional context from the harness.                               |

**Transaction history entry:**

| Field            | Type   | Description                                                          |
|------------------|--------|----------------------------------------------------------------------|
| `transaction_id` | string | Unique transaction identifier.                                       |
| `timestamp`      | string | ISO 8601 timestamp.                                                  |
| `type`           | string | One of: `transfer`, `payment`, `cash_in`, `cash_out`, `settlement`, `refund`. |
| `amount`         | number | Amount in BDT.                                                       |
| `counterparty`   | string | Recipient phone, merchant ID, or agent ID.                           |
| `status`         | string | One of: `completed`, `failed`, `pending`, `reversed`.                |

**Response body** — JSON:

| Field                    | Type    | Required | Description                                                          |
|--------------------------|---------|----------|----------------------------------------------------------------------|
| `ticket_id`              | string  | yes      | Echoes the request value.                                            |
| `relevant_transaction_id`| string/null | yes | Transaction ID the complaint refers to, or `null` if none matches.   |
| `evidence_verdict`       | enum    | yes      | `consistent`, `inconsistent`, or `insufficient_data`.                |
| `case_type`              | enum    | yes      | From the taxonomy below.                                             |
| `severity`               | enum    | yes      | `low`, `medium`, `high`, or `critical`.                              |
| `department`             | enum    | yes      | From the department taxonomy below.                                  |
| `agent_summary`          | string  | yes      | Concise agent-ready summary (1–2 sentences).                         |
| `recommended_next_action`| string  | yes      | Suggested next step for the support agent.                           |
| `customer_reply`         | string  | yes      | Safe official reply respecting all safety rules.                     |
| `human_review_required`  | boolean | yes      | `true` for disputes, suspicious cases, ambiguous evidence.           |
| `confidence`             | number  | optional | Float in `[0, 1]`.                                                   |
| `reason_codes`           | array   | optional | Short labels supporting the decision.                                |

**Error codes:** `422` for validation errors, `400` for malformed JSON, `500` for internal errors. All errors return JSON without leaking stack traces or secrets.

---

## Case Type Taxonomy

| case_type                       | Department              | Default Severity |
|---------------------------------|-------------------------|------------------|
| `wrong_transfer`                | `dispute_resolution`    | `high`           |
| `payment_failed`               | `payments_ops`          | `high`           |
| `refund_request`               | `customer_support`      | `low` (changed mind) / `medium` |
| `duplicate_payment`            | `payments_ops`          | `high`           |
| `merchant_settlement_delay`    | `merchant_operations`   | `medium`         |
| `agent_cash_in_issue`          | `agent_operations`      | `high`           |
| `phishing_or_social_engineering`| `fraud_risk`           | `critical`       |
| `other`                        | `customer_support`      | `low`            |

---

## How It Works

### 1. Evidence Reasoning Engine (35% of score)

The service reads both the complaint text and transaction history. For each case:

- **Extracts** claimed amount, counterparty, and time references from the complaint
- **Matches** against transaction history by amount, type, status, counterparty, and recency
- **Detects inconsistencies**: e.g., multiple prior transfers to the same "wrong number" recipient
- **Handles ambiguity**: when multiple transactions match equally, returns `insufficient_data` and asks for clarification
- **Detects duplicates**: identifies two identical payments within a short time window
- **Returns** `relevant_transaction_id` and `evidence_verdict` (`consistent` / `inconsistent` / `insufficient_data`)

### 2. Rule-Based Classifier

Pure regex signal scoring across 7 case type categories with 40+ weighted patterns. Supports English and Bangla keywords. Context boosting from transaction history (e.g., pending cash_in boosts `agent_cash_in_issue`). User type boosting (e.g., `merchant` boosts `merchant_settlement_delay`).

### 3. Safety Filter (20% of score)

Defence-in-depth safety system:

- **Credential request detection**: blocks complaint text that asks for PIN/OTP/password (phishing)
- **Customer reply validation**: ensures generated replies never request credentials (distinguishes "Do not share your PIN" warnings from requests)
- **Unauthorized refund promise detection**: blocks "we will refund", "we'll reverse", etc.
- **Prompt injection defence**: ignores instructions embedded in complaint text
- **Text scrubbing**: redacts card numbers, credential values, and URLs from agent summaries

### 4. Customer Reply Generation

Generates contextual, safe replies per case type:
- References specific transaction IDs when available
- Uses safe language: "any eligible amount will be returned through official channels"
- Responds in Bangla when `language === 'bn'`
- Always includes a credential safety reminder

---

## Models

**No LLM is used.** The classifier and evidence reasoning engine are pure JavaScript regex and scoring logic. The service:

- Runs in microseconds (mean < 5ms per request)
- Costs $0 in API calls
- Is fully deterministic — same input always produces the same output
- Has no GPU requirement
- Has no external API dependency

This design was chosen because:
1. The task is solvable with rule-based logic for the preliminary round
2. Deterministic behavior makes grading predictable
3. Zero latency from external API calls
4. Zero cost and zero quota concerns

The codebase is LLM-ready: `.env.example` reserves keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) for a future hybrid approach.

---

## Safety Logic

### What the service NEVER does:
1. **Never asks for PIN, OTP, password, CVV, or full card number** — the `validateSafetyOfReply()` function validates every generated `customer_reply` before returning it
2. **Never promises a refund, reversal, account unblock, or recovery** — the `UNSAFE_REFUND_PATTERNS` array catches "we will refund", "we'll reverse", etc.
3. **Never instructs users to contact suspicious third parties** — replies only guide to official support channels
4. **Never leaks credentials in summaries** — `scrubText()` redacts card numbers, credential values, and URLs from `agent_summary`
5. **Ignores prompt injection** — `sanitizeComplaint()` detects instructions embedded in complaint text

### How it's enforced:
- Safety checks run on the **original** complaint text before scrubbing (to detect phishing patterns)
- Generated `customer_reply` is validated post-generation; if unsafe, a safe fallback is returned
- Phishing complaints trigger a hard fallback with `case_type: 'phishing_or_social_engineering'`, `severity: 'critical'`, `department: 'fraud_risk'`

---

## Tests

```bash
npm install
npm test
```

36 tests across 3 files:

- `tests/test_classifier.js` — All 10 public sample cases with exact field assertions + schema/enum validation
- `tests/test_safety.js` — Credential scrubbing, refund promise detection, prompt injection, Bangla reply safety
- `tests/test_api.js` — End-to-end `/health`, `/analyze-ticket`, validation errors, malformed input, safety checks

---

## Deployment

### Render (recommended — free tier)

1. Push to GitHub.
2. Sign in at <https://render.com> → **New** → **Blueprint**.
3. Point at this repo. Render auto-detects `render.yaml`.
4. Wait ~2 minutes. URL: `https://devoops.onrender.com`.

### Docker

```bash
docker build -t queuestorm .
docker run --rm -p 8000:8000 -e PORT=8000 queuestorm
```

### Fly.io

```bash
fly launch --no-deploy
fly deploy
```

### Railway

Click **Deploy from GitHub** → select repo → Railway auto-detects `Procfile`.

---

## Project Structure

```
DevOops/
├── README.md                                ← this file
├── package.json                             ← Node deps + scripts
├── package-lock.json
├── server.js                                ← Express app, evidence reasoning, classifier, safety
├── Dockerfile                               ← container image (node:20-slim)
├── render.yaml                              ← Render blueprint
├── fly.toml                                 ← Fly.io config
├── Procfile                                 ← Heroku / Railway
├── .env.example                             ← env var names (no real secrets)
├── SUST_Preli_Sample_Cases.json             ← 10 public sample cases
├── SUST_Hackathon_Preli_Problem_Statement.pdf
├── SUST_Preli_Evaluation_Rubric_With_Explanations.pdf
├── SUST_Preli_Team_Instructions_Manual.pdf
├── public/
│   └── index.html                           ← demo UI with all 10 sample cases
└── tests/
    ├── test_classifier.js                   ← 10 sample cases + schema tests
    ├── test_safety.js                       ← safety filter tests
    └── test_api.js                          ← end-to-end API tests
```

---

## Known Limitations

1. **Bangla classification depth** — Bangla keyword coverage is narrower than English; some Bangla-only edge cases may fall through to `case_type: 'other'`
2. **No fuzzy amount matching** — the service expects exact numeric amounts in the complaint; "around 5000" works, but "about five thousand" would not extract the amount
3. **No cross-case-type reasoning** — each ticket is analyzed independently; patterns across multiple tickets from the same user are not considered
4. **Timestamp matching** — relative time phrases like "around 2pm" are not parsed against transaction timestamps; matching relies on amount and type
5. **Adversarial resilience** — while prompt injection is detected and handled, novel adversarial patterns may not trigger all safety checks

---

## Constraints Check

| Spec rule                                   | Status |
|---------------------------------------------|--------|
| Public HTTPS endpoint                       | ✅ Render serves HTTPS by default |
| `/health` returns `{"status":"ok"}` within 60s | ✅ Returns immediately, mean ~1ms |
| `/analyze-ticket` responds within 30s       | ✅ Pure CPU regex, mean <5ms |
| No GPU dependency                           | ✅ None |
| No secrets in the repository                | ✅ Only `.env.example`; `.env` is git-ignored |
| All required response fields present        | ✅ 10 required + 2 optional fields |
| Enum values match exactly                   | ✅ Tested in `test_classifier.js` |
| `customer_reply` never asks for PIN/OTP     | ✅ Validated by `validateSafetyOfReply()` |
| `customer_reply` never promises refund      | ✅ Checked by `UNSAFE_REFUND_PATTERNS` |
| Evidence reasoning with transaction_history | ✅ Full evidence engine in `findRelevantTransaction()` |
| All 10 public sample cases pass             | ✅ Covered in `test_classifier.js` |
| Handles empty transaction_history           | ✅ Returns `insufficient_data` |
| Handles malformed input without crashing    | ✅ Returns 400/422 with safe error message |
| Bangla complaint handling                   | ✅ Bangla keywords + Bangla reply |

---

## License

MIT.
