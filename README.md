# QueueStorm — Customer Support Ticket Triage

> **bKash × SUST CSE Carnival 2026 — Codex Community Hackathon**
> Mock Preliminary round submission.

A small, fast, deterministic web service that reads one customer support
message and instantly answers:

1. **What kind of problem is it?** (`wrong_transfer`, `payment_failed`,
   `refund_request`, `phishing_or_social_engineering`, `other`)
2. **How serious?** (`low`, `medium`, `high`, `critical`)
3. **Which team should handle it?** (`customer_support`,
   `dispute_resolution`, `payments_ops`, `fraud_risk`)
4. **A one-sentence summary an agent can read in two seconds.**
5. **Does it need a human to review immediately?**

The response is also guaranteed to **never** ask the customer to share
a PIN, OTP, password, or full card number — a hard safety rule that the
grader explicitly checks.

Backend: **Node.js 20 + Express + Zod**. No LLM, no external services.

---

## Live demo

🚀 **Deployed on Render:** <https://devoops.onrender.com/>

The service is live and exposes:

| Endpoint        | Method | Purpose                                          |
|-----------------|--------|--------------------------------------------------|
| `/`             | GET    | API tester UI (built-in ticket playground)       |
| `/health`       | GET    | Liveness probe — must respond within 10s         |
| `/sort-ticket`  | POST   | Classify one ticket — must respond within 30s    |

Try it now:

- UI:  <https://devoops.onrender.com/>
- API: <https://devoops.onrender.com/sort-ticket>
- Health: <https://devoops.onrender.com/health>

---

## Quick start (local)

```bash
# 1. clone
git clone https://github.com/usaben/DevOops
cd DevOops

# 2. install
npm install

# 3. run
npm start
# or: node server.js
```

The server listens on `process.env.PORT` (defaults to `3000`).
Open the API tester at <http://localhost:3000/>.

### Smoke test the API

```bash
curl -s http://localhost:3000/health
```

```bash
curl -s -X POST http://localhost:3000/sort-ticket \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "T-001",
    "channel": "app",
    "locale": "en",
    "message": "I sent 3000 to wrong number"
  }'
```

Expected response:

```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 3000 to the wrong recipient and requests recovery of the funds.",
  "human_review_required": false,
  "confidence": 0.95,
  "signals": ["wt.amount_keywords", "wt.wrong_number"]
}
```

---

## API reference

### `POST /sort-ticket`

**Request body** — JSON:

| Field       | Type   | Required | Notes                                                            |
|-------------|--------|----------|------------------------------------------------------------------|
| `ticket_id` | string | yes      | Echoed back in the response.                                     |
| `channel`   | string | optional | One of: `app`, `sms`, `call_center`, `merchant_portal`.          |
| `locale`    | string | optional | One of: `bn`, `en`, `mixed`.                                     |
| `message`   | string | yes      | Free-text customer complaint (1–4000 chars, trimmed).            |

**Response body** — JSON:

| Field                   | Type    | Notes                                                              |
|-------------------------|---------|--------------------------------------------------------------------|
| `ticket_id`             | string  | Echoes the request value.                                          |
| `case_type`             | enum    | `wrong_transfer` \| `payment_failed` \| `refund_request` \| `phishing_or_social_engineering` \| `other`. |
| `severity`              | enum    | `low` \| `medium` \| `high` \| `critical`.                          |
| `department`            | enum    | `customer_support` \| `dispute_resolution` \| `payments_ops` \| `fraud_risk`. |
| `agent_summary`         | string  | 1–2 neutral sentences. **Never** asks for credentials.             |
| `human_review_required` | boolean | `true` for phishing or critical.                                   |
| `confidence`            | number  | Float in `[0, 1]`.                                                 |
| `signals`               | array   | Debug list of which keyword signals fired.                         |

**Error codes:** `422` for validation errors (Zod issues returned in `details`).
All errors return JSON.

### `GET /health`

```json
{
  "status": "healthy",
  "service": "queuestorm",
  "version": "1.0.0",
  "uptime_seconds": 12
}
```

---

## How it works

### 1. Rule-based classifier (in `server.js`)

Pure regex, **no LLM**, **no external services**. Each class collects a
weighted score from a catalogue of independent keyword/pattern signals.
The winner is the class with the highest score (≥ 1.5 threshold); below
that, the case is bucketed as `other`. Phishing is treated as
safety-critical and triggers a hard fallback if a phishing request
phrase is detected anywhere in the message.

| Case type                                       | Department          | Severity (default) |
|-------------------------------------------------|---------------------|--------------------|
| `wrong_transfer`                                | `dispute_resolution`| `high`             |
| `payment_failed`                                | `payments_ops`      | `high`             |
| `refund_request`                                | `dispute_resolution`| `low` if "changed my mind", else `medium` |
| `phishing_or_social_engineering`                | `fraud_risk`        | `critical`         |
| `other`                                         | `customer_support`  | `low`              |

- Phishing → always `critical`, always `human_review_required = true`.
- High severity alone does **not** require human review (per spec).
- Money amounts in the message are surfaced in the agent summary.

### 2. Safety filter (in `server.js`)

A separate pass guarantees that **`agent_summary` never contains the
words PIN, OTP, password, CVV, or a 16-digit card number**. It:

1. Detects phishing/scam *request phrases* (e.g. "share your OTP",
   "someone asking my pin") on the **original** message — scrubbing first
   would destroy the tokens we need to match.
2. Substitutes any remaining credential mention (card numbers, password
   values, account numbers) with `[REDACTED]`.
3. If a request phrase was detected, returns a hard-coded safe summary
   and flags `case_type = phishing_or_social_engineering`.

This is defence-in-depth: even if a future classifier or LLM misbehaves,
the response cannot violate the safety rule.

### 3. API layer (Express + Zod)

- Express 4 with permissive CORS so graders can hit it from anywhere.
- Zod validates every request body. Failures return `422` with the
  issue list.
- `express.static` serves the tester UI from `/`.
- Binds to `process.env.PORT` (Render/Railway/Fly all set this).

### 4. Demo UI (`public/index.html`)

A single-file HTML/CSS/JS page with:

- Ticket ID, channel, locale, and message inputs.
- A **Triage** button that `POST`s to `/sort-ticket` and renders the
  full response: case, severity, department, summary, review flag,
  confidence, and matched signals.
- A **Load sample** dropdown pre-filling the 5 PDF cases.
- Pure vanilla JS, no build step, no external CDN. Calls the API via
  a relative URL so it works on any host (localhost, Render, etc.).

---

## Tests

```bash
npm install
npm test
```

23 tests in 3 files (`node --test tests/*.js`):

- `tests/test_classifier.js` — the 5 PDF public sample cases plus
  phishing / refund / severity / human-review edge cases.
- `tests/test_safety.js` — checks that the safety filter scrubs
  dangerous phrasings, redacts card numbers, and leaves safe
  summaries untouched.
- `tests/test_api.js` — end-to-end tests of `/health`, `/sort-ticket`,
  validation errors, and the static UI.

---

## Deployment

The repo ships with config for **Render** (`render.yaml`), **Fly**
(`fly.toml`), and **Railway / Heroku** (`Procfile`). All three bind to
the `$PORT` environment variable.

### Render (recommended — free tier)

1. Push this repo to GitHub.
2. Sign in at <https://render.com> → **New** → **Blueprint**.
3. Point it at this repo. Render auto-detects `render.yaml` and creates
   the web service.
4. Wait ~2 minutes. Your URL looks like
   `https://devoops.onrender.com`.

Manual alternative (without `render.yaml`):

| Setting     | Value                              |
|-------------|------------------------------------|
| Runtime     | Node                                |
| Build cmd   | `npm install`                       |
| Start cmd   | `node server.js`                    |
| Plan        | Free                                |
| Health path | `/health`                           |

### Fly.io

```bash
fly launch --no-deploy
fly deploy
```

### Railway

Click **Deploy from GitHub** → select the repo → Railway auto-detects
the `Procfile`. Set `PORT=3000` if it complains.

### Docker (any host)

```bash
docker build -t queuestorm .
docker run --rm -p 3000:3000 -e PORT=3000 queuestorm
```

---

## Project structure

```
DevOops/
├── README.md                  ← this file
├── package.json               ← Node deps + scripts
├── package-lock.json
├── server.js                  ← Express app, classifier, safety, validation
├── Dockerfile                 ← container image (node:20-slim)
├── render.yaml                ← Render blueprint
├── fly.toml                   ← Fly.io config
├── Procfile                   ← Heroku / Railway
├── public/
│   └── index.html             ← demo UI (single file, no build)
└── tests/
    ├── test_classifier.js     ← PDF public cases + edge cases
    ├── test_safety.js         ← safety scrubber tests
    └── test_api.js            ← end-to-end via http.createServer
```

---

## LLM usage

**No LLM is used.** The classifier is pure JavaScript regex, runs in
microseconds, costs $0, and is fully deterministic — same input always
produces the same output, which makes grader behaviour predictable.

The codebase is LLM-ready: `.env.example` already reserves keys
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) for a future
`classifyWithLlm()` hook, but no LLM call is made on the request path.

---

## Constraints check

| Spec rule                                   | Status |
|---------------------------------------------|--------|
| Public HTTPS endpoint                       | ✅ Render / Fly / Railway all serve HTTPS by default |
| `/health` responds within 10s               | ✅ No I/O on the path; mean ~1ms |
| `/sort-ticket` responds within 30s          | ✅ Pure CPU regex, mean <5ms |
| No GPU dependency                           | ✅ None |
| No secrets in the repository                | ✅ Only `.env.example`; `.env` is git-ignored |
| `agent_summary` never asks for PIN/OTP/password/card number | ✅ Safety filter is a hard guarantee |
| Public sample cases produce expected `case_type` + `severity` | ✅ covered in `tests/test_classifier.js` |

---

## License

MIT.
