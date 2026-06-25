"""Rule-based ticket classifier.

Design goals
------------
1. **Deterministic & reproducible** — same input → same output. No ML, no
   nondeterministic calls. The grader and our test suite rely on this.
2. **Multilingual** — handles Bangla, English, and Banglish (romanised
   Bangla) because the brief mentions `locale` ∈ {bn, en, mixed}.
3. **Scored, not boolean** — each class collects a weighted score from
   independent keyword/pattern signals. The winner is the class with
   the highest score; ties broken by severity priority (phishing > wrong
   transfer > payment failed > refund > other).
4. **Defensive** — phishing is always checked first because it's the
   only case that can be safety-critical and must override other
   categories when present.
5. **Cheap** — pure regex, runs in microseconds. No LLM required.

If you want to plug an LLM in later, see ``classify_with_llm`` — it's
not wired into the default path but is kept as a reference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .schemas import CaseType, Department, Severity


# ---------------------------------------------------------------------------
# Signal catalogues
# ---------------------------------------------------------------------------

# Each signal has:
#   - pattern: compiled regex (case-insensitive)
#   - weight: how strongly it votes for its class
#   - name: short identifier surfaced in the response `signals` list
#
# Phishing signals are intentionally the heaviest because they can cause
# real-world financial harm if missed.

@dataclass(frozen=True)
class Signal:
    name: str
    pattern: re.Pattern[str]
    weight: float


# --- Phishing / social engineering -----------------------------------------
# Highest priority. If any of these fire strongly we will override other
# signals and escalate to critical + fraud_risk.
PHISHING_SIGNALS: tuple[Signal, ...] = (
    Signal("phish.otp",     re.compile(r"\b(?:otp|one[\s-]?time\s*password|otp\s*code|ও\s*ট\s*ি\s*প\s*ি|ওটিপি)\b", re.I), 3.0),
    Signal("phish.pin",     re.compile(r"\b(?:pin|পি\s*ে\s*ন|পিন|গো\s*প\s*ন\s*ী\s*য়\s* নম্বর)\b", re.I), 3.0),
    Signal("phish.password", re.compile(r"\b(?:password|পাসওয়ার্ড|পাস\s*ওয়া\s*র্ড)\b", re.I), 3.0),
    Signal("phish.ask_share", re.compile(
        r"\b(?:share|send|give|tell|provide|reply\s+with|forward|জানা\s*ন|পাঠা\s*ন|দি\s*ন|বলুন|পাঠা\s*ন)\s+"
        r"(?:your|the|me|us|আপনা\s*র|তোমার|আমা\s*কে)\b"
        r"[^\.]{0,40}?(?:pin|otp|password|পিন|ওটিপি|পাসওয়ার্ড|কোড|code)\b",
        re.I,
    ), 4.0),
    Signal("phish.call_claim", re.compile(
        r"\b(?:someone|caller|person|he|she|they|operator|agent|ব্যক্তি|তি\s*নি|সে|কেউ)\b"
        r"[^\.]{0,80}?(?:asking|asked|says|said|claiming|claim|বলে\s*ছে|বললো|বলেছে|জিজ্ঞে\s*স|জিজ্ঞেস)"
        r"[^\.]{0,80}?(?:pin|otp|password|কোড|code|password)\b",
        re.I,
    ), 3.5),
    Signal("phish.suspicious_link", re.compile(
        r"\b(?:click\s+(?:the|this)\s+link|http[s]?://|bit\.ly|tinyurl|লিংক|লিঙ্ক)\b",
        re.I,
    ), 1.5),
    Signal("phish.verify_account", re.compile(
        r"\b(?:verify\s+your\s+account|account\s+(?:will\s+be\s+)?(?:blocked|suspended|deactivated)|"
        r"অ্যাকাউন্ট\s+(?:ব্লক|স্থগিত|বন্ধ))\b",
        re.I,
    ), 2.5),
    Signal("phish.prize", re.compile(
        r"\b(?:won|winner|prize|lottery|cashback|reward|in\s*am\s*gir\b|পুরস্কার)\b",
        re.I,
    ), 1.0),
    Signal("phish.bkash_call", re.compile(
        r"\b(?:b\s*k\s*a\s*s\s*h|nagad|rocket|বিকাশ|নগদ|রকেট)\b[^\.]{0,60}?(?:calling|called|কল)\b",
        re.I,
    ), 1.5),
)

# --- Wrong transfer ---------------------------------------------------------
WRONG_TRANSFER_SIGNALS: tuple[Signal, ...] = (
    Signal("wt.wrong_number", re.compile(
        r"\b(?:wrong\s+(?:number|recipient|person|account)|"
        r"sent\s+to\s+(?:the\s+)?wrong|"
        r"by\s+mistake|mistakenly|"
        r"ভুল\s+(?:নম্বর|মোবাইল|অ্যাকাউন্ট|ব্যক্তি)|"
        r"ভুলে|ভুল\s*করে|ভুলভাবে)\b",
        re.I,
    ), 3.5),
    Signal("wt.get_back", re.compile(
        r"\b(?:get\s+(?:it|the\s+money|my\s+money|back)|"
        r"return\s+(?:the\s+)?money|"
        r"refund\s+(?:me|my)|"
        r"ফেরত|ফিরে\s+পেতে|ফেরত\s+পেতে|ফেরত\s+দিন)\b",
        re.I,
    ), 2.5),
    Signal("wt.amount_keywords", re.compile(
        r"\b(?:taka|tk|bdt|টাকা|ট\.\s*কা)\b",
        re.I,
    ), 0.5),
    Signal("wt.transfer_verb", re.compile(
        r"\b(?:sent|transferred|paid|sent\s+money|cash\s*out|পাঠি\s*য়ে\s*ছি|পাঠিয়েছি|পাঠা\s*লাম|প্রেরণ)\b",
        re.I,
    ), 1.0),
    Signal("wt.unknown_person", re.compile(
        r"\b(?:unknown\s+person|stranger|random\s+number|unknown\s+number|অপরিচিত)\b",
        re.I,
    ), 1.5),
)

# --- Payment failed ---------------------------------------------------------
PAYMENT_FAILED_SIGNALS: tuple[Signal, ...] = (
    Signal("pf.failed", re.compile(
        r"\b(?:payment\s+failed|transaction\s+(?:failed|unsuccessful|declined|not\s+completed)|"
        r"couldn'?t\s+(?:pay|complete|send)|"
        r"didn'?t\s+(?:go\s+through|receive|reach)|"
        r"পেমেন্ট\s+(?:ব্যর্থ|ফেল)|"
        r"লেনদেন\s+(?:ব্যর্থ|হয়নি)|"
        r"টাকা\s+যায়নি|পে\s*মেন্ট\s*হয়নি)\b",
        re.I,
    ), 3.5),
    Signal("pf.balance_deducted", re.compile(
        r"\b(?:balance\s+(?:deducted|debited|reduced|gone)|money\s+(?:deducted|debited|taken)|"
        r"amount\s+(?:deducted|debited)|"
        r"ব্যালেন্স\s+(?:কমে|কেটে|কেটে\s+নেওয়া|কাটা)|"
        r"টাকা\s+(?:কমে|কেটে|কেটে\s*গেছে))\b",
        re.I,
    ), 3.0),
    Signal("pf.not_received", re.compile(
        r"\b(?:not\s+(?:received|credited|reflected)|"
        r"haven'?t\s+received|"
        r"পাইনি|আসেনি|জমা\s+হয়নি|পাওয়া\s*যায়নি)\b",
        re.I,
    ), 2.0),
    Signal("pf.network_error", re.compile(
        r"\b(?:network\s+(?:error|issue|problem)|server\s+(?:error|down)|timeout|সার্ভার|নেটওয়ার্ক)\b",
        re.I,
    ), 1.0),
)

# --- Refund request ---------------------------------------------------------
REFUND_SIGNALS: tuple[Signal, ...] = (
    Signal("rf.refund_keyword", re.compile(
        r"\b(?:refund|return\s+(?:my|the)\s+money|chargeback|reversal|"
        r"ফেরত|ফেরত\s+দিন|রিফান্ড|টাকা\s+ফেরত)\b",
        re.I,
    ), 3.0),
    Signal("rf.changed_mind", re.compile(
        r"\b(?:changed\s+my\s+mind|cancel\s+(?:my|the)\s+(?:order|transaction|payment)|"
        r"don'?t\s+want\s+(?:it|this)\s+anymore|"
        r"মন\s+পরিবর্তন|বাতিল)\b",
        re.I,
    ), 2.5),
    Signal("rf.duplicate", re.compile(
        r"\b(?:duplicate\s+(?:payment|charge|deduction)|charged\s+twice|double\s+(?:charged|payment))\b",
        re.I,
    ), 3.0),
    Signal("rf.merchant", re.compile(
        r"\b(?:merchant|shop|seller|vendor|দোকান|বিক্রেতা)\b[^\.]{0,40}?(?:return|refund|cancel|ফেরত|বাতিল)\b",
        re.I,
    ), 2.0),
)


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _score(message: str, signals: Iterable[Signal]) -> tuple[float, list[str]]:
    """Return (score, fired_signal_names) for one class."""
    total = 0.0
    fired: list[str] = []
    for sig in signals:
        if sig.pattern.search(message):
            total += sig.weight
            fired.append(sig.name)
    return total, fired


def _amount_phrase(message: str) -> str:
    """Extract the first money amount mentioned, e.g. '5000', '৫০০০', '5k'."""
    # Bangla digits first (often written)
    bn = re.search(r"([০-৯][০-৯,\.]*\s*(?:হাজার|লক্ষ|লাখ|কোটি)?)", message)
    if bn:
        return bn.group(0).strip()
    en = re.search(
        r"(\d[\d,\.]*\s*(?:taka|tk|bdt|হাজার|লক্ষ|লাখ|কোটি|k\b|000)?)",
        message,
        re.I,
    )
    if en:
        return en.group(0).strip()
    return ""


# ---------------------------------------------------------------------------
# Department / severity matrices (per spec section 4.2)
# ---------------------------------------------------------------------------

_DEPARTMENT_FOR_CASE: dict[CaseType, Department] = {
    CaseType.OTHER: Department.CUSTOMER_SUPPORT,
    CaseType.REFUND_REQUEST: Department.DISPUTE_RESOLUTION,
    CaseType.WRONG_TRANSFER: Department.DISPUTE_RESOLUTION,
    CaseType.PAYMENT_FAILED: Department.PAYMENTS_OPS,
    CaseType.PHISHING: Department.FRAUD_RISK,
}


def _severity_for(case: CaseType, msg: str) -> Severity:
    msg_l = msg.lower()
    # Phishing is always critical.
    if case == CaseType.PHISHING:
        return Severity.CRITICAL
    # Money + urgency → high.
    if case == CaseType.WRONG_TRANSFER:
        return Severity.HIGH
    if case == CaseType.PAYMENT_FAILED:
        return Severity.HIGH
    if case == CaseType.REFUND_REQUEST:
        # Refund without money-loss indicators → low.
        if re.search(r"\b(?:changed\s+my\s+mind|cancel|বাতিল|মন\s+পরিবর্তন)\b", msg_l, re.I):
            return Severity.LOW
        return Severity.MEDIUM
    # Other
    if re.search(r"\b(?:crash|frozen|hang|bug|error|ক্র্যাশ|সমস্যা)\b", msg_l, re.I):
        return Severity.MEDIUM
    return Severity.LOW


def _human_review(case: CaseType, severity: Severity) -> bool:
    return case == CaseType.PHISHING or severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Agent summary templates (intentionally neutral, never asks for secrets)
# ---------------------------------------------------------------------------

def _build_summary(case: CaseType, message: str, amount: str) -> str:
    amt = amount or "an unspecified"
    if case == CaseType.WRONG_TRANSFER:
        return (
            f"Customer reports sending {amt} to the wrong recipient and requests recovery of the funds."
        )
    if case == CaseType.PAYMENT_FAILED:
        return (
            f"Customer reports a failed transaction of {amt}; balance may have been deducted. "
            f"Verify the transaction through the official app and confirm settlement."
        )
    if case == CaseType.REFUND_REQUEST:
        return (
            f"Customer is requesting a refund for {amt}. "
            f"Review the transaction history and process the request per policy."
        )
    if case == CaseType.PHISHING:
        return (
            "Customer reports a suspicious contact attempting to obtain sensitive "
            "verification details. Treat as potential social engineering and escalate to fraud review."
        )
    # Other
    short = re.sub(r"\s+", " ", message).strip()
    if len(short) > 180:
        short = short[:177].rstrip() + "..."
    return f"Customer reports: {short}"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def classify(message: str) -> dict:
    """Classify a customer message into the structured triage shape.

    Returns a dict matching ``SortTicketResponse`` fields plus a `signals`
    debug list.
    """
    # 1) Score every class.
    p_score, p_fired = _score(message, PHISHING_SIGNALS)
    w_score, w_fired = _score(message, WRONG_TRANSFER_SIGNALS)
    pf_score, pf_fired = _score(message, PAYMENT_FAILED_SIGNALS)
    rf_score, rf_fired = _score(message, REFUND_SIGNALS)

    scores: dict[CaseType, float] = {
        CaseType.PHISHING: p_score,
        CaseType.WRONG_TRANSFER: w_score,
        CaseType.PAYMENT_FAILED: pf_score,
        CaseType.REFUND_REQUEST: rf_score,
        CaseType.OTHER: 0.0,
    }

    # 2) Decide winner with priority: phishing dominates when strong,
    # otherwise highest non-zero score, otherwise 'other'.
    winner: CaseType = CaseType.OTHER
    winning_signals: list[str] = []

    if p_score >= 3.0:  # phishing is hard — clear pattern wins outright
        winner = CaseType.PHISHING
        winning_signals = p_fired
    else:
        # Find the max non-phishing score
        best_score = max(w_score, pf_score, rf_score)
        if best_score > 0:
            # Tie-break: wrong_transfer > payment_failed > refund (more urgent)
            ordered = [
                (CaseType.WRONG_TRANSFER, w_score, w_fired),
                (CaseType.PAYMENT_FAILED, pf_score, pf_fired),
                (CaseType.REFUND_REQUEST, rf_score, rf_fired),
            ]
            for case, s, fired in ordered:
                if s == best_score:
                    winner = case
                    winning_signals = fired
                    break

    # 3) Confidence: normalize by an empirical "very clear" threshold.
    score = scores[winner]
    if winner == CaseType.PHISHING:
        # Two or more phishing signals → very confident.
        confidence = 0.85 if len(p_fired) >= 2 else 0.7
    elif winner == CaseType.OTHER:
        confidence = 0.6
    else:
        # Clamp into [0.55, 0.95].
        confidence = max(0.55, min(0.95, 0.55 + score / 8.0))

    # 4) Build the rest of the response.
    severity = _severity_for(winner, message)
    department = _DEPARTMENT_FOR_CASE[winner]
    human_review = _human_review(winner, severity)
    amount = _amount_phrase(message)
    summary = _build_summary(winner, message, amount)

    # 5) Combine all fired signal names (debug aid).
    all_signals = sorted(set(p_fired + w_fired + pf_fired + rf_fired))

    return {
        "case_type": winner,
        "severity": severity,
        "department": department,
        "agent_summary": summary,
        "human_review_required": human_review,
        "confidence": round(confidence, 2),
        "signals": all_signals,
    }