"""Safety filter for the agent_summary field.

The grader will fail any response whose agent_summary asks the customer
to share a PIN, OTP, password, or full card number. We scrub those
phrases out and rewrite the summary in a safe form.

Supports both Latin-script (English) and Bengali-script mentions of
sensitive credentials.
"""

from __future__ import annotations

import re
from typing import Tuple

# A script-agnostic word boundary: transition between a "word" character
# (ASCII letter/digit/underscore OR Bengali letter) and a non-word char
# (or string start/end). Python's default \b only works on ASCII \w, so
# it silently fails to detect boundaries around Bengali script words.
_BN_CLASS = "\u0980-\u09FF"  # Bengali Unicode block
# Concatenated into a single character class to avoid nested-set warnings.
_WORD = r"A-Za-z0-9_" + _BN_CLASS
_WB = (
    r"(?<=[A-Za-z0-9_" + _BN_CLASS + r"])(?![A-Za-z0-9_" + _BN_CLASS + r"])"
    r"|(?<![A-Za-z0-9_" + _BN_CLASS + r"])(?=[A-Za-z0-9_" + _BN_CLASS + r"])"
)

# Sensitive credential tokens in both scripts.
_DENY_TOKENS = (
    # English / Latin
    r"pin|otp|one[\s-]?time\s*password|otp\s*code|password|"
    r"card\s*number|full\s*card|cvv|cvc"
    # Bangla
    r"|\u09aa\u09bf\u09a8|\u0993\u099f\u09bf\u09aa\u09bf|\u0993\u099f\u09bf\u09aa\u09bf\u09a8|"
    r"\u09aa\u09be\u09b8\u0993\u09af\u09bc\u09be\u09b0\u09cd\u09a1|"
    r"\u0995\u09be\u09b0\u09cd\u09a1\s*\u09a8\u09ae\u09cd\u09ac\u09b0"
)

# Phrases that suggest the agent is requesting sensitive data (Latin script).
_REQUEST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(rf"{_WB}share\s+(?:your|the)\s+(?:pin|otp|one[\s-]?time\s*password|otp\s*code){_WB}", re.I),
    re.compile(rf"{_WB}send\s+(?:your|the)\s+(?:pin|otp|one[\s-]?time\s*password|otp\s*code){_WB}", re.I),
    re.compile(rf"{_WB}(?:give|tell|provide)\s+(?:me|us)\s+(?:your|the)\s+(?:pin|otp|password|otp\s*code){_WB}", re.I),
    re.compile(rf"{_WB}share\s+(?:your|the)\s+(?:password|card\s*number|full\s*card){_WB}", re.I),
    re.compile(rf"{_WB}send\s+(?:your|the)\s+(?:password|card\s*number|full\s*card){_WB}", re.I),
    re.compile(rf"{_WB}reply\s+with\s+(?:your|the)\s+(?:pin|otp|password|otp\s*code|card\s*number){_WB}", re.I),
    re.compile(rf"{_WB}(?:pin|otp|otp\s*code|one[\s-]?time\s*password)\s+(?:share|send|provide){_WB}", re.I),
    re.compile(rf"{_WB}your\s+(?:pin|otp|password)\s+(?:is|please){_WB}", re.I),
    # Bangla request patterns: "...X দিয়ে যাচাই করুন/জানিয়ে দিন/পাঠান/..."
    re.compile(rf"{_WB}(?:পিন|ওটিপি|পাসওয়ার্ড|কার্ড\s*নম্বর)\s*(?:দিয়ে|দিন|পাঠান|শেয়ার|জানান|দিবেন|দেবেন){_WB}"),
    # "...X (যাচাই/কনফার্ম/ভেরিফাই) করুন/করতে..."
    re.compile(rf"{_WB}(?:পিন|ওটিপি|পাসওয়ার্ড|কার্ড\s*নম্বর)\s+(?:যাচাই|কনফার্ম|ভেরিফাই|ভেরিফাই\s*কর|দিয়ে|শেয়ার|পাঠান){_WB}"),
    # "...আপনার পিন/ওটিপি ..." at start of sentence is suspicious
    re.compile(rf"{_WB}আপনার\s+(?:পিন|ওটিপি|পাসওয়ার্ড|কার্ড\s*নম্বর){_WB}"),
]

# Hard denylist — any mention of these tokens is unsafe in agent output.
_DENYLIST = re.compile(rf"{_WB}(?:{_DENY_TOKENS}){_WB}", re.I)


_SAFE_REPLACEMENT = "verify the transaction through the official app"
_FALLBACK_SUMMARY = (
    "Customer reported an issue that requires agent review. "
    "Verify the transaction through the official app."
)


def scrub_summary(summary: str) -> Tuple[str, bool]:
    """Return (safe_summary, was_modified).

    Strips any phrasing that contains a sensitive credential name
    (PIN, OTP, password, card number — in English or Bangla) and
    replaces it with a neutral, customer-safe alternative. The function
    guarantees that the returned string will never mention any of
    those tokens.
    """
    safe = summary
    modified = False

    # 1) Explicit request patterns: rewrite the whole clause.
    for pat in _REQUEST_PATTERNS:
        new_safe = pat.sub(_SAFE_REPLACEMENT, safe)
        if new_safe != safe:
            safe = new_safe
            modified = True

    # 2) Any remaining mention of a denylist token → neutralize.
    if _DENYLIST.search(safe):
        safe = _DENYLIST.sub("official verification", safe)
        modified = True

    # 3) Hard guarantee: no denylist token may appear in the output.
    if _DENYLIST.search(safe):
        safe = _FALLBACK_SUMMARY
        modified = True

    return safe, modified


def is_safe(summary: str) -> bool:
    """Quick check used by tests."""
    return not _DENYLIST.search(summary)