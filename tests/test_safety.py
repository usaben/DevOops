"""Tests for the safety filter — agent_summary must never request secrets."""

import pytest

from app.safety import is_safe, scrub_summary


@pytest.mark.parametrize(
    "bad",
    [
        "Please share your OTP with us to verify.",
        "Reply with your PIN to confirm the transaction.",
        "Send your password to proceed.",
        "Provide your card number so we can process the refund.",
        "Tell us your OTP code.",
        "আপনার পিন নম্বর দিয়ে যাচাই করুন",
        "Please share the one-time password.",
    ],
)
def test_safety_scrubs_request_phrasings(bad: str):
    safe, modified = scrub_summary(bad)
    assert modified is True, f"safety should have rewritten: {bad!r}"
    assert is_safe(safe) is True
    # Hard denylist tokens should not appear after scrubbing.
    assert "pin" not in safe.lower()
    assert "otp" not in safe.lower()
    assert "password" not in safe.lower()


@pytest.mark.parametrize(
    "good",
    [
        "Customer reports a wrong transfer of 5000 taka.",
        "Customer requests a refund for the last transaction.",
        "Failed payment of 3000 taka; balance may have been deducted.",
        "Suspicious contact reported; escalate to fraud review.",
    ],
)
def test_safety_leaves_safe_summaries_alone(good: str):
    safe, modified = scrub_summary(good)
    assert modified is False
    assert safe == good