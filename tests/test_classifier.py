"""Tests for the rule-based classifier against the public sample cases."""

from app.classifier import classify
from app.schemas import CaseType, Severity, Department


def assert_case(msg: str, *, case: CaseType, severity: Severity | None = None):
    out = classify(msg)
    assert out["case_type"] == case, f"for {msg!r} expected {case} got {out['case_type']} (signals={out['signals']})"
    if severity is not None:
        assert out["severity"] == severity, f"for {msg!r} expected severity {severity} got {out['severity']}"
    assert 0.0 <= out["confidence"] <= 1.0
    assert out["agent_summary"]
    # Summary must be a single string, no list/dict types.
    assert isinstance(out["agent_summary"], str)


# --- Public sample cases from the spec --------------------------------------

def test_sample_1_wrong_transfer():
    assert_case(
        "I sent 3000 to wrong number",
        case=CaseType.WRONG_TRANSFER,
        severity=Severity.HIGH,
    )

def test_sample_2_payment_failed():
    assert_case(
        "Payment failed but balance deducted",
        case=CaseType.PAYMENT_FAILED,
        severity=Severity.HIGH,
    )

def test_sample_3_phishing_otp_call():
    out = classify("Someone called asking my OTP, is that bKash?")
    assert out["case_type"] == CaseType.PHISHING
    assert out["severity"] == Severity.CRITICAL
    assert out["department"] == Department.FRAUD_RISK
    assert out["human_review_required"] is True

def test_sample_4_refund_changed_mind():
    assert_case(
        "Please refund my last transaction, I changed my mind",
        case=CaseType.REFUND_REQUEST,
        severity=Severity.LOW,
    )

def test_sample_5_app_crash_other():
    assert_case(
        "App crashed when I opened it",
        case=CaseType.OTHER,
    )


# --- Extra coverage: phishing variants, refunds, edge cases ----------------

def test_phishing_pin_ask():
    out = classify("An officer is calling and asking me to share my PIN to verify my bKash account.")
    assert out["case_type"] == CaseType.PHISHING
    assert out["human_review_required"] is True

def test_phishing_link():
    out = classify("I got an SMS saying my account will be blocked. Click this link http://bit.ly/x to verify.")
    assert out["case_type"] == CaseType.PHISHING

def test_refund_duplicate_charge():
    out = classify("I was charged twice for the same order, please refund the duplicate payment.")
    assert out["case_type"] == CaseType.REFUND_REQUEST

def test_refund_merchant():
    out = classify("I want to return my order to the merchant and get a refund.")
    assert out["case_type"] == CaseType.REFUND_REQUEST

def test_other_unrelated():
    out = classify("Hello, what are your business hours?")
    assert out["case_type"] == CaseType.OTHER

def test_summary_mentions_amount_when_present():
    out = classify("I sent 5000 taka to a wrong number, please help.")
    assert "5000" in out["agent_summary"]


# --- Severity rules --------------------------------------------------------

def test_phishing_is_critical():
    out = classify("Someone asked for my OTP on call.")
    assert out["severity"] == Severity.CRITICAL

def test_refund_low_when_changed_mind():
    out = classify("Please cancel and refund my last transaction, I changed my mind.")
    assert out["severity"] == Severity.LOW


# --- Human review rule -----------------------------------------------------

def test_human_review_for_phishing():
    assert classify("He is asking my OTP.")["human_review_required"] is True

def test_human_review_for_high_severity():
    # High severity alone does NOT require human review per the spec.
    out = classify("I sent 3000 to wrong number")
    assert out["severity"] == Severity.HIGH
    assert out["human_review_required"] is False