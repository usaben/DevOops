"""End-to-end tests for the FastAPI app via httpx."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok():
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "healthy"
    assert body["service"] == "queuestorm"
    assert "uptime_seconds" in body


def test_root_serves_ui():
    res = client.get("/")
    assert res.status_code == 200
    assert "QueueStorm" in res.text


def test_sort_ticket_wrong_transfer():
    res = client.post(
        "/sort-ticket",
        json={
            "ticket_id": "T-100",
            "channel": "app",
            "locale": "en",
            "message": "I sent 5000 taka to a wrong number this morning, please help me get it back",
        },
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ticket_id"] == "T-100"
    assert body["case_type"] == "wrong_transfer"
    assert body["severity"] == "high"
    assert body["department"] == "dispute_resolution"
    assert body["human_review_required"] is False
    assert 0.0 <= body["confidence"] <= 1.0


def test_sort_ticket_phishing():
    res = client.post(
        "/sort-ticket",
        json={
            "ticket_id": "T-200",
            "message": "Someone called asking my OTP, is that bKash?",
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["case_type"] == "phishing_or_social_engineering"
    assert body["severity"] == "critical"
    assert body["department"] == "fraud_risk"
    assert body["human_review_required"] is True


def test_sort_ticket_validation_error_on_empty_message():
    res = client.post("/sort-ticket", json={"ticket_id": "T-1", "message": "   "})
    # FastAPI returns 422 for pydantic validation failures.
    assert res.status_code in (400, 422)


def test_sort_ticket_validation_error_on_missing_ticket_id():
    res = client.post("/sort-ticket", json={"message": "hi"})
    assert res.status_code == 422


def test_openapi_docs_available():
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_safety_filter_engages_on_bad_summary():
    # We can't easily make the classifier produce a bad summary today, but
    # we can verify the API would scrub a known-bad string if it ever did,
    # by directly invoking the scrubber in-line.
    from app.safety import scrub_summary

    safe, modified = scrub_summary("Please share your OTP with us.")
    assert modified is True
    assert "otp" not in safe.lower()