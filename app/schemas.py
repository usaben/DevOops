"""Pydantic schemas for the QueueStorm triage API."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class Channel(str, Enum):
    APP = "app"
    SMS = "sms"
    CALL_CENTER = "call_center"
    MERCHANT_PORTAL = "merchant_portal"


class Locale(str, Enum):
    BN = "bn"
    EN = "en"
    MIXED = "mixed"


class CaseType(str, Enum):
    WRONG_TRANSFER = "wrong_transfer"
    PAYMENT_FAILED = "payment_failed"
    REFUND_REQUEST = "refund_request"
    PHISHING = "phishing_or_social_engineering"
    OTHER = "other"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Department(str, Enum):
    CUSTOMER_SUPPORT = "customer_support"
    DISPUTE_RESOLUTION = "dispute_resolution"
    PAYMENTS_OPS = "payments_ops"
    FRAUD_RISK = "fraud_risk"


class SortTicketRequest(BaseModel):
    """Incoming CRM ticket payload."""

    ticket_id: str = Field(..., min_length=1, max_length=64, description="Echoed back in the response")
    channel: Optional[Channel] = Field(default=None, description="Source channel of the ticket")
    locale: Optional[Locale] = Field(default=None, description="Language hint: bn, en, mixed")
    message: str = Field(..., min_length=1, max_length=4000, description="Free-text customer message")

    @field_validator("message")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("message must not be empty")
        return v


class SortTicketResponse(BaseModel):
    """Structured triage result for one ticket."""

    ticket_id: str
    case_type: CaseType
    severity: Severity
    department: Department
    agent_summary: str = Field(..., min_length=1, max_length=400)
    human_review_required: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    signals: list[str] = Field(
        default_factory=list,
        description="Debug-only: matched signal names that drove the decision",
    )


class HealthResponse(BaseModel):
    status: Literal["healthy", "ok"] = "healthy"
    service: str
    version: str
    uptime_seconds: float


class ErrorResponse(BaseModel):
    detail: str
    code: str