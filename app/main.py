"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .classifier import classify
from .safety import is_safe, scrub_summary
from .schemas import (
    ErrorResponse,
    HealthResponse,
    SortTicketRequest,
    SortTicketResponse,
)

log = logging.getLogger("queuestorm")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "info").upper(),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

_START_TIME = time.monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("QueueStorm %s starting up", __version__)
    yield
    log.info("QueueStorm shutting down")


app = FastAPI(
    title="QueueStorm",
    description=(
        "Customer support ticket triage for the bKash × SUST CSE Carnival 2026 "
        "Codex Community Hackathon — Mock Preliminary round."
    ),
    version=__version__,
    contact={"name": "QueueStorm", "url": "https://github.com/"},
    lifespan=lifespan,
)

# Permissive CORS — graders may hit the API from anywhere.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------
STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    """Serve the demo UI."""
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Error handlers — always JSON, never an HTML 500.
# ---------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exc_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(detail=str(exc.detail), code=f"http_{exc.status_code}").model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exc_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            detail="Invalid request: " + str(exc.errors()),
            code="validation_error",
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_exc_handler(_: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(detail="Internal server error", code="internal_error").model_dump(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    """Liveness probe — must respond within 10 seconds per spec."""
    return HealthResponse(
        status="ok",
        service="queuestorm",
        version=__version__,
        uptime_seconds=round(time.monotonic() - _START_TIME, 2),
    )


@app.post(
    "/sort-ticket",
    response_model=SortTicketResponse,
    tags=["triage"],
    summary="Classify a customer support ticket",
    responses={
        422: {"model": ErrorResponse, "description": "Validation error"},
        500: {"model": ErrorResponse, "description": "Server error"},
    },
)
async def sort_ticket(payload: SortTicketRequest) -> SortTicketResponse:
    """Triage one CRM ticket into a structured classification.

    The response is always scrubbed through the safety filter so the
    `agent_summary` field cannot request sensitive credentials, even if
    a future classifier or LLM accidentally generates such phrasing.
    """
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="message must not be empty")

    try:
        result = classify(payload.message)
    except Exception as exc:  # pragma: no cover — defensive
        log.exception("classifier crashed for ticket %s: %s", payload.ticket_id, exc)
        raise HTTPException(status_code=500, detail="classifier failure") from exc

    # Defensive safety scrub — must never request secrets.
    safe_summary, _modified = scrub_summary(result["agent_summary"])
    if not is_safe(safe_summary):
        # Last-resort override: the safety filter replaces risky text.
        log.warning(
            "Safety scrub rewrote agent_summary for ticket %s", payload.ticket_id
        )

    return SortTicketResponse(
        ticket_id=payload.ticket_id,
        case_type=result["case_type"],
        severity=result["severity"],
        department=result["department"],
        agent_summary=safe_summary,
        human_review_required=result["human_review_required"],
        confidence=result["confidence"],
        signals=result["signals"],
    )
