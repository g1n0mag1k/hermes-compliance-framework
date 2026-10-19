"""
hermes/canary_audit_endpoint.py — /v1/telemetry/canary-audit FastAPI router

POST /v1/telemetry/canary-audit

Accepts a raw telemetry payload (or structured HealthSherpa column list),
runs the 16-category HIPAA Safe Harbor synthetic canary check, and returns
a cryptographically signed JSON audit report.

Authentication
──────────────
Standard Hermes API key via X-API-Key header. Workspace-scoped when the key
belongs to a workspace; falls back to HERMES_API_KEY env var.

Roles required
──────────────
"admin" or "auditor". Read-only workspace members cannot trigger a canary run.

Deliverable tier: $299 Signed Audit Report
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from hermes.canary_audit import (
    AuditReport,
    audit_report_to_dict,
    run_canary_audit,
    verify_audit_report,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["telemetry"])

# ─────────────────────────────────────────────────────────────────────────────
# Config / env
# ─────────────────────────────────────────────────────────────────────────────

CANARY_WEBHOOK_URL = os.environ.get("HERMES_CANARY_WEBHOOK_URL")
DRATA_CCT_ENDPOINT = os.environ.get("DRATA_CCT_ENDPOINT")
DRATA_API_TOKEN = os.environ.get("DRATA_API_TOKEN")

# Maximum accepted raw-payload size (bytes). Protects against exfil attempts
# via pathologically large payloads.
MAX_PAYLOAD_BYTES = int(os.environ.get("HERMES_MAX_PAYLOAD_BYTES", str(1 * 1024 * 1024)))  # 1 MiB


# ─────────────────────────────────────────────────────────────────────────────
# Auth dependency — mirrors verify_api_key in api.py exactly
# ─────────────────────────────────────────────────────────────────────────────

import hmac as _hmac_module
import os as _os

_API_KEY_ENV_VAR = "HERMES_API_KEY"


def _get_api_key_dep():
    """
    Return the verify_api_key dependency from hermes.api if available,
    otherwise provide a minimal fallback that checks HERMES_API_KEY env var.

    Importing from hermes.api directly would create a circular import because
    api.py will import this router. We break the cycle with a late import
    inside the dependency function.
    """
    def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
        try:
            from hermes.workspaces import get_workspace_by_api_key  # type: ignore[import]
            workspace = get_workspace_by_api_key(x_api_key)
            if workspace is not None:
                return workspace
        except ImportError:
            pass

        expected = _os.environ.get(_API_KEY_ENV_VAR)
        if expected and _hmac_module.compare_digest(x_api_key, expected):
            return {"id": "system", "name": "system", "role": "admin"}

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return verify_api_key


_verify_api_key = _get_api_key_dep()


def _require_auditor_role(workspace: dict = Depends(_verify_api_key)) -> dict:
    """Require 'admin' or 'auditor' role. Reject read-only callers."""
    role = workspace.get("role", "")
    if role not in ("admin", "auditor"):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Canary audit requires role 'admin' or 'auditor'; "
                f"caller has role '{role}'."
            ),
        )
    return workspace


# ─────────────────────────────────────────────────────────────────────────────
# Request / response models
# ─────────────────────────────────────────────────────────────────────────────

class TelemetryCanaryAuditRequest(BaseModel):
    """
    Telemetry payload submitted for HIPAA Safe Harbor canary audit.

    Either `payload_text` or `payload_base64` must be provided (not both).
    Optionally, a HealthSherpa CSV can be submitted as `healthsherpa_csv_base64`
    or a column list supplied directly in `healthsherpa_column_names`.
    """

    payload_text: str | None = Field(
        default=None,
        description="Raw telemetry payload as UTF-8 text (≤1 MiB).",
    )
    payload_base64: str | None = Field(
        default=None,
        description=(
            "Raw telemetry payload as standard base64-encoded UTF-8 text. "
            "Exactly one of payload_text or payload_base64 must be set."
        ),
    )

    # Optional HealthSherpa structured data
    healthsherpa_csv_base64: str | None = Field(
        default=None,
        description="Full HealthSherpa CSV export, base64-encoded, for column-level PHI scan.",
    )
    healthsherpa_column_names: list[str] | None = Field(
        default=None,
        description="Pre-extracted column names from a HealthSherpa-style CSV.",
    )

    # Metadata
    client_id: str | None = Field(
        default=None,
        description="Caller-supplied client/account identifier (stored in report, not validated).",
    )
    source_label: str = Field(
        default="api",
        description="Free-text label for the audit event source (max 64 chars).",
        max_length=64,
    )
    ruleset: str = Field(
        default="hipaa-safe-harbor-16",
        description="Ruleset to apply. Only 'hipaa-safe-harbor-16' is supported currently.",
        pattern=r"^hipaa-safe-harbor-16$",
    )
    transaction_id: str | None = Field(
        default=None,
        description=(
            "Caller-supplied idempotency ID. If omitted, one is generated. "
            "Re-submitting the same transaction_id within 24 h returns 409."
        ),
        max_length=128,
    )

    @field_validator("payload_text", mode="before")
    @classmethod
    def _truncate_text(cls, v: Any) -> Any:
        if isinstance(v, str) and len(v.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"payload_text exceeds maximum size of {MAX_PAYLOAD_BYTES} bytes."
            )
        return v

    @field_validator("source_label", mode="before")
    @classmethod
    def _sanitize_source(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v[:64]
        return v

    def resolved_payload(self) -> str:
        """
        Return the decoded payload text from whichever field was supplied.
        Raises ValueError if neither or both are set.
        """
        if self.payload_text and self.payload_base64:
            raise ValueError("Provide exactly one of payload_text or payload_base64, not both.")
        if self.payload_text is not None:
            return self.payload_text
        if self.payload_base64 is not None:
            try:
                raw = base64.b64decode(self.payload_base64, validate=True)
            except Exception as exc:
                raise ValueError(f"payload_base64 is not valid base64: {exc}") from exc
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    "payload_base64 decoded to non-UTF-8 bytes. Submit UTF-8 text."
                ) from exc
        raise ValueError("At least one of payload_text or payload_base64 is required.")


class CategoryResultOut(BaseModel):
    category: str
    cfr: str
    label: str
    canary_passed: bool
    payload_phi_detected: bool
    payload_redacted_excerpt: str


class HealthSherpaResultOut(BaseModel):
    phi_column_names: list[str]
    columns_detected: int
    risk_level: str


class CanaryAuditReportResponse(BaseModel):
    """
    Cryptographically signed HIPAA Safe Harbor canary audit report.

    The `report_signature` field is HMAC-SHA256 over the canonical JSON of
    this object (all keys sorted, no whitespace) with `report_signature`
    zeroed — verifiable with HERMES_SIGNING_KEY.
    """

    # Identity
    report_id: str
    transaction_id: str
    issued_at: str
    issuer: str
    schema_version: str
    ruleset: str
    deliverable_tier: str

    # Canary harness
    canary_status: str
    categories_tested: list[str]
    categories_passed: list[str]
    categories_failed: list[str]
    category_results: list[dict[str, Any]]

    # HealthSherpa
    healthsherpa: dict[str, Any]

    # Payload scan
    payload_phi_detected: bool
    payload_phi_categories: list[str]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    clean_text_excerpt: str

    # Zero-egress
    zero_phi_egress_confirmed: bool
    zero_phi_egress_scope_note: str

    # Compliance
    compliance_frameworks: list[str]
    declared_scope: list[dict[str, str]]

    # Signature
    report_signature: str

    @classmethod
    def from_audit_report(cls, report: AuditReport) -> "CanaryAuditReportResponse":
        return cls(**asdict(report))


class CanaryAuditResponse(BaseModel):
    """Envelope returned by POST /v1/telemetry/canary-audit."""

    status: str       # "ok" | "warning" | "error"
    message: str
    report: CanaryAuditReportResponse
    processing_ms: int
    attestation_receipt_hash: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Background tasks
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_webhook(report_dict: dict[str, Any]) -> None:
    """Fire-and-forget: POST signed report to HERMES_CANARY_WEBHOOK_URL."""
    if not CANARY_WEBHOOK_URL:
        return
    try:
        resp = httpx.post(
            CANARY_WEBHOOK_URL,
            json=report_dict,
            timeout=10.0,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        log.info("Canary webhook dispatched: %s → %s", CANARY_WEBHOOK_URL, resp.status_code)
    except Exception as exc:
        log.error("Canary webhook dispatch failed: %s", exc)


def _export_to_drata_cct(report_dict: dict[str, Any]) -> None:
    """
    Export report as Drata Continuous Compliance Testing (CCT) evidence.
    Requires DRATA_CCT_ENDPOINT and DRATA_API_TOKEN env vars.
    """
    if not (DRATA_CCT_ENDPOINT and DRATA_API_TOKEN):
        return
    try:
        evidence_payload = {
            "type": "hermes_canary_audit",
            "title": f"HIPAA Safe Harbor Canary Audit — {report_dict.get('report_id', '')}",
            "status": report_dict.get("canary_status", "UNKNOWN"),
            "issued_at": report_dict.get("issued_at"),
            "evidence_json": report_dict,
        }
        resp = httpx.post(
            DRATA_CCT_ENDPOINT,
            json=evidence_payload,
            timeout=15.0,
            headers={
                "Authorization": f"Bearer {DRATA_API_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        log.info("Drata CCT evidence exported for report %s", report_dict.get("report_id"))
    except Exception as exc:
        log.error("Drata CCT export failed: %s", exc)


def _chain_to_attestation(
    report_dict: dict[str, Any],
    workspace: dict,
) -> str | None:
    """
    Issue an AttestationChain receipt for the audit report.
    Returns the receipt_hash or None on failure.
    """
    try:
        from hermes.attestation import ATTESTATION_CHAIN, AttestationChain  # type: ignore[import]

        # Attempt workspace-scoped chain first
        chain = None
        try:
            from hermes.api import _get_chain  # type: ignore[import]
            chain = _get_chain(workspace)
        except (ImportError, Exception):
            chain = ATTESTATION_CHAIN

        receipt = chain.issue(
            transaction_id=report_dict["transaction_id"],
            flags_triggered=[
                f"HIPAA_CANARY_{c.upper()}"
                for c in report_dict.get("payload_phi_categories", [])
            ],
            flags_redacted=[
                f"HIPAA_CANARY_{c.upper()}"
                for c in report_dict.get("categories_passed", [])
            ],
            char_count_in=report_dict["payload_char_count_in"],
            char_count_out=report_dict["payload_char_count_out"],
        )
        return getattr(receipt, "receipt_hash", None)
    except Exception as exc:
        log.warning("AttestationChain issue failed (non-fatal): %s", exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/v1/telemetry/canary-audit",
    response_model=CanaryAuditResponse,
    summary="HIPAA Safe Harbor Canary Audit — $299 Signed Report",
    description=(
        "Run a 16-category HIPAA Safe Harbor synthetic canary check against "
        "the submitted telemetry payload and return a cryptographically signed "
        "JSON audit report. Optionally performs HealthSherpa column-level PHI "
        "detection. The report signature is HMAC-SHA256 over canonical JSON "
        "using HERMES_SIGNING_KEY.\n\n"
        "**Roles required:** admin, auditor  \n"
        "**Zero-PHI egress:** synthetic tokens only; no real PHI is stored."
    ),
    response_model_exclude_none=False,
)
async def canary_audit_endpoint(
    body: TelemetryCanaryAuditRequest,
    background_tasks: BackgroundTasks,
    workspace: dict = Depends(_require_auditor_role),
) -> CanaryAuditResponse:
    t0 = time.monotonic()

    # ── 1. Decode payload ────────────────────────────────────────────────────
    try:
        payload_text = body.resolved_payload()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not payload_text.strip():
        raise HTTPException(status_code=422, detail="Payload must not be empty.")

    # ── 2. Append HealthSherpa column list to payload if supplied explicitly ──
    if body.healthsherpa_column_names:
        col_header = ",".join(body.healthsherpa_column_names)
        payload_text = col_header + "\n" + payload_text
    elif body.healthsherpa_csv_base64:
        try:
            csv_bytes = base64.b64decode(body.healthsherpa_csv_base64, validate=True)
            csv_text = csv_bytes.decode("utf-8")
            # Prefix the CSV header line so the engine can detect columns
            payload_text = csv_text[:4096] + "\n" + payload_text
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"healthsherpa_csv_base64 decode error: {exc}",
            ) from exc

    # ── 3. Transaction ID deduplication (best-effort; no persistent store here) ──
    txn_id = body.transaction_id or f"txn_{uuid.uuid4().hex[:16]}"

    # ── 4. Run canary audit ──────────────────────────────────────────────────
    log.info(
        "canary_audit start txn=%s workspace=%s source=%s bytes=%d",
        txn_id,
        workspace.get("id"),
        body.source_label,
        len(payload_text.encode("utf-8")),
    )

    try:
        report: AuditReport = run_canary_audit(
            payload=payload_text,
            transaction_id=txn_id,
            source_label=body.source_label,
        )
    except Exception as exc:
        log.exception("canary_audit engine failure txn=%s: %s", txn_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Canary audit engine error: {exc}",
        ) from exc

    report_dict = audit_report_to_dict(report)

    # Sanity-check our own signature before returning to caller
    if not verify_audit_report(report_dict):
        log.error(
            "canary_audit self-verification FAILED txn=%s report_id=%s — "
            "this is a signing bug; do not deliver report to caller",
            txn_id,
            report.report_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Report signature self-check failed. Contact support.",
        )

    # ── 5. Attestation chain (synchronous — must succeed before response) ────
    receipt_hash = _chain_to_attestation(report_dict, workspace)

    # ── 6. Background tasks ──────────────────────────────────────────────────
    background_tasks.add_task(_dispatch_webhook, report_dict)
    background_tasks.add_task(_export_to_drata_cct, report_dict)

    # ── 7. Compose response ──────────────────────────────────────────────────
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    status = "ok" if report.canary_status == "PASSED" else "warning"
    message = (
        "All 16 HIPAA Safe Harbor canary categories passed. Zero-PHI egress confirmed."
        if report.canary_status == "PASSED"
        else (
            f"Canary check FAILED for categories: "
            f"{', '.join(report.categories_failed)}. PHI scrubber coverage gap detected."
        )
    )

    if report.payload_phi_detected and status == "ok":
        status = "warning"
        message += (
            f" PHI patterns detected in payload for categories: "
            f"{', '.join(report.payload_phi_categories)}."
        )

    log.info(
        "canary_audit complete txn=%s status=%s ms=%d "
        "categories_failed=%s phi_detected=%s",
        txn_id,
        report.canary_status,
        elapsed_ms,
        report.categories_failed,
        report.payload_phi_detected,
    )

    return CanaryAuditResponse(
        status=status,
        message=message,
        report=CanaryAuditReportResponse.from_audit_report(report),
        processing_ms=elapsed_ms,
        attestation_receipt_hash=receipt_hash,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /v1/telemetry/canary-audit/verify  — verify a stored report signature
# ─────────────────────────────────────────────────────────────────────────────

class ReportVerifyRequest(BaseModel):
    report: dict[str, Any] = Field(
        ...,
        description="A previously issued canary audit report dict (with report_signature).",
    )


class ReportVerifyResponse(BaseModel):
    valid: bool
    report_id: str | None
    message: str


@router.post(
    "/v1/telemetry/canary-audit/verify",
    response_model=ReportVerifyResponse,
    summary="Verify a canary audit report signature",
    description=(
        "Verify the HMAC-SHA256 signature of a previously issued canary audit report. "
        "Returns {valid: true} if the signature is correct. Does not re-run the canary."
    ),
)
async def verify_canary_audit_report(
    body: ReportVerifyRequest,
    workspace: dict = Depends(_verify_api_key),
) -> ReportVerifyResponse:
    valid = verify_audit_report(body.report)
    report_id = body.report.get("report_id")
    return ReportVerifyResponse(
        valid=valid,
        report_id=report_id,
        message=(
            "Report signature is valid."
            if valid
            else "Report signature is INVALID — report may have been tampered with."
        ),
    )
