import hmac
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from hermes.attestation import (
    ATTESTATION_CHAIN,
    ComplianceReceipt,
    HumanReviewReceipt,
    REVIEW_DECISIONS,
)
from hermes.webhooks import dispatch_webhook, dispatch_drata_cct
from hermes.classifier import (
    FlagEntry,
    RedactionAuditLog,
    ScrubberResult,
    scrub_payload,
)

# -------------------------------------------------------------------------
# API APPLICATION & CONFIGURATION
# -------------------------------------------------------------------------
app = FastAPI(
    title="Hermes Compliance API",
    description="Zero-Data-Retention PHI/PII Redaction Layer for MSPs",
    version="1.0.0"
)

# -------------------------------------------------------------------------
# SCHEMAS & AUTHENTICATION
# -------------------------------------------------------------------------
API_KEY_ENV_VAR = "HERMES_API_KEY"

class ScrubRequest(BaseModel):
    payload: str = Field(..., max_length=100_000)


class ComplianceReceiptOut(BaseModel):
    receipt_id: str
    transaction_id: str
    issued_at: str
    issuer: str
    compliance_frameworks: List[str]
    pii_classes_detected: List[str]
    pii_classes_redacted: List[str]
    count_detected: Dict[str, int]
    count_redacted: Dict[str, int]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    zero_pii_egress_confirmed: bool
    zero_pii_egress_scope_note: str
    downstream_target: Optional[str]
    previous_receipt_hash: str
    receipt_hash: str
    chain_position: int
    declared_scope: List[str]
    evidence_incomplete_categories: List[str]
    detectors_executed: Dict[str, str]


class ScrubResponse(BaseModel):
    clean_text: str
    audit_log: RedactionAuditLog
    compliance_receipt: ComplianceReceiptOut


class HumanReviewReceiptOut(BaseModel):
    review_id: str
    transaction_id: str
    reviewed_by: str
    issued_at: str
    decision: str
    override_reason: Optional[str]
    original_receipt_hash: str
    previous_receipt_hash: str
    review_receipt_hash: str
    chain_position: int


class ReviewRequest(BaseModel):
    transaction_id: str = Field(..., min_length=1)
    reviewed_by: str = Field(..., min_length=1)
    decision: str = Field(..., description=f"One of {REVIEW_DECISIONS}")
    override_reason: Optional[str] = None


class StatusResponse(BaseModel):
    chain_position: int
    total_scans: int
    last_scan_at: str
    zero_phi_egress_confirmed: bool
    phi_classes_detected_today: List[str]
    critical_findings_open: int
    evidence_current_as_of: str
    chain_integrity: str


def _flags_to_counts(flags_triggered: Dict[str, FlagEntry]) -> Dict[str, int]:
    """Map audit-log flag entries to per-flag counts for attestation issuance."""
    return {
        k: v.count if isinstance(v, FlagEntry) else v["count"]
        for k, v in flags_triggered.items()
    }


def _issue_scrub_attestation(
    transaction_id: str,
    result: ScrubberResult,
) -> ComplianceReceipt:
    """Issue a hash-chained compliance receipt for a /v1/scrub call."""
    flags = _flags_to_counts(result.audit_log.flags_triggered)
    redacted = _flags_to_counts(result.audit_log.flags_redacted)
    return ATTESTATION_CHAIN.issue(
        transaction_id=transaction_id,
        flags_triggered=flags,
        flags_redacted=redacted,
        char_count_in=result.audit_log.original_char_count,
        char_count_out=result.audit_log.redacted_char_count,
        downstream_target=None,
        detectors_executed=result.detectors_executed,
    )


def verify_api_key(x_api_key: str = Header(...)):
    """Simulates multi-tenant RMM authentication for MSP pilot deployments."""
    expected_key = os.environ.get(API_KEY_ENV_VAR)
    if not expected_key or not hmac.compare_digest(x_api_key, expected_key):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API Key")
    return x_api_key

# -------------------------------------------------------------------------
# ENDPOINTS
# -------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health_check():
    """Load balancer ping endpoint."""
    return {"status": "operational", "compliance_mode": "enforced", "version": "1.0.0"}

@app.post(
    "/v1/scrub",
    response_model=ScrubResponse,
    tags=["Pipeline"],
    dependencies=[Depends(verify_api_key)],
)
def scrub_endpoint(request: ScrubRequest, background_tasks: BackgroundTasks):
    """
    Synchronous endpoint execution. FastAPI delegates this to a
    background threadpool to cleanly respect our _PIPELINE_LOCK.
    """
    txn_id = f"txn_api_{uuid.uuid4().hex[:12]}"
    result = scrub_payload(transaction_id=txn_id, text=request.payload)
    receipt = _issue_scrub_attestation(transaction_id=txn_id, result=result)
    background_tasks.add_task(dispatch_webhook, receipt)
    background_tasks.add_task(dispatch_drata_cct, receipt)
    return ScrubResponse(
        clean_text=result.clean_text,
        audit_log=result.audit_log,
        compliance_receipt=ComplianceReceiptOut.model_validate(asdict(receipt)),
    )


@app.post(
    "/v1/review",
    response_model=HumanReviewReceiptOut,
    tags=["Pipeline"],
    dependencies=[Depends(verify_api_key)],
)
def review_endpoint(request: ReviewRequest):
    """Record a human review/override decision for a prior /v1/scrub
    transaction, chained into the same AttestationChain as tamper-evident
    proof that a control was actually looked at by a person."""
    try:
        review = ATTESTATION_CHAIN.issue_review(
            transaction_id=request.transaction_id,
            reviewed_by=request.reviewed_by,
            decision=request.decision,
            override_reason=request.override_reason,
        )
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if "No ComplianceReceipt found" in message else 400
        raise HTTPException(status_code=status_code, detail=message) from exc

    return HumanReviewReceiptOut.model_validate(asdict(review))


@app.get(
    "/v1/status",
    response_model=StatusResponse,
    tags=["System"],
    dependencies=[Depends(verify_api_key)],
)
def status_endpoint():
    """Dashboard data source — aggregate attestation-chain metrics for MSP UI."""
    chain = ATTESTATION_CHAIN.export_chain()
    total_scans = len(chain)

    if total_scans == 0:
        return StatusResponse(
            chain_position=0,
            total_scans=0,
            last_scan_at="",
            zero_phi_egress_confirmed=True,
            phi_classes_detected_today=[],
            critical_findings_open=0,
            evidence_current_as_of="",
            chain_integrity="no_data",
        )

    latest = chain[-1]
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    # Most recent ComplianceReceipt for zero_phi (reviews lack this field)
    zero_phi = True
    for item in reversed(chain):
        if "zero_pii_egress_confirmed" in item:
            zero_phi = bool(item["zero_pii_egress_confirmed"])
            break

    phi_today: set = set()
    critical_findings_open = 0
    for item in chain:
        classes = item.get("pii_classes_detected")
        if classes is None:
            continue
        issued_at = datetime.fromisoformat(item["issued_at"])
        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)
        if issued_at >= cutoff_24h:
            phi_today.update(classes)
        if issued_at >= cutoff_7d and len(classes) > 0:
            critical_findings_open += 1

    return StatusResponse(
        chain_position=latest["chain_position"],
        total_scans=total_scans,
        last_scan_at=latest["issued_at"],
        zero_phi_egress_confirmed=zero_phi,
        phi_classes_detected_today=sorted(phi_today),
        critical_findings_open=critical_findings_open,
        evidence_current_as_of=latest["issued_at"],
        chain_integrity=(
            "verified" if ATTESTATION_CHAIN.verify_chain() else "no_data"
        ),
    )
