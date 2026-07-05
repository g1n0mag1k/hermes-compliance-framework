import os
import uuid
from dataclasses import asdict
from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel

from hermes.attestation import ATTESTATION_CHAIN, ComplianceReceipt
from hermes.webhooks import dispatch_webhook
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
# The expected tenant API key is sourced from the environment so that no
# credential is committed to source control (set HERMES_API_KEY at deploy).
API_KEY_ENV_VAR = "HERMES_API_KEY"

class ScrubRequest(BaseModel):
    payload: str


class ComplianceReceiptOut(BaseModel):
    receipt_id: str
    transaction_id: str
    issued_at: str
    issuer: str
    compliance_frameworks: List[str]
    pii_classes_detected: List[str]
    pii_classes_redacted: List[str]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    zero_pii_egress_confirmed: bool
    downstream_target: Optional[str]
    previous_receipt_hash: str
    receipt_hash: str
    chain_position: int


class ScrubResponse(BaseModel):
    clean_text: str
    audit_log: RedactionAuditLog
    compliance_receipt: ComplianceReceiptOut


def _flags_to_counts(flags_triggered: Dict[str, FlagEntry]) -> Dict[str, int]:
    """Map audit-log flag entries to per-flag counts for attestation issuance. Not a detection change."""
    return {
        k: v.count if isinstance(v, FlagEntry) else v["count"]
        for k, v in flags_triggered.items()
    }


def _issue_scrub_attestation(
    transaction_id: str,
    result: ScrubberResult,
) -> ComplianceReceipt:
    """Issue a hash-chained compliance receipt for a /v1/scrub call via the shared AttestationChain. Not a detection change."""
    flags = _flags_to_counts(result.audit_log.flags_triggered)
    redacted = _flags_to_counts(result.audit_log.flags_redacted)
    return ATTESTATION_CHAIN.issue(
        transaction_id=transaction_id,
        flags_triggered=flags,
        flags_redacted=redacted,
        char_count_in=result.audit_log.original_char_count,
        char_count_out=result.audit_log.redacted_char_count,
        downstream_target=None,
    )


def verify_api_key(x_api_key: str = Header(...)):
    """Simulates multi-tenant RMM authentication for MSP pilot deployments."""
    expected_key = os.environ.get(API_KEY_ENV_VAR)
    if not expected_key or x_api_key != expected_key:
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
    return ScrubResponse(
        clean_text=result.clean_text,
        audit_log=result.audit_log,
        compliance_receipt=ComplianceReceiptOut.model_validate(asdict(receipt)),
    )
