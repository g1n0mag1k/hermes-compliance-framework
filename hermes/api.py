import hmac
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

from hermes.attestation import (
    ATTESTATION_CHAIN,
    ComplianceReceipt,
    REVIEW_DECISIONS,
    DEFAULT_DB_PATH,
)
from hermes.webhooks import dispatch_webhook, dispatch_drata_cct
from hermes.classifier import (
    FlagEntry,
    RedactionAuditLog,
    ScrubberResult,
    scrub_payload,
)
from hermes.auditor import CANARY_CORPUS

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
TRIAL_SCAN_LIMIT = 5
TRIAL_WINDOW_DAYS = 14
_DEFAULT_WORKSPACE_ID = "default"
_trial_quota_lock = threading.Lock()


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
    occurrence_gaps: Dict[str, int] = Field(default_factory=dict)


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
    scans_used: int
    scans_remaining: int
    trial_active: bool
    trial_expires_at: Optional[str] = None


def _flags_to_counts(flags_triggered: Dict[str, FlagEntry]) -> Dict[str, int]:
    """Map audit-log flag entries to per-flag counts for attestation issuance."""
    return {
        k: v.count if isinstance(v, FlagEntry) else v["count"]
        for k, v in flags_triggered.items()
    }


def _get_chain(workspace):
    """Return the AttestationChain for a workspace (or global for legacy)."""
    if isinstance(workspace, _LegacyWorkspace):
        return ATTESTATION_CHAIN
    from hermes.workspaces import get_chain_for_workspace
    return get_chain_for_workspace(workspace)


def _issue_scrub_attestation(
    transaction_id: str,
    result: ScrubberResult,
    workspace=None,
) -> ComplianceReceipt:
    """Issue a hash-chained compliance receipt for a /v1/scrub call."""
    flags = _flags_to_counts(result.audit_log.flags_triggered)
    redacted = _flags_to_counts(result.audit_log.flags_redacted)
    chain = _get_chain(workspace) if workspace else ATTESTATION_CHAIN
    # occurrence_gaps from post-scan verification: non-empty forces
    # zero_pii_egress_confirmed=False inside chain.issue() regardless of
    # flags_triggered == flags_redacted count parity.
    return chain.issue(
        transaction_id=transaction_id,
        flags_triggered=flags,
        flags_redacted=redacted,
        char_count_in=result.audit_log.original_char_count,
        char_count_out=result.audit_log.redacted_char_count,
        downstream_target=None,
        detectors_executed=result.detectors_executed,
        occurrence_gaps=result.occurrence_gaps,
    )


def verify_api_key(x_api_key: str = Header(...)):
    """
    Workspace-aware authentication.

    Looks up the workspace by API key in the registry. Falls back to the
    legacy HERMES_API_KEY env var for backward-compatible single-tenant
    deployments. Raises 401 if no match is found.
    """
    from hermes.workspaces import get_workspace_by_api_key, get_workspace

    # Try workspace registry first
    workspace = get_workspace_by_api_key(x_api_key)
    if workspace is not None:
        return workspace

    # Legacy fallback: single HERMES_API_KEY env var
    expected_key = os.environ.get(API_KEY_ENV_VAR)
    if expected_key and hmac.compare_digest(x_api_key, expected_key):
        ws = get_workspace("default")
        if ws is not None:
            return ws
        return _LegacyWorkspace()

    raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API Key")


class _LegacyWorkspace:
    """Synthetic workspace wrapping the legacy global chain/vault."""
    workspace_id = "default"
    name = "Default"
    owner_email = ""
    plan = "production"
    parent_workspace_id = None


# -------------------------------------------------------------------------
# TRIAL QUOTA (same hermes_chain.db as attestation — HERMES_DB_PATH)
# -------------------------------------------------------------------------
def _trial_db_path() -> str:
    return os.environ.get("HERMES_DB_PATH", DEFAULT_DB_PATH)


def _ensure_trial_quota_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS trial_quota (
            workspace_id TEXT PRIMARY KEY DEFAULT 'default',
            scans_used INTEGER DEFAULT 0,
            first_scan_at TEXT,
            extended_by INTEGER DEFAULT 0
        )
        """
    )


def _get_trial_quota(
    workspace_id: str = _DEFAULT_WORKSPACE_ID,
) -> Tuple[int, Optional[str], int]:
    """Return (scans_used, first_scan_at, extended_by) for workspace."""
    with _trial_quota_lock:
        conn = sqlite3.connect(_trial_db_path(), check_same_thread=False)
        try:
            with conn:
                _ensure_trial_quota_table(conn)
                row = conn.execute(
                    "SELECT scans_used, first_scan_at, extended_by "
                    "FROM trial_quota WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                if row is None:
                    return 0, None, 0
                return int(row[0] or 0), row[1], int(row[2] or 0)
        finally:
            conn.close()


def _increment_trial_quota(
    workspace_id: str = _DEFAULT_WORKSPACE_ID,
) -> Tuple[int, str]:
    """Increment scans_used after a successful trial scan. Returns (scans_used, first_scan_at)."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with _trial_quota_lock:
        conn = sqlite3.connect(_trial_db_path(), check_same_thread=False)
        try:
            with conn:
                _ensure_trial_quota_table(conn)
                row = conn.execute(
                    "SELECT scans_used, first_scan_at, extended_by "
                    "FROM trial_quota WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO trial_quota "
                        "(workspace_id, scans_used, first_scan_at, extended_by) "
                        "VALUES (?, 1, ?, 0)",
                        (workspace_id, now_iso),
                    )
                    return 1, now_iso
                scans_used = int(row[0] or 0) + 1
                first_scan_at = row[1] or now_iso
                conn.execute(
                    "UPDATE trial_quota SET scans_used = ?, first_scan_at = ? "
                    "WHERE workspace_id = ?",
                    (scans_used, first_scan_at, workspace_id),
                )
                return scans_used, first_scan_at
        finally:
            conn.close()


def _parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _trial_expires_at(first_scan_at: Optional[str]) -> Optional[str]:
    if not first_scan_at:
        return None
    return (_parse_iso(first_scan_at) + timedelta(days=TRIAL_WINDOW_DAYS)).isoformat()


def _trial_window_expired(first_scan_at: Optional[str], now: Optional[datetime] = None) -> bool:
    if not first_scan_at:
        return False
    current = now or datetime.now(timezone.utc)
    return current >= _parse_iso(first_scan_at) + timedelta(days=TRIAL_WINDOW_DAYS)


def _trial_active(scans_used: int, first_scan_at: Optional[str]) -> bool:
    if scans_used >= TRIAL_SCAN_LIMIT:
        return False
    if _trial_window_expired(first_scan_at):
        return False
    return True


def _canary_payload() -> str:
    return "\n".join(f"{e['flag']}: {e['value']}" for e in CANARY_CORPUS)


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
)
def scrub_endpoint(request: ScrubRequest, background_tasks: BackgroundTasks, workspace=Depends(verify_api_key)):
    """
    Synchronous endpoint execution. FastAPI delegates this to a
    background threadpool to cleanly respect our _PIPELINE_LOCK.
    """
    txn_id = f"txn_api_{uuid.uuid4().hex[:12]}"
    result = scrub_payload(transaction_id=txn_id, text=request.payload)
    receipt = _issue_scrub_attestation(transaction_id=txn_id, result=result, workspace=workspace)
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
)
def review_endpoint(request: ReviewRequest, workspace=Depends(verify_api_key)):
    """Record a human review/override decision for a prior /v1/scrub
    transaction, chained into the same AttestationChain as tamper-evident
    proof that a control was actually looked at by a person."""
    try:
        chain = _get_chain(workspace)
        review = chain.issue_review(
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
)
def status_endpoint(workspace=Depends(verify_api_key)):
    """Dashboard data source — aggregate attestation-chain metrics for MSP UI."""
    chain_obj = _get_chain(workspace)
    chain = chain_obj.export_chain()
    total_scans = len(chain)
    from hermes.workspaces import get_trial_quota as _ws_trial_quota
    scans_used, first_scan_at, _extended = _ws_trial_quota(workspace.workspace_id)
    scans_remaining = max(TRIAL_SCAN_LIMIT - scans_used, 0)
    expires_at = _trial_expires_at(first_scan_at)
    active = _trial_active(scans_used, first_scan_at)

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
            scans_used=scans_used,
            scans_remaining=scans_remaining,
            trial_active=active,
            trial_expires_at=expires_at,
        )

    latest = chain[-1]
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

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
        issued_at = _parse_iso(item["issued_at"])
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
            "verified" if chain_obj.verify_chain() else "no_data"
        ),
        scans_used=scans_used,
        scans_remaining=scans_remaining,
        trial_active=active,
        trial_expires_at=expires_at,
    )


@app.post(
    "/v1/trial-scan",
    response_model=ScrubResponse,
    tags=["Pipeline"],
)
def trial_scan_endpoint(background_tasks: BackgroundTasks, workspace=Depends(verify_api_key)):
    """Run a fixed canary PHI scan subject to persistent trial quota limits."""
    from hermes.workspaces import get_trial_quota as _ws_trial_quota, increment_trial_quota as _ws_increment
    scans_used, first_scan_at, _extended = _ws_trial_quota(workspace.workspace_id)
    if scans_used >= TRIAL_SCAN_LIMIT or _trial_window_expired(first_scan_at):
        raise HTTPException(
            status_code=429,
            detail="Trial scan quota exhausted or trial window expired",
        )

    txn_id = f"txn_trial_{uuid.uuid4().hex[:12]}"
    try:
        result = scrub_payload(transaction_id=txn_id, text=_canary_payload())
        receipt = _issue_scrub_attestation(transaction_id=txn_id, result=result, workspace=workspace)
    except Exception as exc:
        # Never increment quota on error / failed scan
        raise HTTPException(status_code=500, detail="Trial scan failed") from exc

    _ws_increment(workspace.workspace_id)
    background_tasks.add_task(dispatch_webhook, receipt)
    background_tasks.add_task(dispatch_drata_cct, receipt)
    return ScrubResponse(
        clean_text=result.clean_text,
        audit_log=result.audit_log,
        compliance_receipt=ComplianceReceiptOut.model_validate(asdict(receipt)),
    )


# -------------------------------------------------------------------------
# WORKSPACE MANAGEMENT ENDPOINTS
# -------------------------------------------------------------------------

class WorkspaceCreateRequest(BaseModel):
    workspace_id: str = Field(..., min_length=3, max_length=64, pattern=r'^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$')
    name: str = Field(..., min_length=1, max_length=120)
    owner_email: str = Field(..., min_length=3)
    plan: str = Field(default="trial")
    parent_workspace_id: Optional[str] = None


class WorkspaceOut(BaseModel):
    workspace_id: str
    name: str
    owner_email: str
    created_at: str
    plan: str
    parent_workspace_id: Optional[str]


class WorkspaceCreateResponse(BaseModel):
    workspace: WorkspaceOut
    api_key: str   # shown ONCE — never retrievable again


@app.post("/v1/workspaces", response_model=WorkspaceCreateResponse, tags=["Workspaces"])
def create_workspace_endpoint(request: WorkspaceCreateRequest):
    """Create a new tenant workspace and return its one-time API key."""
    from hermes.workspaces import create_workspace
    try:
        workspace, raw_key = create_workspace(
            workspace_id=request.workspace_id,
            name=request.name,
            owner_email=request.owner_email,
            plan=request.plan,
            parent_workspace_id=request.parent_workspace_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return WorkspaceCreateResponse(
        workspace=WorkspaceOut(
            workspace_id=workspace.workspace_id,
            name=workspace.name,
            owner_email=workspace.owner_email,
            created_at=workspace.created_at,
            plan=workspace.plan,
            parent_workspace_id=workspace.parent_workspace_id,
        ),
        api_key=raw_key,
    )


@app.get("/v1/workspaces", response_model=List[WorkspaceOut], tags=["Workspaces"])
def list_workspaces_endpoint(workspace=Depends(verify_api_key)):
    """List all workspaces. MSPs see their own client workspaces."""
    from hermes.workspaces import list_workspaces
    workspaces = list_workspaces(parent_workspace_id=workspace.workspace_id)
    return [
        WorkspaceOut(
            workspace_id=w.workspace_id,
            name=w.name,
            owner_email=w.owner_email,
            created_at=w.created_at,
            plan=w.plan,
            parent_workspace_id=w.parent_workspace_id,
        )
        for w in workspaces
    ]


@app.post("/v1/workspaces/{workspace_id}/rotate-key", tags=["Workspaces"])
def rotate_key_endpoint(workspace_id: str, workspace=Depends(verify_api_key)):
    """Rotate the API key for a workspace. Returns new key once."""
    if workspace.workspace_id != workspace_id and workspace.parent_workspace_id != workspace_id:
        raise HTTPException(status_code=403, detail="Cannot rotate a key you do not own.")
    from hermes.workspaces import rotate_api_key
    new_key = rotate_api_key(workspace_id)
    return {"workspace_id": workspace_id, "api_key": new_key}


# Serve React dashboard — API routes take priority, static files fall through
_dashboard_dist = Path(__file__).parent.parent / "dashboard" / "dist"
if _dashboard_dist.exists():
    from starlette.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_dashboard_dist), html=True), name="dashboard")
