import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from hermes.attestation import (
    ATTESTATION_CHAIN,
    ComplianceReceipt,
    REVIEW_DECISIONS,
    DEFAULT_DB_PATH,
)
from hermes.webhooks import dispatch_webhook, dispatch_drata_cct
from hermes.drata_state import (
    DRATA_API_KEY_ENV_VAR,
    DRATA_CCT_URL_ENV_VAR,
    DrataConfigState,
    get_drata_config_state,
)
from hermes.classifier import (
    FlagEntry,
    RedactionAuditLog,
    ScrubberResult,
    scrub_payload,
)
from hermes.auditor import CANARY_CORPUS
from hermes.demo_receipts import (
    EPHEMERAL_KEY_WARNING,
    demo_receipt_db_path,
    get_demo_receipt,
    get_signer,
    issue_demo_receipt,
    splice_payload,
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


class ScanHistoryEntry(BaseModel):
    date: str
    scan_count: int


class ScanHistoryResponse(BaseModel):
    workspace_id: str
    days: int
    history: List[ScanHistoryEntry]


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


def require_role(allowed_roles: list[str]):
    """
    Dependency factory: authenticate via API key and enforce workspace.role.

    Uses the same X-API-Key header as verify_api_key. Raises 403 when the
    workspace role is not in allowed_roles.
    """
    def _dependency(x_api_key: str = Header(..., alias="X-API-Key")):
        from hermes.workspaces import get_workspace_by_api_key

        workspace = get_workspace_by_api_key(x_api_key)
        if workspace is None:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized: Invalid or missing API Key",
            )
        if workspace.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )
        return workspace

    return _dependency


class _LegacyWorkspace:
    """Synthetic workspace wrapping the legacy global chain/vault."""
    workspace_id = "default"
    name = "Default"
    owner_email = ""
    plan = "production"
    parent_workspace_id = None
    role = "msp_admin"
    created_at = ""

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


def _has_trial_quota_row(workspace_id: str) -> bool:
    """Return True if workspace has a trial_quota row (trial tenant, not production)."""
    import hermes.workspaces as ws_mod

    with ws_mod._registry_lock:
        conn = ws_mod._get_registry_conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM trial_quota WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            return row is not None
        finally:
            conn.close()


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
    from hermes.workspaces import get_trial_quota, increment_trial_quota

    scans_used, first_scan_at, _ = get_trial_quota(workspace.workspace_id)
    has_trial_row = _has_trial_quota_row(workspace.workspace_id)
    in_trial = (
        has_trial_row
        and scans_used is not None
        and scans_used < TRIAL_SCAN_LIMIT
        and not _trial_window_expired(first_scan_at)
    )

    if in_trial:
        if scans_used >= TRIAL_SCAN_LIMIT or _trial_window_expired(first_scan_at):
            raise HTTPException(
                status_code=429,
                detail="Trial scan quota exhausted — use /v1/trial-scan or upgrade",
            )
    elif has_trial_row:
        raise HTTPException(
            status_code=429,
            detail="Trial scan quota exhausted — use /v1/trial-scan or upgrade",
        )

    txn_id = f"txn_api_{uuid.uuid4().hex[:12]}"
    result = scrub_payload(transaction_id=txn_id, text=request.payload)
    receipt = _issue_scrub_attestation(transaction_id=txn_id, result=result, workspace=workspace)
    if in_trial:
        increment_trial_quota(workspace.workspace_id)
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


@app.get(
    "/v1/scan-history",
    response_model=ScanHistoryResponse,
    tags=["Status"],
)
def scan_history_endpoint(days: int = 7, workspace=Depends(verify_api_key)):
    """Daily scan counts for the dashboard trend sparkline — zero-seeded by calendar day."""
    if days < 1:
        raise HTTPException(status_code=400, detail="days must be at least 1")

    chain_obj = _get_chain(workspace)
    db_path = chain_obj._db_path

    today = datetime.now(timezone.utc).date()
    date_range = [today - timedelta(days=offset) for offset in range(days - 1, -1, -1)]
    start_cutoff = datetime.combine(date_range[0], datetime.min.time(), tzinfo=timezone.utc)

    counts_by_date: Dict[str, int] = {d.isoformat(): 0 for d in date_range}

    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        rows = conn.execute(
            """
            SELECT json_extract(receipt_json, '$.issued_at') AS issued_at
            FROM receipts
            WHERE json_extract(receipt_json, '$.issued_at') >= ?
            """,
            (start_cutoff.isoformat(),),
        ).fetchall()
    finally:
        conn.close()

    for (issued_at,) in rows:
        if not issued_at:
            continue
        day_key = _parse_iso(issued_at).date().isoformat()
        if day_key in counts_by_date:
            counts_by_date[day_key] += 1

    history = [
        ScanHistoryEntry(date=day_key, scan_count=counts_by_date[day_key])
        for day_key in (d.isoformat() for d in date_range)
    ]

    return ScanHistoryResponse(
        workspace_id=workspace.workspace_id,
        days=days,
        history=history,
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
    role: str = "msp_admin"


class WorkspaceCreateResponse(BaseModel):
    workspace: WorkspaceOut
    api_key: str   # shown ONCE — never retrievable again


def _workspace_out(workspace) -> WorkspaceOut:
    return WorkspaceOut(
        workspace_id=workspace.workspace_id,
        name=workspace.name,
        owner_email=workspace.owner_email,
        created_at=getattr(workspace, "created_at", "") or "",
        plan=workspace.plan,
        parent_workspace_id=workspace.parent_workspace_id,
        role=getattr(workspace, "role", "msp_admin") or "msp_admin",
    )


@app.post("/v1/workspaces", response_model=WorkspaceCreateResponse, tags=["Workspaces"])
def create_workspace_endpoint(
    request: WorkspaceCreateRequest,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Create a new tenant workspace and return its one-time API key."""
    expected = os.environ.get("HERMES_ADMIN_TOKEN")
    if not expected or not hmac.compare_digest(x_admin_token or "", expected):
        raise HTTPException(status_code=401, detail="Admin token required to create workspaces")

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
        workspace=_workspace_out(workspace),
        api_key=raw_key,
    )


@app.get("/v1/workspaces", response_model=List[WorkspaceOut], tags=["Workspaces"])
def list_workspaces_endpoint(workspace=Depends(verify_api_key)):
    """List all workspaces. MSPs see their own client workspaces."""
    from hermes.workspaces import list_workspaces
    workspaces = list_workspaces(parent_workspace_id=workspace.workspace_id)
    return [_workspace_out(w) for w in workspaces]


@app.get("/v1/workspace", response_model=WorkspaceOut, tags=["Workspaces"])
def current_workspace_endpoint(workspace=Depends(verify_api_key)):
    """Return the authenticated caller's workspace (includes role for RBAC UI)."""
    return _workspace_out(workspace)


@app.post("/api/v1/sentry/config", tags=["Integrations"])
def sentry_config_endpoint(workspace=Depends(require_role(["msp_admin", "msp_tech"]))):
    """Update Sentry DSN configuration for this workspace (RBAC-gated stub)."""
    return {"status": "updated"}


@app.post("/api/v1/drata/config", tags=["Integrations"])
def drata_config_endpoint(workspace=Depends(require_role(["msp_admin", "msp_tech"]))):
    """
    Report Drata configuration state. Configuring or syncing Drata from the
    dashboard is not implemented: this endpoint stores nothing and does not
    contact Drata. Credential values are never included in the response.

    state comes from DrataConnector.test_connection(), an offline structural
    check (URL set, https, API key present). It is never a live validation.
    """
    from gateway.evidence_export.drata_connector import DrataConnector

    result = DrataConnector().test_connection()
    return JSONResponse(
        status_code=501,
        content={
            "status": "not_implemented",
            "state": result.state,
            "reason": result.reason,
            "live_validated": result.live_validated,
            "cct_url_configured": bool(os.environ.get(DRATA_CCT_URL_ENV_VAR)),
            "api_key_configured": bool(os.environ.get(DRATA_API_KEY_ENV_VAR)),
            "connection_tested": False,
            "detail": (
                "Drata configuration and sync from the dashboard are not implemented. "
                f"Drata CCT export is configured only via the {DRATA_CCT_URL_ENV_VAR} and "
                f"{DRATA_API_KEY_ENV_VAR} environment variables, and no connection test "
                "has been run."
            ),
        },
    )


class DrataIntegrationStatus(BaseModel):
    configured: bool
    connection_state: Literal["NOT_CONFIGURED", "CONFIG_INVALID", "CONFIGURED"]
    live_validated: Literal[False] = False
    transport: Literal["CCT"] = "CCT"
    events_pending: Optional[int]
    events_exported: Optional[int]
    events_dead_letter: Optional[int]
    last_exported_at: Optional[str]
    last_error: Optional[str]
    partner_connection: Literal[False] = False


@app.get(
    "/v1/integrations/drata/status",
    response_model=DrataIntegrationStatus,
    tags=["Integrations"],
)
def drata_integration_status_endpoint(
    workspace=Depends(require_role(["msp_admin", "msp_tech"])),
):
    """
    Report Drata integration state computed only from local Hermes state.

    connection_state is the offline structural check from
    DrataConnector.test_connection(); no network call is made and no live
    validation exists, so live_validated is always false. Drata config is
    global (env vars); outbox counts are scoped to the caller's workspace_id.
    If the outbox cannot be read, outbox fields are null instead of failing.
    """
    from gateway.evidence_export.drata_connector import DrataConnector
    from gateway.evidence_export.outbox import outbox_stats, sanitize_error

    result = DrataConnector().test_connection()
    status = DrataIntegrationStatus(
        configured=result.state != DrataConfigState.NOT_CONFIGURED.value,
        connection_state=result.state,
        events_pending=None,
        events_exported=None,
        events_dead_letter=None,
        last_exported_at=None,
        last_error=None,
    )
    try:
        stats = outbox_stats(workspace.workspace_id)
    except Exception as exc:
        logging.getLogger("hermes.api").warning(
            "Drata status: evidence outbox unavailable: %s", sanitize_error(str(exc))
        )
        return status
    return status.model_copy(
        update={
            "events_pending": stats["pending"],
            "events_exported": stats["exported"],
            "events_dead_letter": stats["dead_letter"],
            "last_exported_at": stats["last_exported_at"],
            "last_error": stats["last_error"],
        }
    )


@app.post("/api/v1/evaluate", tags=["Canary"])
async def evaluate_phi_canary(
    payload: dict,
    background_tasks: BackgroundTasks,
    workspace=Depends(verify_api_key),
):
    """Run PHI canary evaluation; open a PSA ticket on drift via BackgroundTasks."""
    from gateway.evidence_export.dispatch import dispatch_psa_ticket
    from hermes.auditor import load_prior_result, run_canary, save_result

    canary_db = None
    if not isinstance(workspace, _LegacyWorkspace):
        canary_db = workspace.canary_db_path
        Path(canary_db).parent.mkdir(parents=True, exist_ok=True)

    prior = load_prior_result(db_path=canary_db) if canary_db else load_prior_result()
    result = run_canary(prior_result=prior)
    if canary_db:
        save_result(result, db_path=canary_db)
    else:
        save_result(result)

    # Treat missed covered flags as drift even on the first baseline run.
    drift_detected = bool(result.drift_detected) or bool(result.flags_missed)

    if drift_detected:
        failed_category = (
            result.flags_missed[0]
            if result.flags_missed
            else (
                result.flags_unexpected[0]
                if result.flags_unexpected
                else str(payload.get("failed_category") or "unknown")
            )
        )
        evidence_url = str(
            payload.get("evidence_url")
            or f"/v1/receipts/{result.receipt.receipt_id}"
        )
        background_tasks.add_task(
            dispatch_psa_ticket,
            workspace.workspace_id,
            failed_category,
            evidence_url,
        )

    return {"status": "evaluated", "drift_detected": drift_detected}


class TelemetryReceiptIngestResponse(BaseModel):
    status: Literal["ingested"] = "ingested"
    receipt_id: str
    repository: str
    commit_sha: str
    state_drift_detected: bool
    prior_receipt_id: Optional[str] = None
    ingested_at: str
    drata_cct: dict


@app.post(
    "/v1/telemetry/receipt",
    response_model=TelemetryReceiptIngestResponse,
    tags=["Telemetry"],
)
async def ingest_telemetry_receipt(
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_hermes_signature_256: Optional[str] = Header(
        None, alias="X-Hermes-Signature-256"
    ),
):
    """
    Ingest a signed CI telemetry compliance receipt (metadata only).

    The raw request body must be signed with HMAC-SHA256 using the workspace API
    secret; the digest is sent in X-Hermes-Signature-256.
    """
    from hermes.telemetry_receipts import (
        TelemetryReceiptPayload,
        store_telemetry_receipt,
        sync_telemetry_receipt_to_drata_cct,
        telemetry_db_path,
        verify_request_signature,
    )

    body = await request.body()
    if not verify_request_signature(x_api_key, body, x_hermes_signature_256):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing X-Hermes-Signature-256",
        )

    try:
        workspace = verify_api_key(x_api_key)
    except HTTPException:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid or missing X-Hermes-Signature-256",
        ) from None

    try:
        payload_dict = json.loads(body.decode("utf-8"))
        receipt_payload = TelemetryReceiptPayload.model_validate(payload_dict)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid JSON body") from exc
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    chain_db_path = (
        workspace.chain_db_path
        if not isinstance(workspace, _LegacyWorkspace)
        else None
    )
    db_path = telemetry_db_path(workspace.workspace_id, chain_db_path)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    stored = store_telemetry_receipt(
        workspace_id=workspace.workspace_id,
        payload=receipt_payload,
        db_path=db_path,
    )
    drata_result = sync_telemetry_receipt_to_drata_cct(stored)

    return TelemetryReceiptIngestResponse(
        receipt_id=stored.receipt_id,
        repository=stored.repository,
        commit_sha=stored.commit_sha,
        state_drift_detected=stored.state_drift_detected,
        prior_receipt_id=stored.prior_receipt_id,
        ingested_at=stored.ingested_at,
        drata_cct={
            "attempted": drata_result.attempted,
            "synchronized": drata_result.synchronized,
            "reason": drata_result.reason,
        },
    )


@app.post("/v1/workspaces/{workspace_id}/rotate-key", tags=["Workspaces"])
def rotate_key_endpoint(workspace_id: str, workspace=Depends(verify_api_key)):
    """Rotate the API key for a workspace. Returns new key once."""
    from hermes.workspaces import can_access_workspace, get_workspace, rotate_api_key

    target = get_workspace(workspace_id)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Workspace '{workspace_id}' not found.",
        )
    if not can_access_workspace(workspace, target):
        raise HTTPException(status_code=403, detail="Cannot rotate a key you do not own.")
    new_key = rotate_api_key(workspace_id)
    return {"workspace_id": workspace_id, "api_key": new_key}


# -------------------------------------------------------------------------
# V2 RECEIPTS — DEMO SIGNING ORACLE
# -------------------------------------------------------------------------
# These two endpoints exist for the procurement demo. /v2/receipts signs a
# client-supplied payload, which makes it a signing oracle: it will attest to
# anything posted to it. In production, V2 receipts are issued by the gateway
# enforcement path (issue_gateway_receipt in gateway/evidence.py) from a
# decision the gateway observed itself. Do not route production evidence here.
class ReceiptIssueRequest(BaseModel):
    payload: Dict[str, Any] = Field(..., description="Action payload to sign.")


class ReceiptIssueResponse(BaseModel):
    receipt_id: str
    action_digest: str          # first 16 hex chars, for display
    action_digest_full: str
    issued_at: str
    key_id: str
    algorithm: str
    ephemeral_key: bool
    warning: Optional[str] = None


class ReceiptVerifyRequest(BaseModel):
    receipt_id: str = Field(..., min_length=1)
    tampered_payload: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Replacement payload spliced into the stored COSE_Sign1 envelope "
            "in place of the signed one, keeping the original signature. "
            "Omit to verify the receipt as stored."
        ),
    )


class ReceiptVerifyResponse(BaseModel):
    receipt_id: str
    verified_payload: Literal["stored", "tampered"]
    fully_valid: bool
    signature_valid: bool
    receipt_digest_valid: bool
    chain_link_valid: Optional[bool] = None
    signer_key_id: str
    algorithm: str
    issued_at: str
    claims: Dict[str, Any]
    errors: List[str]
    warnings: List[str]


def _demo_receipt_db(workspace) -> str:
    chain_db_path = (
        workspace.chain_db_path
        if not isinstance(workspace, _LegacyWorkspace)
        else None
    )
    return demo_receipt_db_path(workspace.workspace_id, chain_db_path)


@app.post("/v2/receipts", response_model=ReceiptIssueResponse, tags=["Receipts V2"])
def issue_v2_receipt_endpoint(
    request: ReceiptIssueRequest,
    workspace=Depends(verify_api_key),
):
    """Sign a caller-supplied payload as a V2 COSE_Sign1 receipt. Demo only."""
    try:
        issued = issue_demo_receipt(
            payload=request.payload,
            workspace_id=workspace.workspace_id,
            db_path=_demo_receipt_db(workspace),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ReceiptIssueResponse(
        receipt_id=issued.receipt_id,
        action_digest=issued.action_digest[:16],
        action_digest_full=issued.action_digest,
        issued_at=issued.issued_at,
        key_id=issued.key_id,
        algorithm=issued.algorithm,
        ephemeral_key=issued.ephemeral_key,
        warning=issued.warning,
    )


@app.post("/v2/verify", response_model=ReceiptVerifyResponse, tags=["Receipts V2"])
def verify_v2_receipt_endpoint(
    request: ReceiptVerifyRequest,
    workspace=Depends(verify_api_key),
):
    """Verify a stored V2 receipt claim by claim, optionally after tampering."""
    from hermes.receipts.v2.verifier import verify_receipt

    stored = get_demo_receipt(request.receipt_id, _demo_receipt_db(workspace))
    if stored is None:
        raise HTTPException(
            status_code=404,
            detail=f"Receipt '{request.receipt_id}' not found.",
        )

    warnings: List[str] = []
    signer, _ = get_signer()
    active = signer.public_key_manifest()
    if active["key_id"] == stored.key_id:
        public_key_pem = active["public_key_pem"]
    else:
        public_key_pem = stored.public_key_pem
        warnings.append(
            f"Receipt was signed by key {stored.key_id}, not the key currently "
            f"loaded ({active['key_id']}). Verified against the public key recorded "
            "with the receipt, not against a published key manifest."
        )
    if stored.ephemeral_key:
        warnings.append(EPHEMERAL_KEY_WARNING)

    cose_bytes = stored.cose_sign1_bytes
    verified_payload = "stored"
    if request.tampered_payload is not None:
        try:
            cose_bytes = splice_payload(cose_bytes, request.tampered_payload)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        verified_payload = "tampered"

    result = verify_receipt(cose_bytes, public_key_pem)
    return ReceiptVerifyResponse(
        receipt_id=stored.receipt_id,
        verified_payload=verified_payload,
        fully_valid=result.fully_valid,
        signature_valid=result.signature_valid,
        receipt_digest_valid=result.receipt_digest_valid,
        chain_link_valid=result.chain_link_valid,
        signer_key_id=result.signer_key_id,
        algorithm=result.algorithm,
        issued_at=result.issued_at or stored.issued_at,
        claims=result.claims,
        errors=result.errors,
        warnings=warnings + result.warnings,
    )


# Serve React dashboard — API routes take priority, static files fall through
_dashboard_dist = Path(__file__).parent.parent / "dashboard" / "dist"
if _dashboard_dist.exists():
    from starlette.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_dashboard_dist), html=True), name="dashboard")
