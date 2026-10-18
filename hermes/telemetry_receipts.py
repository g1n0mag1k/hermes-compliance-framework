"""
hermes/telemetry_receipts.py — Signed CI telemetry receipt ingestion and storage.

Clients POST metadata-only compliance receipts (repository scan results) with an
HMAC-SHA256 signature over the raw request body, keyed with their workspace API
secret (X-API-Key). Receipts are persisted locally; state drift is detected
when a repository's status or Safe Harbor summary changes vs. the prior receipt.
Optional best-effort Drata CCT export uses the same env configuration as Path A.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from hermes.attestation import DEFAULT_DB_PATH
from hermes.drata_state import DRATA_API_KEY_ENV_VAR, DRATA_CCT_URL_ENV_VAR

logger = logging.getLogger("hermes.telemetry")

SIGNATURE_HEADER = "X-Hermes-Signature-256"
WEBHOOK_TIMEOUT_SECONDS = 3.0

# 16 covered HIPAA Safe Harbor identifier letters (P and Q are reference-only).
SAFE_HARBOR_SUMMARY_KEYS = frozenset(
    {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "R"}
)


class TelemetryReceiptPayload(BaseModel):
    receipt_id: str = Field(..., min_length=1)
    timestamp: str = Field(..., min_length=1)
    repository: str = Field(..., min_length=1)
    commit_sha: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    controls_verified: List[str] = Field(default_factory=list)
    summary: Dict[str, Any]

    @field_validator("summary")
    @classmethod
    def _validate_summary_keys(cls, summary: Dict[str, Any]) -> Dict[str, Any]:
        keys = frozenset(summary.keys())
        if keys != SAFE_HARBOR_SUMMARY_KEYS:
            missing = SAFE_HARBOR_SUMMARY_KEYS - keys
            extra = keys - SAFE_HARBOR_SUMMARY_KEYS
            detail_parts = []
            if missing:
                detail_parts.append(f"missing keys: {sorted(missing)}")
            if extra:
                detail_parts.append(f"unexpected keys: {sorted(extra)}")
            raise ValueError(
                "summary must include exactly the 16 covered Safe Harbor "
                f"category keys ({sorted(SAFE_HARBOR_SUMMARY_KEYS)}); "
                + "; ".join(detail_parts)
            )
        return summary


@dataclass(frozen=True)
class StoredTelemetryReceipt:
    receipt_id: str
    workspace_id: str
    ingested_at: str
    timestamp: str
    repository: str
    commit_sha: str
    status: str
    controls_verified: List[str]
    summary: Dict[str, Any]
    state_drift_detected: bool
    prior_receipt_id: Optional[str]


@dataclass(frozen=True)
class DrataCctSyncResult:
    attempted: bool
    synchronized: bool
    reason: Optional[str] = None


def _normalize_signature_header(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256="):
        return value.split("=", 1)[1].strip()
    return value


def compute_body_signature(api_secret: str, body: bytes) -> str:
    """HMAC-SHA256 hex digest of the raw request body keyed with the API secret."""
    return hmac.new(
        api_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()


def verify_request_signature(
    api_secret: str,
    body: bytes,
    signature_header: Optional[str],
) -> bool:
    if not signature_header:
        return False
    provided = _normalize_signature_header(signature_header)
    if not provided:
        return False
    expected = compute_body_signature(api_secret, body)
    try:
        return hmac.compare_digest(provided.lower(), expected.lower())
    except TypeError:
        return False


def telemetry_db_path(workspace_id: str, chain_db_path: Optional[str] = None) -> str:
    if chain_db_path:
        return str(Path(chain_db_path).parent / "telemetry_receipts.db")
    base = os.environ.get("HERMES_DB_PATH", DEFAULT_DB_PATH)
    if workspace_id != "default":
        from hermes.workspaces import _data_dir

        return str(_data_dir() / workspace_id / "telemetry_receipts.db")
    return str(Path(base).parent / "telemetry_receipts.db")


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS telemetry_receipts (
            receipt_id          TEXT PRIMARY KEY,
            workspace_id        TEXT NOT NULL,
            ingested_at         TEXT NOT NULL,
            timestamp           TEXT NOT NULL,
            repository          TEXT NOT NULL,
            commit_sha          TEXT NOT NULL,
            status              TEXT NOT NULL,
            controls_verified   TEXT NOT NULL,
            summary_json        TEXT NOT NULL,
            state_drift_detected INTEGER NOT NULL,
            prior_receipt_id    TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_telemetry_repo_workspace
        ON telemetry_receipts (workspace_id, repository, ingested_at DESC)
        """
    )


def _load_latest_for_repository(
    conn: sqlite3.Connection,
    workspace_id: str,
    repository: str,
) -> Optional[dict]:
    row = conn.execute(
        """
        SELECT receipt_id, status, controls_verified, summary_json
        FROM telemetry_receipts
        WHERE workspace_id = ? AND repository = ?
        ORDER BY ingested_at DESC
        LIMIT 1
        """,
        (workspace_id, repository),
    ).fetchone()
    if row is None:
        return None
    return {
        "receipt_id": row[0],
        "status": row[1],
        "controls_verified": json.loads(row[2]),
        "summary": json.loads(row[3]),
    }


def _detect_state_drift(prior: Optional[dict], payload: TelemetryReceiptPayload) -> bool:
    if prior is None:
        return False
    if prior["status"] != payload.status:
        return True
    if sorted(prior["controls_verified"]) != sorted(payload.controls_verified):
        return True
    if prior["summary"] != payload.summary:
        return True
    return False


def store_telemetry_receipt(
    workspace_id: str,
    payload: TelemetryReceiptPayload,
    db_path: str,
) -> StoredTelemetryReceipt:
    ingested_at = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        with conn:
            _init_db(conn)
            prior = _load_latest_for_repository(conn, workspace_id, payload.repository)
            drift = _detect_state_drift(prior, payload)
            prior_receipt_id = prior["receipt_id"] if prior else None
            conn.execute(
                """
                INSERT OR REPLACE INTO telemetry_receipts (
                    receipt_id, workspace_id, ingested_at, timestamp,
                    repository, commit_sha, status, controls_verified,
                    summary_json, state_drift_detected, prior_receipt_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.receipt_id,
                    workspace_id,
                    ingested_at,
                    payload.timestamp,
                    payload.repository,
                    payload.commit_sha,
                    payload.status,
                    json.dumps(payload.controls_verified, sort_keys=True),
                    json.dumps(payload.summary, sort_keys=True),
                    int(drift),
                    prior_receipt_id,
                ),
            )
    finally:
        conn.close()

    if drift:
        logger.warning(
            "Telemetry state drift for repository=%s workspace=%s prior=%s new=%s",
            payload.repository,
            workspace_id,
            prior_receipt_id,
            payload.receipt_id,
        )
    else:
        logger.info(
            "Telemetry receipt ingested receipt_id=%s repository=%s workspace=%s",
            payload.receipt_id,
            payload.repository,
            workspace_id,
        )

    return StoredTelemetryReceipt(
        receipt_id=payload.receipt_id,
        workspace_id=workspace_id,
        ingested_at=ingested_at,
        timestamp=payload.timestamp,
        repository=payload.repository,
        commit_sha=payload.commit_sha,
        status=payload.status,
        controls_verified=list(payload.controls_verified),
        summary=dict(payload.summary),
        state_drift_detected=drift,
        prior_receipt_id=prior_receipt_id,
    )


def sync_telemetry_receipt_to_drata_cct(
    stored: StoredTelemetryReceipt,
) -> DrataCctSyncResult:
    """
    Best-effort Drata CCT POST for telemetry metadata (flat JSON, Path A style).
    No-op when Drata is not configured; failures do not affect ingestion.

    .. deprecated::
        Use ``gateway.evidence_export.drata_connector.DrataConnector`` (Path B) instead.
        This function (Path A) duplicates Drata dispatch and will be removed in a
        future release once the dual-path architecture is consolidated.
    """
    warnings.warn(
        "sync_telemetry_receipt_to_drata_cct is deprecated and will be removed. "
        "Use gateway.evidence_export.drata_connector.DrataConnector instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    cct_url = os.environ.get(DRATA_CCT_URL_ENV_VAR)
    if not cct_url:
        return DrataCctSyncResult(
            attempted=False,
            synchronized=False,
            reason="not_configured",
        )

    payload = {
        "source": "hermes-relay-telemetry",
        "event_type": "telemetry_receipt",
        "receipt_id": stored.receipt_id,
        "timestamp": stored.timestamp,
        "ingested_at": stored.ingested_at,
        "workspace_id": stored.workspace_id,
        "repository": stored.repository,
        "commit_sha": stored.commit_sha,
        "status": stored.status,
        "controls_verified": stored.controls_verified,
        "summary": stored.summary,
        "state_drift_detected": stored.state_drift_detected,
        "prior_receipt_id": stored.prior_receipt_id,
    }
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "hermes-relay-telemetry-drata/1.0",
    }
    api_key = os.environ.get(DRATA_API_KEY_ENV_VAR)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(cct_url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as resp:
            success = 200 <= resp.status < 300
            if not success:
                logger.warning(
                    "Telemetry Drata CCT dispatch returned non-2xx: %s", resp.status
                )
            return DrataCctSyncResult(
                attempted=True,
                synchronized=success,
                reason=None if success else f"http_{resp.status}",
            )
    except urllib.error.URLError as exc:
        logger.warning("Telemetry Drata CCT dispatch failed: %s", exc)
        return DrataCctSyncResult(
            attempted=True,
            synchronized=False,
            reason="transport_error",
        )
    except Exception as exc:
        logger.warning("Telemetry Drata CCT dispatch unexpected error: %s", exc)
        return DrataCctSyncResult(
            attempted=True,
            synchronized=False,
            reason="unexpected_error",
        )
