"""
gateway/evidence_export/outbox.py — persistent local outbox for Drata evidence.

Drata export is never on the enforcement critical path. ``enqueue_event`` runs
only after the enforcement decision is made and the signed receipt is
persisted; it is a local SQLite insert with no network I/O. ``flush_outbox``
performs the Drata call and is scheduled by the gateway as a FastAPI
background task, which Starlette runs after the response has been sent.

States used:
  PENDING      queued, or waiting for a transient-failure retry (next_attempt_at)
  PROCESSING   claimed by a flush; next_attempt_at is the lease expiry, after
               which a crashed flush's row is reclaimed
  EXPORTED     Drata returned 2xx
  DEAD_LETTER  permanent failure or MAX_OUTBOX_ATTEMPTS reached; never retried,
               row retained for operator review
FAILED is not used: a transient failure returns the row to PENDING with a
later next_attempt_at, so a separate state would carry no extra meaning.

Whether Drata honors X-Idempotency-Key is UNKNOWN. Every attempt for a row
sends the same event_id as the key, but duplicate records in Drata after a
retry cannot be ruled out.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from gateway.evidence_export.drata_connector import (
    INSECURE_URL_ERROR,
    NOT_CONFIGURED_ERROR,
    PHI_SAFETY_ERROR,
    DrataConnector,
)
from gateway.evidence_export.event import _PHI_FORBIDDEN_PATTERNS, EvidenceEvent
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    ExportResult,
)

logger = logging.getLogger("hermes.gateway.evidence_export")

OUTBOX_DB_FILENAME = "evidence_outbox.db"
MAX_OUTBOX_ATTEMPTS = 8
RETRY_BASE_DELAY_SECONDS = 30
RETRY_MAX_DELAY_SECONDS = 3600
PROCESSING_LEASE_SECONDS = 300
FLUSH_BATCH_LIMIT = 50
MAX_ERROR_LENGTH = 200
MALFORMED_PAYLOAD_ERROR = "malformed_outbox_payload"

_PERMANENT_CONNECTOR_ERRORS = frozenset(
    {PHI_SAFETY_ERROR, INSECURE_URL_ERROR, NOT_CONFIGURED_ERROR, MALFORMED_PAYLOAD_ERROR}
)

_OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_outbox (
    event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    evidence_payload TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    status TEXT NOT NULL,
    last_error TEXT,
    exported_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_evidence_outbox_due
    ON evidence_outbox (status, next_attempt_at);
"""


class OutboxStatus(str, Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    EXPORTED = "EXPORTED"
    DEAD_LETTER = "DEAD_LETTER"


class DuplicateEventError(Exception):
    """An outbox row with this event_id already exists."""


_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+\S+")
_KEY_VALUE_RE = re.compile(
    r"(?i)\b(authorization|api[_\-]?key|x-api-key|token|secret|password|passwd)"
    r"(\s*[:=]\s*)\S+"
)
_HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9\-]+\.)+[a-z]{2,}(?::\d+)?\b")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def outbox_db_path() -> Path:
    # Deferred: resolved per call so HERMES_DATA_DIR overrides apply.
    from hermes.workspaces import _data_dir

    return _data_dir() / OUTBOX_DB_FILENAME


def _connect() -> sqlite3.Connection:
    path = outbox_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    conn.executescript(_OUTBOX_SCHEMA)
    _migrate_exported_at(conn)
    return conn


def _migrate_exported_at(conn: sqlite3.Connection) -> None:
    # Rows exported before this column existed keep exported_at NULL: their
    # export time was never recorded and is not reconstructed.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence_outbox)")}
    if "exported_at" in columns:
        return
    try:
        conn.execute("ALTER TABLE evidence_outbox ADD COLUMN exported_at TEXT")
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise


def sanitize_error(message: Optional[str]) -> str:
    """Strip URLs, hosts, credentials, and PHI-shaped values before storage."""
    if not message:
        return ""
    text = str(message)
    for env_name in (DRATA_API_KEY_ENV, DRATA_CCT_URL_ENV):
        secret = os.environ.get(env_name)
        if secret:
            text = text.replace(secret, "[redacted]")
    text = _URL_RE.sub("[url]", text)
    text = _BEARER_RE.sub(r"\1 [redacted]", text)
    text = _KEY_VALUE_RE.sub(r"\1\2[redacted]", text)
    text = _HOST_RE.sub("[host]", text)
    text = _LONG_TOKEN_RE.sub("[redacted]", text)
    for pattern in _PHI_FORBIDDEN_PATTERNS:
        text = pattern.sub("[redacted]", text)
    text = " ".join(text.split())
    return text[:MAX_ERROR_LENGTH]


def is_permanent_failure(error: Optional[str]) -> bool:
    """4xx except 429 and connector refusals are permanent; all else is transient."""
    if error in _PERMANENT_CONNECTOR_ERRORS:
        return True
    match = re.fullmatch(r"HTTP (\d{3})", error or "")
    if match is None:
        return False
    status = int(match.group(1))
    return 400 <= status < 500 and status != 429


def retry_delay_seconds(attempt_count: int) -> int:
    exponent = max(attempt_count - 1, 0)
    return min(RETRY_BASE_DELAY_SECONDS * (2**exponent), RETRY_MAX_DELAY_SECONDS)


def enqueue_event(event: EvidenceEvent, *, now: Optional[datetime] = None) -> None:
    """
    Persist a metadata-only EvidenceEvent as PENDING. No network I/O.

    Raises DuplicateEventError if event_id is already queued, ValueError if the
    event fails assert_phi_safe().
    """
    event.assert_phi_safe()
    current = now or _utc_now()
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO evidence_outbox (
                event_id, workspace_id, created_at, evidence_payload,
                attempt_count, next_attempt_at, status, last_error
            ) VALUES (?, ?, ?, ?, 0, ?, ?, NULL)
            """,
            (
                event.event_id,
                event.workspace_id,
                _iso(current),
                event.serialize(),
                _iso(current),
                OutboxStatus.PENDING.value,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateEventError(f"Outbox already contains event_id {event.event_id}") from exc
    finally:
        conn.close()


def _row_to_dict(row: tuple) -> dict[str, Any]:
    return {
        "event_id": row[0],
        "workspace_id": row[1],
        "created_at": row[2],
        "evidence_payload": row[3],
        "attempt_count": row[4],
        "next_attempt_at": row[5],
        "status": row[6],
        "last_error": row[7],
    }


_SELECT_COLUMNS = """
    SELECT event_id, workspace_id, created_at, evidence_payload,
           attempt_count, next_attempt_at, status, last_error
    FROM evidence_outbox
"""


def get_outbox_row(event_id: str) -> Optional[dict[str, Any]]:
    conn = _connect()
    try:
        row = conn.execute(f"{_SELECT_COLUMNS} WHERE event_id = ?", (event_id,)).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


def list_outbox_rows(workspace_id: Optional[str] = None) -> list[dict[str, Any]]:
    conn = _connect()
    try:
        if workspace_id is None:
            rows = conn.execute(f"{_SELECT_COLUMNS} ORDER BY created_at ASC").fetchall()
        else:
            rows = conn.execute(
                f"{_SELECT_COLUMNS} WHERE workspace_id = ? ORDER BY created_at ASC",
                (workspace_id,),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]
    finally:
        conn.close()


def outbox_stats(workspace_id: str) -> dict[str, Any]:
    """
    Read-only outbox summary for one workspace. No network I/O.

    pending counts PENDING and PROCESSING rows (not yet exported, not dead).
    last_error is the stored, already-sanitized error of the most recently
    enqueued row that currently has one, sanitized again before returning.
    Raises on database errors; callers decide how to degrade.
    """
    conn = _connect()
    try:
        counts = dict(
            conn.execute(
                "SELECT status, COUNT(*) FROM evidence_outbox WHERE workspace_id = ? GROUP BY status",
                (workspace_id,),
            ).fetchall()
        )
        (last_exported_at,) = conn.execute(
            "SELECT MAX(exported_at) FROM evidence_outbox WHERE workspace_id = ? AND status = ?",
            (workspace_id, OutboxStatus.EXPORTED.value),
        ).fetchone()
        error_row = conn.execute(
            """
            SELECT last_error FROM evidence_outbox
            WHERE workspace_id = ? AND last_error IS NOT NULL AND last_error != ''
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (workspace_id,),
        ).fetchone()
    finally:
        conn.close()
    return {
        "pending": counts.get(OutboxStatus.PENDING.value, 0)
        + counts.get(OutboxStatus.PROCESSING.value, 0),
        "exported": counts.get(OutboxStatus.EXPORTED.value, 0),
        "dead_letter": counts.get(OutboxStatus.DEAD_LETTER.value, 0),
        "last_exported_at": last_exported_at,
        "last_error": (sanitize_error(error_row[0]) or None) if error_row else None,
    }


def _claim_due_rows(
    conn: sqlite3.Connection,
    workspace_id: Optional[str],
    current: datetime,
    limit: int,
) -> list[tuple[str, str, int]]:
    """Atomically move due rows to PROCESSING and count the attempt."""
    now_iso = _iso(current)
    lease_iso = _iso(current + timedelta(seconds=PROCESSING_LEASE_SECONDS))
    workspace_clause = "AND workspace_id = ?" if workspace_id is not None else ""
    workspace_args: tuple = (workspace_id,) if workspace_id is not None else ()

    conn.execute("BEGIN IMMEDIATE")
    try:
        # A PROCESSING row whose lease expired belongs to a flush that crashed
        # mid-send; its attempt was already counted at claim time.
        conn.execute(
            f"""
            UPDATE evidence_outbox
            SET status = ?, last_error = ?
            WHERE status = ? AND next_attempt_at <= ? AND attempt_count >= ?
            {workspace_clause}
            """,
            (
                OutboxStatus.DEAD_LETTER.value,
                "max_attempts_exceeded",
                OutboxStatus.PROCESSING.value,
                now_iso,
                MAX_OUTBOX_ATTEMPTS,
                *workspace_args,
            ),
        )
        rows = conn.execute(
            f"""
            SELECT event_id, evidence_payload, attempt_count
            FROM evidence_outbox
            WHERE status IN (?, ?) AND next_attempt_at <= ? AND attempt_count < ?
            {workspace_clause}
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (
                OutboxStatus.PENDING.value,
                OutboxStatus.PROCESSING.value,
                now_iso,
                MAX_OUTBOX_ATTEMPTS,
                *workspace_args,
                limit,
            ),
        ).fetchall()
        for event_id, _, _ in rows:
            conn.execute(
                """
                UPDATE evidence_outbox
                SET status = ?, attempt_count = attempt_count + 1, next_attempt_at = ?
                WHERE event_id = ?
                """,
                (OutboxStatus.PROCESSING.value, lease_iso, event_id),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return [(event_id, payload, attempts + 1) for event_id, payload, attempts in rows]


def _record_outcome(
    conn: sqlite3.Connection,
    event_id: str,
    status: OutboxStatus,
    *,
    next_attempt_at: Optional[datetime] = None,
    last_error: Optional[str] = None,
    exported_at: Optional[datetime] = None,
) -> None:
    if exported_at is not None:
        conn.execute(
            "UPDATE evidence_outbox SET status = ?, last_error = ?, exported_at = ? WHERE event_id = ?",
            (status.value, last_error, _iso(exported_at), event_id),
        )
    elif next_attempt_at is None:
        conn.execute(
            "UPDATE evidence_outbox SET status = ?, last_error = ? WHERE event_id = ?",
            (status.value, last_error, event_id),
        )
    else:
        conn.execute(
            """
            UPDATE evidence_outbox
            SET status = ?, last_error = ?, next_attempt_at = ?
            WHERE event_id = ?
            """,
            (status.value, last_error, _iso(next_attempt_at), event_id),
        )


def _send(connector: DrataConnector, payload: str) -> tuple[bool, Optional[str]]:
    """Return (success, raw_error). Never raises."""
    try:
        event = EvidenceEvent.model_validate_json(payload)
    except Exception:
        return False, MALFORMED_PAYLOAD_ERROR
    try:
        result = connector.send_evidence(event)
    except Exception as exc:
        return False, f"exporter_exception: {type(exc).__name__}: {exc}"
    if not isinstance(result, ExportResult) or not isinstance(result.success, bool):
        return False, "malformed_exporter_result"
    if result.success:
        return True, None
    return False, result.error if isinstance(result.error, str) else "malformed_exporter_result"


def flush_outbox(
    workspace_id: Optional[str] = None,
    *,
    connector: Optional[DrataConnector] = None,
    now: Optional[datetime] = None,
    limit: int = FLUSH_BATCH_LIMIT,
) -> dict[str, int]:
    """
    Attempt one Drata export for each due row. Never raises.

    Returns counts of outcomes: exported, retry_scheduled, dead_lettered.
    """
    counts = {"exported": 0, "retry_scheduled": 0, "dead_lettered": 0}
    current = now or _utc_now()
    try:
        connector = connector or DrataConnector()
        if not connector.is_configured():
            return counts
        conn = _connect()
    except Exception as exc:
        logger.warning("Gateway evidence outbox unavailable: %s", sanitize_error(str(exc)))
        return counts

    try:
        claimed = _claim_due_rows(conn, workspace_id, current, limit)
        for event_id, payload, attempt_count in claimed:
            success, raw_error = _send(connector, payload)
            if success:
                _record_outcome(conn, event_id, OutboxStatus.EXPORTED, exported_at=current)
                counts["exported"] += 1
                continue

            safe_error = sanitize_error(raw_error) or "unknown_error"
            if is_permanent_failure(raw_error) or attempt_count >= MAX_OUTBOX_ATTEMPTS:
                _record_outcome(conn, event_id, OutboxStatus.DEAD_LETTER, last_error=safe_error)
                counts["dead_lettered"] += 1
                logger.warning(
                    "Gateway evidence event %s moved to DEAD_LETTER after %s attempt(s): %s",
                    event_id,
                    attempt_count,
                    safe_error,
                )
            else:
                _record_outcome(
                    conn,
                    event_id,
                    OutboxStatus.PENDING,
                    next_attempt_at=current + timedelta(seconds=retry_delay_seconds(attempt_count)),
                    last_error=safe_error,
                )
                counts["retry_scheduled"] += 1
    except Exception as exc:
        logger.warning("Gateway evidence outbox flush failed: %s", sanitize_error(str(exc)))
    finally:
        conn.close()
    return counts
