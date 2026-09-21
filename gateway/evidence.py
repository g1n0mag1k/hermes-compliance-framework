from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from hermes.receipts.v2.builder import ReceiptV2, ReceiptV2Builder
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519
from hermes.workspaces import Workspace, get_chain_for_workspace

from gateway import __version__
from gateway.evidence_export.dispatch import try_export_evidence
from gateway.exceptions import ReceiptPersistenceError
from gateway.policy import EnforcementDecision, PolicyDecision

_GATEWAY_RECEIPTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id TEXT NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE,
    prev_receipt_digest TEXT,
    gateway_sequence INTEGER NOT NULL,
    transaction_id TEXT NOT NULL,
    cose_sign1_hex TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_v2_chain_heads: dict[str, Optional[str]] = {}
_chain_lock = threading.Lock()


def _is_production_env() -> bool:
    return os.environ.get("HERMES_ENV", "development") == "production"


def validate_gateway_signing_config() -> None:
    """Fail fast in production when no persistent gateway signing key is configured."""
    if not _is_production_env():
        return
    keystore_path = os.environ.get("HERMES_GATEWAY_KEYSTORE_PATH")
    keystore_passphrase = os.environ.get("HERMES_GATEWAY_KEYSTORE_PASSPHRASE")
    if not keystore_path or not keystore_passphrase:
        raise RuntimeError(
            "HERMES_GATEWAY_KEYSTORE_PATH and HERMES_GATEWAY_KEYSTORE_PASSPHRASE "
            "are required when HERMES_ENV=production. Ephemeral gateway signing "
            "keys are not permitted in production."
        )


def _load_signer_from_env() -> SoftwareSignerEd25519:
    validate_gateway_signing_config()
    keystore_path = os.environ.get("HERMES_GATEWAY_KEYSTORE_PATH")
    keystore_passphrase = os.environ.get("HERMES_GATEWAY_KEYSTORE_PASSPHRASE")
    if keystore_path and keystore_passphrase:
        passphrase = (
            keystore_passphrase.encode("utf-8")
            if isinstance(keystore_passphrase, str)
            else keystore_passphrase
        )
        store = KeyStore.open(keystore_path, passphrase)
        return store.load_signer()
    return SoftwareSignerEd25519.generate()


_GATEWAY_SIGNER: SoftwareSignerEd25519 | None = None


def _get_gateway_signer() -> SoftwareSignerEd25519:
    global _GATEWAY_SIGNER
    if _GATEWAY_SIGNER is None:
        _GATEWAY_SIGNER = _load_signer_from_env()
    return _GATEWAY_SIGNER


def _decision_label(decision: PolicyDecision) -> str:
    return {
        "ALLOW": "allowed",
        "REDACT": "redacted",
        "BLOCK": "blocked",
    }[decision]


def _ensure_gateway_receipts_table(conn: sqlite3.Connection) -> None:
    conn.executescript(_GATEWAY_RECEIPTS_SCHEMA)
    conn.commit()


def _get_chain_db_conn(workspace: Workspace) -> sqlite3.Connection:
    Path(workspace.chain_db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(workspace.chain_db_path, check_same_thread=False)
    _ensure_gateway_receipts_table(conn)
    return conn


def _get_last_persisted_digest(workspace: Workspace) -> Optional[str]:
    conn = _get_chain_db_conn(workspace)
    try:
        row = conn.execute(
            """
            SELECT receipt_digest FROM gateway_receipts
            WHERE workspace_id = ?
            ORDER BY gateway_sequence DESC
            LIMIT 1
            """,
            (workspace.workspace_id,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _next_gateway_sequence(workspace: Workspace) -> int:
    conn = _get_chain_db_conn(workspace)
    try:
        row = conn.execute(
            """
            SELECT MAX(gateway_sequence) FROM gateway_receipts
            WHERE workspace_id = ?
            """,
            (workspace.workspace_id,),
        ).fetchone()
        if row is None or row[0] is None:
            return 0
        return int(row[0]) + 1
    finally:
        conn.close()


def _row_to_receipt_dict(row: tuple) -> dict[str, Any]:
    return {
        "receipt_digest": row[0],
        "prev_receipt_digest": row[1],
        "gateway_sequence": row[2],
        "cose_sign1_hex": row[3],
        "payload": json.loads(row[4]),
        "transaction_id": row[5],
        "created_at": row[6],
    }


def _persist_gateway_receipt(
    workspace: Workspace,
    receipt: ReceiptV2,
    gateway_sequence: int,
    transaction_id: str,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    conn = _get_chain_db_conn(workspace)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO gateway_receipts (
                    workspace_id, receipt_digest, prev_receipt_digest,
                    gateway_sequence, transaction_id, cose_sign1_hex,
                    payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace.workspace_id,
                    receipt.receipt_digest,
                    receipt.prev_receipt_digest,
                    gateway_sequence,
                    transaction_id,
                    receipt.cose_sign1_bytes.hex(),
                    json.dumps(receipt.payload, sort_keys=True),
                    created_at,
                ),
            )
    except Exception as exc:
        raise ReceiptPersistenceError(
            receipt,
            f"Gateway receipt persistence failed: {exc}",
        ) from exc
    finally:
        conn.close()


def issue_gateway_receipt(
    workspace: Workspace,
    transaction_id: str,
    decision: EnforcementDecision,
    provider_id: str,
    endpoint_path: str,
    flags_triggered: dict[str, int],
    flags_redacted: dict[str, int],
    detectors_executed: dict[str, str],
    *,
    forwarded: bool = False,
    upstream_status: Optional[int] = None,
    failure_class: Optional[str] = None,
) -> ReceiptV2:
    """Issue a V2 COSE_Sign1 receipt linked to the workspace receipt chain."""
    get_chain_for_workspace(workspace)

    with _chain_lock:
        prev_digest = _v2_chain_heads.get(workspace.workspace_id)
    if prev_digest is None:
        prev_digest = _get_last_persisted_digest(workspace)

    gateway_sequence = _next_gateway_sequence(workspace)

    payload = {
        "transaction_id": transaction_id,
        "gateway_decision": _decision_label(decision.decision),
        "decision": decision.decision,
        "forwarded": forwarded,
        "upstream_provider": provider_id,
        "endpoint_path": endpoint_path,
        "phi_categories_detected": sorted(flags_triggered.keys()),
        "phi_categories_redacted": sorted(flags_redacted.keys()),
        "content_types_inspected": decision.content_types_inspected,
        "content_types_not_inspected": decision.content_types_not_inspected,
        "detector_states": detectors_executed,
        "policy_version": decision.policy_version,
        "policy_digest": decision.policy_digest,
        "policy_id": decision.policy_id,
        "gateway_version": __version__,
        "workspace_id": workspace.workspace_id,
        "all_detectors_clean": decision.all_detectors_clean,
        "gateway_sequence": gateway_sequence,
    }
    if upstream_status is not None:
        payload["upstream_status"] = upstream_status
    if failure_class is not None:
        payload["failure_class"] = failure_class

    builder = ReceiptV2Builder(_GATEWAY_SIGNER)
    receipt = builder.build(payload, prev_receipt_digest=prev_digest)

    try:
        _persist_gateway_receipt(
            workspace,
            receipt,
            gateway_sequence,
            transaction_id,
        )
    except ReceiptPersistenceError:
        raise
    except Exception as exc:
        raise ReceiptPersistenceError(
            receipt,
            f"Gateway receipt persistence failed: {exc}",
        ) from exc

    with _chain_lock:
        _v2_chain_heads[workspace.workspace_id] = receipt.receipt_digest

    try_export_evidence(receipt, workspace.workspace_id)

    return receipt


def list_gateway_receipts(workspace: Workspace) -> list[dict[str, Any]]:
    conn = _get_chain_db_conn(workspace)
    try:
        rows = conn.execute(
            """
            SELECT receipt_digest, prev_receipt_digest, gateway_sequence,
                   cose_sign1_hex, payload, transaction_id, created_at
            FROM gateway_receipts
            WHERE workspace_id = ?
            ORDER BY gateway_sequence ASC
            """,
            (workspace.workspace_id,),
        ).fetchall()
        return [_row_to_receipt_dict(row) for row in rows]
    finally:
        conn.close()


def get_gateway_receipt(
    workspace: Workspace,
    receipt_digest: str,
) -> Optional[dict[str, Any]]:
    conn = _get_chain_db_conn(workspace)
    try:
        row = conn.execute(
            """
            SELECT receipt_digest, prev_receipt_digest, gateway_sequence,
                   cose_sign1_hex, payload, transaction_id, created_at
            FROM gateway_receipts
            WHERE workspace_id = ? AND receipt_digest = ?
            """,
            (workspace.workspace_id, receipt_digest),
        ).fetchone()
        if row is None:
            return None
        return _row_to_receipt_dict(row)
    finally:
        conn.close()


def get_v2_chain_head(workspace_id: str) -> Optional[str]:
    with _chain_lock:
        return _v2_chain_heads.get(workspace_id)


def reset_v2_chains() -> None:
    global _GATEWAY_SIGNER
    with _chain_lock:
        _v2_chain_heads.clear()
        _GATEWAY_SIGNER = _load_signer_from_env()
