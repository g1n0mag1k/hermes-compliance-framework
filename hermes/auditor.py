"""
hermes/auditor.py — Scheduled canary testing engine.

Fires synthetic PHI-shaped tokens through the classifier, verifies detection
against COVERED_FLAGS, compares against a prior run for drift, and optionally
generates a signed PDF evidence report.

Canary run results persist in a dedicated SQLite DB (default hermes_canary.db),
separate from ATTESTATION_CHAIN's hermes_chain.db.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from hermes.attestation import ATTESTATION_CHAIN, ComplianceReceipt
from hermes.classifier import (
    COVERED_FLAGS,
    DECLARED_SCOPE,
    FlagEntry,
    scrub_payload,
)
from hermes.report import generate_evidence_report

DEFAULT_CANARY_DB_PATH = os.environ.get("HERMES_CANARY_DB_PATH", "hermes_canary.db")

# Synthetic PHI tokens — one representative per covered Safe Harbor category.
# Realistic format, not real PHI. Driven by DECLARED_SCOPE covered entries.
CANARY_CORPUS: List[Dict[str, str]] = [
    {
        "category": "45 CFR §164.514(b)(2)(i)(A)",
        "flag": "HIPAA_PHI_PERSON",
        "value": "John Testpatient",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(B)",
        "flag": "HIPAA_PHI_ADDRESS",
        "value": "742 Evergreen Terrace, Springfield, Illinois",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(C)",
        "flag": "HIPAA_PHI_DATE",
        "value": "March 15, 1982",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(D)",
        "flag": "HIPAA_PHI_PHONE",
        "value": "555-867-5309",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(E)",
        "flag": "HIPAA_PHI_FAX",
        "value": "fax: 555-321-9876",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(F)",
        "flag": "HIPAA_PHI_EMAIL",
        "value": "john.testpatient@example.com",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(G)",
        "flag": "HIPAA_SSN",
        "value": "372-18-5421",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(H)",
        "flag": "HIPAA_PHI_MRN",
        "value": "MRN: 1234567",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(I)",
        "flag": "HIPAA_PHI_HPBN",
        "value": "Member ID: 1EG4TE5MK72",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(J)",
        "flag": "HIPAA_PHI_ACCOUNT",
        "value": "account number 123456789012",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(K)",
        "flag": "HIPAA_PHI_CERT_LICENSE",
        "value": "DEA: AB1234563",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(L)",
        "flag": "HIPAA_PHI_VIN",
        "value": "1HGBH41JXMN109186",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(M)",
        "flag": "HIPAA_PHI_DEVICE_ID",
        "value": "(01)00855361005016(21)S12345",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(N)",
        "flag": "HIPAA_PHI_URL",
        "value": "https://records.clinic.example/patient/42",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(O)",
        "flag": "HIPAA_PHI_IP",
        "value": "10.20.30.40",
    },
    {
        "category": "45 CFR §164.514(b)(2)(i)(R)",
        "flag": "HIPAA_PHI_UNIQUE_CODE",
        "value": "ENC-789012",
    },
]

# Sanity: corpus flags align with covered DECLARED_SCOPE entries
assert {e["flag"] for e in CANARY_CORPUS} == set(COVERED_FLAGS)
assert all(
    any(s["flag"] == e["flag"] and s["status"] == "covered" for s in DECLARED_SCOPE)
    for e in CANARY_CORPUS
)


def _flags_to_counts(flags: Dict[str, FlagEntry]) -> Dict[str, int]:
    """Map audit-log flag entries to per-flag counts for attestation issuance."""
    return {
        k: v.count if isinstance(v, FlagEntry) else v["count"]
        for k, v in flags.items()
    }


@dataclass
class CanaryRunResult:
    run_id: str
    run_at: str  # ISO UTC
    flags_expected: List[str]
    flags_detected: List[str]
    flags_missed: List[str]
    flags_unexpected: List[str]
    drift_detected: bool
    prior_run_id: Optional[str]
    receipt: ComplianceReceipt
    report_bytes: Optional[bytes]  # signed PDF, if engagement_meta provided


def _init_canary_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS canary_runs (
            run_id           TEXT PRIMARY KEY,
            run_at           TEXT NOT NULL,
            flags_expected   TEXT NOT NULL,
            flags_detected   TEXT NOT NULL,
            flags_missed     TEXT NOT NULL,
            flags_unexpected TEXT NOT NULL,
            drift_detected   INTEGER NOT NULL,
            prior_run_id     TEXT,
            receipt_json     TEXT NOT NULL,
            report_bytes     BLOB
        )
        """
    )
    conn.commit()


def _receipt_from_dict(data: dict) -> ComplianceReceipt:
    return ComplianceReceipt(**data)


def save_result(result: CanaryRunResult, db_path: str = DEFAULT_CANARY_DB_PATH) -> None:
    """Persist a canary run to the dedicated canary SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        _init_canary_db(conn)
        conn.execute(
            """
            INSERT OR REPLACE INTO canary_runs (
                run_id, run_at, flags_expected, flags_detected,
                flags_missed, flags_unexpected, drift_detected,
                prior_run_id, receipt_json, report_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.run_id,
                result.run_at,
                json.dumps(result.flags_expected),
                json.dumps(result.flags_detected),
                json.dumps(result.flags_missed),
                json.dumps(result.flags_unexpected),
                int(result.drift_detected),
                result.prior_run_id,
                json.dumps(asdict(result.receipt)),
                result.report_bytes,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def load_prior_result(
    db_path: str = DEFAULT_CANARY_DB_PATH,
) -> Optional[CanaryRunResult]:
    """Load the most recent canary run from the canary SQLite database."""
    if not os.path.exists(db_path):
        return None

    conn = sqlite3.connect(db_path)
    try:
        _init_canary_db(conn)
        row = conn.execute(
            """
            SELECT run_id, run_at, flags_expected, flags_detected,
                   flags_missed, flags_unexpected, drift_detected,
                   prior_run_id, receipt_json, report_bytes
            FROM canary_runs
            ORDER BY run_at DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return CanaryRunResult(
            run_id=row[0],
            run_at=row[1],
            flags_expected=json.loads(row[2]),
            flags_detected=json.loads(row[3]),
            flags_missed=json.loads(row[4]),
            flags_unexpected=json.loads(row[5]),
            drift_detected=bool(row[6]),
            prior_run_id=row[7],
            receipt=_receipt_from_dict(json.loads(row[8])),
            report_bytes=row[9],
        )
    finally:
        conn.close()


def run_canary(
    engagement_meta: Optional[dict] = None,
    prior_result: Optional[CanaryRunResult] = None,
) -> CanaryRunResult:
    """Fire the canary corpus through scrub_payload once and check for drift."""
    run_id = f"canary_{uuid.uuid4().hex[:12]}"
    run_at = datetime.now(timezone.utc).isoformat()
    transaction_id = f"txn_{run_id}"

    # Assemble all canary values into a single payload — one scrub_payload call.
    payload = "\n".join(
        f"{entry['flag']}: {entry['value']}" for entry in CANARY_CORPUS
    )

    scrub_result = scrub_payload(transaction_id=transaction_id, text=payload)

    flags_expected = sorted(COVERED_FLAGS)
    flags_detected = sorted(scrub_result.audit_log.flags_triggered.keys())
    expected_set = set(flags_expected)
    detected_set = set(flags_detected)
    flags_missed = sorted(expected_set - detected_set)
    flags_unexpected = sorted(detected_set - expected_set)

    prior_run_id: Optional[str] = None
    if prior_result is not None:
        prior_run_id = prior_result.run_id
        drift_detected = detected_set != set(prior_result.flags_detected)
    else:
        drift_detected = False

    flags_triggered = _flags_to_counts(scrub_result.audit_log.flags_triggered)
    flags_redacted = _flags_to_counts(scrub_result.audit_log.flags_redacted)

    receipt = ATTESTATION_CHAIN.issue(
        transaction_id=transaction_id,
        flags_triggered=flags_triggered,
        flags_redacted=flags_redacted,
        char_count_in=scrub_result.audit_log.original_char_count,
        char_count_out=scrub_result.audit_log.redacted_char_count,
        downstream_target="hermes-canary",
        detectors_executed=scrub_result.detectors_executed,
    )

    report_bytes: Optional[bytes] = None
    if engagement_meta is not None:
        report_bytes = generate_evidence_report(receipt, engagement_meta)

    return CanaryRunResult(
        run_id=run_id,
        run_at=run_at,
        flags_expected=flags_expected,
        flags_detected=flags_detected,
        flags_missed=flags_missed,
        flags_unexpected=flags_unexpected,
        drift_detected=drift_detected,
        prior_run_id=prior_run_id,
        receipt=receipt,
        report_bytes=report_bytes,
    )
