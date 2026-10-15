"""
hermes/agent.py — Single-scan pipeline orchestrator.

Chains scrub → attestation → optional PDF evidence report → optional webhook
so callers do not wire those steps manually.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Optional

from hermes.attestation import ATTESTATION_CHAIN, ComplianceReceipt
from hermes.classifier import FlagEntry, RedactionAuditLog, scrub_payload
from hermes.report import generate_evidence_report
from hermes.webhooks import dispatch_webhook

if TYPE_CHECKING:
    import pandas as pd


def _flags_to_counts(flags: Dict[str, FlagEntry]) -> Dict[str, int]:
    """Map audit-log flag entries to per-flag counts for attestation issuance."""
    return {
        k: v.count if isinstance(v, FlagEntry) else v["count"]
        for k, v in flags.items()
    }


@dataclass
class AgentResult:
    transaction_id: str
    clean_text: str
    receipt: ComplianceReceipt
    report_bytes: Optional[bytes]  # None if engagement_meta not provided
    audit_log: RedactionAuditLog


@dataclass
class PseudonymizationScanResult:
    transaction_id: str
    coded_df: "pd.DataFrame"
    linkage_table: dict
    receipt: ComplianceReceipt


def run_pseudonymization_scan(
    df: "pd.DataFrame",
    phi_columns: list[str],
    downstream_target: Optional[str] = None,
    transaction_id: Optional[str] = None,
) -> PseudonymizationScanResult:
    """Pseudonymize broker CSV columns and issue a compliance receipt."""
    from hermes.pseudonymizer import Pseudonymizer

    txn_id = transaction_id or f"txn_pseudo_{uuid.uuid4().hex[:12]}"
    pseudonymizer = Pseudonymizer(phi_columns)
    coded_df, linkage_table = pseudonymizer.pseudonymize(df, txn_id)

    flags_triggered: Dict[str, int] = {}
    flags_redacted: Dict[str, int] = {}
    char_count_in = 0
    char_count_out = 0
    for col in phi_columns:
        if col not in df.columns:
            continue
        for value in df[col]:
            text = str(value)
            if text == "" or text.lower() == "nan":
                continue
            char_count_in += len(text)
            flags_triggered[f"pseudonymize:{col}"] = (
                flags_triggered.get(f"pseudonymize:{col}", 0) + 1
            )
        for value in coded_df[col]:
            text = str(value)
            if text == "" or text.lower() == "nan":
                continue
            char_count_out += len(text)
            flags_redacted[f"pseudonymize:{col}"] = (
                flags_redacted.get(f"pseudonymize:{col}", 0) + 1
            )

    receipt = ATTESTATION_CHAIN.issue(
        transaction_id=txn_id,
        flags_triggered=flags_triggered,
        flags_redacted=flags_redacted,
        char_count_in=char_count_in,
        char_count_out=char_count_out,
        downstream_target=downstream_target,
        detectors_executed={"pseudonymizer": "HMAC_SHA256"},
    )

    return PseudonymizationScanResult(
        transaction_id=txn_id,
        coded_df=coded_df,
        linkage_table=linkage_table,
        receipt=receipt,
    )


def run_scan(
    text: str,
    transaction_id: Optional[str] = None,
    downstream_target: Optional[str] = None,
    engagement_meta: Optional[dict] = None,
    fire_webhook: bool = True,
) -> AgentResult:
    """Run one full scrub → attest → optional report/webhook scan."""
    txn_id = transaction_id or f"txn_agent_{uuid.uuid4().hex[:12]}"

    result = scrub_payload(transaction_id=txn_id, text=text)

    flags_triggered = _flags_to_counts(result.audit_log.flags_triggered)
    flags_redacted = _flags_to_counts(result.audit_log.flags_redacted)

    receipt = ATTESTATION_CHAIN.issue(
        transaction_id=txn_id,
        flags_triggered=flags_triggered,
        flags_redacted=flags_redacted,
        char_count_in=result.audit_log.original_char_count,
        char_count_out=result.audit_log.redacted_char_count,
        downstream_target=downstream_target,
        detectors_executed=result.detectors_executed,
    )

    report_bytes: Optional[bytes] = None
    if engagement_meta is not None:
        report_bytes = generate_evidence_report(receipt, engagement_meta)

    if fire_webhook:
        dispatch_webhook(receipt)

    return AgentResult(
        transaction_id=txn_id,
        clean_text=result.clean_text,
        receipt=receipt,
        report_bytes=report_bytes,
        audit_log=result.audit_log,
    )
