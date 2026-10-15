"""
hermes/agent.py — Single-scan pipeline orchestrator.

Chains scrub → attestation → optional PDF evidence report → optional webhook
so callers do not wire those steps manually.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from hermes.attestation import ATTESTATION_CHAIN, ComplianceReceipt
from hermes.classifier import FlagEntry, RedactionAuditLog, scrub_payload
from hermes.report import generate_evidence_report
from hermes.webhooks import dispatch_webhook

import pandas as pd
from hermes.pseudonymizer import Pseudonymizer


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


@dataclass
class PseudonymizationResult:
    transaction_id: str
    coded_df: pd.DataFrame
    linkage_table: dict
    receipt: ComplianceReceipt


def run_pseudonymization_scan(
    df: pd.DataFrame,
    phi_columns: list[str],
    transaction_id: Optional[str] = None,
    downstream_target: Optional[str] = None,
) -> PseudonymizationResult:
    """
    Pseudonymize a DataFrame and issue a signed ComplianceReceipt.

    Steps (in order):
    1. txn_id = transaction_id or f"txn_pseudo_{uuid.uuid4().hex[:12]}"
    2. p = Pseudonymizer(phi_columns)
    3. coded_df, linkage_table = p.pseudonymize(df, txn_id)
    4. flags_triggered = {
           col: int(df[col].notna().sum())
           for col in phi_columns if col in df.columns
       }
    5. flags_redacted = flags_triggered  (same — all detected values were coded)
    6. char_count_in = sum(
           len(str(v)) for col in phi_columns
           if col in df.columns
           for v in df[col].dropna()
       )
    7. char_count_out = sum(
           len(str(v)) for col in phi_columns
           if col in coded_df.columns
           for v in coded_df[col].dropna()
       )
    8. receipt = ATTESTATION_CHAIN.issue(
           transaction_id=txn_id,
           flags_triggered=flags_triggered,
           flags_redacted=flags_redacted,
           char_count_in=char_count_in,
           char_count_out=char_count_out,
           downstream_target=downstream_target,
           detectors_executed={
               "PSEUDONYMIZER": "ok",
               "STRUCTURED_CSV": "ok",
           },
       )
    9. return PseudonymizationResult(txn_id, coded_df, linkage_table, receipt)

    Do NOT call dispatch_webhook().
    Do NOT call generate_evidence_report().
    """
    txn_id = transaction_id or f"txn_pseudo_{uuid.uuid4().hex[:12]}"
    p = Pseudonymizer(phi_columns)
    coded_df, linkage_table = p.pseudonymize(df, txn_id)
    flags_triggered = {
        col: int(df[col].notna().sum())
        for col in phi_columns
        if col in df.columns
    }
    flags_redacted = flags_triggered
    char_count_in = sum(
        len(str(v))
        for col in phi_columns
        if col in df.columns
        for v in df[col].dropna()
    )
    char_count_out = sum(
        len(str(v))
        for col in phi_columns
        if col in coded_df.columns
        for v in coded_df[col].dropna()
    )
    receipt = ATTESTATION_CHAIN.issue(
        transaction_id=txn_id,
        flags_triggered=flags_triggered,
        flags_redacted=flags_redacted,
        char_count_in=char_count_in,
        char_count_out=char_count_out,
        downstream_target=downstream_target,
        detectors_executed={
            "PSEUDONYMIZER": "ok",
            "STRUCTURED_CSV": "ok",
        },
    )
    return PseudonymizationResult(txn_id, coded_df, linkage_table, receipt)
