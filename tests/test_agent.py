"""Tests for hermes.agent single-scan orchestration."""

from hermes.agent import AgentResult, run_scan
from hermes.auditor import CANARY_CORPUS


def _canary_payload() -> str:
    """Build scan text from the canary corpus — no hardcoded PHI in tests."""
    return "\n".join(f"{e['flag']}: {e['value']}" for e in CANARY_CORPUS)


def test_run_scan_populates_agent_result_fields() -> None:
    result = run_scan(text=_canary_payload(), fire_webhook=False)

    assert isinstance(result, AgentResult)
    assert result.transaction_id.startswith("txn_agent_")
    assert result.clean_text
    assert result.receipt is not None
    assert result.receipt.transaction_id == result.transaction_id
    assert result.audit_log.transaction_id == result.transaction_id
    assert result.report_bytes is None


def test_run_scan_report_bytes_none_without_engagement_meta() -> None:
    result = run_scan(text=_canary_payload(), fire_webhook=False)
    assert result.report_bytes is None


def test_run_scan_generates_pdf_when_engagement_meta_provided() -> None:
    meta = {
        "client_name": "Test Client",
        "scan_date": "2026-09-12",
        "engineer": "Hermes Test",
        "scope": "Canary corpus",
        "excluded": "none",
    }
    result = run_scan(
        text=_canary_payload(),
        engagement_meta=meta,
        fire_webhook=False,
    )
    assert result.report_bytes is not None
    assert result.report_bytes[:4] == b"%PDF"


def test_run_scan_zero_pii_egress_confirmed_on_full_redaction() -> None:
    result = run_scan(text=_canary_payload(), fire_webhook=False)
    assert result.receipt.zero_pii_egress_confirmed is True
    assert result.receipt.count_detected == result.receipt.count_redacted


def test_run_scan_respects_explicit_transaction_id() -> None:
    txn = "txn_agent_explicit_001"
    result = run_scan(
        text=_canary_payload(),
        transaction_id=txn,
        fire_webhook=False,
    )
    assert result.transaction_id == txn
    assert result.receipt.transaction_id == txn


def test_run_scan_sets_downstream_target_on_receipt() -> None:
    result = run_scan(
        text=_canary_payload(),
        downstream_target="ollama",
        fire_webhook=False,
    )
    assert result.receipt.downstream_target == "ollama"
