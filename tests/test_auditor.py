"""Tests for hermes.auditor canary engine."""

from dataclasses import replace

from hermes.auditor import (
    CANARY_CORPUS,
    CanaryRunResult,
    load_prior_result,
    run_canary,
    save_result,
)
from hermes.classifier import COVERED_FLAGS, scrub_payload


def test_canary_corpus_covers_all_covered_flags() -> None:
    corpus_flags = {entry["flag"] for entry in CANARY_CORPUS}
    assert corpus_flags == set(COVERED_FLAGS)


def test_run_canary_fires_all_covered_flags() -> None:
    result = run_canary()
    assert isinstance(result, CanaryRunResult)
    assert result.flags_missed == []
    assert set(COVERED_FLAGS).issubset(set(result.flags_detected))
    # G4: No unexpected flags should fire — confirms corpus is tightly scoped
    assert result.flags_unexpected == [], (
        f"Unexpected flags fired during canary run: {result.flags_unexpected}. "
        "Update CANARY_CORPUS or COVERED_FLAGS so the sets align."
    )
    assert result.receipt.zero_pii_egress_confirmed is True
    assert result.report_bytes is None
    assert result.run_at.endswith("+00:00") or "T" in result.run_at


def test_run_canary_scrub_removes_canary_values() -> None:
    """G4: Canary values must be absent from clean_text after scrubbing."""
    payload = "\n".join(
        f"{entry['flag']}: {entry['value']}" for entry in CANARY_CORPUS
    )
    scrub_result = scrub_payload(transaction_id="txn_canary_scrub_test", text=payload)
    clean = scrub_result.clean_text
    for entry in CANARY_CORPUS:
        assert entry["value"] not in clean, (
            f"Canary value for {entry['flag']} ({entry['value']!r}) "
            f"survived scrubbing and is still present in clean_text."
        )


def test_run_canary_no_drift_on_identical_runs() -> None:
    first = run_canary()
    second = run_canary(prior_result=first)
    assert second.drift_detected is False
    assert second.prior_run_id == first.run_id
    assert set(second.flags_detected) == set(first.flags_detected)


def test_run_canary_drift_when_flag_suppressed() -> None:
    first = run_canary()
    # Simulate a prior run that missed a covered flag the current run still sees.
    suppressed = [f for f in first.flags_detected if f != "HIPAA_SSN"]
    assert "HIPAA_SSN" in first.flags_detected
    prior = replace(first, flags_detected=suppressed)
    second = run_canary(prior_result=prior)
    assert second.drift_detected is True
    assert second.prior_run_id == first.run_id


def test_run_canary_generates_pdf_with_engagement_meta() -> None:
    meta = {
        "client_name": "Canary Client",
        "scan_date": "2026-09-12",
        "engineer": "Hermes Canary",
        "scope": "Safe Harbor covered flags",
        "excluded": "reference_only",
    }
    result = run_canary(engagement_meta=meta)
    assert result.report_bytes is not None
    assert result.report_bytes[:4] == b"%PDF"


def test_canary_save_and_load_roundtrip(tmp_path) -> None:
    db_path = str(tmp_path / "hermes_canary.db")
    result = run_canary()
    save_result(result, db_path=db_path)

    loaded = load_prior_result(db_path=db_path)
    assert loaded is not None
    assert loaded.run_id == result.run_id
    assert loaded.flags_detected == result.flags_detected
    assert loaded.flags_expected == result.flags_expected
    assert loaded.drift_detected == result.drift_detected
    assert loaded.receipt.receipt_hash == result.receipt.receipt_hash


def test_load_prior_result_empty_db(tmp_path) -> None:
    db_path = str(tmp_path / "empty_canary.db")
    assert load_prior_result(db_path=db_path) is None
