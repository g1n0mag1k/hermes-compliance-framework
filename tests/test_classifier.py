import pytest
from hermes.classifier import scrub_payload, ScrubberResult
def test_ssn_redaction():
    result = scrub_payload("txn_001", "Patient SSN is 123-45-6789.")
    assert "[REDACTED_SSN]" in result.clean_text
    assert result.audit_log.flags_triggered.get("HIPAA_SSN", 0) >= 1
def test_pan_redaction():
    result = scrub_payload("txn_002", "Card number: 4111111111111111")
    assert "[REDACTED_PAN]" in result.clean_text
    assert result.audit_log.flags_triggered.get("PCI_PAN", 0) >= 1
def test_audit_log_structure():
    result = scrub_payload("txn_003", "SSN: 234-56-7890 and card 4111111111111111")
    assert result.audit_log.transaction_id == "txn_003"
    assert result.audit_log.original_char_count > 0
    assert isinstance(result.audit_log.flags_triggered, dict)
