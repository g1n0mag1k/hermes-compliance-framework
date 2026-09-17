"""Tests for scrub_payload_reversible vault-token redaction."""

from hermes.auditor import CANARY_CORPUS
from hermes.classifier import scrub_payload, scrub_payload_reversible
from hermes.vault import VAULT


def _ssn_entry() -> dict:
    return next(e for e in CANARY_CORPUS if e["flag"] == "HIPAA_SSN")


def test_scrub_payload_reversible_inserts_vault_tokens() -> None:
    entry = _ssn_entry()
    text = f"Patient SSN: {entry['value']}"
    txn = "txn_reversible_ssn"
    before = VAULT.size()

    result = scrub_payload_reversible(transaction_id=txn, text=text)

    assert entry["value"] not in result.clean_text
    assert "[REDACTED_SSN]" not in result.clean_text
    assert "HIPAA_SSN" in result.audit_log.flags_triggered
    # Vault grew and clean_text contains a vault-shaped token
    assert VAULT.size() >= before + 1
    assert "[REDACTED_HIPAA_SSN_" in result.clean_text


def test_scrub_payload_reversible_roundtrips_via_vault() -> None:
    entry = _ssn_entry()
    text = f"SSN on file {entry['value']}"
    txn = "txn_reversible_roundtrip"

    result = scrub_payload_reversible(transaction_id=txn, text=text)
    # Extract vault token from clean text
    start = result.clean_text.index("[REDACTED_HIPAA_SSN_")
    end = result.clean_text.index("]", start) + 1
    token = result.clean_text[start:end]

    assert VAULT.retrieve(token) == entry["value"]


def test_scrub_payload_unchanged_uses_static_placeholders() -> None:
    entry = _ssn_entry()
    text = f"SSN: {entry['value']}"
    result = scrub_payload(transaction_id="txn_static_ssn", text=text)
    assert "[REDACTED_SSN]" in result.clean_text
    assert entry["value"] not in result.clean_text


def test_scrub_payload_reversible_audit_log_structure_matches_static() -> None:
    entry = _ssn_entry()
    text = f"SSN: {entry['value']}"
    static = scrub_payload(transaction_id="txn_struct_static", text=text)
    reversible = scrub_payload_reversible(
        transaction_id="txn_struct_reversible", text=text
    )

    assert set(static.audit_log.flags_triggered.keys()) == set(
        reversible.audit_log.flags_triggered.keys()
    )
    assert set(static.audit_log.flags_redacted.keys()) == set(
        reversible.audit_log.flags_redacted.keys()
    )
    for flag in static.audit_log.flags_triggered:
        assert (
            static.audit_log.flags_triggered[flag].count
            == reversible.audit_log.flags_triggered[flag].count
        )
