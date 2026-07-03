"""Tests for the hermes.classifier scrubbing pipeline."""

import pytest

from hermes.classifier import (
    CFR_CITATION_MAP,
    detect_with_presidio,
    scrub_payload,
)


@pytest.fixture
def txn_id() -> str:
    return "test_txn_classifier"


def test_classifier_module_imports() -> None:
    """The hermes.classifier module imports cleanly."""
    from hermes import classifier  # noqa: F401


def test_classifier_module_is_a_module() -> None:
    """Sanity: classifier is a real module, not unexpectedly mocked."""
    import types

    from hermes import classifier

    assert isinstance(classifier, types.ModuleType)


def test_detect_with_presidio_returns_phone_entities() -> None:
    text = "Reach the clinic at 555-867-5309 for follow-up."
    entities = detect_with_presidio(text)
    phone_entities = [e for e in entities if e["entity_type"] == "PHONE_NUMBER"]
    assert phone_entities
    assert phone_entities[0]["flag"] == "HIPAA_PHI_PHONE"
    assert "555-867-5309" in phone_entities[0]["text"]


def test_phone_number_detection_and_redaction(txn_id: str) -> None:
    text = "Callback number: 555-867-5309."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "555-867-5309" not in result.clean_text
    assert "[REDACTED_PHONE]" in result.clean_text
    assert result.audit_log.flags_triggered["HIPAA_PHI_PHONE"].count == 1
    assert result.audit_log.flags_triggered["HIPAA_PHI_PHONE"].cfr_citation == (
        CFR_CITATION_MAP["HIPAA_PHI_PHONE"]
    )


def test_email_detection_and_redaction(txn_id: str) -> None:
    text = "Send records to patient.care@hospital.org today."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "patient.care@hospital.org" not in result.clean_text
    assert "[REDACTED_EMAIL]" in result.clean_text
    assert result.audit_log.flags_triggered["HIPAA_PHI_EMAIL"].count == 1
    assert result.audit_log.flags_triggered["HIPAA_PHI_EMAIL"].cfr_citation == (
        CFR_CITATION_MAP["HIPAA_PHI_EMAIL"]
    )


def test_url_detection_and_redaction(txn_id: str) -> None:
    text = "Portal link: https://records.clinic.example/patient/42"
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "https://records.clinic.example/patient/42" not in result.clean_text
    assert "[REDACTED_URL]" in result.clean_text
    assert result.audit_log.flags_triggered["HIPAA_PHI_URL"].count >= 1
    assert result.audit_log.flags_triggered["HIPAA_PHI_URL"].cfr_citation == (
        CFR_CITATION_MAP["HIPAA_PHI_URL"]
    )


def test_ip_address_detection_and_redaction(txn_id: str) -> None:
    text = "Workstation logged in from 10.20.30.40 during the visit."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "10.20.30.40" not in result.clean_text
    assert "[REDACTED_IP]" in result.clean_text
    assert result.audit_log.flags_triggered["HIPAA_PHI_IP"].count == 1
    assert result.audit_log.flags_triggered["HIPAA_PHI_IP"].cfr_citation == (
        CFR_CITATION_MAP["HIPAA_PHI_IP"]
    )


def test_combined_phi_payload_redaction(txn_id: str) -> None:
    text = (
        "Patient Jane Doe (DOB March 15, 1982) SSN 123-45-6789. "
        "Phone 555-123-4567, email jane.doe@clinic.org, "
        "portal https://portal.clinic.org, workstation IP 192.168.0.44."
    )
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "Jane Doe" not in result.clean_text
    assert "March 15, 1982" not in result.clean_text
    assert "123-45-6789" not in result.clean_text
    assert "555-123-4567" not in result.clean_text
    assert "jane.doe@clinic.org" not in result.clean_text
    assert "https://portal.clinic.org" not in result.clean_text
    assert "192.168.0.44" not in result.clean_text

    flags = result.audit_log.flags_triggered
    assert flags["HIPAA_SSN"].count == 1
    assert flags["HIPAA_PHI_PERSON"].count >= 1
    assert flags["HIPAA_PHI_DATE"].count >= 1
    assert flags["HIPAA_PHI_PHONE"].count == 1
    assert flags["HIPAA_PHI_EMAIL"].count == 1
    assert flags["HIPAA_PHI_URL"].count >= 1
    assert flags["HIPAA_PHI_IP"].count == 1

    assert flags["HIPAA_SSN"].cfr_citation == CFR_CITATION_MAP["HIPAA_SSN"]
    assert flags["HIPAA_PHI_PHONE"].cfr_citation == CFR_CITATION_MAP["HIPAA_PHI_PHONE"]
    assert flags["HIPAA_PHI_EMAIL"].cfr_citation == CFR_CITATION_MAP["HIPAA_PHI_EMAIL"]


def test_email_domain_url_not_double_counted(txn_id: str) -> None:
    """Presidio URL hits on an email domain must not inflate flags_triggered."""
    text = "Send results to patient@email.com by Friday."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "patient@email.com" not in result.clean_text
    assert "[REDACTED_EMAIL]" in result.clean_text
    flags = result.audit_log.flags_triggered
    assert flags["HIPAA_PHI_EMAIL"].count == 1
    assert "HIPAA_PHI_URL" not in flags


def test_standalone_url_still_detected(txn_id: str) -> None:
    """Real URLs outside email addresses must still trigger HIPAA_PHI_URL."""
    text = "Review the chart at https://example.com/page before discharge."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert "https://example.com/page" not in result.clean_text
    assert "[REDACTED_URL]" in result.clean_text
    flags = result.audit_log.flags_triggered
    assert flags["HIPAA_PHI_URL"].count >= 1
    assert flags["HIPAA_PHI_URL"].cfr_citation == CFR_CITATION_MAP["HIPAA_PHI_URL"]


def test_overlapping_spacy_and_presidio_spans_redacted_once(txn_id: str) -> None:
    """Overlapping detections must produce one placeholder, not nested redactions."""
    text = "Contact Jane Doe at jane.doe@example.com."
    result = scrub_payload(transaction_id=txn_id, text=text)

    assert result.clean_text.count("[REDACTED_") >= 1
    assert "jane.doe@example.com" not in result.clean_text
    assert "][REDACTED_" not in result.clean_text


def test_ssn_dot_notation_redacted() -> None:
    """SSN with dot separators must be caught — confirmed live leak before fix."""
    from hermes.classifier import scrub_payload
    result = scrub_payload('test_ssn_dot', 'SSN: 372.18.5421')
    assert '[REDACTED_SSN]' in result.clean_text
    assert '372.18.5421' not in result.clean_text


def test_ssn_space_notation_redacted() -> None:
    """SSN with space separators must be caught — confirmed live leak before fix."""
    from hermes.classifier import scrub_payload
    result = scrub_payload('test_ssn_space', 'social 372 18 5421')
    assert '[REDACTED_SSN]' in result.clean_text
    assert '372 18 5421' not in result.clean_text


def test_ssn_mixed_separator_not_redacted() -> None:
    """Mixed separators (372-18.5421) must NOT match — not a valid SSN format."""
    from hermes.classifier import scrub_payload
    result = scrub_payload('test_ssn_mixed', '372-18.5421')
    assert '[REDACTED_SSN]' not in result.clean_text


def test_ssn_invalid_ranges_not_redacted() -> None:
    """000/666/9xx area, 00 group, 0000 serial must never be redacted."""
    from hermes.classifier import scrub_payload
    non_ssns = [
        ('000 area', '000-12-3456'),
        ('666 area', '666-12-3456'),
        ('900 area', '900-12-3456'),
        ('00 group', '123-00-6789'),
        ('0000 serial', '123-45-0000'),
    ]
    for label, text in non_ssns:
        result = scrub_payload(f'test_ssn_invalid_{label}', text)
        assert '[REDACTED_SSN]' not in result.clean_text, (
            f'False positive on {label}: {text}'
        )


# -------------------------------------------------------------------------
# VAULT TESTS — AES-256-GCM
# -------------------------------------------------------------------------
def test_vault_aesgcm_roundtrip() -> None:
    """Stored PII must decrypt back to original value exactly."""
    from hermes.vault import VAULT
    values = [
        ("SSN", "372-18-5421"),
        ("PAN", "4111111111111111"),
        ("EMAIL", "jane.doe@hospital.org"),
        ("PERSON", "Jane Doe"),
        ("IP", "192.168.0.44"),
    ]
    for pii_type, value in values:
        token = VAULT.store(pii_type, value, "txn_vault_test")
        recovered = VAULT.retrieve(token)
        assert recovered == value, f"Roundtrip failed for {pii_type}: {value}"


def test_vault_tamper_detection() -> None:
    """Flipping a byte in encrypted_value must raise on decrypt — not silently return garbage."""
    from hermes.vault import VAULT, _aesgcm_decrypt, VAULT_KEY
    from cryptography.exceptions import InvalidTag
    token = VAULT.store("SSN", "372-18-5421", "txn_tamper_test")
    entry = VAULT.retrieve_entry(token)
    ct_bytes = bytearray(bytes.fromhex(entry.encrypted_value))
    ct_bytes[20] ^= 0xFF
    tampered_hex = bytes(ct_bytes).hex()
    try:
        _aesgcm_decrypt(tampered_hex, VAULT_KEY)
        assert False, "Tampered ciphertext decrypted without error — authentication broken"
    except InvalidTag:
        pass


def test_vault_nonce_uniqueness() -> None:
    """Same plaintext encrypted twice must produce different ciphertexts."""
    from hermes.vault import _aesgcm_encrypt, VAULT_KEY
    ct1 = _aesgcm_encrypt("372-18-5421", VAULT_KEY)
    ct2 = _aesgcm_encrypt("372-18-5421", VAULT_KEY)
    assert ct1 != ct2, "Nonce reuse detected — encryption is deterministic"


def test_vault_unknown_token_returns_none() -> None:
    """Retrieving a non-existent token must return None, not raise."""
    from hermes.vault import VAULT
    result = VAULT.retrieve("[REDACTED_SSN_doesnotexist]")
    assert result is None


def test_vault_purge_transaction() -> None:
    """purge_transaction must remove all entries for that transaction only."""
    from hermes.vault import VAULT
    VAULT.store("SSN", "111-22-3333", "txn_purge_a")
    VAULT.store("PAN", "4111111111111111", "txn_purge_a")
    t_keep = VAULT.store("SSN", "444-55-6666", "txn_purge_b")
    purged = VAULT.purge_transaction("txn_purge_a")
    assert purged == 2
    assert VAULT.retrieve(t_keep) == "444-55-6666"
