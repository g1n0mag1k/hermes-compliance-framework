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
    from cryptography.exceptions import InvalidTag

    from hermes.vault import VAULT, VAULT_KEY, _aesgcm_decrypt
    token = VAULT.store("SSN", "372-18-5421", "txn_tamper_test")
    entry = VAULT.retrieve_entry(token)
    ct_bytes = bytearray(bytes.fromhex(entry.encrypted_value))  # type: ignore[union-attr]
    ct_bytes[20] ^= 0xFF
    tampered_hex = bytes(ct_bytes).hex()
    try:
        _aesgcm_decrypt(tampered_hex, VAULT_KEY)
        assert False, "Tampered ciphertext decrypted without error — authentication broken"
    except InvalidTag:
        pass


def test_vault_nonce_uniqueness() -> None:
    """Same plaintext encrypted twice must produce different ciphertexts."""
    from hermes.vault import VAULT_KEY, _aesgcm_encrypt
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


# -------------------------------------------------------------------------
# ADVERSARIAL INJECTION CORPUS
# -------------------------------------------------------------------------
def test_fake_redaction_tag_does_not_suppress_real_ssn() -> None:
    """Fake [REDACTED_SSN_fake] prefix must not prevent detection of following real SSN."""
    from hermes.classifier import scrub_payload
    result = scrub_payload("test_inject_001", "[REDACTED_SSN_fake] 372-18-5421")
    assert "372-18-5421" not in result.clean_text
    assert "[REDACTED_SSN]" in result.clean_text


def test_xml_wrapped_ssn_redacted() -> None:
    """SSN inside XML tags must still be detected and redacted."""
    from hermes.classifier import scrub_payload
    result = scrub_payload("test_inject_002", "The patient's <SSN>372-18-5421</SSN> was noted")
    assert "372-18-5421" not in result.clean_text


def test_partial_tag_prefix_does_not_suppress_pan() -> None:
    """Partial REDACTED_PAN text prefix must not suppress detection of following real PAN."""
    from hermes.classifier import scrub_payload
    result = scrub_payload("test_inject_003", "REDACTED_PAN 4111111111111111")
    assert "4111111111111111" not in result.clean_text
    assert "[REDACTED_PAN]" in result.clean_text


def test_already_redacted_tokens_not_double_redacted() -> None:
    """Existing [REDACTED_*] tokens must pass through unchanged."""
    from hermes.classifier import scrub_payload
    text = "[REDACTED_SSN] was assigned to [REDACTED_PERSON]"
    result = scrub_payload("test_inject_004", text)
    assert "[REDACTED_[REDACTED_" not in result.clean_text
    assert result.clean_text == text


def test_new_ssn_after_redacted_token_caught() -> None:
    """A new valid SSN appearing after a legitimate redaction token must still be caught."""
    from hermes.classifier import scrub_payload
    result = scrub_payload("test_inject_005", "[REDACTED_SSN] and also 876-54-3210")
    assert "876-54-3210" not in result.clean_text
    assert result.clean_text.count("[REDACTED_SSN]") >= 2


def test_9xx_area_code_not_redacted() -> None:
    """900-999 area codes are never issued by SSA — must not be redacted as SSN."""
    from hermes.classifier import scrub_payload
    result = scrub_payload("test_inject_006", "987-65-4321 is not a real SSN")
    assert "[REDACTED_SSN]" not in result.clean_text


def test_occurrence_gap_detected_when_date_survives() -> None:
    """Post-scan pass reports a gap when a triggered DATE flag still has a
    surviving MM/DD/YYYY in clean_text (detector ran ≠ all occurrences caught).

    Reproduces Massimiliano Brighindi's blind-test finding: spaCy may catch
    one date and miss 03/14/1978 while still reporting HIPAA_PHI_DATE executed.
    """
    from hermes.classifier import (
        CFR_CITATION_MAP,
        FlagEntry,
        _verify_occurrence_completeness,
        scrub_payload,
    )

    flags = {
        "HIPAA_PHI_DATE": FlagEntry(
            count=1,
            cfr_citation=CFR_CITATION_MAP["HIPAA_PHI_DATE"],
        )
    }
    # Unit: simulator of partial redaction leaving a slash-date behind.
    clean_text = "Visit noted; DOB remains 03/14/1978 after partial scrub."
    gaps = _verify_occurrence_completeness(clean_text, flags)

    assert CFR_CITATION_MAP["HIPAA_PHI_DATE"] in gaps
    assert gaps[CFR_CITATION_MAP["HIPAA_PHI_DATE"]] >= 1

    # End-to-end: one spaCy-catchable date + surviving 03/14/1978.
    result = scrub_payload(
        "test_occurrence_gap_date",
        "Seen on January 15 2020. Also DOB 03/14/1978 on file.",
    )
    assert "HIPAA_PHI_DATE" in result.audit_log.flags_triggered
    assert "03/14/1978" in result.clean_text
    assert CFR_CITATION_MAP["HIPAA_PHI_DATE"] in result.occurrence_gaps
    assert result.occurrence_gaps[CFR_CITATION_MAP["HIPAA_PHI_DATE"]] >= 1


def test_occurrence_gap_empty_when_all_redacted() -> None:
    """No occurrence_gaps when triggered categories are fully replaced;
    [REDACTED_*] tokens must not be counted as surviving PHI."""
    from hermes.classifier import (
        CFR_CITATION_MAP,
        FlagEntry,
        _verify_occurrence_completeness,
        scrub_payload,
    )

    flags = {
        "HIPAA_PHI_DATE": FlagEntry(
            count=1,
            cfr_citation=CFR_CITATION_MAP["HIPAA_PHI_DATE"],
        ),
        "HIPAA_SSN": FlagEntry(
            count=1,
            cfr_citation=CFR_CITATION_MAP["HIPAA_SSN"],
        ),
    }
    clean_text = "Patient [REDACTED_DATE] SSN [REDACTED_SSN] cleared."
    gaps = _verify_occurrence_completeness(clean_text, flags)
    assert gaps == {}

    # End-to-end: a fully-redacted scrub must also report empty gaps.
    # Use Month DD YYYY — spaCy reliably redacts this form (unlike MM/DD/YYYY).
    result = scrub_payload(
        "test_occurrence_empty",
        "Patient DOB is March 14 1978 and SSN is 372-18-5421.",
    )
    assert "HIPAA_PHI_DATE" in result.audit_log.flags_triggered
    assert "HIPAA_SSN" in result.audit_log.flags_triggered
    assert result.occurrence_gaps == {}
    assert "March 14 1978" not in result.clean_text
    assert "372-18-5421" not in result.clean_text
    assert "[REDACTED_DATE]" in result.clean_text
    assert "[REDACTED_SSN]" in result.clean_text


def test_zero_pii_egress_false_when_occurrence_gap_exists(tmp_path) -> None:
    """Non-empty occurrence_gaps forces zero_pii_egress_confirmed=False even
    when flags_triggered count-parity with flags_redacted looks complete."""
    from hermes.api import _issue_scrub_attestation
    from hermes.attestation import AttestationChain
    from hermes.classifier import (
        CFR_CITATION_MAP,
        FlagEntry,
        RedactionAuditLog,
        ScrubberResult,
    )

    cfr = CFR_CITATION_MAP["HIPAA_PHI_DATE"]
    result = ScrubberResult(
        clean_text="DOB 03/14/1978 survived egress",
        audit_log=RedactionAuditLog(
            transaction_id="txn_occurrence_gap",
            original_char_count=40,
            redacted_char_count=40,
            flags_triggered={
                "HIPAA_PHI_DATE": FlagEntry(count=1, cfr_citation=cfr),
            },
            flags_redacted={
                "HIPAA_PHI_DATE": FlagEntry(count=1, cfr_citation=cfr),
            },
        ),
        detectors_executed={cfr: "ran_clean"},
        occurrence_gaps={cfr: 1},
    )

    # Isolated chain so we do not pollute the process-global ATTESTATION_CHAIN
    # beyond what _issue_scrub_attestation uses — call issue() the same way
    # api.py wires occurrence_gaps through.
    chain = AttestationChain(db_path=str(tmp_path / "occurrence_gap_chain.db"))
    receipt = chain.issue(
        transaction_id="txn_occurrence_gap",
        flags_triggered={"HIPAA_PHI_DATE": 1},
        flags_redacted={"HIPAA_PHI_DATE": 1},
        char_count_in=40,
        char_count_out=40,
        detectors_executed=result.detectors_executed,
        occurrence_gaps=result.occurrence_gaps,
    )

    assert receipt.occurrence_gaps == {cfr: 1}
    assert receipt.zero_pii_egress_confirmed is False

    # api wiring path: same ScrubberResult must also yield False via helper
    # (uses global chain — only assert the confirmation flag).
    api_receipt = _issue_scrub_attestation("txn_occurrence_gap_api", result)
    assert api_receipt.occurrence_gaps == {cfr: 1}
    assert api_receipt.zero_pii_egress_confirmed is False
