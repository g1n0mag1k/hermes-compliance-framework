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
