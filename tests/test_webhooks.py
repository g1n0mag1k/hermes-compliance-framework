import json
import os
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from hermes.attestation import ComplianceReceipt
from hermes.webhooks import (
    WEBHOOK_AUTH_HEADER_ENV_VAR,
    WEBHOOK_AUTH_VALUE_ENV_VAR,
    WEBHOOK_URL_ENV_VAR,
    build_event_payload,
    dispatch_webhook,
)


def _sample_receipt() -> ComplianceReceipt:
    return ComplianceReceipt(
        receipt_id="rcpt_test_000001",
        transaction_id="txn_test_abc123",
        issued_at="2026-07-04T12:00:00+00:00",
        issuer="Hermes Relay v1.0.0 -- hermesrelay.dev",
        compliance_frameworks=["HIPAA", "PCI-DSS"],
        pii_classes_detected=["HIPAA_SSN", "HIPAA_NAME"],
        pii_classes_redacted=["HIPAA_SSN", "HIPAA_NAME"],
        payload_char_count_in=100,
        payload_char_count_out=80,
        chars_removed=20,
        zero_pii_egress_confirmed=True,
        downstream_target=None,
        previous_receipt_hash="genesis_hash",
        receipt_hash="receipt_hash_abc",
        chain_position=0,
    )


@pytest.fixture(autouse=True)
def _clear_webhook_env(monkeypatch):
    """Ensure no leftover env state from one test bleeds into the next."""
    monkeypatch.delenv(WEBHOOK_URL_ENV_VAR, raising=False)
    monkeypatch.delenv(WEBHOOK_AUTH_HEADER_ENV_VAR, raising=False)
    monkeypatch.delenv(WEBHOOK_AUTH_VALUE_ENV_VAR, raising=False)


def test_build_event_payload_contains_expected_fields():
    receipt = _sample_receipt()
    payload = build_event_payload(receipt, event_type="scrub")

    assert payload["event_type"] == "scrub"
    assert payload["source"] == "hermes-relay"
    assert payload["receipt_id"] == receipt.receipt_id
    assert payload["transaction_id"] == receipt.transaction_id
    assert payload["pii_classes_detected"] == receipt.pii_classes_detected
    assert payload["zero_pii_egress_confirmed"] is True
    assert payload["chain_position"] == 0
    assert payload["receipt_hash"] == receipt.receipt_hash


def test_dispatch_webhook_is_noop_when_url_not_configured():
    """No HERMES_WEBHOOK_URL set -- dispatch must return False and must not attempt any network call."""
    receipt = _sample_receipt()
    with patch("urllib.request.urlopen") as mock_urlopen:
        result = dispatch_webhook(receipt)
        assert result is False
        mock_urlopen.assert_not_called()


def test_dispatch_webhook_posts_json_when_url_configured(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV_VAR, "https://example.com/webhook")
    receipt = _sample_receipt()

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        result = dispatch_webhook(receipt)

    assert result is True
    assert mock_urlopen.called
    sent_request = mock_urlopen.call_args[0][0]
    assert sent_request.full_url == "https://example.com/webhook"
    sent_payload = json.loads(sent_request.data.decode("utf-8"))
    assert sent_payload["receipt_id"] == receipt.receipt_id


def test_dispatch_webhook_includes_configured_auth_header(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV_VAR, "https://example.com/webhook")
    monkeypatch.setenv(WEBHOOK_AUTH_HEADER_ENV_VAR, "Authorization")
    monkeypatch.setenv(WEBHOOK_AUTH_VALUE_ENV_VAR, "Splunk abc123")
    receipt = _sample_receipt()

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        dispatch_webhook(receipt)

    sent_request = mock_urlopen.call_args[0][0]
    assert sent_request.get_header("Authorization") == "Splunk abc123"


def test_dispatch_webhook_handles_non_2xx_gracefully(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV_VAR, "https://example.com/webhook")
    receipt = _sample_receipt()

    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        result = dispatch_webhook(receipt)

    assert result is False


def test_dispatch_webhook_never_raises_on_network_failure(monkeypatch):
    """A downstream SIEM/webhook outage must never propagate as an exception --
    scrubbing must succeed regardless of webhook delivery status."""
    monkeypatch.setenv(WEBHOOK_URL_ENV_VAR, "https://unreachable.example.com/webhook")
    receipt = _sample_receipt()

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
        result = dispatch_webhook(receipt)

    assert result is False
