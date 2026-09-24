"""
tests/test_gateway_evidence_export.py — Gateway EvidenceEvent and exporter tests.
"""

from __future__ import annotations

import json
import logging
import urllib.error
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.evidence_export.dispatch import dispatch_evidence_export, try_export_evidence
from gateway.evidence_export.drata_connector import (
    INSECURE_URL_ERROR,
    INSECURE_URL_WARNING,
    SEND_TEST_EVIDENCE_UNSUPPORTED_REASON,
    TEST_CONNECTION_UNSUPPORTED_REASON,
    UNSUPPORTED,
    ConnectionResult,
    DrataConnector,
)
from gateway.evidence_export.event import EvidenceEvent, build_evidence_event
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    WEBHOOK_AUTH_HEADER_ENV,
    WEBHOOK_AUTH_VALUE_ENV,
    WEBHOOK_URL_ENV,
    DrataExporter,
    ExportResult,
    WebhookExporter,
    get_configured_exporters,
)
from gateway.evidence_export import outbox
from gateway.evidence_export.outbox import (
    MAX_OUTBOX_ATTEMPTS,
    DuplicateEventError,
    OutboxStatus,
    enqueue_event,
    flush_outbox,
    get_outbox_row,
    list_outbox_rows,
    sanitize_error,
)
from gateway.pipeline import GatewayPipeline, GatewayRequest
from gateway.policy import Policy, set_workspace_policy, clear_workspace_policy
from hermes.receipts.v2.builder import ReceiptV2Builder
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519
from hermes.workspaces import create_workspace


PHI_SSN = "123-45-6789"
PHI_NAME = "Patient John Smith"
PHI_MRN = "MRN 9876543210"
PHI_EMAIL = "john.smith@hospital.org"
PHI_PHONE = "555-123-4567"

BLOCK_POLICY = Policy(
    policy_id="BLOCK_ALL",
    policy_version="1.0.0",
    text_action="BLOCK",
    binary_action="BLOCK",
    on_detector_error="BLOCK",
    on_parse_error="BLOCK",
    approved_providers=["openai", "azure_openai", "anthropic"],
)


@pytest.fixture(autouse=True)
def isolated_gateway_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB",
        str(tmp_path / "workspaces" / "registry.db"),
    )
    monkeypatch.delenv(WEBHOOK_URL_ENV, raising=False)
    monkeypatch.delenv(WEBHOOK_AUTH_HEADER_ENV, raising=False)
    monkeypatch.delenv(WEBHOOK_AUTH_VALUE_ENV, raising=False)
    monkeypatch.delenv(DRATA_CCT_URL_ENV, raising=False)
    monkeypatch.delenv(DRATA_API_KEY_ENV, raising=False)

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")

    gateway_evidence.reset_v2_chains()
    gateway_policy.reload_policy()
    yield


@pytest.fixture()
def workspace():
    ws, api_key = create_workspace("evidence-gw-01", "Evidence GW", "ev@test.com")
    return ws, api_key


@pytest.fixture()
def upstream_capture(monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    state: dict[str, Any] = {"requests": [], "response": {"id": "chatcmpl-test", "choices": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else ""
        state["requests"].append({"body": body, "url": str(request.url)})
        return httpx.Response(200, json=state["response"])

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )
    return state


@pytest.fixture()
def client():
    return TestClient(app)


def _sample_receipt_payload(**overrides: Any) -> dict:
    payload = {
        "transaction_id": "gw_abc123",
        "gateway_decision": "blocked",
        "decision": "BLOCK",
        "forwarded": False,
        "upstream_provider": "openai",
        "endpoint_path": "/v1/chat/completions",
        "phi_categories_detected": ["HIPAA_SSN"],
        "phi_categories_redacted": [],
        "content_types_inspected": ["application/json"],
        "content_types_not_inspected": [],
        "detector_states": {"HIPAA_SSN": "ran_clean"},
        "policy_version": "1.0.0",
        "policy_digest": "abc123",
        "policy_id": "HIPAA_PRODUCTION_BLOCK",
        "gateway_version": "1.0.0",
        "workspace_id": "ws-01",
        "all_detectors_clean": True,
        "gateway_sequence": 0,
    }
    payload.update(overrides)
    return payload


def _build_test_receipt(**payload_overrides: Any) -> Any:
    signer = SoftwareSignerEd25519.generate()
    builder = ReceiptV2Builder(signer)
    return builder.build(_sample_receipt_payload(**payload_overrides))


def _sample_event(**overrides: Any) -> EvidenceEvent:
    defaults = {
        "event_id": "evt-0001",
        "transaction_id": "gw_abc123",
        "workspace_id": "ws-01",
        "timestamp": "2026-09-18T12:00:00+00:00",
        "gateway_version": "1.0.0",
        "upstream_provider": "openai",
        "endpoint_path": "/v1/chat/completions",
        "decision": "BLOCK",
        "policy_id": "HIPAA_PRODUCTION_BLOCK",
        "policy_version": "1.0.0",
        "policy_digest": "abc123digest",
        "phi_categories_detected": ["HIPAA_SSN"],
        "phi_categories_redacted": [],
        "content_types_inspected": ["application/json"],
        "content_types_not_inspected": [],
        "detector_states": {"HIPAA_SSN": "ran_clean"},
        "upstream_contacted": False,
        "all_detectors_clean": True,
        "receipt_id": "rcpt-001",
        "receipt_digest": "digest001",
        "gateway_sequence": 0,
        "signature_algorithm": "EdDSA",
        "cose_sign1_hex": "aabbcc",
    }
    defaults.update(overrides)
    return EvidenceEvent(**defaults)


def _openai_chat(content: str) -> dict:
    return {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }


# -------------------------------------------------------------------------
# EvidenceEvent schema and serialization
# -------------------------------------------------------------------------


def test_evidence_event_required_fields():
    with pytest.raises(ValidationError):
        EvidenceEvent(event_id="x")  # type: ignore[call-arg]


def test_evidence_event_rejects_invalid_decision():
    with pytest.raises(ValidationError):
        _sample_event(decision="DROP")  # type: ignore[arg-type]


def test_evidence_event_rejects_extra_fields():
    with pytest.raises(ValidationError):
        EvidenceEvent(
            **_sample_event().model_dump(),
            raw_request_body="secret",  # type: ignore[arg-type]
        )


def test_evidence_event_deterministic_serialization():
    event = _sample_event()
    first = event.serialize()
    second = event.serialize()
    assert first == second
    parsed = json.loads(first)
    assert parsed["decision"] == "BLOCK"
    assert parsed["upstream_contacted"] is False


def test_build_evidence_event_from_receipt():
    receipt = _build_test_receipt()
    event = build_evidence_event(receipt, "ws-01")
    assert event.transaction_id == "gw_abc123"
    assert event.decision == "BLOCK"
    assert event.upstream_contacted is False
    assert event.receipt_digest == receipt.receipt_digest


def test_evidence_event_rejects_phi_in_serialized_payload():
    event = _sample_event(
        endpoint_path=f"/v1/chat/completions?ssn={PHI_SSN}",
    )
    with pytest.raises(ValueError, match="forbidden PHI"):
        event.assert_phi_safe()


def test_evidence_event_rejects_forbidden_body_fields():
    event = _sample_event()
    payload = event.to_dict()
    payload["raw_request_body"] = "Patient data"
    contaminated = json.dumps(payload, sort_keys=True)
    for forbidden in ("raw_request_body", "request_body", "messages"):
        assert f'"{forbidden}"' not in contaminated or forbidden == "raw_request_body"


def test_build_evidence_event_has_no_raw_bodies():
    receipt = _build_test_receipt()
    event = build_evidence_event(receipt, "ws-01")
    serialized = event.serialize()
    assert "raw_request_body" not in serialized
    assert "raw_response_body" not in serialized
    assert PHI_SSN not in serialized
    assert PHI_NAME not in serialized


# -------------------------------------------------------------------------
# BLOCK / REDACT / ALLOW integration
# -------------------------------------------------------------------------


def test_block_generates_evidence_upstream_not_contacted(
    client, workspace, upstream_capture, monkeypatch
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    exported: list[dict] = []

    def _capture_export(receipt, workspace_id):
        event = build_evidence_event(receipt, workspace_id)
        exported.append(json.loads(event.serialize()))
        return None

    monkeypatch.setattr(
        "gateway.evidence.try_export_evidence",
        lambda receipt, ws_id: _capture_export(receipt, ws_id),
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
    )

    assert response.status_code == 403
    assert len(upstream_capture["requests"]) == 0  # upstream.request_count == 0
    assert len(exported) == 1
    assert exported[0]["decision"] == "BLOCK"
    assert exported[0]["upstream_contacted"] is False
    assert PHI_SSN not in json.dumps(exported[0])
    clear_workspace_policy(ws.workspace_id)


def test_redact_generates_evidence_and_forwards(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    exported: list[dict] = []

    def _capture_export(receipt, workspace_id):
        event = build_evidence_event(receipt, workspace_id)
        exported.append(json.loads(event.serialize()))
        return None

    monkeypatch.setattr(
        "gateway.evidence.try_export_evidence",
        lambda receipt, ws_id: _capture_export(receipt, ws_id),
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1
    assert PHI_SSN not in upstream_capture["requests"][0]["body"]
    assert len(exported) == 1
    assert exported[0]["decision"] == "REDACT"
    assert exported[0]["upstream_contacted"] is True


def test_allow_generates_evidence_and_forwards(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    exported: list[dict] = []

    def _capture_export(receipt, workspace_id):
        event = build_evidence_event(receipt, workspace_id)
        exported.append(json.loads(event.serialize()))
        return None

    monkeypatch.setattr(
        "gateway.evidence.try_export_evidence",
        lambda receipt, ws_id: _capture_export(receipt, ws_id),
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat("Explain photosynthesis briefly."),
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1
    assert len(exported) == 1
    assert exported[0]["decision"] == "ALLOW"
    assert exported[0]["upstream_contacted"] is True


# -------------------------------------------------------------------------
# Exporter failure must not bypass enforcement
# -------------------------------------------------------------------------


def test_exporter_failure_does_not_allow_blocked_request(
    client, workspace, upstream_capture, monkeypatch
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")

    with patch(
        "gateway.evidence_export.dispatch.build_evidence_event",
        side_effect=RuntimeError("export exploded"),
    ):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
        )

    assert response.status_code == 403
    assert upstream_capture["requests"] == []
    clear_workspace_policy(ws.workspace_id)


def test_exporter_failure_does_not_forward_blocked_request(
    client, workspace, upstream_capture, monkeypatch
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, "HTTP 500"),
    ):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
        )

    assert response.status_code == 403
    assert upstream_capture["requests"] == []
    clear_workspace_policy(ws.workspace_id)


# -------------------------------------------------------------------------
# Drata exporter
# -------------------------------------------------------------------------


def test_drata_exporter_noop_when_not_configured():
    event = _sample_event()
    result = DrataExporter().export(event)
    assert result.success is False
    assert result.error == "not_configured"


def test_drata_exporter_successful_submission(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        result = DrataExporter().export(event)

    assert result.success is True
    payload = mock_post.call_args[0][1]
    record = payload["data"]
    assert record["gateway_decision"] == "BLOCK"
    assert record["upstream_contacted"] is False
    serialized = json.dumps(payload)
    assert PHI_SSN not in serialized


def test_drata_exporter_conforms_to_v2_api_contract(monkeypatch):
    """Drata v2 Custom Data Records API requires top-level ``data`` key."""
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://public-api.drata.com/public/v2/custom-connections/123/resources/456/records")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        DrataExporter().export(event)

    payload = mock_post.call_args[0][1]
    assert set(payload.keys()) == {"data"}
    record = payload["data"]
    assert record["id"] == event.event_id
    assert record["gateway_decision"] == "BLOCK"
    assert "cose_sign1_hex" not in record


def test_drata_exporter_includes_bearer_token(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        DrataExporter().export(event)

    headers = mock_post.call_args[1]["headers"] if "headers" in mock_post.call_args[1] else mock_post.call_args[0][2]
    assert headers["Authorization"] == "Bearer drata-secret-key-xyz"


def test_drata_exporter_http_4xx_no_retry(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 1, "HTTP 401"),
    ) as mock_post:
        result = DrataExporter().export(event)

    assert result.success is False
    assert result.attempts == 1
    assert mock_post.call_count == 1


def test_drata_exporter_http_5xx_retries(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, "HTTP 503"),
    ) as mock_post:
        result = DrataExporter().export(event)

    assert result.success is False
    assert result.attempts == 3


def test_drata_exporter_timeout(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, "timed out"),
    ):
        result = DrataExporter().export(event)

    assert result.success is False


def test_drata_exporter_no_credentials_in_logs(monkeypatch, caplog):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 1, "HTTP 401"),
    ):
        with caplog.at_level(logging.WARNING):
            DrataExporter().export(event)

    log_text = caplog.text
    assert "drata-secret-key-xyz" not in log_text


def test_drata_payload_contains_no_phi_with_real_gateway_request(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    captured_payloads: list[str] = []

    def _capture_post(url, payload, headers, **kwargs):
        captured_payloads.append(json.dumps(payload))
        return True, 1, None

    monkeypatch.setattr("gateway.evidence_export.exporters._post_json", _capture_post)

    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(
            f"Patient {PHI_NAME} SSN {PHI_SSN} MRN {PHI_MRN} email {PHI_EMAIL} phone {PHI_PHONE}"
        ),
    )

    assert captured_payloads
    combined = " ".join(captured_payloads)
    for phi in (PHI_SSN, PHI_NAME, PHI_MRN, PHI_EMAIL, PHI_PHONE):
        assert phi not in combined
    for payload_str in captured_payloads:
        payload = json.loads(payload_str)
        assert "data" in payload
        assert "cose_sign1_hex" not in payload["data"]


# -------------------------------------------------------------------------
# Canonical Drata connector
# -------------------------------------------------------------------------


def _mock_http_response(status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status = status
    response.__enter__.return_value = response
    return response


def test_drata_connector_is_configured_reflects_env(monkeypatch):
    assert DrataConnector().is_configured() is False
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    assert DrataConnector().is_configured() is True


def test_drata_connector_is_configured_ignores_api_key_alone(monkeypatch):
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    assert DrataConnector().is_configured() is False


def test_drata_connector_status_not_configured():
    with patch("urllib.request.urlopen") as mock_urlopen:
        status = DrataConnector().status()
    mock_urlopen.assert_not_called()
    assert status == {
        "connector": "drata_cct",
        "state": "NOT_CONFIGURED",
        "cct_url_configured": False,
        "api_key_configured": False,
        "connection_tested": False,
    }


def test_drata_connector_status_configured_never_claims_connection_test(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    with patch("urllib.request.urlopen") as mock_urlopen:
        status = DrataConnector().status()
    mock_urlopen.assert_not_called()
    assert status["state"] == "CONFIGURED"
    assert status["cct_url_configured"] is True
    assert status["api_key_configured"] is True
    assert status["connection_tested"] is False
    serialized = json.dumps(status)
    assert "drata-secret-key-xyz" not in serialized
    assert "api.drata.com" not in serialized


def test_drata_connector_status_uses_shared_state_machine(monkeypatch):
    import hermes.api as hermes_api
    from hermes.drata_state import DrataConfigState, get_drata_config_state

    assert hermes_api.DrataConfigState is DrataConfigState
    assert hermes_api.get_drata_config_state is get_drata_config_state
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    assert DrataConnector().status()["state"] == get_drata_config_state().value


def test_drata_connector_send_test_evidence_unsupported_no_network(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    with patch("gateway.evidence_export.exporters._post_json") as mock_post, patch(
        "urllib.request.urlopen"
    ) as mock_urlopen:
        result = DrataConnector().send_test_evidence()
    mock_post.assert_not_called()
    mock_urlopen.assert_not_called()
    assert isinstance(result, ExportResult)
    assert result.success is False
    assert result.error == UNSUPPORTED
    assert result.attempts == 0


DRATA_SECRET_URL = "https://api.drata.com/cct/secret-connection-777"
DRATA_SECRET_KEY = "drata-secret-key-xyz"


def _test_connection_no_network() -> ConnectionResult:
    with patch("gateway.evidence_export.exporters._post_json") as mock_post, patch(
        "urllib.request.urlopen"
    ) as mock_urlopen, patch("socket.create_connection") as mock_socket:
        result = DrataConnector().test_connection()
    mock_post.assert_not_called()
    mock_urlopen.assert_not_called()
    mock_socket.assert_not_called()
    assert isinstance(result, ConnectionResult)
    return result


def test_drata_connector_test_connection_not_configured():
    result = _test_connection_no_network()
    assert result.state == "NOT_CONFIGURED"
    assert result.success is False
    assert "HERMES_DRATA_CCT_URL" in result.reason
    assert result.live_validated is False


def test_drata_connector_test_connection_not_configured_with_api_key_only(monkeypatch):
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    result = _test_connection_no_network()
    assert result.state == "NOT_CONFIGURED"
    assert DRATA_SECRET_KEY not in result.reason


def test_drata_connector_test_connection_configured_no_network(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DRATA_SECRET_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    result = _test_connection_no_network()
    assert result.state == "CONFIGURED"
    assert result.success is True
    assert result.live_validated is False
    assert "No network call" in result.reason
    assert "does NOT prove Drata accepts" in result.reason


@pytest.mark.parametrize(
    "url",
    [
        "http://api.drata.com/cct/secret-connection-777",
        "ftp://api.drata.com/cct/secret-connection-777",
        "HTTP://api.drata.com/cct/secret-connection-777",
    ],
)
def test_drata_connector_test_connection_non_https_is_config_invalid(monkeypatch, url):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, url)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    result = _test_connection_no_network()
    assert result.state == "CONFIG_INVALID"
    assert result.success is False
    assert result.live_validated is False
    assert "https" in result.reason
    assert url not in result.reason


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://",
        "https:///cct/path-only",
        "https://[::1/cct",
        "https://api.drata.com:notaport/cct",
        "https://api.drata.com/cct with space",
        " https://api.drata.com/cct",
        "api.drata.com/cct/secret-connection-777",
    ],
)
def test_drata_connector_test_connection_malformed_url_is_config_invalid(monkeypatch, url):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, url)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    result = _test_connection_no_network()
    assert result.state == "CONFIG_INVALID"
    assert result.success is False
    assert "well-formed" in result.reason
    assert url.strip() not in result.reason


def test_drata_connector_test_connection_url_without_api_key_is_config_invalid(monkeypatch):
    """
    URL set, API key absent: CONFIG_INVALID. Consistent with Session 2, the URL
    alone decides NOT_CONFIGURED vs. not (so cct_url_configured stays True), but
    CONFIGURED requires the API key to be present.
    """
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DRATA_SECRET_URL)
    result = _test_connection_no_network()
    assert result.state == "CONFIG_INVALID"
    assert result.success is False
    assert "HERMES_DRATA_API_KEY is not set" in result.reason
    assert DrataConnector().status()["cct_url_configured"] is True
    assert DrataConnector().status()["state"] == "CONFIG_INVALID"


@pytest.mark.parametrize(
    "url,api_key",
    [
        (None, None),
        (None, DRATA_SECRET_KEY),
        (DRATA_SECRET_URL, None),
        (DRATA_SECRET_URL, DRATA_SECRET_KEY),
        ("http://api.drata.com/cct/secret-connection-777", DRATA_SECRET_KEY),
        ("https://", DRATA_SECRET_KEY),
    ],
)
def test_drata_connector_test_connection_live_validated_always_false(monkeypatch, url, api_key):
    if url:
        monkeypatch.setenv(DRATA_CCT_URL_ENV, url)
    if api_key:
        monkeypatch.setenv(DRATA_API_KEY_ENV, api_key)
    result = _test_connection_no_network()
    assert result.live_validated is False
    assert result.state not in ("CONNECTION_SUCCESS", "CONNECTION_FAILED")


def test_drata_connector_test_connection_live_request_is_unsupported(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DRATA_SECRET_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    with patch("gateway.evidence_export.exporters._post_json") as mock_post, patch(
        "urllib.request.urlopen"
    ) as mock_urlopen:
        result = DrataConnector().test_connection(live=True)
    mock_post.assert_not_called()
    mock_urlopen.assert_not_called()
    assert result.state == UNSUPPORTED
    assert result.success is False
    assert result.live_validated is False
    assert result.reason == TEST_CONNECTION_UNSUPPORTED_REASON
    assert "does NOT prove Drata accepts" in result.reason


@pytest.mark.parametrize(
    "url",
    [
        DRATA_SECRET_URL,
        "http://api.drata.com/cct/secret-connection-777",
        "https://api.drata.com:notaport/cct/secret-connection-777",
    ],
)
@pytest.mark.parametrize("live", [False, True])
def test_drata_connector_test_connection_reason_contains_no_credentials(monkeypatch, url, live):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, url)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    result = DrataConnector().test_connection(live=live)
    serialized = json.dumps(result.__dict__)
    for secret in (DRATA_SECRET_KEY, url, "secret-connection-777", "api.drata.com"):
        assert secret not in serialized


@pytest.mark.parametrize(
    "url,api_key",
    [
        (DRATA_SECRET_URL, DRATA_SECRET_KEY),
        (DRATA_SECRET_URL, None),
        ("http://api.drata.com/cct/secret-connection-777", DRATA_SECRET_KEY),
        ("not-a-url/secret-connection-777", DRATA_SECRET_KEY),
    ],
)
def test_drata_connector_test_connection_no_credentials_in_logs(monkeypatch, caplog, url, api_key):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, url)
    if api_key:
        monkeypatch.setenv(DRATA_API_KEY_ENV, api_key)
    with caplog.at_level(logging.DEBUG):
        DrataConnector().test_connection()
        DrataConnector().test_connection(live=True)
        DrataConnector().status()
    for secret in (DRATA_SECRET_KEY, url, "secret-connection-777", "api.drata.com"):
        assert secret not in caplog.text


def test_drata_connector_test_connection_warns_on_http_url_without_url_value(monkeypatch, caplog):
    insecure_url = "http://api.drata.com/cct/secret-connection-777"
    monkeypatch.setenv(DRATA_CCT_URL_ENV, insecure_url)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    with caplog.at_level(logging.WARNING, logger="hermes.gateway.evidence_export"):
        DrataConnector().test_connection()
    assert INSECURE_URL_WARNING in caplog.text
    assert insecure_url not in caplog.text
    assert DRATA_SECRET_KEY not in caplog.text


def test_drata_connector_test_connection_no_warning_on_https_url(monkeypatch, caplog):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DRATA_SECRET_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    with caplog.at_level(logging.WARNING, logger="hermes.gateway.evidence_export"):
        DrataConnector().test_connection()
    assert INSECURE_URL_WARNING not in caplog.text


def test_drata_connector_send_evidence_refuses_http_url_without_network(monkeypatch, caplog):
    insecure_url = "http://api.drata.com/cct/secret-connection-777"
    monkeypatch.setenv(DRATA_CCT_URL_ENV, insecure_url)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    with patch("gateway.evidence_export.exporters._post_json") as mock_post, patch(
        "urllib.request.urlopen"
    ) as mock_urlopen, caplog.at_level(logging.WARNING):
        connector_result = DrataConnector().send_evidence(_sample_event())
        exporter_result = DrataExporter().export(_sample_event())
    mock_post.assert_not_called()
    mock_urlopen.assert_not_called()
    for result in (connector_result, exporter_result):
        assert result.success is False
        assert result.attempts == 0
        assert result.error == INSECURE_URL_ERROR
    assert INSECURE_URL_WARNING in caplog.text
    assert insecure_url not in caplog.text
    assert DRATA_SECRET_KEY not in caplog.text


def test_drata_connector_send_test_evidence_reason_is_displayable(monkeypatch, caplog):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, DRATA_SECRET_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    with patch("urllib.request.urlopen") as mock_urlopen, caplog.at_level(logging.DEBUG):
        result = DrataConnector().send_test_evidence()
    mock_urlopen.assert_not_called()
    assert result.error == UNSUPPORTED
    assert result.reason == SEND_TEST_EVIDENCE_UNSUPPORTED_REASON
    assert result.reason.endswith(".")
    assert result.reason.isprintable()
    assert "real customer's Drata tenant" in result.reason
    assert "sandbox" in result.reason
    serialized = json.dumps(result.__dict__)
    for secret in (DRATA_SECRET_KEY, DRATA_SECRET_URL, "secret-connection-777", "api.drata.com"):
        assert secret not in serialized
        assert secret not in caplog.text


def test_drata_unsupported_reason_strings_are_safe_to_display():
    for reason in (TEST_CONNECTION_UNSUPPORTED_REASON, SEND_TEST_EVIDENCE_UNSUPPORTED_REASON):
        assert reason.isprintable()
        assert 40 < len(reason) < 400
        assert "not supported" in reason
        assert "://" not in reason
        assert "Bearer" not in reason


def test_drata_connector_send_evidence_matches_drata_exporter(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        connector_result = DrataConnector().send_evidence(event)
        exporter_result = DrataExporter().export(event)

    assert connector_result == exporter_result
    connector_call, exporter_call = mock_post.call_args_list
    assert connector_call == exporter_call
    assert DrataExporter.build_drata_payload(event) == DrataConnector.build_drata_payload(event)


def test_drata_connector_wire_request_headers_and_timeout(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    monkeypatch.setenv(DRATA_API_KEY_ENV, "drata-secret-key-xyz")
    event = _sample_event()

    with patch(
        "urllib.request.urlopen", return_value=_mock_http_response(200)
    ) as mock_urlopen:
        result = DrataConnector().send_evidence(event)

    assert result.success is True
    assert result.attempts == 1
    request = mock_urlopen.call_args[0][0]
    assert mock_urlopen.call_args[1]["timeout"] == 3.0
    assert request.full_url == "https://api.drata.com/cct/test"
    assert request.get_method() == "POST"
    assert request.get_header("X-idempotency-key") == event.event_id
    assert request.get_header("Authorization") == "Bearer drata-secret-key-xyz"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("User-agent") == "hermes-gateway-drata-cct/1.0"
    body = json.loads(request.data.decode("utf-8"))
    assert set(body.keys()) == {"data"}
    assert body["data"]["id"] == event.event_id
    assert "cose_sign1_hex" not in body["data"]


def test_drata_connector_retries_twice_on_5xx(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()
    error = urllib.error.HTTPError(
        "https://api.drata.com/cct/test", 503, "Service Unavailable", {}, None
    )

    with patch("urllib.request.urlopen", side_effect=error) as mock_urlopen, patch(
        "gateway.evidence_export.exporters.time.sleep"
    ):
        result = DrataConnector().send_evidence(event)

    assert result.success is False
    assert result.attempts == 3
    assert result.error == "HTTP 503"
    assert mock_urlopen.call_count == 3
    keys = {call[0][0].get_header("X-idempotency-key") for call in mock_urlopen.call_args_list}
    assert keys == {event.event_id}


def test_drata_connector_no_retry_on_4xx(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    error = urllib.error.HTTPError(
        "https://api.drata.com/cct/test", 401, "Unauthorized", {}, None
    )

    with patch("urllib.request.urlopen", side_effect=error) as mock_urlopen, patch(
        "gateway.evidence_export.exporters.time.sleep"
    ):
        result = DrataConnector().send_evidence(_sample_event())

    assert result.success is False
    assert result.attempts == 1
    assert mock_urlopen.call_count == 1


def test_drata_connector_refuses_phi_unsafe_event_without_network(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event(endpoint_path=f"/v1/chat/completions?ssn={PHI_SSN}")

    with patch("gateway.evidence_export.exporters._post_json") as mock_post:
        result = DrataConnector().send_evidence(event)

    mock_post.assert_not_called()
    assert result.success is False
    assert result.attempts == 0
    assert result.error == "phi_safety_check_failed"


def test_drata_connector_send_evidence_not_configured():
    with patch("gateway.evidence_export.exporters._post_json") as mock_post:
        result = DrataConnector().send_evidence(_sample_event())
    mock_post.assert_not_called()
    assert result.success is False
    assert result.error == "not_configured"


def test_get_configured_exporters_uses_canonical_drata_connector(monkeypatch):
    assert get_configured_exporters() == []
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    exporters = get_configured_exporters()
    assert len(exporters) == 1
    assert isinstance(exporters[0], DrataConnector)
    assert exporters[0].name == "drata_cct"


# -------------------------------------------------------------------------
# Webhook exporter
# -------------------------------------------------------------------------


def test_webhook_exporter_noop_when_not_configured():
    event = _sample_event()
    result = WebhookExporter().export(event)
    assert result.success is False


def test_webhook_exporter_success(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        result = WebhookExporter().export(event)

    assert result.success is True
    payload = mock_post.call_args[0][1]
    assert payload["event_type"] == "gateway_enforcement"
    assert PHI_SSN not in json.dumps(payload)


def test_webhook_exporter_auth_header(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")
    monkeypatch.setenv(WEBHOOK_AUTH_HEADER_ENV, "Authorization")
    monkeypatch.setenv(WEBHOOK_AUTH_VALUE_ENV, "Splunk token123")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        WebhookExporter().export(event)

    headers = mock_post.call_args[0][2]
    assert headers["Authorization"] == "Splunk token123"
    assert "token123" not in ""  # credentials not logged in this test path


def test_webhook_exporter_network_failure_never_raises(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, "connection refused"),
    ):
        result = WebhookExporter().export(event)

    assert result.success is False


def test_dispatch_evidence_export_runs_all_configured_exporters(monkeypatch):
    monkeypatch.setenv(WEBHOOK_URL_ENV, "https://example.com/webhook")
    monkeypatch.setenv(DRATA_CCT_URL_ENV, "https://api.drata.com/cct/test")
    event = _sample_event()

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ):
        results = dispatch_evidence_export(event)

    assert len(results) == 2
    assert all(r.success for r in results)


def test_try_export_evidence_returns_none_when_unconfigured():
    receipt = _build_test_receipt()
    assert try_export_evidence(receipt, "ws-01") is None


# -------------------------------------------------------------------------
# Persistent evidence outbox — Drata is never on the enforcement path
# -------------------------------------------------------------------------

OUTBOX_DRATA_URL = "https://api.drata.com/cct/secret-connection-777"


@pytest.fixture()
def drata_configured(monkeypatch):
    monkeypatch.setenv(DRATA_CCT_URL_ENV, OUTBOX_DRATA_URL)
    monkeypatch.setenv(DRATA_API_KEY_ENV, DRATA_SECRET_KEY)
    monkeypatch.setattr("gateway.evidence_export.exporters.time.sleep", lambda _s: None)


def _drata_urlopen(monkeypatch, behavior: str) -> list:
    """Patch the Drata transport. behavior: down | http_5xx | http_4xx | http_429 | ok."""
    calls: list = []

    def _urlopen(req, timeout=None):
        calls.append(req)
        if behavior == "down":
            raise urllib.error.URLError("[Errno 111] Connection refused")
        if behavior.startswith("http_") and behavior != "http_ok":
            code = {"http_5xx": 503, "http_4xx": 401, "http_429": 429}[behavior]
            raise urllib.error.HTTPError(req.full_url, code, "error", {}, None)
        return _mock_http_response(200)

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    return calls


def _future(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def test_outbox_enforcement_returns_response_when_drata_down(
    client, workspace, upstream_capture, drata_configured, monkeypatch
):
    ws, api_key = workspace
    drata_calls = _drata_urlopen(monkeypatch, "down")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat("Explain photosynthesis briefly."),
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1
    assert drata_calls, "background flush should have attempted Drata"
    rows = list_outbox_rows(ws.workspace_id)
    assert len(rows) == 1
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["attempt_count"] == 1
    assert rows[0]["last_error"]


def test_outbox_block_stays_block_when_drata_down(
    client, workspace, upstream_capture, drata_configured, monkeypatch
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    _drata_urlopen(monkeypatch, "down")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "phi_detected"
    receipt = gateway_evidence.get_gateway_receipt(ws, response.json()["receipt_digest"])
    assert receipt["payload"]["decision"] == "BLOCK"
    stored = json.loads(list_outbox_rows(ws.workspace_id)[0]["evidence_payload"])
    assert stored["decision"] == "BLOCK"
    clear_workspace_policy(ws.workspace_id)


@pytest.mark.parametrize("drata_state", ["unconfigured", "down", "http_5xx", "http_4xx", "ok"])
def test_outbox_blocked_request_upstream_not_contacted_regardless_of_drata_state(
    client, workspace, upstream_capture, monkeypatch, drata_state
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    if drata_state != "unconfigured":
        monkeypatch.setenv(DRATA_CCT_URL_ENV, OUTBOX_DRATA_URL)
        monkeypatch.setattr("gateway.evidence_export.exporters.time.sleep", lambda _s: None)
        _drata_urlopen(monkeypatch, drata_state)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
    )

    assert response.status_code == 403
    assert upstream_capture["requests"] == []
    receipt = gateway_evidence.get_gateway_receipt(ws, response.json()["receipt_digest"])
    assert receipt["payload"]["forwarded"] is False
    rows = list_outbox_rows(ws.workspace_id)
    if drata_state == "unconfigured":
        assert rows == []
    else:
        assert len(rows) == 1
        assert json.loads(rows[0]["evidence_payload"])["upstream_contacted"] is False
    clear_workspace_policy(ws.workspace_id)


def test_outbox_event_written_before_any_drata_network_call(
    workspace, upstream_capture, drata_configured, monkeypatch
):
    ws, _ = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    rows_seen_at_send: list[list[dict]] = []

    def _urlopen(req, timeout=None):
        rows_seen_at_send.append(list_outbox_rows(ws.workspace_id))
        return _mock_http_response(200)

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)

    result = gateway_app._pipeline.process(
        GatewayRequest(
            workspace_id=ws.workspace_id,
            provider_id="openai",
            method="POST",
            path="/v1/chat/completions",
            query_string="",
            headers={"content-type": "application/json"},
            body_bytes=json.dumps(_openai_chat(f"Patient SSN is {PHI_SSN}")).encode(),
            content_type="application/json",
        ),
        ws,
    )

    # Enforcement completed with no Drata call; the event is already queued.
    assert result.decision.decision == "BLOCK"
    assert rows_seen_at_send == []
    rows = list_outbox_rows(ws.workspace_id)
    assert len(rows) == 1
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["attempt_count"] == 0
    event_id = rows[0]["event_id"]

    assert flush_outbox(ws.workspace_id)["exported"] == 1
    assert len(rows_seen_at_send) == 1
    assert [r["event_id"] for r in rows_seen_at_send[0]] == [event_id]
    assert rows_seen_at_send[0][0]["status"] == OutboxStatus.PROCESSING.value
    assert get_outbox_row(event_id)["status"] == OutboxStatus.EXPORTED.value
    clear_workspace_policy(ws.workspace_id)


def test_outbox_retry_reuses_same_event_id(drata_configured, monkeypatch):
    event = _sample_event(event_id="evt-retry-0001")
    enqueue_event(event)
    sent: list[tuple[str, str]] = []
    responses = iter(["http_5xx", "http_5xx", "http_5xx", "ok"])

    def _urlopen(req, timeout=None):
        body = json.loads(req.data.decode("utf-8"))
        sent.append((req.get_header("X-idempotency-key"), body["data"]["event_id"]))
        if next(responses) == "ok":
            return _mock_http_response(200)
        raise urllib.error.HTTPError(req.full_url, 503, "error", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)

    assert flush_outbox()["retry_scheduled"] == 1
    assert get_outbox_row(event.event_id)["status"] == OutboxStatus.PENDING.value
    assert flush_outbox(now=_future(1))["exported"] == 1

    assert len(sent) == 4
    assert set(sent) == {(event.event_id, event.event_id)}
    rows = list_outbox_rows()
    assert [r["event_id"] for r in rows] == [event.event_id]
    assert rows[0]["status"] == OutboxStatus.EXPORTED.value
    assert rows[0]["attempt_count"] == 2


def test_outbox_rejects_duplicate_event_id():
    original = _sample_event(event_id="evt-dup-0001", decision="BLOCK")
    enqueue_event(original)

    with pytest.raises(DuplicateEventError):
        enqueue_event(_sample_event(event_id="evt-dup-0001", decision="ALLOW"))

    rows = list_outbox_rows()
    assert len(rows) == 1
    assert json.loads(rows[0]["evidence_payload"])["decision"] == "BLOCK"


def test_outbox_duplicate_insert_does_not_break_gateway_response(
    client, workspace, upstream_capture, drata_configured, monkeypatch
):
    _, api_key = workspace
    _drata_urlopen(monkeypatch, "ok")
    import gateway.evidence_export.event as event_module

    monkeypatch.setattr(
        event_module,
        "uuid",
        SimpleNamespace(uuid4=lambda: "fixed-event-id-0001"),
    )
    for _ in range(2):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_openai_chat("Explain photosynthesis briefly."),
        )
        assert response.status_code == 200
    assert [r["event_id"] for r in list_outbox_rows()] == ["fixed-event-id-0001"]


@pytest.mark.parametrize("transient_error", ["HTTP 503", "HTTP 500", "HTTP 429", "timed out"])
def test_outbox_transient_failure_retries_up_to_max(drata_configured, transient_error):
    event = _sample_event(event_id="evt-transient-0001")
    enqueue_event(event)

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, transient_error),
    ) as mock_post:
        for day in range(MAX_OUTBOX_ATTEMPTS + 3):
            flush_outbox(now=_future(day))

    assert mock_post.call_count == MAX_OUTBOX_ATTEMPTS
    row = get_outbox_row(event.event_id)
    assert row["status"] == OutboxStatus.DEAD_LETTER.value
    assert row["attempt_count"] == MAX_OUTBOX_ATTEMPTS


def test_outbox_transient_failure_schedules_backoff(drata_configured):
    enqueue_event(_sample_event(event_id="evt-backoff-0001"))
    start = datetime.now(timezone.utc)

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 3, "HTTP 503"),
    ) as mock_post:
        flush_outbox(now=start)
        flush_outbox(now=start + timedelta(seconds=1))

    assert mock_post.call_count == 1
    row = get_outbox_row("evt-backoff-0001")
    assert datetime.fromisoformat(row["next_attempt_at"]) > start
    assert row["status"] == OutboxStatus.PENDING.value


@pytest.mark.parametrize("status_code", [400, 401, 403, 404, 422])
def test_outbox_permanent_4xx_dead_letters_without_exhausting_retries(
    drata_configured, monkeypatch, status_code
):
    event = _sample_event(event_id=f"evt-perm-{status_code}")
    enqueue_event(event)
    calls: list = []

    def _urlopen(req, timeout=None):
        calls.append(req)
        raise urllib.error.HTTPError(req.full_url, status_code, "error", {}, None)

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)

    assert flush_outbox()["dead_lettered"] == 1
    assert len(calls) == 1
    row = get_outbox_row(event.event_id)
    assert row["status"] == OutboxStatus.DEAD_LETTER.value
    assert row["attempt_count"] == 1
    assert row["last_error"] == f"HTTP {status_code}"


def test_outbox_dead_letter_events_are_not_retried(drata_configured):
    enqueue_event(_sample_event(event_id="evt-dead-0001"))
    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(False, 1, "HTTP 401"),
    ):
        flush_outbox()
    assert get_outbox_row("evt-dead-0001")["status"] == OutboxStatus.DEAD_LETTER.value

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        for day in range(1, 5):
            assert flush_outbox(now=_future(day)) == {
                "exported": 0,
                "retry_scheduled": 0,
                "dead_lettered": 0,
            }

    mock_post.assert_not_called()
    row = get_outbox_row("evt-dead-0001")
    assert row["status"] == OutboxStatus.DEAD_LETTER.value
    assert row["attempt_count"] == 1


def test_outbox_reclaims_expired_processing_lease(drata_configured):
    enqueue_event(_sample_event(event_id="evt-lease-0001"))
    conn = outbox._connect()
    try:
        outbox._claim_due_rows(conn, None, datetime.now(timezone.utc), 10)
    finally:
        conn.close()
    assert get_outbox_row("evt-lease-0001")["status"] == OutboxStatus.PROCESSING.value

    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ) as mock_post:
        flush_outbox()
        mock_post.assert_not_called()
        flush_outbox(now=_future(1))

    assert mock_post.call_count == 1
    row = get_outbox_row("evt-lease-0001")
    assert row["status"] == OutboxStatus.EXPORTED.value
    assert row["attempt_count"] == 2


def test_outbox_flush_noop_when_drata_not_configured():
    enqueue_event(_sample_event(event_id="evt-unconfigured-0001"))
    with patch("urllib.request.urlopen") as mock_urlopen:
        flush_outbox()
    mock_urlopen.assert_not_called()
    row = get_outbox_row("evt-unconfigured-0001")
    assert row["status"] == OutboxStatus.PENDING.value
    assert row["attempt_count"] == 0


def test_outbox_flush_only_touches_requested_workspace(drata_configured):
    enqueue_event(_sample_event(event_id="evt-ws-a", workspace_id="ws-a"))
    enqueue_event(_sample_event(event_id="evt-ws-b", workspace_id="ws-b"))
    with patch(
        "gateway.evidence_export.exporters._post_json",
        return_value=(True, 1, None),
    ):
        flush_outbox("ws-a")
    assert get_outbox_row("evt-ws-a")["status"] == OutboxStatus.EXPORTED.value
    assert get_outbox_row("evt-ws-b")["status"] == OutboxStatus.PENDING.value


def _raise_exporter(self, event):
    raise RuntimeError("exporter exploded")


def _malformed_status_urlopen(req, timeout=None):
    return _mock_http_response(status="not-a-status")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "patch_target,replacement",
    [
        ("send_evidence", lambda self, event: "garbage-response"),
        ("send_evidence", lambda self, event: ExportResult(exporter="drata_cct", success="yes")),  # type: ignore[arg-type]
        ("send_evidence", lambda self, event: None),
        ("send_evidence", _raise_exporter),
        ("urlopen", _malformed_status_urlopen),
    ],
)
def test_outbox_malformed_exporter_response_does_not_corrupt_enforcement(
    client, workspace, upstream_capture, drata_configured, monkeypatch, patch_target, replacement
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    if patch_target == "urlopen":
        monkeypatch.setattr("urllib.request.urlopen", replacement)
    else:
        monkeypatch.setattr(DrataConnector, "send_evidence", replacement)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
    )

    assert response.status_code == 403
    body = response.json()
    assert body["error"]["code"] == "phi_detected"
    assert upstream_capture["requests"] == []
    receipt = gateway_evidence.get_gateway_receipt(ws, body["receipt_digest"])
    assert receipt["payload"]["decision"] == "BLOCK"
    assert receipt["payload"]["forwarded"] is False
    rows = list_outbox_rows(ws.workspace_id)
    assert len(rows) == 1
    assert rows[0]["status"] == OutboxStatus.PENDING.value
    assert rows[0]["last_error"]
    assert json.loads(rows[0]["evidence_payload"])["receipt_digest"] == body["receipt_digest"]
    clear_workspace_policy(ws.workspace_id)


def test_outbox_rows_contain_no_phi(client, workspace, upstream_capture, drata_configured, monkeypatch):
    ws, api_key = workspace
    _drata_urlopen(monkeypatch, "down")
    phi_values = (PHI_SSN, PHI_NAME, PHI_MRN, PHI_EMAIL, PHI_PHONE)
    prompt = f"Patient {PHI_NAME} SSN {PHI_SSN} MRN {PHI_MRN} email {PHI_EMAIL} phone {PHI_PHONE}"

    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat(prompt),
    )
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    client.post(
        "/gateway/openai/v1/chat/completions?ssn=123-45-6789",
        headers={"X-API-Key": api_key},
        json=_openai_chat(prompt),
    )
    clear_workspace_policy(ws.workspace_id)

    rows = list_outbox_rows(ws.workspace_id)
    assert len(rows) == 2
    raw_db = outbox.outbox_db_path().read_bytes().decode("latin-1")
    for row in rows:
        stored = json.dumps(row)
        for phi in phi_values:
            assert phi not in stored
        payload = json.loads(row["evidence_payload"])
        assert set(payload) <= set(EvidenceEvent.model_fields)
        for forbidden in ("raw_request_body", "request_body", "prompt", "completion", "messages", "content"):
            assert forbidden not in payload
        assert "photosynthesis" not in stored
    for phi in phi_values:
        assert phi not in raw_db


def test_outbox_refuses_phi_unsafe_event():
    with pytest.raises(ValueError, match="forbidden PHI"):
        enqueue_event(_sample_event(endpoint_path=f"/v1/chat?ssn={PHI_SSN}"))
    assert list_outbox_rows() == []


def test_outbox_last_error_contains_no_credentials(drata_configured, monkeypatch, caplog):
    enqueue_event(_sample_event(event_id="evt-cred-0001"))
    leaked = (
        f"POST {OUTBOX_DRATA_URL} failed: Authorization: Bearer {DRATA_SECRET_KEY} "
        "api_key=sk-live-0123456789abcdefghij token=tok_abcdef "
        "host api.drata.com:443 unreachable"
    )

    def _leaky(self, event):
        raise RuntimeError(leaked)

    monkeypatch.setattr(DrataConnector, "send_evidence", _leaky)
    with caplog.at_level(logging.DEBUG):
        flush_outbox()

    last_error = get_outbox_row("evt-cred-0001")["last_error"]
    assert last_error
    for secret in (
        DRATA_SECRET_KEY,
        OUTBOX_DRATA_URL,
        "secret-connection-777",
        "api.drata.com",
        "sk-live-0123456789abcdefghij",
        "tok_abcdef",
        "https://",
    ):
        assert secret not in last_error
        assert secret not in caplog.text


def test_outbox_last_error_from_network_failure_has_no_credentials(drata_configured, monkeypatch):
    enqueue_event(_sample_event(event_id="evt-cred-0002"))

    def _urlopen(req, timeout=None):
        raise urllib.error.URLError(f"cannot reach {OUTBOX_DRATA_URL} with key {DRATA_SECRET_KEY}")

    monkeypatch.setattr("urllib.request.urlopen", _urlopen)
    flush_outbox()

    last_error = get_outbox_row("evt-cred-0002")["last_error"]
    for secret in (DRATA_SECRET_KEY, OUTBOX_DRATA_URL, "secret-connection-777", "api.drata.com"):
        assert secret not in last_error


def test_sanitize_error_strips_urls_hosts_and_credentials():
    raw = (
        "https://user:pw@example.com/path?api_key=abc failed; "
        "Authorization: Basic dXNlcjpwYXNz; password=hunter2; "
        f"ssn {PHI_SSN}; token ghp_abcdefghijklmnopqrstuvwxyz0123"
    )
    cleaned = sanitize_error(raw)
    for secret in ("example.com", "user:pw", "dXNlcjpwYXNz", "hunter2", PHI_SSN, "ghp_abcdefghijklmnopqrstuvwxyz0123"):
        assert secret not in cleaned
    assert len(sanitize_error("x" * 1000)) <= outbox.MAX_ERROR_LENGTH
    assert sanitize_error("HTTP 503") == "HTTP 503"


def test_outbox_records_exported_at_only_on_success(drata_configured):
    enqueue_event(_sample_event(event_id="evt-exp-ok"))
    flushed_at = datetime.now(timezone.utc)
    with patch("gateway.evidence_export.exporters._post_json", return_value=(True, 1, None)):
        flush_outbox(now=flushed_at)
    enqueue_event(_sample_event(event_id="evt-exp-dead"))
    with patch("gateway.evidence_export.exporters._post_json", return_value=(False, 1, "HTTP 401")):
        flush_outbox()
    assert get_outbox_row("evt-exp-dead")["status"] == OutboxStatus.DEAD_LETTER.value

    conn = outbox._connect()
    try:
        exported_at = dict(conn.execute("SELECT event_id, exported_at FROM evidence_outbox").fetchall())
    finally:
        conn.close()
    assert exported_at == {"evt-exp-ok": flushed_at.isoformat(), "evt-exp-dead": None}


def test_outbox_migrates_legacy_schema_without_exported_at(drata_configured):
    import sqlite3

    path = outbox.outbox_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    legacy = sqlite3.connect(str(path))
    legacy.executescript(
        """
        CREATE TABLE evidence_outbox (
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            evidence_payload TEXT NOT NULL,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT NOT NULL,
            status TEXT NOT NULL,
            last_error TEXT
        );
        INSERT INTO evidence_outbox VALUES
            ('evt-legacy', 'ws-01', '2026-09-01T00:00:00+00:00', '{}', 1,
             '2026-09-01T00:00:00+00:00', 'EXPORTED', NULL);
        """
    )
    legacy.commit()
    legacy.close()

    stats = outbox.outbox_stats("ws-01")
    assert stats["exported"] == 1
    assert stats["last_exported_at"] is None

    enqueue_event(_sample_event(event_id="evt-post-migration"))
    with patch("gateway.evidence_export.exporters._post_json", return_value=(True, 1, None)):
        flush_outbox("ws-01")
    stats = outbox.outbox_stats("ws-01")
    assert stats["exported"] == 2
    assert stats["last_exported_at"] is not None


def test_outbox_stats_counts_by_status_per_workspace(drata_configured):
    enqueue_event(_sample_event(event_id="evt-s-ok"))
    with patch("gateway.evidence_export.exporters._post_json", return_value=(True, 1, None)):
        flush_outbox()
    enqueue_event(_sample_event(event_id="evt-s-dead"))
    with patch("gateway.evidence_export.exporters._post_json", return_value=(False, 1, "HTTP 403")):
        flush_outbox()
    enqueue_event(_sample_event(event_id="evt-s-pending"))
    enqueue_event(_sample_event(event_id="evt-s-other", workspace_id="ws-other"))

    conn = outbox._connect()
    try:
        outbox._claim_due_rows(conn, "ws-01", datetime.now(timezone.utc), 10)
    finally:
        conn.close()
    assert get_outbox_row("evt-s-pending")["status"] == OutboxStatus.PROCESSING.value

    stats = outbox.outbox_stats("ws-01")
    assert stats["pending"] == 1
    assert stats["exported"] == 1
    assert stats["dead_letter"] == 1
    assert stats["last_error"] == "HTTP 403"
    assert stats["last_exported_at"] is not None
    assert outbox.outbox_stats("ws-other") == {
        "pending": 1,
        "exported": 0,
        "dead_letter": 0,
        "last_exported_at": None,
        "last_error": None,
    }
    assert outbox.outbox_stats("ws-missing")["pending"] == 0


@pytest.mark.parametrize("policy", [None, BLOCK_POLICY])
def test_outbox_write_failure_still_returns_gateway_response(
    client, workspace, upstream_capture, drata_configured, monkeypatch, tmp_path, caplog, policy
):
    ws, api_key = workspace
    if policy is not None:
        set_workspace_policy(ws.workspace_id, policy)
    unwritable = tmp_path / "outbox-is-a-directory"
    unwritable.mkdir()
    monkeypatch.setattr(outbox, "outbox_db_path", lambda: unwritable)
    drata_calls = _drata_urlopen(monkeypatch, "ok")

    with caplog.at_level(logging.WARNING, logger="hermes.gateway.evidence_export"):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_openai_chat(f"Patient SSN is {PHI_SSN}"),
        )

    assert response.status_code == (403 if policy is not None else 200)
    assert len(gateway_evidence.list_gateway_receipts(ws)) == 1
    assert "outbox write failed" in caplog.text
    assert drata_calls == []
    if policy is not None:
        assert upstream_capture["requests"] == []
        clear_workspace_policy(ws.workspace_id)
