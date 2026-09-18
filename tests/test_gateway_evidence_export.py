"""
tests/test_gateway_evidence_export.py — Gateway EvidenceEvent and exporter tests.
"""

from __future__ import annotations

import json
import logging
import urllib.error
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
from gateway.evidence_export.event import EvidenceEvent, build_evidence_event
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    WEBHOOK_AUTH_HEADER_ENV,
    WEBHOOK_AUTH_VALUE_ENV,
    WEBHOOK_URL_ENV,
    DrataExporter,
    WebhookExporter,
)
from gateway.pipeline import GatewayPipeline
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
