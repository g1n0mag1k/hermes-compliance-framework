"""
Security regression suite — BLOCK policy must prevent upstream HTTP requests.

Every BLOCK test asserts upstream.request_count == 0.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
from gateway.policy import Policy, set_workspace_policy, clear_workspace_policy
from hermes.classifier import DetectorFailureError
from hermes.workspaces import create_workspace


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
    ws, api_key = create_workspace("sec-gw-01", "Security GW", "sec@test.com")
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    yield ws, api_key
    clear_workspace_policy(ws.workspace_id)


@pytest.fixture()
def upstream_state(monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("HERMES_AZURE_OPENAI_KEY", "test-azure-key")
    monkeypatch.setenv("HERMES_AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")

    state = {"requests": [], "response": {"id": "chatcmpl-test", "choices": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else ""
        state["requests"].append(
            {
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": body,
                "query": str(request.url.query),
                "path": request.url.path,
            }
        )
        return httpx.Response(200, json=state["response"])

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )
    return state


@pytest.fixture()
def client():
    return TestClient(app)


def _chat(content: str, **extra: Any) -> dict:
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }
    payload.update(extra)
    return payload


def _assert_blocked(response, upstream_state):
    assert response.status_code in (403, 503)
    assert len(upstream_state["requests"]) == 0


def test_phi_in_user_message_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("Patient SSN is 123-45-6789"),
    )
    _assert_blocked(response, upstream_state)
    assert response.json()["receipt_digest"]


def test_phi_in_system_message_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Patient MRN is MRN 1234567890"},
                {"role": "user", "content": "Summarize"},
            ],
        },
    )
    _assert_blocked(response, upstream_state)


def test_phi_in_assistant_message_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [
                {"role": "assistant", "content": "The fax number is 555-123-4567"},
            ],
        },
    )
    _assert_blocked(response, upstream_state)


def test_phi_in_tool_arguments_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "save",
                                "arguments": '{"ssn": "123-45-6789"}',
                            },
                        }
                    ],
                }
            ],
        },
    )
    _assert_blocked(response, upstream_state)


def test_phi_in_deeply_nested_json_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "run"}],
            "metadata": {"level1": {"level2": {"note": "email patient@example.com"}}},
        },
    )
    _assert_blocked(response, upstream_state)


def test_phi_in_query_string_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions?debug_ssn=123-45-6789",
        headers={"X-API-Key": api_key},
        json=_chat("hello"),
    )
    _assert_blocked(response, upstream_state)


def test_multiple_phi_categories_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("SSN 123-45-6789 and email patient@example.com"),
    )
    _assert_blocked(response, upstream_state)


def test_detector_failure_blocked(client, workspace, upstream_state, monkeypatch):
    _, api_key = workspace

    def _fail(*args, **kwargs):
        raise DetectorFailureError("forced")

    monkeypatch.setattr("gateway.inspector.scrub_payload", _fail)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("hello"),
    )
    assert response.status_code == 503
    assert len(upstream_state["requests"]) == 0


def test_parser_failure_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        content=b'{"model": "gpt-4o", "messages": [',
    )
    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0


def test_policy_failure_blocked(client, workspace, upstream_state, monkeypatch):
    _, api_key = workspace

    def _boom(*args, **kwargs):
        raise RuntimeError("policy engine exploded")

    monkeypatch.setattr("gateway.pipeline.PolicyEngine.decide", _boom)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("hello"),
    )
    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0


def test_unsupported_content_type_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key, "Content-Type": "image/jpeg"},
        content=b"\xff\xd8\xff",
    )
    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0


def test_unsupported_provider_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/unknown_provider/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("hello"),
    )
    assert response.status_code == 400
    assert len(upstream_state["requests"]) == 0


def test_malformed_request_blocked(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        content=b"not json at all",
    )
    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0


def test_clean_request_forwarded(client, workspace, upstream_state):
    ws, api_key = workspace
    clear_workspace_policy(ws.workspace_id)
    gateway_policy.reload_policy()

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("Explain photosynthesis."),
    )
    assert response.status_code == 200
    assert len(upstream_state["requests"]) == 1


def test_redact_policy_redacts_and_forwards(client, workspace, upstream_state):
    ws, api_key = workspace
    clear_workspace_policy(ws.workspace_id)
    gateway_policy.reload_policy()

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("Patient SSN is 123-45-6789"),
    )
    assert response.status_code == 200
    assert len(upstream_state["requests"]) == 1
    assert "123-45-6789" not in upstream_state["requests"][0]["body"]
    assert "[REDACTED_SSN]" in upstream_state["requests"][0]["body"]


def test_unapproved_provider_blocked(client, workspace, upstream_state):
    ws, api_key = workspace
    restricted = Policy(
        policy_id="OPENAI_ONLY",
        policy_version="1.0.0",
        text_action="BLOCK",
        binary_action="BLOCK",
        on_detector_error="BLOCK",
        on_parse_error="BLOCK",
        approved_providers=["openai"],
    )
    set_workspace_policy(ws.workspace_id, restricted)

    response = client.post(
        "/gateway/anthropic/v1/messages",
        headers={"X-API-Key": api_key},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0
    clear_workspace_policy(ws.workspace_id)


def test_exporter_failure_blocked(client, workspace, upstream_state, monkeypatch):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_WEBHOOK_URL", "https://example.com/webhook")

    with patch(
        "gateway.evidence_export.dispatch.build_evidence_event",
        side_effect=RuntimeError("export exploded"),
    ):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_chat("Patient SSN is 123-45-6789"),
        )

    assert response.status_code == 403
    assert len(upstream_state["requests"]) == 0


def test_block_receipt_records_forwarded_false(client, workspace, upstream_state):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_chat("Patient SSN is 123-45-6789"),
    )
    assert response.status_code == 403
    digest = response.json()["receipt_digest"]
    ws, _ = workspace
    row = gateway_evidence.get_gateway_receipt(ws, digest)
    assert row is not None
    assert row["payload"]["forwarded"] is False
    assert row["payload"]["decision"] == "BLOCK"
