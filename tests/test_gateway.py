"""
tests/test_gateway.py — Hermes Relay enforcement gateway tests.
"""

from __future__ import annotations

import json
import threading
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
from gateway.policy import Policy, set_workspace_policy, clear_workspace_policy
from gateway.providers import PROVIDER_REGISTRY
from hermes.classifier import DetectorFailureError
from hermes.workspaces import create_workspace


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
    gateway_app._stats.clear()
    yield


@pytest.fixture()
def workspace():
    ws, api_key = create_workspace("gw-test-01", "Gateway Test", "gw@test.com")
    return ws, api_key


@pytest.fixture()
def upstream_capture(monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    state = {"requests": [], "response": {"id": "chatcmpl-test", "choices": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else ""
        state["requests"].append(
            {
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": body,
            }
        )
        return httpx.Response(
            200,
            json=state["response"],
            headers={
                "content-type": "application/json",
                "openai-organization": "org-secret",
                "x-ratelimit-remaining-requests": "999",
            },
        )

    transport = httpx.MockTransport(handler)
    pipeline = GatewayPipeline(client_factory=lambda: httpx.Client(transport=transport))
    gateway_app._pipeline = pipeline
    return state


@pytest.fixture()
def client():
    return TestClient(app)


def _openai_chat_payload(content: str, **extra: Any) -> dict:
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }
    payload.update(extra)
    return payload


def test_clean_request_passes_through(client, workspace, upstream_capture):
    _, api_key = workspace
    payload = _openai_chat_payload("Explain photosynthesis briefly.")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1
    assert "photosynthesis" in upstream_capture["requests"][0]["body"]


def test_phi_in_messages_content_is_redacted(client, workspace, upstream_capture):
    _, api_key = workspace
    payload = _openai_chat_payload("Patient SSN is 123-45-6789")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    forwarded = upstream_capture["requests"][0]["body"]
    assert "123-45-6789" not in forwarded
    assert "[REDACTED_SSN]" in forwarded


def test_phi_in_deeply_nested_tool_parameter_is_redacted(
    client, workspace, upstream_capture
):
    _, api_key = workspace
    payload = _openai_chat_payload(
        "Run the lookup tool.",
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "Lookup helper",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "nested_context": {
                                "type": "object",
                                "properties": {
                                    "secret_note": {
                                        "type": "string",
                                        "description": "Patient SSN is 123-45-6789",
                                    }
                                },
                            }
                        },
                    },
                },
            }
        ],
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    forwarded = upstream_capture["requests"][0]["body"]
    assert "123-45-6789" not in forwarded
    assert "[REDACTED_SSN]" in forwarded


def test_phi_in_tool_call_arguments_is_redacted(client, workspace, upstream_capture):
    _, api_key = workspace
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "save_patient",
                            "arguments": '{"patient_ssn": "123-45-6789"}',
                        },
                    }
                ],
            }
        ],
    }

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    forwarded = upstream_capture["requests"][0]["body"]
    assert "123-45-6789" not in forwarded
    assert "[REDACTED_SSN]" in forwarded


def test_phi_in_anthropic_tool_result_content_is_redacted(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 256,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": [
                            {"type": "text", "text": "Patient MRN is MRN 1234567890"}
                        ],
                    }
                ],
            }
        ],
    }

    response = client.post(
        "/gateway/anthropic/v1/messages",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    forwarded = upstream_capture["requests"][0]["body"]
    assert "1234567890" not in forwarded or "[REDACTED" in forwarded


def test_phi_detected_block_policy_returns_403(client, workspace, upstream_capture):
    ws, api_key = workspace
    block_policy = Policy(
        policy_id="BLOCK_ALL",
        policy_version="1.0.0",
        text_action="BLOCK",
        binary_action="BLOCK",
        on_detector_error="BLOCK",
        on_parse_error="BLOCK",
        approved_providers=["openai", "azure_openai", "anthropic"],
    )
    set_workspace_policy(ws.workspace_id, block_policy)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("Patient SSN is 123-45-6789"),
    )

    assert response.status_code == 403
    assert upstream_capture["requests"] == []
    body = response.json()
    assert body["error"]["code"] == "phi_detected"
    clear_workspace_policy(ws.workspace_id)


def test_detector_failure_blocks_request(client, workspace, upstream_capture, monkeypatch):
    _, api_key = workspace

    def _raise_detector_failure(*args, **kwargs):
        raise DetectorFailureError("detector failed")

    monkeypatch.setattr("gateway.inspector.scrub_payload", _raise_detector_failure)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 503
    assert upstream_capture["requests"] == []
    body = response.json()
    assert body["error"]["code"] == "detector_error"


def test_binary_content_type_blocked(client, workspace, upstream_capture):
    _, api_key = workspace

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={
            "X-API-Key": api_key,
            "Content-Type": "image/jpeg",
        },
        content=b"\xff\xd8\xff",
    )

    assert response.status_code == 403
    assert upstream_capture["requests"] == []


def test_unknown_provider_returns_400(client, workspace):
    _, api_key = workspace

    response = client.post(
        "/gateway/unknown_provider/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 400


def test_invalid_api_key_returns_401(client):
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": "totally-invalid"},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 401


def test_phi_in_query_string_detected(client, workspace, upstream_capture):
    _, api_key = workspace

    response = client.post(
        "/gateway/openai/v1/chat/completions?patient_name=John+Smith&dob=1981-05-15",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("Summarize the visit."),
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1


def test_query_string_phi_is_sanitized_before_forwarding(
    client, workspace, upstream_capture, monkeypatch
):
    """PHI in query string must not reach the upstream URL."""
    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-key")

    response = client.post(
        "/gateway/openai/v1/chat/completions?debug_ssn=123-45-6789",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    # Regardless of status, the upstream request must not contain the raw SSN
    assert len(upstream_capture["requests"]) >= 1
    forwarded_url = upstream_capture["requests"][0]["url"]
    assert "123-45-6789" not in forwarded_url


def test_clean_query_string_passes_through(client, workspace, upstream_capture, monkeypatch):
    """A clean query string should reach upstream unchanged."""
    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-key")

    response = client.post(
        "/gateway/openai/v1/chat/completions?stream=false",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert len(upstream_capture["requests"]) >= 1
    forwarded_url = upstream_capture["requests"][0]["url"]
    assert "stream=false" in forwarded_url


def test_client_auth_header_stripped_from_upstream(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={
            "X-API-Key": api_key,
            "Authorization": "Bearer client-secret",
        },
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 200
    forwarded_headers = upstream_capture["requests"][0]["headers"]
    assert forwarded_headers.get("authorization") != "Bearer client-secret"
    assert "Bearer test-openai-key" in forwarded_headers.get("authorization", "")


def test_provider_credential_injected_openai(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 200
    forwarded_headers = upstream_capture["requests"][0]["headers"]
    assert forwarded_headers.get("authorization") == "Bearer test-openai-key"


def test_anthropic_x_api_key_not_authorization(
    client, workspace, upstream_capture, monkeypatch
):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")

    response = client.post(
        "/gateway/anthropic/v1/messages",
        headers={"X-API-Key": api_key},
        json={
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 32,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert response.status_code == 200
    forwarded_headers = {k.lower(): v for k, v in upstream_capture["requests"][0]["headers"].items()}
    assert forwarded_headers.get("x-api-key") == "test-anthropic-key"
    assert "authorization" not in forwarded_headers


def test_provider_response_headers_stripped(client, workspace, upstream_capture, monkeypatch):
    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 200
    assert "openai-organization" not in {k.lower() for k in response.headers.keys()}
    assert "x-ratelimit-remaining-requests" not in {k.lower() for k in response.headers.keys()}
    assert "x-gateway-request-id" in {k.lower() for k in response.headers.keys()}


def test_response_detector_failure_blocks_response(client, workspace, monkeypatch):
    """If response body inspection raises DetectorFailureError, the response must be blocked."""
    import gateway.inspector as inspector_mod
    import gateway.pipeline as pipeline_mod

    _, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "SSN 372-18-5421"}}]},
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )

    call_count = {"n": 0}
    original = inspector_mod.inspect_json_recursive

    def patched(obj, txn_id):
        call_count["n"] += 1
        if call_count["n"] > 1:  # First call is request body, second is response body
            raise DetectorFailureError("forced failure")
        return original(obj, txn_id)

    monkeypatch.setattr(pipeline_mod, "inspect_json_recursive", patched)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "detector_error"
    assert "372-18-5421" not in response.text


def test_response_phi_detected_and_redacted(client, workspace, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": "The patient SSN is 123-45-6789 on file."
                        }
                    }
                ]
            },
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("hello"),
    )

    assert response.status_code == 200
    body = response.json()
    assert "123-45-6789" not in body["choices"][0]["message"]["content"]
    assert "[REDACTED_SSN]" in body["choices"][0]["message"]["content"]


def test_concurrent_requests_isolated_by_workspace(client, monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    ws1, key1 = create_workspace("gw-concurrent-a", "A", "a@test.com")
    ws2, key2 = create_workspace("gw-concurrent-b", "B", "b@test.com")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )

    results = {}

    def _call(workspace_key: str, api_key: str) -> None:
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": api_key},
            json=_openai_chat_payload("hello"),
        )
        results[workspace_key] = response.json()

    t1 = threading.Thread(target=_call, args=("a", key1))
    t2 = threading.Thread(target=_call, args=("b", key2))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    head_a = gateway_evidence.get_v2_chain_head(ws1.workspace_id)
    head_b = gateway_evidence.get_v2_chain_head(ws2.workspace_id)
    assert head_a is not None
    assert head_b is not None
    assert head_a != head_b


def test_health_endpoint_all_healthy(client, monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("HERMES_AZURE_OPENAI_KEY", "test-azure-key")
    monkeypatch.setenv("HERMES_AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")

    response = client.get("/gateway/health")

    assert response.status_code == 200
    body = response.json()
    assert body["gateway_service"] == "healthy"
    assert body["policy_engine"] == "healthy"
    assert body["detector_state"] == "healthy"
    assert body["evidence_chain"] == "healthy"


def test_health_endpoint_degraded_on_detector_failure(client, monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("HERMES_AZURE_OPENAI_KEY", "test-azure-key")

    def _raise_detector_failure(*args, **kwargs):
        raise DetectorFailureError("detector failed")

    monkeypatch.setattr("gateway.app.scrub_payload", _raise_detector_failure)

    response = client.get("/gateway/health")
    assert response.status_code == 503
    assert response.json()["detector_state"] == "degraded"


def test_stats_increment_correctly(client, workspace, upstream_capture, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("Explain photosynthesis briefly."),
    )
    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("Patient SSN is 123-45-6789"),
    )

    block_policy = Policy(
        policy_id="BLOCK_ALL",
        policy_version="1.0.0",
        text_action="BLOCK",
        binary_action="BLOCK",
        on_detector_error="BLOCK",
        on_parse_error="BLOCK",
        approved_providers=["openai", "azure_openai", "anthropic"],
    )
    set_workspace_policy(ws.workspace_id, block_policy)
    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_chat_payload("Patient SSN is 987-65-4321"),
    )
    clear_workspace_policy(ws.workspace_id)

    stats = client.get("/gateway/stats", headers={"X-API-Key": api_key}).json()
    assert stats["requests_total"] == 3
    assert stats["requests_allowed"] == 1
    assert stats["requests_redacted"] == 1
    assert stats["requests_blocked"] == 1


def test_gateway_stats_requires_auth(client):
    response = client.get("/gateway/stats")
    assert response.status_code == 401


def test_policy_reload_wrong_token(client, monkeypatch):
    monkeypatch.setenv("HERMES_ADMIN_TOKEN", "correct-secret")
    response = client.post(
        "/gateway/policy/reload",
        headers={"X-Admin-Token": "wrong-secret"},
    )
    assert response.status_code == 401


def test_policy_reload_no_token(client, monkeypatch):
    monkeypatch.setenv("HERMES_ADMIN_TOKEN", "correct-secret")
    response = client.post("/gateway/policy/reload")
    assert response.status_code == 401


def test_policy_reload_correct_token(client, monkeypatch):
    monkeypatch.setenv("HERMES_ADMIN_TOKEN", "correct-secret")
    response = client.post(
        "/gateway/policy/reload",
        headers={"X-Admin-Token": "correct-secret"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "reloaded"
