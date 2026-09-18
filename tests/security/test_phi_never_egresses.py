"""
tests/security/test_phi_never_egresses.py — Hermes PHI-egress security suite.

Critical invariant: when Hermes decides to BLOCK, the upstream provider
receives zero bytes. This suite exists solely to prove that invariant across
every defined failure and enforcement path.

18 tests. All must pass before any design-partner or production deployment.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
from gateway.policy import Policy, clear_workspace_policy, set_workspace_policy
from hermes.classifier import DetectorFailureError
from hermes.workspaces import create_workspace


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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
    gateway_policy._workspace_policies.clear()
    gateway_policy.reload_policy()
    gateway_app._stats.update(
        {
            "requests_total": 0,
            "requests_allowed": 0,
            "requests_redacted": 0,
            "requests_blocked": 0,
            "phi_events_total": 0,
            "detector_errors_total": 0,
        }
    )
    yield


@pytest.fixture()
def workspace():
    ws, api_key = create_workspace("sec-test-01", "Security Test", "sec@test.com")
    return ws, api_key


@pytest.fixture()
def upstream_capture(monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "test-anthropic-key")
    state: dict[str, Any] = {
        "requests": [],
        "response": {"id": "chatcmpl-test", "choices": []},
    }

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
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    pipeline = GatewayPipeline(client_factory=lambda: httpx.Client(transport=transport))
    gateway_app._pipeline = pipeline
    return state


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def block_policy():
    return Policy(
        policy_id="SEC_BLOCK",
        policy_version="1.0.0",
        text_action="BLOCK",
        binary_action="BLOCK",
        on_detector_error="BLOCK",
        on_parse_error="BLOCK",
        approved_providers=["openai", "azure_openai", "anthropic"],
    )


def _openai_payload(content: str, **extra: Any) -> dict:
    payload: dict[str, Any] = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }
    payload.update(extra)
    return payload


def _assert_zero_upstream(state: dict) -> None:
    assert state["requests"] == [], (
        f"INVARIANT VIOLATED: upstream received {len(state['requests'])} request(s) "
        "when zero were expected."
    )


# 1. SSN — BLOCK policy
def test_ssn_never_egresses_under_block_policy(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("Patient SSN is 123-45-6789"),
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 2. Credit card — BLOCK policy
def test_pan_never_egresses_under_block_policy(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("Charge card 4111 1111 1111 1111 for the invoice"),
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 3. Named entity — BLOCK policy
def test_named_entity_never_egresses_under_block_policy(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("Patient John Smith was admitted on 01/15/1980"),
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 4. PHI in nested tool arguments — BLOCK policy
def test_phi_in_tool_arguments_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = _openai_payload(
        "look up patient",
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup_patient",
                    "parameters": {"ssn": "987-65-4321", "dob": "1975-03-22"},
                },
            }
        ],
    )
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 5. PHI in system message — BLOCK policy
def test_phi_in_system_message_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Context: patient SSN 321-54-9876"},
            {"role": "user", "content": "Summarize the above"},
        ],
    }
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 6. PHI in query string — BLOCK policy
def test_phi_in_query_string_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    response = client.post(
        "/gateway/openai/v1/chat/completions?patient_ssn=123-45-6789",
        headers={"X-API-Key": api_key},
        json=_openai_payload("run the report"),
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 7. Detector failure — fails closed
def test_detector_failure_never_egresses(client, workspace, upstream_capture, monkeypatch):
    _, api_key = workspace
    def _raise(*args, **kwargs):
        raise DetectorFailureError("simulated detector crash")
    monkeypatch.setattr("gateway.inspector.scrub_payload", _raise)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("hello"),
    )
    assert response.status_code == 503
    _assert_zero_upstream(upstream_capture)


# 8. Binary content — blocked
def test_binary_content_never_egresses(client, workspace, upstream_capture):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key, "Content-Type": "application/octet-stream"},
        content=b"\x89PNG\r\n\x1a\n binary payload",
    )
    assert response.status_code in (400, 403, 415)
    _assert_zero_upstream(upstream_capture)


# 9. Unapproved provider — blocked
def test_unapproved_provider_never_egresses(client, workspace, upstream_capture):
    ws, api_key = workspace
    restricted_policy = Policy(
        policy_id="SEC_RESTRICTED_PROVIDER",
        policy_version="1.0.0",
        text_action="BLOCK",
        binary_action="BLOCK",
        on_detector_error="BLOCK",
        on_parse_error="BLOCK",
        approved_providers=["anthropic"],
    )
    set_workspace_policy(ws.workspace_id, restricted_policy)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("hello"),
    )
    assert response.status_code in (400, 403)
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 10. Invalid API key — blocked
def test_invalid_api_key_never_egresses(client, upstream_capture):
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": "invalid-key-000"},
        json=_openai_payload("hello"),
    )
    assert response.status_code == 401
    _assert_zero_upstream(upstream_capture)


# 11. Missing API key — blocked
def test_missing_api_key_never_egresses(client, upstream_capture):
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        json=_openai_payload("hello"),
    )
    assert response.status_code == 401
    _assert_zero_upstream(upstream_capture)


# 12. PHI across multi-turn — BLOCK policy
def test_phi_in_multi_turn_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "I need help with a patient"},
            {"role": "assistant", "content": "Sure, what is their information?"},
            {"role": "user", "content": "Her SSN is 456-78-9012 and DOB 03/15/1965"},
        ],
    }
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 13. PHI in array content — BLOCK policy
def test_phi_in_array_content_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Patient SSN: 654-32-1098"},
                    {"type": "text", "text": "Please summarize"},
                ],
            }
        ],
    }
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 14. Anthropic provider — BLOCK policy
def test_phi_never_egresses_via_anthropic_provider(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "Patient SSN is 789-01-2345"}],
    }
    response = client.post(
        "/gateway/anthropic/v1/messages",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 15. BLOCK survives evidence export failure
def test_block_decision_survives_evidence_export_failure(
    client, workspace, upstream_capture, block_policy, monkeypatch
):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    monkeypatch.setattr(
        "gateway.pipeline.issue_gateway_receipt",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("evidence store down")),
    )
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("SSN 111-22-3333"),
    )
    assert response.status_code in (403, 503)
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 16. Control — clean request DOES reach upstream
def test_clean_request_does_reach_upstream(client, workspace, upstream_capture):
    _, api_key = workspace
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=_openai_payload("What is the capital of France?"),
    )
    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1, (
        "Control case failed: clean request did not reach upstream. "
        "The upstream_capture fixture may be broken."
    )


# 17. PHI in deeply nested structure — BLOCK policy
def test_phi_in_deeply_nested_structure_never_egresses(client, workspace, upstream_capture, block_policy):
    ws, api_key = workspace
    set_workspace_policy(ws.workspace_id, block_policy)
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "run audit"}],
        "functions": [
            {
                "name": "audit_record",
                "parameters": {
                    "patient": {
                        "identity": {
                            "ssn": "333-22-1111",
                            "name": "Jane Doe",
                        }
                    }
                },
            }
        ],
    }
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json=payload,
    )
    assert response.status_code == 403
    _assert_zero_upstream(upstream_capture)
    clear_workspace_policy(ws.workspace_id)


# 18. Workspace isolation — BLOCK does not bleed into clean workspace
def test_phi_block_isolated_per_workspace(client, upstream_capture, block_policy):
    ws_block, key_block = create_workspace("sec-block-ws", "Block WS", "block@test.com")
    ws_clean, key_clean = create_workspace("sec-clean-ws", "Clean WS", "clean@test.com")
    set_workspace_policy(ws_block.workspace_id, block_policy)

    r_block = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": key_block},
        json=_openai_payload("SSN 222-33-4444"),
    )
    blocked_upstream_count = len(upstream_capture["requests"])

    r_clean = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": key_clean},
        json=_openai_payload("What is 2 + 2?"),
    )

    assert r_block.status_code == 403
    assert blocked_upstream_count == 0, (
        f"INVARIANT VIOLATED: BLOCK workspace sent {blocked_upstream_count} upstream request(s)."
    )
    assert r_clean.status_code == 200
    assert len(upstream_capture["requests"]) == 1
    clear_workspace_policy(ws_block.workspace_id)
