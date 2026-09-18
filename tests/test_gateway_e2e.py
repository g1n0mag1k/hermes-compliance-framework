"""End-to-end gateway integration tests across mock upstream providers."""

from __future__ import annotations

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
from hermes.receipts.v2.verifier import verify_receipt
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
def upstream():
    state = {"requests": [], "response": {"id": "ok", "choices": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(
            {
                "url": str(request.url),
                "body": request.content.decode("utf-8") if request.content else "",
                "headers": dict(request.headers),
            }
        )
        return httpx.Response(200, json=state["response"])

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )
    return state


@pytest.fixture()
def client():
    return TestClient(app)


def _verify_latest_receipt(ws) -> None:
    rows = gateway_evidence.list_gateway_receipts(ws)
    assert rows
    pub_pem = gateway_evidence._get_gateway_signer().public_key_manifest()["public_key_pem"]
    cose_bytes = bytes.fromhex(rows[-1]["cose_sign1_hex"])
    result = verify_receipt(cose_bytes, pub_pem)
    assert result.fully_valid, result.errors


@pytest.mark.parametrize(
    "route,env_key,env_val,payload",
    [
        (
            "/gateway/openai/v1/chat/completions",
            "HERMES_OPENAI_API_KEY",
            "test-openai",
            {"model": "gpt-4o", "messages": [{"role": "user", "content": "clean"}]},
        ),
        (
            "/gateway/anthropic/v1/messages",
            "HERMES_ANTHROPIC_API_KEY",
            "test-anthropic",
            {
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 32,
                "messages": [{"role": "user", "content": "clean"}],
            },
        ),
        (
            "/gateway/azure_openai/openai/deployments/gpt-4/chat/completions",
            "HERMES_AZURE_OPENAI_KEY",
            "test-azure",
            {"messages": [{"role": "user", "content": "clean"}]},
        ),
    ],
)
def test_clean_request_e2e(client, upstream, monkeypatch, route, env_key, env_val, payload):
    ws, api_key = create_workspace("e2e-clean", "E2E", "e2e@test.com")
    monkeypatch.setenv(env_key, env_val)
    if "azure" in route:
        monkeypatch.setenv("HERMES_AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com")

    response = client.post(route, headers={"X-API-Key": api_key}, json=payload)
    assert response.status_code == 200
    assert len(upstream["requests"]) == 1
    _verify_latest_receipt(ws)


def test_phi_redact_e2e(client, upstream, monkeypatch):
    ws, api_key = create_workspace("e2e-redact", "E2E", "e2e@test.com")
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai")

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "SSN 123-45-6789"}],
        },
    )
    assert response.status_code == 200
    assert len(upstream["requests"]) == 1
    assert "123-45-6789" not in upstream["requests"][0]["body"]
    _verify_latest_receipt(ws)


def test_phi_block_e2e(client, upstream, monkeypatch):
    ws, api_key = create_workspace("e2e-block", "E2E", "e2e@test.com")
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai")
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "SSN 123-45-6789"}],
        },
    )
    assert response.status_code == 403
    assert len(upstream["requests"]) == 0
    _verify_latest_receipt(ws)
    clear_workspace_policy(ws.workspace_id)


def test_detector_failure_e2e(client, upstream, monkeypatch):
    ws, api_key = create_workspace("e2e-det", "E2E", "e2e@test.com")
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai")
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)

    def _fail(*args, **kwargs):
        raise DetectorFailureError("forced")

    monkeypatch.setattr("gateway.inspector.scrub_payload", _fail)
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 503
    assert len(upstream["requests"]) == 0
    _verify_latest_receipt(ws)
    clear_workspace_policy(ws.workspace_id)


def test_malformed_json_e2e(client, upstream, monkeypatch):
    ws, api_key = create_workspace("e2e-parse", "E2E", "e2e@test.com")
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai")
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        content=b"{bad",
    )
    assert response.status_code == 403
    assert len(upstream["requests"]) == 0
    _verify_latest_receipt(ws)
    clear_workspace_policy(ws.workspace_id)


def test_provider_failure_e2e(client, monkeypatch):
    ws, api_key = create_workspace("e2e-upstream", "E2E", "e2e@test.com")
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai")

    def _fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(_fail)
        )
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_transport_failure"
    _verify_latest_receipt(ws)
