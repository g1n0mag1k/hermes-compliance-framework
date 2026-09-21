"""
tests/test_gateway_path_redaction.py — PHI in path is sanitized before upstream forward.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
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
def upstream_capture(monkeypatch):
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")
    state = {"requests": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(
            {
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
            }
        )
        return httpx.Response(
            200,
            json={"id": "chatcmpl-test", "choices": []},
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )
    return state


@pytest.fixture()
def client():
    return TestClient(app)


def test_phi_in_path_is_sanitized_before_forward(client, upstream_capture):
    _, api_key = create_workspace("path-redact-ws", "Path Redact", "path@test.com")

    original_path = "/v1/chat/completions/patient/123-45-6789"
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Explain photosynthesis briefly."}],
    }

    response = client.post(
        f"/gateway/openai{original_path}",
        headers={"X-API-Key": api_key},
        json=payload,
    )

    assert response.status_code == 200
    assert len(upstream_capture["requests"]) == 1

    forwarded = upstream_capture["requests"][0]
    assert "123-45-6789" not in forwarded["url"]
    assert "123-45-6789" not in forwarded["path"]
    assert "[REDACTED_SSN]" in forwarded["path"]
    assert forwarded["path"] == "/v1/chat/completions/patient/[REDACTED_SSN]"
