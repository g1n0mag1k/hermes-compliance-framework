"""
tests/test_gateway_stats_isolation.py — workspace-isolated gateway stats.
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

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"id": "chatcmpl-test", "choices": []},
            headers={"content-type": "application/json"},
        )

    transport = httpx.MockTransport(handler)
    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=transport)
    )


@pytest.fixture()
def client():
    return TestClient(app)


def test_stats_are_workspace_isolated(client, upstream_capture):
    ws_a, key_a = create_workspace("stats-ws-a", "Stats A", "a@stats.test")
    ws_b, key_b = create_workspace("stats-ws-b", "Stats B", "b@stats.test")

    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Explain photosynthesis briefly."}],
    }

    # Workspace A: two requests
    for _ in range(2):
        response = client.post(
            "/gateway/openai/v1/chat/completions",
            headers={"X-API-Key": key_a},
            json=payload,
        )
        assert response.status_code == 200

    # Workspace B: one request
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": key_b},
        json=payload,
    )
    assert response.status_code == 200

    stats_a = client.get("/gateway/stats", headers={"X-API-Key": key_a}).json()
    stats_b = client.get("/gateway/stats", headers={"X-API-Key": key_b}).json()

    assert stats_a["requests_total"] == 2
    assert stats_a["requests_allowed"] == 2
    assert stats_b["requests_total"] == 1
    assert stats_b["requests_allowed"] == 1

    # Cross-check: neither workspace sees the other's totals
    assert stats_a["requests_total"] != stats_b["requests_total"]
    assert ws_a.workspace_id != ws_b.workspace_id
