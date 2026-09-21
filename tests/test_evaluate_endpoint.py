"""Tests for POST /api/v1/evaluate canary evaluation endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes.api import app
from hermes.workspaces import create_workspace


@pytest.fixture(autouse=True)
def isolated_workspace_registry(tmp_path, monkeypatch):
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
    yield


@pytest.fixture()
def client():
    return TestClient(app)


def test_evaluate_endpoint_returns_evaluated_status(client):
    _, api_key = create_workspace(
        "eval-tenant-01",
        "Evaluate Workspace",
        "eval@test.com",
    )
    response = client.post(
        "/api/v1/evaluate",
        headers={"X-API-Key": api_key},
        json={},
    )
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert body["status"] == "evaluated"
    assert "drift_detected" in body
