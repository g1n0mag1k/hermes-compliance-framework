"""
tests/test_rbac.py — Workspace role-based access control for config endpoints.
"""

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


def test_msp_admin_can_access_config_endpoint(client):
    _, api_key = create_workspace(
        "rbac-admin-01",
        "Admin Workspace",
        "admin@test.com",
        role="msp_admin",
    )
    response = client.post(
        "/api/v1/sentry/config",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "updated"}


def test_client_readonly_blocked_from_config_endpoint(client):
    _, api_key = create_workspace(
        "rbac-readonly-01",
        "Readonly Workspace",
        "ro@test.com",
        role="client_readonly",
    )
    response = client.post(
        "/api/v1/sentry/config",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"
