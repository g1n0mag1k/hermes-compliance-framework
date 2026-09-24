"""
tests/test_rbac.py — Workspace role-based access control for config endpoints.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from hermes.api import DrataConfigState, app, get_drata_config_state
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


# -------------------------------------------------------------------------
# /api/v1/drata/config — honest state, no fake success
# -------------------------------------------------------------------------

DRATA_TEST_URL = "https://drata.example.invalid/cct/secret-connection-123"
DRATA_TEST_KEY = "drata-secret-key-must-not-leak"


@pytest.fixture()
def clear_drata_env(monkeypatch):
    monkeypatch.delenv("HERMES_DRATA_CCT_URL", raising=False)
    monkeypatch.delenv("HERMES_DRATA_API_KEY", raising=False)


def _admin_key(workspace_id="rbac-drata-admin"):
    _, api_key = create_workspace(
        workspace_id, "Drata Admin", "drata@test.com", role="msp_admin"
    )
    return api_key


def test_drata_config_not_configured_when_env_unset(client, clear_drata_env):
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    body = response.json()
    assert body["status"] == "not_implemented"
    assert body["state"] == "NOT_CONFIGURED"
    assert body["cct_url_configured"] is False
    assert body["api_key_configured"] is False
    assert body["connection_tested"] is False


def test_drata_config_configured_when_env_set(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.status_code == 501
    body = response.json()
    assert body["state"] == "CONFIGURED"
    assert body["cct_url_configured"] is True
    assert body["api_key_configured"] is True
    assert body["connection_tested"] is False


def test_drata_config_api_key_alone_is_not_configured(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert response.json()["state"] == "NOT_CONFIGURED"
    assert response.json()["api_key_configured"] is True


@pytest.mark.parametrize("configured", [False, True])
def test_drata_config_never_returns_fake_updated(client, clear_drata_env, monkeypatch, configured):
    if configured:
        monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
    )
    assert not (200 <= response.status_code < 300)
    assert response.json() != {"status": "updated"}
    assert response.json()["status"] != "updated"


def test_drata_config_does_not_contact_network(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with patch("urllib.request.urlopen") as mock_urlopen:
        client.post("/api/v1/drata/config", headers={"X-API-Key": _admin_key()})
    mock_urlopen.assert_not_called()


def test_drata_config_response_contains_no_credentials(client, clear_drata_env, monkeypatch, caplog):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    monkeypatch.setenv("HERMES_DRATA_API_KEY", DRATA_TEST_KEY)
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/v1/drata/config", headers={"X-API-Key": _admin_key()}
        )
    raw = response.text
    assert DRATA_TEST_KEY not in raw
    assert DRATA_TEST_URL not in raw
    assert "secret-connection-123" not in raw
    for header_value in response.headers.values():
        assert DRATA_TEST_KEY not in header_value
    assert DRATA_TEST_KEY not in caplog.text


def test_drata_config_msp_tech_allowed(client, clear_drata_env):
    _, api_key = create_workspace(
        "rbac-drata-tech", "Drata Tech", "tech@test.com", role="msp_tech"
    )
    response = client.post("/api/v1/drata/config", headers={"X-API-Key": api_key})
    assert response.status_code == 501
    assert response.json()["state"] == "NOT_CONFIGURED"


def test_drata_config_client_readonly_blocked(client, clear_drata_env, monkeypatch):
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    _, api_key = create_workspace(
        "rbac-drata-readonly", "Drata RO", "ro-drata@test.com", role="client_readonly"
    )
    response = client.post("/api/v1/drata/config", headers={"X-API-Key": api_key})
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"
    assert "state" not in response.json()


def test_drata_config_invalid_api_key_rejected(client, clear_drata_env):
    response = client.post(
        "/api/v1/drata/config", headers={"X-API-Key": "not-a-real-key"}
    )
    assert response.status_code == 401


def test_drata_config_missing_api_key_rejected(client, clear_drata_env):
    response = client.post("/api/v1/drata/config")
    assert response.status_code == 422


def test_get_drata_config_state_transitions(clear_drata_env, monkeypatch):
    assert get_drata_config_state() is DrataConfigState.NOT_CONFIGURED
    assert get_drata_config_state(True) is DrataConfigState.NOT_CONFIGURED
    assert get_drata_config_state(False) is DrataConfigState.NOT_CONFIGURED

    monkeypatch.setenv("HERMES_DRATA_CCT_URL", DRATA_TEST_URL)
    assert get_drata_config_state() is DrataConfigState.CONFIGURED
    assert get_drata_config_state(False) is DrataConfigState.CONNECTION_TEST_FAILED
    assert get_drata_config_state(True) is DrataConfigState.CONNECTION_TEST_SUCCEEDED
