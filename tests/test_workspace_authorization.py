"""
tests/test_workspace_authorization.py — Workspace hierarchy authorization
and rotate-key endpoint access control.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from hermes.api import app
from hermes.workspaces import can_access_workspace, create_workspace


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


@pytest.fixture()
def workspace_hierarchy():
    parent, parent_key = create_workspace("msp-parent-auth", "MSP Parent", "p@test.com")
    child, child_key = create_workspace(
        "client-child-auth",
        "Client Child",
        "c@test.com",
        parent_workspace_id=parent.workspace_id,
    )
    sibling, sibling_key = create_workspace(
        "client-sibling-auth",
        "Client Sibling",
        "s@test.com",
        parent_workspace_id=parent.workspace_id,
    )
    unrelated, unrelated_key = create_workspace(
        "unrelated-auth",
        "Unrelated",
        "u@test.com",
    )
    return {
        "parent": (parent, parent_key),
        "child": (child, child_key),
        "sibling": (sibling, sibling_key),
        "unrelated": (unrelated, unrelated_key),
    }


class TestCanAccessWorkspace:
    def test_self_access_allowed(self, workspace_hierarchy):
        parent, _ = workspace_hierarchy["parent"]
        assert can_access_workspace(parent, parent) is True

    def test_parent_can_access_child(self, workspace_hierarchy):
        parent, _ = workspace_hierarchy["parent"]
        child, _ = workspace_hierarchy["child"]
        assert can_access_workspace(parent, child) is True

    def test_child_cannot_access_parent(self, workspace_hierarchy):
        parent, _ = workspace_hierarchy["parent"]
        child, _ = workspace_hierarchy["child"]
        assert can_access_workspace(child, parent) is False

    def test_siblings_cannot_access_each_other(self, workspace_hierarchy):
        child, _ = workspace_hierarchy["child"]
        sibling, _ = workspace_hierarchy["sibling"]
        assert can_access_workspace(child, sibling) is False
        assert can_access_workspace(sibling, child) is False

    def test_unrelated_cannot_access(self, workspace_hierarchy):
        parent, _ = workspace_hierarchy["parent"]
        unrelated, _ = workspace_hierarchy["unrelated"]
        assert can_access_workspace(unrelated, parent) is False
        assert can_access_workspace(parent, unrelated) is False


class TestRotateKeyAuthorization:
    def test_workspace_can_rotate_own_key(self, client, workspace_hierarchy):
        parent, parent_key = workspace_hierarchy["parent"]
        response = client.post(
            f"/v1/workspaces/{parent.workspace_id}/rotate-key",
            headers={"X-API-Key": parent_key},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["workspace_id"] == parent.workspace_id
        assert body["api_key"]

    def test_parent_can_rotate_child_key(self, client, workspace_hierarchy):
        parent, parent_key = workspace_hierarchy["parent"]
        child, _ = workspace_hierarchy["child"]
        response = client.post(
            f"/v1/workspaces/{child.workspace_id}/rotate-key",
            headers={"X-API-Key": parent_key},
        )
        assert response.status_code == 200
        assert response.json()["workspace_id"] == child.workspace_id

    def test_child_cannot_rotate_parent_key(self, client, workspace_hierarchy):
        parent, _ = workspace_hierarchy["parent"]
        _, child_key = workspace_hierarchy["child"]
        response = client.post(
            f"/v1/workspaces/{parent.workspace_id}/rotate-key",
            headers={"X-API-Key": child_key},
        )
        assert response.status_code == 403

    def test_nonexistent_target_is_not_rotated(self, client, workspace_hierarchy):
        _, parent_key = workspace_hierarchy["parent"]
        response = client.post(
            "/v1/workspaces/does-not-exist/rotate-key",
            headers={"X-API-Key": parent_key},
        )
        assert response.status_code == 404
