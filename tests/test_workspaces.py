"""
tests/test_workspaces.py — Multi-tenant workspace model tests.
"""

import os
import pytest
import tempfile

# Point workspace system at a temp directory for all tests
@pytest.fixture(autouse=True)
def isolated_workspace_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB", str(tmp_path / "workspaces" / "registry.db")
    )
    # Clear module-level caches between tests
    import hermes.workspaces as ws_mod
    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    # Reload _DEFAULT_DATA_DIR and _DEFAULT_REGISTRY_DB from env
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")
    yield


from hermes.workspaces import (
    create_workspace,
    get_workspace,
    get_workspace_by_api_key,
    list_workspaces,
    rotate_api_key,
    update_plan,
    get_chain_for_workspace,
    get_vault_for_workspace,
)


class TestCreateWorkspace:
    def test_returns_workspace_and_key(self):
        ws, key = create_workspace("test-msp-01", "Test MSP", "msp@test.com")
        assert ws.workspace_id == "test-msp-01"
        assert ws.name == "Test MSP"
        assert ws.owner_email == "msp@test.com"
        assert len(key) == 64  # 32 bytes hex

    def test_api_key_not_stored_in_plaintext(self):
        ws, key = create_workspace("test-msp-02", "Test MSP", "msp@test.com")
        assert key not in ws.api_key_hash
        assert ws.api_key_hash != key

    def test_duplicate_workspace_id_raises(self):
        create_workspace("test-msp-03", "Test MSP", "a@test.com")
        with pytest.raises(ValueError, match="already exists"):
            create_workspace("test-msp-03", "Another", "b@test.com")

    def test_invalid_workspace_id_raises(self):
        with pytest.raises(ValueError, match="workspace_id"):
            create_workspace("UPPERCASE", "Bad", "x@test.com")
        with pytest.raises(ValueError, match="workspace_id"):
            create_workspace("ab", "Too Short", "x@test.com")  # min 3 chars

    def test_creates_workspace_directory(self, tmp_path):
        ws, _ = create_workspace("test-msp-04", "Test", "t@test.com")
        from pathlib import Path
        import hermes.workspaces as ws_mod
        ws_dir = Path(ws_mod._DEFAULT_DATA_DIR) / "test-msp-04"
        assert ws_dir.exists()

    def test_default_plan_is_trial(self):
        ws, _ = create_workspace("test-msp-05", "Test", "t@test.com")
        assert ws.plan == "trial"

    def test_parent_workspace_id(self):
        parent, _ = create_workspace("parent-msp", "Parent MSP", "p@test.com")
        child, _ = create_workspace(
            "client-01", "Client One", "c@test.com",
            parent_workspace_id="parent-msp"
        )
        assert child.parent_workspace_id == "parent-msp"

    def test_db_paths_are_workspace_scoped(self):
        ws, _ = create_workspace("test-msp-06", "Test", "t@test.com")
        assert "test-msp-06" in ws.chain_db_path
        assert "test-msp-06" in ws.vault_db_path
        assert "test-msp-06" in ws.canary_db_path


class TestGetWorkspace:
    def test_get_by_id(self):
        ws, _ = create_workspace("lookup-test", "Lookup", "l@test.com")
        found = get_workspace("lookup-test")
        assert found is not None
        assert found.workspace_id == "lookup-test"

    def test_get_missing_returns_none(self):
        assert get_workspace("does-not-exist") is None

    def test_get_by_api_key(self):
        ws, key = create_workspace("key-test", "Key Test", "k@test.com")
        found = get_workspace_by_api_key(key)
        assert found is not None
        assert found.workspace_id == "key-test"

    def test_get_by_wrong_key_returns_none(self):
        create_workspace("wrong-key-test", "Wrong", "w@test.com")
        assert get_workspace_by_api_key("a" * 64) is None


class TestListWorkspaces:
    def test_lists_all(self):
        create_workspace("list-a", "A", "a@test.com")
        create_workspace("list-b", "B", "b@test.com")
        all_ws = list_workspaces()
        ids = {w.workspace_id for w in all_ws}
        assert "list-a" in ids
        assert "list-b" in ids

    def test_filter_by_parent(self):
        create_workspace("msp-parent", "MSP", "msp@test.com")
        create_workspace("client-x", "Client X", "x@test.com", parent_workspace_id="msp-parent")
        create_workspace("client-y", "Client Y", "y@test.com", parent_workspace_id="msp-parent")
        create_workspace("unrelated", "Unrelated", "u@test.com")

        children = list_workspaces(parent_workspace_id="msp-parent")
        ids = {w.workspace_id for w in children}
        assert ids == {"client-x", "client-y"}


class TestRotateKey:
    def test_new_key_works(self):
        ws, old_key = create_workspace("rotate-test", "Rotate", "r@test.com")
        new_key = rotate_api_key("rotate-test")
        assert new_key != old_key
        # New key resolves the workspace
        found = get_workspace_by_api_key(new_key)
        assert found is not None
        assert found.workspace_id == "rotate-test"

    def test_old_key_no_longer_works(self):
        ws, old_key = create_workspace("rotate-test-2", "Rotate2", "r2@test.com")
        rotate_api_key("rotate-test-2")
        assert get_workspace_by_api_key(old_key) is None

    def test_rotate_nonexistent_raises(self):
        with pytest.raises(ValueError):
            rotate_api_key("does-not-exist-xyz")


class TestUpdatePlan:
    def test_update_to_production(self):
        create_workspace("plan-test", "Plan", "p@test.com")
        update_plan("plan-test", "production")
        ws = get_workspace("plan-test")
        assert ws.plan == "production"

    def test_invalid_plan_raises(self):
        create_workspace("plan-test-2", "Plan2", "p2@test.com")
        with pytest.raises(ValueError, match="plan"):
            update_plan("plan-test-2", "enterprise-plus-gold")


class TestPerWorkspaceChainAndVault:
    def test_different_workspaces_have_different_chains(self):
        ws1, _ = create_workspace("chain-ws-1", "WS1", "a@test.com")
        ws2, _ = create_workspace("chain-ws-2", "WS2", "b@test.com")
        chain1 = get_chain_for_workspace(ws1)
        chain2 = get_chain_for_workspace(ws2)
        assert chain1 is not chain2
        assert chain1._db_path != chain2._db_path

    def test_chain_is_cached(self):
        ws, _ = create_workspace("cache-test", "Cache", "c@test.com")
        chain_a = get_chain_for_workspace(ws)
        chain_b = get_chain_for_workspace(ws)
        assert chain_a is chain_b

    def test_workspace_chain_is_isolated(self):
        ws1, _ = create_workspace("iso-ws-1", "Iso1", "a@test.com")
        ws2, _ = create_workspace("iso-ws-2", "Iso2", "b@test.com")
        chain1 = get_chain_for_workspace(ws1)
        chain2 = get_chain_for_workspace(ws2)

        chain1.issue(
            transaction_id="txn_ws1",
            flags_triggered={"HIPAA_SSN": 1},
            flags_redacted={"HIPAA_SSN": 1},
            char_count_in=50,
            char_count_out=40,
        )
        # ws2 chain should still be empty
        assert chain2.chain_length() == 0
        assert chain1.chain_length() == 1

    def test_different_workspaces_have_different_vaults(self):
        ws1, _ = create_workspace("vault-ws-1", "VW1", "a@test.com")
        ws2, _ = create_workspace("vault-ws-2", "VW2", "b@test.com")
        vault1 = get_vault_for_workspace(ws1)
        vault2 = get_vault_for_workspace(ws2)
        assert vault1 is not vault2
        assert vault1._db_path != vault2._db_path

    def test_workspace_vault_is_isolated(self):
        ws1, _ = create_workspace("vault-iso-1", "V1", "a@test.com")
        ws2, _ = create_workspace("vault-iso-2", "V2", "b@test.com")
        vault1 = get_vault_for_workspace(ws1)
        vault2 = get_vault_for_workspace(ws2)
        token = vault1.store(
            "SSN",
            "372-18-5421",
            "txn_iso",
            workspace_id=ws1.workspace_id,
        )
        assert vault2.retrieve(token, workspace_id=ws2.workspace_id) is None
