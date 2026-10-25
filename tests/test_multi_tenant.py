"""
tests/test_multi_tenant.py — Multi-tenant isolation.

Covers per-workspace signing and vault keys (with legacy-chain migration
safety), workspace ID hardening, role enforcement on the core endpoints,
per-workspace gateway policies and AI provider credentials, and the
MSP -> client management boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import warnings

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.credentials import (
    ProviderCredentialStore,
    resolve_upstream_for_workspace,
    validate_provider_base_url,
)
from gateway.pipeline import GatewayPipeline
from gateway.providers import resolve_provider
from hermes.api import app as api_app
from hermes.attestation import SIGNING_KEY, AttestationChain
from hermes.tenant_keys import (
    KEY_SCHEME_GLOBAL,
    KEY_SCHEME_PER_WORKSPACE,
    PURPOSE_ATTESTATION,
    PURPOSE_VAULT,
    derive_workspace_key,
    workspace_signing_key,
)
from hermes.vault import TokenVault
from hermes.workspaces import (
    _validate_workspace_id,
    create_workspace,
    get_chain_for_workspace,
    get_vault_for_workspace,
)

ADMIN_TOKEN = "test-admin-token-multi-tenant"
SCRUB_TEXT = "Patient John Smith SSN 372-18-5421 was seen today."


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "workspaces"
    monkeypatch.setenv("HERMES_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HERMES_REGISTRY_DB", str(data_dir / "registry.db"))
    monkeypatch.setenv("HERMES_ADMIN_TOKEN", ADMIN_TOKEN)
    monkeypatch.delenv("HERMES_POLICY_DB", raising=False)
    monkeypatch.delenv("HERMES_PROVIDER_CREDENTIALS_DB", raising=False)

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    monkeypatch.setattr(ws_mod, "_DEFAULT_DATA_DIR", str(data_dir))
    monkeypatch.setattr(ws_mod, "_DEFAULT_REGISTRY_DB", str(data_dir / "registry.db"))

    gateway_evidence.reset_v2_chains()
    gateway_policy.reload_policy()
    gateway_policy._workspace_policies.clear()
    gateway_app._stats.clear()
    yield
    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    gateway_policy._workspace_policies.clear()


@pytest.fixture()
def api():
    return TestClient(api_app)


def _create(api, workspace_id, *, parent=None, role="org_admin", plan="production"):
    body = {
        "workspace_id": workspace_id,
        "name": workspace_id,
        "owner_email": f"{workspace_id}@example.com",
        "plan": plan,
        "role": role,
    }
    if parent:
        body["parent_workspace_id"] = parent
    resp = api.post("/v1/workspaces", json=body, headers={"X-Admin-Token": ADMIN_TOKEN})
    assert resp.status_code == 200, resp.text
    return resp.json()["api_key"]


def _h(key):
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


class TestKeyDerivation:
    @staticmethod
    def test_deterministic_and_32_bytes():
        k1 = derive_workspace_key(b"root", PURPOSE_ATTESTATION, "acme")
        k2 = derive_workspace_key(b"root", PURPOSE_ATTESTATION, "acme")
        assert k1 == k2 and len(k1) == 32

    @staticmethod
    def test_differs_by_workspace_purpose_and_root():
        base = derive_workspace_key(b"root", PURPOSE_ATTESTATION, "acme")
        assert base != derive_workspace_key(b"root", PURPOSE_ATTESTATION, "beta")
        assert base != derive_workspace_key(b"root", PURPOSE_VAULT, "acme")
        assert base != derive_workspace_key(b"other", PURPOSE_ATTESTATION, "acme")

    @staticmethod
    def test_rejects_bad_inputs():
        with pytest.raises(ValueError):
            derive_workspace_key(b"root", "nope", "acme")
        with pytest.raises(ValueError):
            derive_workspace_key(b"root", PURPOSE_VAULT, "")
        with pytest.raises(ValueError):
            derive_workspace_key(b"", PURPOSE_VAULT, "acme")


# ---------------------------------------------------------------------------
# Attestation chain keys + migration safety
# ---------------------------------------------------------------------------


class TestChainKeys:
    @staticmethod
    def test_new_workspace_chain_uses_per_workspace_key():
        ws, _ = create_workspace("chainkey-a", "A", "a@example.com")
        chain = get_chain_for_workspace(ws)
        assert chain.key_scheme == KEY_SCHEME_PER_WORKSPACE
        receipt = chain.issue("txn-a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 10, 5)
        assert chain.verify_chain()
        # Receipt is NOT verifiable with the deployment-wide key.
        canonical = json.dumps(
            chain._build_sign_content(receipt), sort_keys=True, separators=(",", ":")
        )
        global_sig = hmac.new(SIGNING_KEY, canonical.encode(), hashlib.sha256).hexdigest()
        assert receipt.receipt_hash != global_sig

    @staticmethod
    def test_workspace_chains_cannot_verify_each_other(tmp_path):
        ws_a, _ = create_workspace("chainkey-b1", "B1", "b1@example.com")
        ws_b, _ = create_workspace("chainkey-b2", "B2", "b2@example.com")
        get_chain_for_workspace(ws_a).issue("txn-1", {}, {}, 4, 4)

        import hermes.workspaces as ws_mod

        ws_mod._chain_cache.clear()
        # Reopen A's chain with B's key: must not verify.
        forged = AttestationChain(
            db_path=ws_a.chain_db_path,
            signing_key=workspace_signing_key(ws_b.workspace_id),
        )
        assert forged.verify_chain() is False

    @staticmethod
    def test_per_workspace_chain_refuses_to_open_without_key():
        ws, _ = create_workspace("chainkey-c", "C", "c@example.com")
        get_chain_for_workspace(ws).issue("txn-c", {}, {}, 1, 1)
        with pytest.raises(ValueError, match="per-workspace"):
            AttestationChain(db_path=ws.chain_db_path)

    @staticmethod
    def test_reopen_with_key_round_trips():
        ws, _ = create_workspace("chainkey-d", "D", "d@example.com")
        get_chain_for_workspace(ws).issue("txn-d", {}, {}, 1, 1)
        reopened = AttestationChain(
            db_path=ws.chain_db_path, signing_key=workspace_signing_key(ws.workspace_id)
        )
        assert reopened.chain_length() == 1
        assert reopened.verify_chain()
        checkpoint = reopened.issue_checkpoint()
        assert reopened.verify_checkpoint(checkpoint)

    @staticmethod
    def test_legacy_chain_with_receipts_keeps_global_key():
        ws, _ = create_workspace("chainkey-legacy", "L", "l@example.com")
        # Simulate a chain written before this change: global key, no chain_meta.
        legacy = AttestationChain(db_path=ws.chain_db_path)
        legacy.issue("txn-old", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 10, 5)
        legacy._conn.execute("DROP TABLE chain_meta")
        legacy._conn.commit()
        legacy._conn.close()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            chain = get_chain_for_workspace(ws)
        assert chain.key_scheme == KEY_SCHEME_GLOBAL
        assert chain.verify_chain(), "pre-existing receipts must still verify"
        chain.issue("txn-new", {}, {}, 1, 1)
        assert chain.verify_chain()
        assert any("predates per-workspace" in str(w.message) for w in caught)

    @staticmethod
    def test_global_singleton_chain_unchanged(tmp_path):
        chain = AttestationChain(db_path=str(tmp_path / "legacy.db"))
        assert chain.key_scheme == KEY_SCHEME_GLOBAL
        chain.issue("txn", {}, {}, 1, 1)
        assert chain.verify_chain()
        assert AttestationChain(db_path=str(tmp_path / "legacy.db")).verify_chain()

    @staticmethod
    def test_chain_refuses_legacy_db_path(monkeypatch):
        ws, _ = create_workspace("chainkey-shared", "S", "s@example.com")
        monkeypatch.setenv("HERMES_DB_PATH", ws.chain_db_path)
        with pytest.raises(RuntimeError, match="legacy single-tenant"):
            get_chain_for_workspace(ws)


# ---------------------------------------------------------------------------
# Vault keys
# ---------------------------------------------------------------------------


class TestVaultKeys:
    @staticmethod
    def test_same_value_gives_different_tokens_per_workspace():
        ws_a, _ = create_workspace("vaultkey-a", "A", "a@example.com")
        ws_b, _ = create_workspace("vaultkey-b", "B", "b@example.com")
        va, vb = get_vault_for_workspace(ws_a), get_vault_for_workspace(ws_b)
        assert va.key_scheme == vb.key_scheme == KEY_SCHEME_PER_WORKSPACE
        ta = va.store("SSN", "372-18-5421", "t1", workspace_id=ws_a.workspace_id)
        tb = vb.store("SSN", "372-18-5421", "t1", workspace_id=ws_b.workspace_id)
        assert ta != tb
        assert va.retrieve(ta, workspace_id=ws_a.workspace_id) == "372-18-5421"
        assert vb.retrieve(tb, workspace_id=ws_b.workspace_id) == "372-18-5421"

    @staticmethod
    def test_vault_ciphertext_not_decryptable_with_other_key():
        from cryptography.exceptions import InvalidTag

        ws_a, _ = create_workspace("vaultkey-c", "C", "c@example.com")
        ws_b, _ = create_workspace("vaultkey-d", "D", "d@example.com")
        token = get_vault_for_workspace(ws_a).store(
            "SSN", "123-45-6789", "t", workspace_id="shared-row"
        )
        from hermes.tenant_keys import workspace_vault_key

        # Copy A's row into a vault opened with B's key.
        foreign = TokenVault(
            db_path=ws_a.vault_db_path + ".copy",
            vault_key=workspace_vault_key(ws_b.workspace_id),
        )
        src = sqlite3.connect(ws_a.vault_db_path)
        row = src.execute(
            "SELECT token, pii_type, encrypted_value, transaction_id, created_at, workspace_id "
            "FROM vault_entries WHERE token = ?",
            (token,),
        ).fetchone()
        src.close()
        dst = sqlite3.connect(ws_a.vault_db_path + ".copy")
        dst.execute("INSERT INTO vault_entries VALUES (?, ?, ?, ?, ?, ?)", row)
        dst.commit()
        dst.close()
        with pytest.raises(InvalidTag):
            foreign.retrieve(token, workspace_id="shared-row")

    @staticmethod
    def test_per_workspace_vault_refuses_to_open_without_key():
        ws, _ = create_workspace("vaultkey-e", "E", "e@example.com")
        get_vault_for_workspace(ws).store("SSN", "1", "t", workspace_id=ws.workspace_id)
        with pytest.raises(ValueError, match="per-workspace"):
            TokenVault(db_path=ws.vault_db_path)

    @staticmethod
    def test_legacy_vault_with_entries_keeps_global_key(tmp_path):
        path = str(tmp_path / "legacy_vault.db")
        legacy = TokenVault(db_path=path)
        token = legacy.store("SSN", "372-18-5421", "t")
        conn = sqlite3.connect(path)
        conn.execute("DROP TABLE vault_meta")
        conn.commit()
        conn.close()
        with pytest.warns(UserWarning, match="predates per-workspace"):
            reopened = TokenVault(db_path=path, vault_key=b"\x01" * 32)
        assert reopened.key_scheme == KEY_SCHEME_GLOBAL
        assert reopened.retrieve(token) == "372-18-5421"


# ---------------------------------------------------------------------------
# Workspace ID hardening + hierarchy
# ---------------------------------------------------------------------------


class TestWorkspaceIds:
    @pytest.mark.parametrize("bad", ["default", "abc\n", "ab", "-abc", "ABC", "a/b/c"])
    @staticmethod
    def test_invalid_or_reserved_ids_rejected(bad):
        with pytest.raises(ValueError):
            _validate_workspace_id(bad)

    @staticmethod
    def test_api_rejects_unknown_parent(api):
        resp = api.post(
            "/v1/workspaces",
            json={
                "workspace_id": "orphan-client",
                "name": "Orphan",
                "owner_email": "o@example.com",
                "parent_workspace_id": "msp-that-does-not-exist",
            },
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 400

    @staticmethod
    def test_api_rejects_grandchild(api):
        _create(api, "hier-msp")
        _create(api, "hier-client", parent="hier-msp")
        resp = api.post(
            "/v1/workspaces",
            json={
                "workspace_id": "hier-grandchild",
                "name": "G",
                "owner_email": "g@example.com",
                "parent_workspace_id": "hier-client",
            },
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 400

    @staticmethod
    def test_api_sets_role(api):
        key = _create(api, "role-tech", role="operator")
        assert api.get("/v1/workspace", headers=_h(key)).json()["role"] == "operator"


# ---------------------------------------------------------------------------
# Role enforcement on core endpoints
# ---------------------------------------------------------------------------


class TestRoles:
    @staticmethod
    def test_new_workspaces_default_to_org_admin(api):
        resp = api.post(
            "/v1/workspaces",
            json={"workspace_id": "role-default", "name": "D", "owner_email": "d@example.com"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.json()["workspace"]["role"] == "org_admin"

    @staticmethod
    def test_unknown_role_rejected(api):
        resp = api.post(
            "/v1/workspaces",
            json={"workspace_id": "role-bad", "name": "B", "owner_email": "b@example.com", "role": "superuser"},
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "legacy, canonical",
        [("msp_admin", "org_admin"), ("msp_tech", "operator"), ("client_readonly", "viewer")],
    )
    @staticmethod
    def test_legacy_role_names_behave_like_canonical(api, legacy, canonical):
        key_legacy = _create(api, f"alias-{legacy.replace('_', '-')}", role=legacy)
        key_canon = _create(api, f"alias-{canonical.replace('_', '-')}", role=canonical)
        probes = [
            ("post", "/v1/scrub", {"payload": "hello"}),
            ("get", "/v1/status", None),
            ("get", "/v1/workspaces", None),
        ]
        for method, path, body in probes:
            kwargs = {"json": body} if body is not None else {}
            a = getattr(api, method)(path, headers=_h(key_legacy), **kwargs).status_code
            b = getattr(api, method)(path, headers=_h(key_canon), **kwargs).status_code
            assert a == b, (legacy, path, a, b)
        # Stored role is not rewritten.
        assert api.get("/v1/workspace", headers=_h(key_legacy)).json()["role"] == legacy

    @staticmethod
    def test_canonical_role_mapping():
        from hermes.workspaces import canonical_role

        assert canonical_role("msp_admin") == "org_admin"
        assert canonical_role("operator") == "operator"
        assert canonical_role("root") is None
        assert canonical_role(None) is None

    @staticmethod
    def test_require_role_rejects_empty_role_list():
        from hermes.api import require_role

        with pytest.raises(ValueError):
            require_role(["not-a-role"])

    @staticmethod
    def test_viewer_cannot_scrub_or_review(api):
        key = _create(api, "ro-client", role="viewer")
        assert api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(key)).status_code == 403
        assert api.post("/v1/trial-scan", headers=_h(key)).status_code == 403
        assert api.post(
            "/v1/review",
            json={"transaction_id": "x", "reviewed_by": "r", "decision": "accepted"},
            headers=_h(key),
        ).status_code == 403

    @staticmethod
    def test_viewer_can_read_status_and_history(api):
        key = _create(api, "ro-reader", role="viewer")
        assert api.get("/v1/status", headers=_h(key)).status_code == 200
        assert api.get("/v1/scan-history", headers=_h(key)).status_code == 200

    @staticmethod
    def test_operator_can_scrub_but_not_list_or_rotate(api):
        key = _create(api, "tech-user", role="operator")
        assert api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(key)).status_code == 200
        assert api.get("/v1/workspaces", headers=_h(key)).status_code == 403
        assert api.post("/v1/workspaces/tech-user/rotate-key", headers=_h(key)).status_code == 403

    @staticmethod
    def test_unknown_key_is_401(api):
        assert api.get("/v1/status", headers=_h("not-a-key")).status_code == 401

    @staticmethod
    def test_legacy_env_key_still_works(api, monkeypatch):
        monkeypatch.setenv("HERMES_API_KEY", "legacy-single-tenant-key")
        resp = api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h("legacy-single-tenant-key"))
        assert resp.status_code == 200
        assert "372-18-5421" not in resp.json()["clean_text"]


# ---------------------------------------------------------------------------
# Chain isolation through the API
# ---------------------------------------------------------------------------


class TestCanaryAuditRoles:
    """Registered workspace keys used to crash /v1/telemetry/canary-audit (500)."""

    @pytest.mark.parametrize("role", ["org_admin", "operator", "msp_admin", "msp_tech"])
    @staticmethod
    def test_operating_roles_can_run_canary_audit(api, role):
        key = _create(api, f"canary-{role.replace('_', '-')}", role=role)
        resp = api.post(
            "/v1/telemetry/canary-audit", json={"payload_text": "hello"}, headers=_h(key)
        )
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize("role", ["viewer", "client_readonly"])
    @staticmethod
    def test_viewer_cannot_run_canary_audit(api, role):
        key = _create(api, f"canary-{role.replace('_', '-')}", role=role)
        resp = api.post(
            "/v1/telemetry/canary-audit", json={"payload_text": "hello"}, headers=_h(key)
        )
        assert resp.status_code == 403


class TestChainIsolationApi:
    @staticmethod
    def test_two_workspaces_have_independent_chains(api):
        key_a = _create(api, "iso-api-a")
        key_b = _create(api, "iso-api-b")
        api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(key_a))
        api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(key_a))
        api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(key_b))
        assert api.get("/v1/status", headers=_h(key_a)).json()["total_scans"] == 2
        assert api.get("/v1/status", headers=_h(key_b)).json()["total_scans"] == 1

    @staticmethod
    def test_chain_integrity_access_rules(api):
        msp = _create(api, "ci-msp")
        client = _create(api, "ci-client", parent="ci-msp", role="operator")
        other = _create(api, "ci-other")
        api.post("/v1/scrub", json={"payload": SCRUB_TEXT}, headers=_h(client))

        own = api.get("/v1/workspaces/ci-client/chain-integrity", headers=_h(client))
        assert own.status_code == 200
        by_parent = api.get("/v1/workspaces/ci-client/chain-integrity", headers=_h(msp))
        assert by_parent.status_code == 200
        body = by_parent.json()
        assert body["chain_integrity"] == "verified"
        assert body["chain_length"] == 1
        assert body["key_scheme"] == KEY_SCHEME_PER_WORKSPACE

        assert api.get("/v1/workspaces/ci-client/chain-integrity", headers=_h(other)).status_code == 403
        assert api.get("/v1/workspaces/ci-msp/chain-integrity", headers=_h(client)).status_code == 403
        assert api.get("/v1/workspaces/nope-missing/chain-integrity", headers=_h(msp)).status_code == 404

    @staticmethod
    def test_empty_chain_reports_no_data(api):
        key = _create(api, "ci-empty")
        resp = api.get("/v1/workspaces/ci-empty/chain-integrity", headers=_h(key))
        assert resp.json()["chain_integrity"] == "no_data"


# ---------------------------------------------------------------------------
# Gateway policy per workspace
# ---------------------------------------------------------------------------


class TestWorkspacePolicyApi:
    @staticmethod
    def test_default_then_set_then_delete(api):
        key = _create(api, "pol-msp")
        resp = api.get("/v1/workspaces/pol-msp/policy", headers=_h(key))
        assert resp.json()["source"] == "default"
        assert resp.json()["policy_id"] == "HIPAA_STRICT"

        resp = api.put(
            "/v1/workspaces/pol-msp/policy",
            json={"policy_id": "HIPAA_PRODUCTION_BLOCK"},
            headers=_h(key),
        )
        assert resp.status_code == 200
        assert resp.json()["policy_id"] == "HIPAA_PRODUCTION_BLOCK"
        assert resp.json()["source"] == "workspace"

        resp = api.delete("/v1/workspaces/pol-msp/policy", headers=_h(key))
        assert resp.json()["source"] == "default"

    @staticmethod
    def test_unknown_policy_rejected(api):
        key = _create(api, "pol-bad")
        resp = api.put(
            "/v1/workspaces/pol-bad/policy", json={"policy_id": "ALLOW_EVERYTHING"}, headers=_h(key)
        )
        assert resp.status_code == 400

    @staticmethod
    def test_client_cannot_change_own_policy_but_msp_can(api):
        msp = _create(api, "pol-parent")
        client = _create(api, "pol-child", parent="pol-parent")  # even as org_admin
        assert api.put(
            "/v1/workspaces/pol-child/policy",
            json={"policy_id": "HIPAA_PRODUCTION_BLOCK"},
            headers=_h(client),
        ).status_code == 403
        assert api.put(
            "/v1/workspaces/pol-child/policy",
            json={"policy_id": "HIPAA_PRODUCTION_BLOCK"},
            headers=_h(msp),
        ).status_code == 200
        assert api.get("/v1/workspaces/pol-child/policy", headers=_h(client)).json()["policy_id"] == "HIPAA_PRODUCTION_BLOCK"

    @staticmethod
    def test_unrelated_workspace_cannot_read_or_set(api):
        _create(api, "pol-victim")
        attacker = _create(api, "pol-attacker")
        assert api.get("/v1/workspaces/pol-victim/policy", headers=_h(attacker)).status_code == 403
        assert api.put(
            "/v1/workspaces/pol-victim/policy", json={"policy_id": "HIPAA_STRICT"}, headers=_h(attacker)
        ).status_code == 403

    @staticmethod
    def test_operator_cannot_set_policy(api):
        key = _create(api, "pol-tech", role="operator")
        assert api.put(
            "/v1/workspaces/pol-tech/policy", json={"policy_id": "HIPAA_STRICT"}, headers=_h(key)
        ).status_code == 403

    @staticmethod
    def test_policy_store_failure_fails_closed(monkeypatch):
        def broken(*_a, **_k):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(gateway_policy, "_policy_conn", broken)
        with pytest.raises(RuntimeError, match="policy store unavailable"):
            gateway_policy.PolicyEngine("any-workspace")

    @staticmethod
    def test_unknown_persisted_policy_fails_closed():
        gateway_policy.save_workspace_policy("ghost-ws", "HIPAA_STRICT")
        conn = gateway_policy._policy_conn()
        conn.execute("UPDATE workspace_policies SET policy_id = 'REMOVED_POLICY'")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="unknown policy"):
            gateway_policy.PolicyEngine("ghost-ws")


# ---------------------------------------------------------------------------
# Provider credentials per workspace
# ---------------------------------------------------------------------------


class TestProviderCredentials:
    @staticmethod
    def test_encrypted_at_rest_and_round_trip():
        store = ProviderCredentialStore()
        store.set_credential("cred-ws", "openai", "sk-secret-value-123")
        raw = sqlite3.connect(store._db_path).execute(
            "SELECT encrypted_credential FROM provider_credentials"
        ).fetchone()[0]
        assert "sk-secret-value-123" not in raw
        assert store.get_credential("cred-ws", "openai") == ("sk-secret-value-123", None)

    @staticmethod
    def test_other_workspace_cannot_decrypt():
        store = ProviderCredentialStore()
        store.set_credential("cred-a", "openai", "sk-a")
        conn = sqlite3.connect(store._db_path)
        conn.execute("UPDATE provider_credentials SET workspace_id = 'cred-b'")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="could not be decrypted"):
            store.get_credential("cred-b", "openai")

    @pytest.mark.parametrize(
        "url",
        [
            "http://acme.openai.azure.com",
            "https://evil.example.com",
            "https://acme.openai.azure.com.evil.com",
            "https://user:pw@acme.openai.azure.com",
            "https://acme.openai.azure.com/path",
            "https://acme.openai.azure.com:8443",
            "https://acme.openai.azure.com?x=1",
        ],
    )
    @staticmethod
    def test_azure_base_url_rejected(url):
        with pytest.raises(ValueError):
            validate_provider_base_url("azure_openai", url)

    @staticmethod
    def test_azure_base_url_accepted_and_normalized():
        assert validate_provider_base_url("azure_openai", "https://Acme.OpenAI.Azure.com/") == "https://acme.openai.azure.com"

    @staticmethod
    def test_base_url_only_for_azure():
        with pytest.raises(ValueError):
            validate_provider_base_url("openai", "https://acme.openai.azure.com")

    @staticmethod
    def test_resolve_falls_back_to_env(monkeypatch):
        monkeypatch.setenv("HERMES_OPENAI_API_KEY", "sk-env")
        headers, base = resolve_upstream_for_workspace({}, resolve_provider("openai"), "no-creds-ws")
        assert headers["Authorization"] == "Bearer sk-env"
        assert base == "https://api.openai.com"

    @staticmethod
    def test_resolve_prefers_workspace_credential(monkeypatch):
        monkeypatch.setenv("HERMES_ANTHROPIC_API_KEY", "env-key")
        ProviderCredentialStore().set_credential("has-creds-ws", "anthropic", "ws-key")
        headers, _ = resolve_upstream_for_workspace({}, resolve_provider("anthropic"), "has-creds-ws")
        assert headers["x-api-key"] == "ws-key"
        assert headers["anthropic-version"] == "2023-06-01"

    @staticmethod
    def test_api_never_returns_credential(api):
        key = _create(api, "cred-api")
        resp = api.put(
            "/v1/workspaces/cred-api/provider-credentials/openai",
            json={"credential": "sk-should-never-come-back"},
            headers=_h(key),
        )
        assert resp.status_code == 200
        assert "sk-should-never-come-back" not in resp.text
        assert [c["provider_id"] for c in resp.json()["configured"]] == ["openai"]
        listing = api.get("/v1/workspaces/cred-api/provider-credentials", headers=_h(key))
        assert "sk-should-never-come-back" not in listing.text

    @staticmethod
    def test_api_rejects_unknown_provider_and_bad_azure_url(api):
        key = _create(api, "cred-bad")
        assert api.put(
            "/v1/workspaces/cred-bad/provider-credentials/not-a-provider",
            json={"credential": "x"},
            headers=_h(key),
        ).status_code == 400
        assert api.put(
            "/v1/workspaces/cred-bad/provider-credentials/azure_openai",
            json={"credential": "x", "base_url": "https://attacker.example.com"},
            headers=_h(key),
        ).status_code == 400

    @staticmethod
    def test_api_delete(api):
        key = _create(api, "cred-del")
        api.put("/v1/workspaces/cred-del/provider-credentials/openai", json={"credential": "x"}, headers=_h(key))
        assert api.delete("/v1/workspaces/cred-del/provider-credentials/openai", headers=_h(key)).status_code == 200
        assert api.delete("/v1/workspaces/cred-del/provider-credentials/openai", headers=_h(key)).status_code == 404

    @staticmethod
    def test_client_cannot_set_own_credentials(api):
        _create(api, "cred-parent")
        client = _create(api, "cred-child", parent="cred-parent")
        assert api.put(
            "/v1/workspaces/cred-child/provider-credentials/openai",
            json={"credential": "x"},
            headers=_h(client),
        ).status_code == 403


# ---------------------------------------------------------------------------
# Gateway end to end: per-workspace policy and credentials actually apply
# ---------------------------------------------------------------------------


class TestGatewayEndToEnd:
    @pytest.fixture()
    def gateway(self, monkeypatch):
        monkeypatch.setenv("HERMES_OPENAI_API_KEY", "sk-deployment-default")
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(
                200,
                json={"id": "chatcmpl-test", "choices": []},
                headers={"content-type": "application/json"},
            )

        transport = httpx.MockTransport(handler)
        monkeypatch.setattr(
            gateway_app,
            "_pipeline",
            GatewayPipeline(client_factory=lambda: httpx.Client(transport=transport)),
        )
        return TestClient(gateway_app.app), captured

    @staticmethod
    def _chat(text):
        return {"model": "gpt-4o", "messages": [{"role": "user", "content": text}]}

    def test_policy_applies_per_workspace_without_restart(self, gateway, api):
        gw, captured = gateway
        key_block = _create(api, "gw-block")
        key_redact = _create(api, "gw-redact")
        api.put("/v1/workspaces/gw-block/policy", json={"policy_id": "HIPAA_PRODUCTION_BLOCK"}, headers=_h(key_block))

        blocked = gw.post("/gateway/openai/v1/chat/completions", json=self._chat(SCRUB_TEXT), headers=_h(key_block))
        assert blocked.status_code == 403
        assert captured == [], "BLOCK policy must forward zero bytes upstream"

        redacted = gw.post("/gateway/openai/v1/chat/completions", json=self._chat(SCRUB_TEXT), headers=_h(key_redact))
        assert redacted.status_code == 200
        assert len(captured) == 1
        assert b"372-18-5421" not in captured[0].content

    def test_workspace_credential_is_injected(self, gateway, api):
        gw, captured = gateway
        key_own = _create(api, "gw-own-creds")
        key_env = _create(api, "gw-env-creds")
        api.put(
            "/v1/workspaces/gw-own-creds/provider-credentials/openai",
            json={"credential": "sk-client-specific"},
            headers=_h(key_own),
        )
        gw.post("/gateway/openai/v1/chat/completions", json=self._chat("hello"), headers=_h(key_own))
        gw.post("/gateway/openai/v1/chat/completions", json=self._chat("hello"), headers=_h(key_env))
        assert captured[0].headers["authorization"] == "Bearer sk-client-specific"
        assert captured[1].headers["authorization"] == "Bearer sk-deployment-default"

    def test_azure_workspace_endpoint_is_used(self, gateway, api):
        gw, captured = gateway
        key = _create(api, "gw-azure")
        api.put(
            "/v1/workspaces/gw-azure/provider-credentials/azure_openai",
            json={"credential": "az-key", "base_url": "https://clinic-one.openai.azure.com"},
            headers=_h(key),
        )
        gw.post(
            "/gateway/azure_openai/openai/deployments/gpt4/chat/completions?api-version=2024-02-01",
            json=self._chat("hello"),
            headers=_h(key),
        )
        assert captured[0].url.host == "clinic-one.openai.azure.com"
        assert captured[0].headers["api-key"] == "az-key"

    def test_gateway_receipts_land_in_each_workspace_db(self, gateway, api):
        gw, _ = gateway
        key_a = _create(api, "gw-rcpt-a")
        key_b = _create(api, "gw-rcpt-b")
        gw.post("/gateway/openai/v1/chat/completions", json=self._chat("hi"), headers=_h(key_a))
        gw.post("/gateway/openai/v1/chat/completions", json=self._chat("hi"), headers=_h(key_b))
        gw.post("/gateway/openai/v1/chat/completions", json=self._chat("hi"), headers=_h(key_b))

        import hermes.workspaces as ws_mod

        def count(ws_id):
            ws = ws_mod.get_workspace(ws_id)
            conn = sqlite3.connect(ws.chain_db_path)
            try:
                rows = conn.execute("SELECT workspace_id, payload FROM gateway_receipts").fetchall()
            finally:
                conn.close()
            assert all(r[0] == ws_id and json.loads(r[1])["workspace_id"] == ws_id for r in rows)
            return len(rows)

        assert count("gw-rcpt-a") == 1
        assert count("gw-rcpt-b") == 2
