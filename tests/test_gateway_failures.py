"""Gateway upstream, receipt persistence, and production signing tests."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
from hermes.receipts.v2.key_store import KeyStore
from hermes.workspaces import create_workspace

PASSPHRASE = b"gateway-keystore-passphrase"


@pytest.fixture(autouse=True)
def isolated_gateway_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB",
        str(tmp_path / "workspaces" / "registry.db"),
    )
    monkeypatch.setenv("HERMES_ENV", "development")
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")

    gateway_evidence.reset_v2_chains()
    gateway_policy.reload_policy()
    yield


@pytest.fixture()
def workspace():
    return create_workspace("fail-gw-01", "Failure GW", "f@test.com")


@pytest.fixture()
def client():
    return TestClient(app)


def test_upstream_connection_failure_returns_502(client, workspace, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    def _fail_transport(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(_fail_transport)
        )
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "upstream_transport_failure"
    assert body["forwarded"] is True
    assert body["receipt_digest"]

    row = gateway_evidence.get_gateway_receipt(ws, body["receipt_digest"])
    assert row["payload"]["failure_class"] == "upstream_connect_error"


def test_upstream_timeout_returns_502(client, workspace, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    def _timeout_transport(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(_timeout_transport)
        )
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_timeout"


def test_upstream_5xx_returns_502(client, workspace, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    def _5xx_transport(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "provider overloaded"})

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(_5xx_transport)
        )
    )

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["upstream_status"] == 503
    row = gateway_evidence.get_gateway_receipt(ws, body["receipt_digest"])
    assert row["payload"]["upstream_status"] == 503


def test_receipt_persistence_failure_returns_503(client, workspace, monkeypatch):
    ws, api_key = workspace
    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "test-openai-key")

    def _raise_persist(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(
        gateway_evidence,
        "_persist_gateway_receipt_in_transaction",
        _raise_persist,
    )

    before_head = gateway_evidence.get_v2_chain_head(ws.workspace_id)

    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers={"X-API-Key": api_key},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "evidence_persistence_error"
    assert body["receipt_digest"]
    assert body["forwarded"] is True
    assert gateway_evidence.get_v2_chain_head(ws.workspace_id) == before_head


def test_production_refuses_ephemeral_signer(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)

    with pytest.raises(RuntimeError, match="HERMES_GATEWAY_KEYSTORE"):
        gateway_evidence.validate_gateway_signing_config()


def test_development_allows_ephemeral_signer(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "development")
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)

    gateway_evidence.reset_v2_chains()
    signer = gateway_evidence._get_gateway_signer()
    assert signer is not None


def test_production_loads_persistent_keystore(tmp_path, monkeypatch):
    store_path = tmp_path / "gateway.keystore"
    KeyStore.create(store_path, PASSPHRASE)
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(store_path))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE.decode())

    gateway_evidence.reset_v2_chains()
    signer_a = gateway_evidence._get_gateway_signer()
    key_id = signer_a.key_id

    gateway_evidence.reset_v2_chains()
    signer_b = gateway_evidence._get_gateway_signer()
    assert signer_b.key_id == key_id


def test_production_startup_fails_without_keystore(monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)

    with pytest.raises(RuntimeError, match="HERMES_GATEWAY_KEYSTORE"):
        gateway_evidence.validate_gateway_signing_config()


def test_production_app_startup_fails_when_keystore_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(tmp_path / "missing.keystore"))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE.decode())
    monkeypatch.setattr(gateway_evidence, "_GATEWAY_SIGNER", None)

    with pytest.raises(FileNotFoundError, match="Key store not found"), TestClient(app):
        pass


def test_production_app_startup_fails_with_wrong_passphrase(tmp_path, monkeypatch):
    store_path = tmp_path / "gateway.keystore"
    KeyStore.create(store_path, PASSPHRASE)
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(store_path))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", "wrong-passphrase")
    monkeypatch.setattr(gateway_evidence, "_GATEWAY_SIGNER", None)

    with pytest.raises(ValueError, match="wrong passphrase"), TestClient(app):
        pass


def test_production_app_startup_loads_keystore_signer(tmp_path, monkeypatch):
    store_path = tmp_path / "gateway.keystore"
    store = KeyStore.create(store_path, PASSPHRASE)
    monkeypatch.setenv("HERMES_ENV", "production")
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(store_path))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE.decode())
    monkeypatch.setattr(gateway_evidence, "_GATEWAY_SIGNER", None)

    with TestClient(app):
        assert gateway_evidence._GATEWAY_SIGNER is not None
        assert gateway_evidence._GATEWAY_SIGNER.key_id.hex() == store.key_id
