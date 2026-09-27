"""Tests for the /v2/receipts and /v2/verify demo signing oracle endpoints."""

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("HERMES_API_KEY", "unit-test-key")

from hermes.api import app
from hermes.demo_receipts import (
    KEYSTORE_PASSPHRASE_ENV_VAR,
    KEYSTORE_PATH_ENV_VAR,
    reset_signer,
)
from hermes.receipts.v2.key_store import KeyStore

client = TestClient(app)

API_KEY = os.environ["HERMES_API_KEY"]
AUTH = {"X-API-Key": API_KEY}

PO_PAYLOAD = {
    "action": "purchase_order.approve",
    "actor": "agent:procurement-copilot",
    "po_number": "PO-2026-04817",
    "vendor": "Meridian Medical Supply",
    "amount_usd": 12480.0,
    "currency": "USD",
    "authorized": True,
}


@pytest.fixture(autouse=True)
def _isolated_signer(monkeypatch):
    """Each test starts with no cached signer and no keystore configured."""
    monkeypatch.delenv(KEYSTORE_PATH_ENV_VAR, raising=False)
    monkeypatch.delenv(KEYSTORE_PASSPHRASE_ENV_VAR, raising=False)
    reset_signer()
    yield
    reset_signer()


def _issue(payload=None):
    response = client.post(
        "/v2/receipts",
        headers=AUTH,
        json={"payload": payload or PO_PAYLOAD},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_issue_returns_receipt_id_action_digest_and_issued_at():
    data = _issue()

    assert data["receipt_id"]
    assert len(data["action_digest_full"]) == 64
    int(data["action_digest_full"], 16)  # hex
    assert data["action_digest"] == data["action_digest_full"][:16]
    assert data["issued_at"].startswith("20")
    assert data["algorithm"] == "EdDSA"


def test_issue_without_keystore_warns_about_ephemeral_key():
    data = _issue()

    assert data["ephemeral_key"] is True
    assert KEYSTORE_PATH_ENV_VAR in data["warning"]
    assert "not independently verifiable" in data["warning"]


def test_issue_uses_configured_keystore_without_warning(tmp_path, monkeypatch):
    keystore_path = tmp_path / "demo.keystore"
    store = KeyStore.create(keystore_path, passphrase=b"correct-horse-battery")
    monkeypatch.setenv(KEYSTORE_PATH_ENV_VAR, str(keystore_path))
    monkeypatch.setenv(KEYSTORE_PASSPHRASE_ENV_VAR, "correct-horse-battery")
    reset_signer()

    data = _issue()

    assert data["ephemeral_key"] is False
    assert data["warning"] is None
    assert data["key_id"] == store.key_id


def test_unreadable_keystore_falls_back_with_warning_instead_of_crashing(
    tmp_path, monkeypatch
):
    missing = tmp_path / "does-not-exist.keystore"
    monkeypatch.setenv(KEYSTORE_PATH_ENV_VAR, str(missing))
    monkeypatch.setenv(KEYSTORE_PASSPHRASE_ENV_VAR, "whatever")
    reset_signer()

    data = _issue()

    assert data["ephemeral_key"] is True
    assert "could not be opened" in data["warning"]


def test_verify_stored_receipt_passes_every_claim():
    issued = _issue()

    response = client.post(
        "/v2/verify",
        headers=AUTH,
        json={"receipt_id": issued["receipt_id"]},
    )
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["verified_payload"] == "stored"
    assert data["signature_valid"] is True
    assert data["receipt_digest_valid"] is True
    assert data["fully_valid"] is True
    assert data["errors"] == []
    assert data["algorithm"] == "EdDSA"
    assert data["issued_at"] == issued["issued_at"]
    assert data["claims"]["po_number"] == "PO-2026-04817"
    assert data["claims"]["amount_usd"] == 12480.0


def test_verify_tampered_payload_fails_signature():
    issued = _issue()
    stored = client.post(
        "/v2/verify", headers=AUTH, json={"receipt_id": issued["receipt_id"]}
    ).json()

    tampered = dict(stored["claims"])
    tampered["amount_usd"] = 124800.0

    response = client.post(
        "/v2/verify",
        headers=AUTH,
        json={"receipt_id": issued["receipt_id"], "tampered_payload": tampered},
    )
    assert response.status_code == 200, response.text
    data = response.json()

    assert data["verified_payload"] == "tampered"
    assert data["signature_valid"] is False
    assert data["receipt_digest_valid"] is False
    assert data["fully_valid"] is False
    assert any("Signature verification FAILED" in err for err in data["errors"])


def test_verify_reports_key_mismatch_when_signer_is_replaced():
    issued = _issue()
    reset_signer()  # next request generates a different ephemeral key

    data = client.post(
        "/v2/verify", headers=AUTH, json={"receipt_id": issued["receipt_id"]}
    ).json()

    assert data["signature_valid"] is True
    assert any("not the key currently loaded" in w for w in data["warnings"])


def test_verify_unknown_receipt_id_returns_404():
    response = client.post(
        "/v2/verify",
        headers=AUTH,
        json={"receipt_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert response.status_code == 404


def test_v2_endpoints_require_api_key():
    assert client.post("/v2/receipts", json={"payload": PO_PAYLOAD}).status_code == 422
    assert (
        client.post(
            "/v2/receipts",
            headers={"X-API-Key": "wrong-key"},
            json={"payload": PO_PAYLOAD},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/v2/verify",
            headers={"X-API-Key": "wrong-key"},
            json={"receipt_id": "abc"},
        ).status_code
        == 401
    )
