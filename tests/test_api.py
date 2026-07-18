import hashlib
import hmac
import json
import os

from fastapi.testclient import TestClient

from hermes.api import API_KEY_ENV_VAR, app
from hermes.attestation import ATTESTATION_CHAIN, SIGNING_KEY

os.environ.setdefault("HERMES_API_KEY", "unit-test-key")

client = TestClient(app)


def _verify_receipt_dict(receipt: dict) -> bool:
    """Recompute the HMAC for a compliance receipt payload returned by the API."""
    content = dict(receipt)
    stored_hash = content.pop("receipt_hash")
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(
        SIGNING_KEY,
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(stored_hash, expected)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "operational"

def test_unauthorized_access_blocked():
    """Ensure payloads are rejected without the correct MSP tenant key."""
    response = client.post("/v1/scrub", json={"payload": "Test"})
    assert response.status_code == 422
    
    response = client.post(
        "/v1/scrub", 
        headers={"X-API-Key": "invalid_key"}, 
        json={"payload": "Test"}
    )
    assert response.status_code == 401


def test_rejects_when_env_var_unset(monkeypatch):
    """Reject authenticated-looking requests when HERMES_API_KEY is unset."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    local_client = TestClient(app)
    response = local_client.post(
        "/v1/scrub",
        headers={"x-api-key": "anything"},
        json={"payload": "Test"},
    )
    assert response.status_code == 401


def test_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "correct-key-123")
    local_client = TestClient(app)
    response = local_client.post(
        "/v1/scrub",
        headers={"x-api-key": "wrong-key-456"},
        json={"payload": "Test"},
    )
    assert response.status_code == 401


def test_accepts_correct_key(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "correct-key-123")
    local_client = TestClient(app)
    response = local_client.post(
        "/v1/scrub",
        headers={"x-api-key": "correct-key-123"},
        json={"payload": "Test"},
    )
    assert response.status_code != 401


def test_successful_payload_scrub():
    """Verify end-to-end routing through the REST layer."""
    test_payload = "Patient SSN is 123-45-6789. Card 4242424242424242 charged."
    response = client.post(
        "/v1/scrub",
        headers={"X-API-Key": os.environ["HERMES_API_KEY"]},
        json={"payload": test_payload}
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert "[REDACTED_SSN]" in data["clean_text"]
    assert "[REDACTED_PAN]" in data["clean_text"]
    assert "123-45-6789" not in data["clean_text"]
    
    assert "audit_log" in data
    assert data["audit_log"]["flags_triggered"]["HIPAA_SSN"]["count"] == 1
    assert data["audit_log"]["flags_triggered"]["PCI_PAN"]["count"] == 1
    assert data["audit_log"]["flags_triggered"]["HIPAA_SSN"]["cfr_citation"] == (
        "45 CFR §164.514(b)(2)(i)(G)"
    )


def test_scrub_returns_verifiable_attestation_receipt():
    """Every /v1/scrub response must include an HMAC-verifiable compliance receipt."""
    test_payload = "Patient SSN is 123-45-6789."
    response = client.post(
        "/v1/scrub",
        headers={"X-API-Key": os.environ["HERMES_API_KEY"]},
        json={"payload": test_payload},
    )

    assert response.status_code == 200
    data = response.json()

    assert "compliance_receipt" in data
    receipt = data["compliance_receipt"]
    assert receipt["transaction_id"] == data["audit_log"]["transaction_id"]
    assert receipt["payload_char_count_in"] == len(test_payload)
    assert receipt["payload_char_count_out"] == len(data["clean_text"])
    assert "HIPAA_SSN" in receipt["pii_classes_detected"]
    assert receipt["pii_classes_detected"] == receipt["pii_classes_redacted"]
    assert receipt["receipt_hash"]
    assert receipt["previous_receipt_hash"]
    assert _verify_receipt_dict(receipt)
    assert ATTESTATION_CHAIN.verify_chain()


def test_sequential_scrub_calls_produce_hash_chained_receipts():
    """Two consecutive /v1/scrub calls must append linked receipts to the shared chain."""
    headers = {"X-API-Key": os.environ["HERMES_API_KEY"]}

    first = client.post("/v1/scrub", headers=headers, json={"payload": "SSN 123-45-6789"})
    second = client.post("/v1/scrub", headers=headers, json={"payload": "Card 4242424242424242"})

    assert first.status_code == 200
    assert second.status_code == 200

    receipt_one = first.json()["compliance_receipt"]
    receipt_two = second.json()["compliance_receipt"]

    assert receipt_two["previous_receipt_hash"] == receipt_one["receipt_hash"]
    assert receipt_two["chain_position"] == receipt_one["chain_position"] + 1
    assert _verify_receipt_dict(receipt_one)
    assert _verify_receipt_dict(receipt_two)
    assert ATTESTATION_CHAIN.verify_chain()
