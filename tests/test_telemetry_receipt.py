import hashlib
import hmac
import json
import os
import tempfile
from unittest import mock

from fastapi.testclient import TestClient

from hermes.api import app
from hermes.telemetry_receipts import SAFE_HARBOR_SUMMARY_KEYS, compute_body_signature

os.environ.setdefault("HERMES_API_KEY", "unit-test-key")

client = TestClient(app)


def _summary_template() -> dict:
    return {key: "pass" for key in sorted(SAFE_HARBOR_SUMMARY_KEYS)}


def _signed_post(body: dict, api_key: str | None = None, signature: str | None = None):
    api_key = api_key or os.environ["HERMES_API_KEY"]
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    sig = signature if signature is not None else compute_body_signature(api_key, raw)
    headers = {
        "X-API-Key": api_key,
        "X-Hermes-Signature-256": sig,
        "Content-Type": "application/json",
    }
    return client.post("/v1/telemetry/receipt", content=raw, headers=headers)


def _sample_receipt(receipt_id: str = "rcpt-001", **overrides) -> dict:
    payload = {
        "receipt_id": receipt_id,
        "timestamp": "2026-09-25T00:00:00Z",
        "repository": "org/hermes-compliance-framework",
        "commit_sha": "abc123def456",
        "status": "pass",
        "controls_verified": ["hipaa-safe-harbor-scan"],
        "summary": _summary_template(),
    }
    payload.update(overrides)
    return payload


def test_telemetry_receipt_missing_signature_returns_401():
    raw = json.dumps(_sample_receipt()).encode("utf-8")
    response = client.post(
        "/v1/telemetry/receipt",
        content=raw,
        headers={"X-API-Key": os.environ["HERMES_API_KEY"]},
    )
    assert response.status_code == 401


def test_telemetry_receipt_invalid_signature_returns_401():
    response = _signed_post(_sample_receipt(), signature="deadbeef")
    assert response.status_code == 401


def test_telemetry_receipt_ingestion_success():
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, "hermes_chain.db")
        os.environ["HERMES_DB_PATH"] = db_file
        response = _signed_post(_sample_receipt())
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ingested"
        assert body["receipt_id"] == "rcpt-001"
        assert body["state_drift_detected"] is False
        assert body["drata_cct"]["attempted"] is False
        assert body["drata_cct"]["synchronized"] is False
        assert body["drata_cct"]["reason"] == "not_configured"


def test_telemetry_receipt_detects_state_drift():
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, "hermes_chain.db")
        os.environ["HERMES_DB_PATH"] = db_file
        first = _signed_post(_sample_receipt("rcpt-001"))
        assert first.status_code == 200
        second = _signed_post(
            _sample_receipt("rcpt-002", status="fail"),
        )
        assert second.status_code == 200
        body = second.json()
        assert body["state_drift_detected"] is True
        assert body["prior_receipt_id"] == "rcpt-001"


def test_telemetry_receipt_drata_sync_when_configured():
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, "hermes_chain.db")
        os.environ["HERMES_DB_PATH"] = db_file
        os.environ["HERMES_DRATA_CCT_URL"] = "https://drata-mock.example/records"
        os.environ["HERMES_DRATA_API_KEY"] = "drata-test-key"
        with mock.patch("urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.status = 200
            response = _signed_post(_sample_receipt("rcpt-drata"))
        assert response.status_code == 200
        drata = response.json()["drata_cct"]
        assert drata["attempted"] is True
        assert drata["synchronized"] is True
        os.environ.pop("HERMES_DRATA_CCT_URL", None)
        os.environ.pop("HERMES_DRATA_API_KEY", None)


def test_telemetry_receipt_summary_must_have_16_categories():
    bad = _sample_receipt()
    bad["summary"] = {"A": "pass"}
    response = _signed_post(bad)
    assert response.status_code == 422
