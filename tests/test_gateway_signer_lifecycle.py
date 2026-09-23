"""
tests/test_gateway_signer_lifecycle.py — V2 gateway signer in a fresh process.

Every other gateway test calls gateway_evidence.reset_v2_chains() in an autouse
fixture, which assigns the module-level signer directly. A real
`hermes-relay serve --both` / uvicorn gateway process never calls that helper,
so the signer must be initialized through the normal lazy path on the first
receipt. These tests run the gateway in a fresh interpreter to reproduce that
module state exactly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.verifier import verify_receipt, verify_receipt_chain

REPO_ROOT = Path(__file__).resolve().parents[1]
PASSPHRASE = b"signer-lifecycle-test-passphrase"

_FRESH_PROCESS_SCRIPT = r"""
import json

import httpx
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
from gateway.pipeline import GatewayPipeline
from hermes.workspaces import create_workspace

upstream_requests = []


def handler(request):
    upstream_requests.append(request.content.decode("utf-8"))
    return httpx.Response(
        200,
        json={"id": "chatcmpl-lifecycle", "choices": []},
        headers={"content-type": "application/json"},
    )


gateway_app._pipeline = GatewayPipeline(
    client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler))
)

signer_unset_before_requests = gateway_evidence._GATEWAY_SIGNER is None

ws, api_key = create_workspace("signer-lifecycle", "Signer Lifecycle", "s@test.invalid")
url = "/gateway/openai/v1/chat/completions"
headers = {"X-API-Key": api_key}

def post(client, content):
    try:
        response = client.post(
            url,
            headers=headers,
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": content}]},
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return response.status_code, response.text


with TestClient(gateway_app.app) as client:
    clean_status, clean_body = post(client, "Explain photosynthesis briefly.")
    phi_status, phi_body = post(client, "Patient SSN 123-45-6789 needs follow-up.")

print(json.dumps({
    "signer_unset_before_requests": signer_unset_before_requests,
    "clean_status": clean_status,
    "clean_body": clean_body,
    "phi_status": phi_status,
    "phi_body": phi_body,
    "upstream_request_count": len(upstream_requests),
    "receipts": gateway_evidence.list_gateway_receipts(ws),
}))
"""


def _run_fresh_gateway_process(tmp_path: Path, keystore_path: Path) -> dict:
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("HERMES_"):
            del env[name]
    env.update(
        {
            "HERMES_ENV": "production",
            "HERMES_GATEWAY_KEYSTORE_PATH": str(keystore_path),
            "HERMES_GATEWAY_KEYSTORE_PASSPHRASE": PASSPHRASE.decode(),
            "HERMES_GATEWAY_POLICY": "HIPAA_PRODUCTION_BLOCK",
            "HERMES_SIGNING_KEY": "11" * 32,
            "HERMES_VAULT_KEY": "22" * 32,
            "HERMES_OPENAI_API_KEY": "test-openai-key",
            "HERMES_DATA_DIR": str(tmp_path / "workspaces"),
            "HERMES_REGISTRY_DB": str(tmp_path / "workspaces" / "registry.db"),
            "HERMES_DB_PATH": str(tmp_path / "hermes_chain.db"),
            "HERMES_CANARY_DB_PATH": str(tmp_path / "hermes_canary.db"),
        }
    )
    proc = subprocess.run(
        [sys.executable, "-c", _FRESH_PROCESS_SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def fresh_process_result(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("signer_lifecycle")
    keystore_path = tmp_path / "gateway.keystore"
    KeyStore.create(keystore_path, PASSPHRASE)
    signer = KeyStore.open(keystore_path, PASSPHRASE).load_signer()
    result = _run_fresh_gateway_process(tmp_path, keystore_path)
    return result, signer


def test_fresh_process_starts_without_preloaded_signer(fresh_process_result):
    result, _ = fresh_process_result
    assert result["signer_unset_before_requests"] is True


def test_fresh_process_clean_request_succeeds_with_receipt(fresh_process_result):
    result, _ = fresh_process_result
    assert result["clean_status"] == 200, result["clean_body"]
    assert result["upstream_request_count"] == 1


def test_fresh_process_phi_request_blocks_with_receipt(fresh_process_result):
    result, _ = fresh_process_result
    assert result["phi_status"] == 403, result["phi_body"]
    body = json.loads(result["phi_body"])
    assert body["error"]["code"] == "phi_detected"
    assert body["receipt_digest"]


def test_fresh_process_receipts_verify_with_keystore_key(fresh_process_result):
    result, signer = fresh_process_result
    receipts = result["receipts"]
    assert [r["payload"]["decision"] for r in receipts] == ["ALLOW", "BLOCK"]
    assert receipts[0]["payload"]["forwarded"] is True
    assert receipts[1]["payload"]["forwarded"] is False

    public_key_pem = signer.public_key_manifest()["public_key_pem"]
    cose_list = [bytes.fromhex(r["cose_sign1_hex"]) for r in receipts]
    for cose in cose_list:
        verification = verify_receipt(cose, public_key_pem)
        assert verification.fully_valid, verification.errors
        assert verification.signer_key_id == signer.key_id.hex()

    chain = verify_receipt_chain(cose_list, public_key_pem, "signer-lifecycle")
    assert chain.valid, chain.errors
