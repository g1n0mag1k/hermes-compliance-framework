"""
Regression tests for correctness-audit findings that are not yet fixed.

Each test is a strict xfail: it fails against the current code and documents
the expected behavior. When a finding is fixed the test XPASSes, which strict
mode reports as a failure, so the xfail marker must be removed with the fix.
"""
from __future__ import annotations

import gzip
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient


def _bug(reason: str):
    return pytest.mark.xfail(strict=True, reason=reason)


def _digest(i: int) -> bytes:
    return hashlib.sha256(f"leaf-{i}".encode()).digest()


# ---------------------------------------------------------------------------
# hermes/receipts/v2
# ---------------------------------------------------------------------------

def test_single_leaf_inclusion_proof_has_empty_path():
    from hermes.receipts.v2.merkle_tree import MerkleTree

    t = MerkleTree()
    t.append(_digest(0))
    proof = t.inclusion_proof(0)
    assert proof.path == []
    assert proof.verify()


@_bug("_recompute_root_from_inclusion applies top-down splits to a bottom-up path")
def test_inclusion_proof_verifies_every_leaf_of_three_leaf_tree():
    from hermes.receipts.v2.merkle_tree import MerkleTree

    t = MerkleTree()
    for i in range(3):
        t.append(_digest(i))
    assert [t.inclusion_proof(i).verify() for i in range(3)] == [True, True, True]


@_bug("canonical.build_merkle_root duplicates the last node instead of RFC 9162 split")
def test_build_merkle_root_matches_merkle_tree_root():
    from hermes.receipts.v2.canonical import build_merkle_root
    from hermes.receipts.v2.merkle_tree import MerkleTree

    digests = [_digest(i) for i in range(3)]
    t = MerkleTree()
    for d in digests:
        t.append(d)
    assert build_merkle_root(digests) == t.root()


@_bug("MerkleTree.append only checks len(), so a 32-char str is accepted")
def test_merkle_append_rejects_non_bytes():
    from hermes.receipts.v2.merkle_tree import MerkleTree

    with pytest.raises((TypeError, ValueError)):
        MerkleTree().append("x" * 32)


@_bug("KeyStore.open leaks KeyError/AttributeError for malformed files")
@pytest.mark.parametrize("content", [{"format_version": 1}, [1, 2]])
def test_keystore_open_malformed_file_raises_value_error(tmp_path, content):
    from hermes.receipts.v2.key_store import KeyStore

    path = tmp_path / "ks.json"
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError):
        KeyStore.open(path, b"pw")


# ---------------------------------------------------------------------------
# hermes/attestation.py
# ---------------------------------------------------------------------------

@_bug("receipt.compliance_frameworks aliases the AttestationChain class attribute")
def test_receipt_lists_do_not_alias_shared_state(tmp_path):
    from hermes.attestation import AttestationChain

    chain = AttestationChain(db_path=str(tmp_path / "c.db"))
    receipt = chain.issue("tx", {}, {}, 1, 1)
    assert receipt.compliance_frameworks is not AttestationChain.COMPLIANCE_FRAMEWORKS


# ---------------------------------------------------------------------------
# hermes/classifier.py
# ---------------------------------------------------------------------------

@_bug("cert_license_replacer upper-cases the DEA candidate before str.replace")
def test_lowercase_dea_number_is_removed():
    from hermes.classifier import scrub_payload

    result = scrub_payload("t", "dea: ab1234563")
    assert "ab1234563" not in result.clean_text.lower()


@_bug("base64 pass strips URLs and re-appends them at the end of the text")
def test_url_is_redacted_in_place_without_leaking_path():
    from hermes.classifier import scrub_payload

    result = scrub_payload("t", "see https://records.clinic.example/patient/42 now")
    assert "patient/42" not in result.clean_text
    assert result.clean_text.startswith("see [REDACTED_URL]")


# ---------------------------------------------------------------------------
# hermes/auditor.py
# ---------------------------------------------------------------------------

@_bug("run_canary does not pass flags_missed/occurrence_gaps into the receipt")
def test_canary_receipt_not_zero_egress_when_flag_missed(monkeypatch):
    from hermes import auditor
    from hermes.classifier import scrub_payload

    def scrub_dropping_ssn(transaction_id, text):
        result = scrub_payload(transaction_id=transaction_id, text=text)
        result.audit_log.flags_triggered.pop("HIPAA_SSN", None)
        result.audit_log.flags_redacted.pop("HIPAA_SSN", None)
        return result

    monkeypatch.setattr(auditor, "scrub_payload", scrub_dropping_ssn)
    result = auditor.run_canary()
    assert "HIPAA_SSN" in result.flags_missed
    assert result.receipt.zero_pii_egress_confirmed is False


# ---------------------------------------------------------------------------
# hermes/telemetry_receipts.py
# ---------------------------------------------------------------------------

@_bug("TelemetryReceiptPayload.schema_version accepts any string")
def test_telemetry_payload_rejects_unknown_schema_version():
    from hermes.telemetry_receipts import (
        SAFE_HARBOR_SUMMARY_KEYS,
        TelemetryReceiptPayload,
    )

    with pytest.raises(ValueError):
        TelemetryReceiptPayload.model_validate({
            "schema_version": "9.9",
            "receipt_id": "r1",
            "timestamp": "2026-10-18T00:00:00Z",
            "repository": "org/repo",
            "commit_sha": "abc",
            "status": "pass",
            "summary": {k: "pass" for k in SAFE_HARBOR_SUMMARY_KEYS},
        })


# ---------------------------------------------------------------------------
# hermes/webhooks.py
# ---------------------------------------------------------------------------

class _FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@_bug("Sprinto dispatcher treats a GraphQL error body with HTTP 200 as success")
def test_sprinto_graphql_error_is_not_success(monkeypatch, tmp_path):
    import urllib.request

    from hermes.attestation import AttestationChain
    from hermes.webhooks import dispatch_sprinto_custom_evidence

    receipt = AttestationChain(db_path=str(tmp_path / "c.db")).issue("tx", {}, {}, 1, 1)
    monkeypatch.setenv("HERMES_SPRINTO_API_KEY", "k")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda *a, **kw: _FakeResponse(b'{"errors":[{"message":"bad mutation"}]}'),
    )
    assert dispatch_sprinto_custom_evidence(receipt) is False


# ---------------------------------------------------------------------------
# hermes/proxy.py
# ---------------------------------------------------------------------------

@_bug("ProxyRelay reads RedactionAuditLog.detectors_executed, which does not exist")
def test_proxy_relay_non_json_body_does_not_crash():
    from hermes.proxy import ProxyRelay

    relay = ProxyRelay()
    relay._client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    response, _, _ = relay.relay("http://upstream.test", "POST", "/x", {}, b"SSN 372-18-5421")
    assert response.status_code == 200


@_bug("_deep_scrub only scrubs keys in _TEXT_FIELDS; 'system' is forwarded raw")
def test_proxy_deep_scrub_covers_all_string_fields():
    from hermes.proxy import _deep_scrub

    scrubbed, *_ = _deep_scrub({"system": "SSN 372-18-5421"}, "t")
    assert "372-18-5421" not in scrubbed["system"]


# ---------------------------------------------------------------------------
# hermes/workspaces.py
# ---------------------------------------------------------------------------

@_bug("_WORKSPACE_ID_RE uses re.match with '$', which accepts a trailing newline")
def test_workspace_id_with_trailing_newline_is_rejected():
    from hermes.workspaces import _validate_workspace_id

    with pytest.raises(ValueError):
        _validate_workspace_id("abc\n")


# ---------------------------------------------------------------------------
# gateway/
# ---------------------------------------------------------------------------

@_bug("inspect_json_recursive never inspects dict keys")
def test_gateway_inspects_json_keys():
    from gateway.inspector import inspect_json_recursive

    clean, triggered, _, _ = inspect_json_recursive({"372-18-5421": "x"}, "t")
    assert "372-18-5421" not in json.dumps(clean)
    assert "HIPAA_SSN" in triggered


@_bug("inspect_string_value counts PHI in JSON-in-string payloads twice")
def test_gateway_json_in_string_counts_once():
    from gateway.inspector import inspect_string_value

    _, triggered, _, _ = inspect_string_value('{"a":"372-18-5421"}', "t")
    assert triggered.get("HIPAA_SSN") == 1


@pytest.fixture()
def gateway_client(tmp_path, monkeypatch):
    import gateway.app as gateway_app
    import gateway.evidence as gateway_evidence
    import hermes.workspaces as ws_mod
    from hermes.workspaces import create_workspace

    monkeypatch.setenv("HERMES_OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(ws_mod, "_DEFAULT_DATA_DIR", str(tmp_path / "ws"))
    monkeypatch.setattr(ws_mod, "_DEFAULT_REGISTRY_DB", str(tmp_path / "ws" / "registry.db"))
    ws_mod._chain_cache.clear()
    gateway_evidence.reset_v2_chains()

    state = {"requests": [], "gzip": False}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        body = b'{"id":"x","choices":[]}'
        if state["gzip"]:
            return httpx.Response(
                200,
                content=gzip.compress(body),
                headers={"content-type": "application/json", "content-encoding": "gzip"},
            )
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    monkeypatch.setattr(
        gateway_app,
        "_pipeline",
        gateway_app.GatewayPipeline(
            client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler))
        ),
    )
    _, api_key = create_workspace("audit-ws", "Audit", "audit@test.com")
    yield TestClient(gateway_app.app), {"X-API-Key": api_key}, state
    ws_mod._chain_cache.clear()


@_bug("validate_path is a raw prefix check; '..' segments escape the allow-list")
def test_gateway_rejects_dot_segment_path_escape(gateway_client):
    client, headers, state = gateway_client
    response = client.post(
        "/gateway/openai/v1/chat/completions/..%2F..%2Ffiles",
        headers=headers,
        json={"model": "m", "messages": []},
    )
    assert response.status_code == 400
    assert state["requests"] == []


@_bug("client request headers are forwarded upstream without PHI inspection")
def test_gateway_does_not_forward_phi_in_custom_headers(gateway_client):
    client, headers, state = gateway_client
    client.post(
        "/gateway/openai/v1/chat/completions",
        headers={**headers, "X-Patient-SSN": "372-18-5421"},
        json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
    )
    forwarded = [r.headers.get("x-patient-ssn") for r in state["requests"]]
    assert "372-18-5421" not in forwarded


@_bug("content-encoding is kept after httpx has already decoded the upstream body")
def test_gateway_strips_content_encoding_from_decoded_response(gateway_client):
    client, headers, state = gateway_client
    state["gzip"] = True
    response = client.post(
        "/gateway/openai/v1/chat/completions",
        headers=headers,
        json={"model": "m", "messages": []},
    )
    assert response.json()["id"] == "x"
