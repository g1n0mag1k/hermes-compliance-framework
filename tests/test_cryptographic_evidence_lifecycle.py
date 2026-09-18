"""
tests/test_cryptographic_evidence_lifecycle.py — Gateway V2 receipt persistence,
keystore-backed signing, and chain verification across process restarts.
"""

from __future__ import annotations

import pytest

import gateway.evidence as gateway_evidence
from gateway.policy import EnforcementDecision
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.verifier import verify_receipt_chain
from hermes.workspaces import create_workspace


PASSPHRASE = b"gateway-keystore-passphrase"


@pytest.fixture(autouse=True)
def isolated_gateway_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB",
        str(tmp_path / "workspaces" / "registry.db"),
    )
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PATH", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", raising=False)

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")

    gateway_evidence.reset_v2_chains()
    yield


def _sample_decision() -> EnforcementDecision:
    return EnforcementDecision(
        decision="ALLOW",
        reasons=[],
        policy_id="HIPAA_STRICT",
        policy_version="1.0.0",
        policy_digest="abc123",
        content_types_inspected=["text"],
        content_types_not_inspected=[],
        all_detectors_clean=True,
    )


def _issue_sample_receipt(workspace, txn_suffix: str = "001"):
    return gateway_evidence.issue_gateway_receipt(
        workspace=workspace,
        transaction_id=f"txn-{txn_suffix}",
        decision=_sample_decision(),
        provider_id="openai",
        endpoint_path="/v1/chat/completions",
        flags_triggered={},
        flags_redacted={},
        detectors_executed={"regex": "clean"},
    )


class TestGatewaySigner:
    def test_get_gateway_signer_returns_singleton(self):
        signer_a = gateway_evidence._get_gateway_signer()
        signer_b = gateway_evidence._get_gateway_signer()
        assert signer_a is signer_b


class TestPersistentReceiptStorage:
    def test_issue_persists_receipt_to_sqlite(self):
        ws, _ = create_workspace("evidence-ws-01", "Evidence WS", "e@test.com")
        receipt = _issue_sample_receipt(ws)

        rows = gateway_evidence.list_gateway_receipts(ws)
        assert len(rows) == 1
        assert rows[0]["receipt_digest"] == receipt.receipt_digest
        assert rows[0]["gateway_sequence"] == 0
        assert rows[0]["transaction_id"] == "txn-001"
        assert rows[0]["payload"]["workspace_id"] == ws.workspace_id

    def test_list_gateway_receipts_ordered_by_sequence(self):
        ws, _ = create_workspace("evidence-ws-02", "Evidence WS 2", "e2@test.com")
        _issue_sample_receipt(ws, "001")
        _issue_sample_receipt(ws, "002")
        _issue_sample_receipt(ws, "003")

        rows = gateway_evidence.list_gateway_receipts(ws)
        assert [row["gateway_sequence"] for row in rows] == [0, 1, 2]
        assert rows[1]["prev_receipt_digest"] == rows[0]["receipt_digest"]
        assert rows[2]["prev_receipt_digest"] == rows[1]["receipt_digest"]

    def test_get_gateway_receipt_found(self):
        ws, _ = create_workspace("evidence-ws-03", "Evidence WS 3", "e3@test.com")
        receipt = _issue_sample_receipt(ws)

        row = gateway_evidence.get_gateway_receipt(ws, receipt.receipt_digest)
        assert row is not None
        assert row["receipt_digest"] == receipt.receipt_digest
        assert row["payload"]["transaction_id"] == "txn-001"

    def test_get_gateway_receipt_not_found(self):
        ws, _ = create_workspace("evidence-ws-04", "Evidence WS 4", "e4@test.com")
        _issue_sample_receipt(ws)

        missing = gateway_evidence.get_gateway_receipt(ws, "0" * 64)
        assert missing is None


class TestKeystoreBackedSigner:
    def test_keystore_signer_loaded_when_env_set(self, tmp_path, monkeypatch):
        store_path = tmp_path / "gateway.keystore"
        KeyStore.create(store_path, PASSPHRASE)
        monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(store_path))
        monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE.decode())

        gateway_evidence.reset_v2_chains()
        signer = gateway_evidence._get_gateway_signer()
        pub_pem = signer.public_key_manifest()["public_key_pem"]

        ws, _ = create_workspace("evidence-ws-05", "Keystore WS", "k@test.com")
        receipt = _issue_sample_receipt(ws)

        result = verify_receipt_chain(
            [receipt.cose_sign1_bytes],
            pub_pem,
            expected_workspace_id=ws.workspace_id,
        )
        assert result.valid is True
        assert result.errors == []

    def test_chain_continuity_after_reset_with_keystore(self, tmp_path, monkeypatch):
        store_path = tmp_path / "gateway.keystore"
        KeyStore.create(store_path, PASSPHRASE)
        monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(store_path))
        monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", PASSPHRASE.decode())

        gateway_evidence.reset_v2_chains()
        signer = gateway_evidence._get_gateway_signer()
        pub_pem = signer.public_key_manifest()["public_key_pem"]

        ws, _ = create_workspace("evidence-ws-06", "Reset WS", "r@test.com")
        r1 = _issue_sample_receipt(ws, "001")
        r2 = _issue_sample_receipt(ws, "002")

        gateway_evidence.reset_v2_chains()
        assert gateway_evidence._get_gateway_signer().key_id == signer.key_id

        r3 = _issue_sample_receipt(ws, "003")
        assert r3.prev_receipt_digest == r2.receipt_digest

        chain_result = verify_receipt_chain(
            [r1.cose_sign1_bytes, r2.cose_sign1_bytes, r3.cose_sign1_bytes],
            pub_pem,
            expected_workspace_id=ws.workspace_id,
        )
        assert chain_result.valid is True
        assert chain_result.errors == []


class TestVerifyReceiptChain:
    def test_verify_receipt_chain_valid_sequence(self):
        ws, _ = create_workspace("evidence-ws-07", "Chain WS", "c@test.com")
        r1 = _issue_sample_receipt(ws, "001")
        r2 = _issue_sample_receipt(ws, "002")
        pub_pem = gateway_evidence._get_gateway_signer().public_key_manifest()[
            "public_key_pem"
        ]

        result = verify_receipt_chain(
            [r1.cose_sign1_bytes, r2.cose_sign1_bytes],
            pub_pem,
            expected_workspace_id=ws.workspace_id,
        )
        assert result.valid is True

    def test_verify_receipt_chain_rejects_broken_link(self):
        ws, _ = create_workspace("evidence-ws-08", "Broken WS", "b@test.com")
        r1 = _issue_sample_receipt(ws, "001")
        r2 = _issue_sample_receipt(ws, "002")
        pub_pem = gateway_evidence._get_gateway_signer().public_key_manifest()[
            "public_key_pem"
        ]

        result = verify_receipt_chain(
            [r2.cose_sign1_bytes, r1.cose_sign1_bytes],
            pub_pem,
            expected_workspace_id=ws.workspace_id,
        )
        assert result.valid is False
        assert result.errors

    def test_reset_v2_chains_clears_in_memory_heads(self):
        ws, _ = create_workspace("evidence-ws-09", "Head WS", "h@test.com")
        receipt = _issue_sample_receipt(ws)
        assert gateway_evidence.get_v2_chain_head(ws.workspace_id) == receipt.receipt_digest

        gateway_evidence.reset_v2_chains()
        assert gateway_evidence.get_v2_chain_head(ws.workspace_id) is None

        next_receipt = _issue_sample_receipt(ws, "002")
        assert next_receipt.prev_receipt_digest == receipt.receipt_digest
