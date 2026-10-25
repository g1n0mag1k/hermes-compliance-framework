"""Gateway receipt ledger locking, fail-closed persistence, and threadpool offload."""

from __future__ import annotations

import asyncio
import concurrent.futures

import pytest
from starlette.concurrency import run_in_threadpool

import gateway.evidence as gateway_evidence
from gateway.exceptions import ReceiptPersistenceError
from gateway.policy import EnforcementDecision
from hermes.receipts.v2.key_store import KeyStore
from hermes.workspaces import create_workspace


@pytest.fixture(autouse=True)
def isolated_gateway_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv(
        "HERMES_REGISTRY_DB",
        str(tmp_path / "workspaces" / "registry.db"),
    )
    ks_path = tmp_path / "fixture.keystore"
    KeyStore.create(ks_path, b"gateway-keystore-passphrase")
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PATH", str(ks_path))
    monkeypatch.setenv("HERMES_GATEWAY_KEYSTORE_PASSPHRASE", "gateway-keystore-passphrase")

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = str(tmp_path / "workspaces")
    ws_mod._DEFAULT_REGISTRY_DB = str(tmp_path / "workspaces" / "registry.db")

    gateway_evidence.reset_v2_chains()
    yield


def _sample_decision() -> EnforcementDecision:
    return EnforcementDecision(
        decision="BLOCK",
        reasons=["test"],
        policy_id="HIPAA_STRICT",
        policy_version="1.0.0",
        policy_digest="abc123",
        content_types_inspected=["text"],
        content_types_not_inspected=[],
        all_detectors_clean=False,
    )


def _issue(workspace, suffix: str):
    return gateway_evidence.issue_gateway_receipt(
        workspace=workspace,
        transaction_id=f"txn-{suffix}",
        decision=_sample_decision(),
        provider_id="openai",
        endpoint_path="/v1/chat/completions",
        flags_triggered={"EMAIL_ADDRESS": 1},
        flags_redacted={},
        detectors_executed={"regex": "triggered"},
        forwarded=False,
    )


class TestConcurrentGatewayReceiptIssue:
    def test_concurrent_issues_receive_distinct_sequential_sequences(self):
        ws, _ = create_workspace("gw-rcpt-conc", "Concurrent WS", "c@test.com")
        workers = 8

        def _task(i: int):
            return _issue(ws, f"{i:03d}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            receipts = list(pool.map(_task, range(workers)))

        sequences = sorted(r.payload["gateway_sequence"] for r in receipts)
        assert sequences == list(range(workers))
        assert len(set(sequences)) == workers

        rows = gateway_evidence.list_gateway_receipts(ws)
        assert len(rows) == workers
        assert sorted(row["gateway_sequence"] for row in rows) == sequences


class TestReceiptPersistenceFailClosed:
    def test_ioerror_does_not_advance_chain_head(self, monkeypatch):
        ws, _ = create_workspace("gw-rcpt-io", "IO Error WS", "io@test.com")

        def _raise_io(*args, **kwargs):
            raise IOError("worm write failed")

        monkeypatch.setattr(
            gateway_evidence,
            "_persist_gateway_receipt_in_transaction",
            _raise_io,
        )

        before_head = gateway_evidence.get_v2_chain_head(ws.workspace_id)
        with pytest.raises(ReceiptPersistenceError):
            _issue(ws, "fail")

        assert gateway_evidence.get_v2_chain_head(ws.workspace_id) == before_head
        assert gateway_evidence.list_gateway_receipts(ws) == []
