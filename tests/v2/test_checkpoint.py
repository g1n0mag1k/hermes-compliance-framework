"""
tests/v2/test_checkpoint.py — Signed checkpoint and anchoring tests.
"""

import pytest

from hermes.receipts.v2.builder import ReceiptV2Builder
from hermes.receipts.v2.checkpoint import (
    CheckpointEngine,
    CheckpointRecord,
    verify_checkpoint,
)
from hermes.receipts.v2.anchoring import (
    WORMStore,
    WORMRecord,
    TimestampToken,
    SCITTReceipt,
    timestamp_checkpoint,
    register_with_scitt,
)
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519


@pytest.fixture(scope="module")
def receipt_signer():
    return SoftwareSignerEd25519.generate()


@pytest.fixture(scope="module")
def checkpoint_signer():
    return SoftwareSignerEd25519.generate()


@pytest.fixture(scope="module")
def engine(checkpoint_signer):
    return CheckpointEngine(stream_id="test-stream-001", signer=checkpoint_signer)


@pytest.fixture(scope="module")
def engine_with_receipts(engine, receipt_signer):
    builder = ReceiptV2Builder(receipt_signer)
    for i in range(5):
        r = builder.build({"scan_id": f"scan-{i}", "result": "clean"})
        engine.add_receipt_digest(r.receipt_digest)
    return engine


class TestCheckpointEngine:
    def test_add_receipt_digest_returns_index(self, engine_with_receipts):
        # engine already has 5 from fixture; add one more
        e = CheckpointEngine(stream_id="test-add", signer=SoftwareSignerEd25519.generate())
        idx = e.add_receipt_digest("a" * 64)
        assert idx == 0

    def test_issue_checkpoint_returns_record(self, engine_with_receipts):
        cp = engine_with_receipts.issue_checkpoint()
        assert isinstance(cp, CheckpointRecord)

    def test_checkpoint_tree_size_matches(self, engine_with_receipts):
        cp = engine_with_receipts.latest_checkpoint
        assert cp.tree_size == engine_with_receipts.tree.size

    def test_checkpoint_has_merkle_root(self, engine_with_receipts):
        cp = engine_with_receipts.latest_checkpoint
        assert len(cp.merkle_root) == 64
        bytes.fromhex(cp.merkle_root)

    def test_checkpoint_sequence_monotonic(self, engine_with_receipts):
        seq_before = engine_with_receipts.checkpoint_count - 1
        # Add a new digest and issue another checkpoint
        engine_with_receipts.add_receipt_digest("b" * 64)
        cp2 = engine_with_receipts.issue_checkpoint()
        assert cp2.sequence == seq_before + 1

    def test_checkpoint_chain_links(self, engine_with_receipts):
        # After first checkpoint, subsequent ones have prev_checkpoint_digest
        checkpoints = [
            engine_with_receipts.get_checkpoint(i)
            for i in range(engine_with_receipts.checkpoint_count)
        ]
        assert checkpoints[0].prev_checkpoint_digest is None
        for cp in checkpoints[1:]:
            assert cp.prev_checkpoint_digest is not None

    def test_checkpoint_has_cose_bytes(self, engine_with_receipts):
        cp = engine_with_receipts.latest_checkpoint
        assert len(cp.cose_sign1_bytes) > 0

    def test_empty_tree_checkpoint_raises(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="empty", signer=checkpoint_signer)
        with pytest.raises(ValueError, match="empty"):
            e.issue_checkpoint()

    def test_checkpoint_id_is_uuid(self, engine_with_receipts):
        import uuid
        cp = engine_with_receipts.latest_checkpoint
        uuid.UUID(cp.checkpoint_id)  # raises if invalid

    def test_software_version_stored(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="ver-test", signer=checkpoint_signer)
        e.add_receipt_digest("c" * 64)
        cp = e.issue_checkpoint(software_version="hermes-relay-v2.0.0-rc1")
        assert cp.software_version == "hermes-relay-v2.0.0-rc1"

    def test_policy_digest_stored(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="pol-test", signer=checkpoint_signer)
        e.add_receipt_digest("d" * 64)
        pol = "a" * 64
        cp = e.issue_checkpoint(policy_digest=pol)
        assert cp.policy_digest == pol


class TestCheckpointVerification:
    def test_verify_valid_checkpoint(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="verify-test", signer=checkpoint_signer)
        e.add_receipt_digest("e" * 64)
        cp = e.issue_checkpoint()
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp.cose_sign1_bytes, pub_pem)
        assert result.fully_valid
        assert result.errors == []

    def test_verify_wrong_key_fails(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="wrong-key", signer=checkpoint_signer)
        e.add_receipt_digest("f" * 64)
        cp = e.issue_checkpoint()
        wrong = SoftwareSignerEd25519.generate()
        pub_pem = wrong.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp.cose_sign1_bytes, pub_pem)
        assert not result.fully_valid

    def test_verify_result_has_merkle_root(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="root-check", signer=checkpoint_signer)
        e.add_receipt_digest("1" * 64)
        cp = e.issue_checkpoint()
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp.cose_sign1_bytes, pub_pem)
        assert result.merkle_root == cp.merkle_root

    def test_verify_result_has_tree_size(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="size-check", signer=checkpoint_signer)
        e.add_receipt_digest("2" * 64)
        e.add_receipt_digest("3" * 64)
        cp = e.issue_checkpoint()
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp.cose_sign1_bytes, pub_pem)
        assert result.tree_size == 2

    def test_verify_min_sequence_rejects_replay(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="replay", signer=checkpoint_signer)
        e.add_receipt_digest("4" * 64)
        cp = e.issue_checkpoint()  # sequence=0
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp.cose_sign1_bytes, pub_pem, min_sequence=1)
        assert not result.sequence_monotonic
        assert result.errors

    def test_verify_malformed_bytes(self, checkpoint_signer):
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(b"not cbor", pub_pem)
        assert not result.fully_valid
        assert result.errors

    def test_verify_chain_link_flagged(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="chain-link", signer=checkpoint_signer)
        e.add_receipt_digest("5" * 64)
        e.issue_checkpoint()
        e.add_receipt_digest("6" * 64)
        cp2 = e.issue_checkpoint()
        pub_pem = checkpoint_signer.public_key_manifest()["public_key_pem"]
        result = verify_checkpoint(cp2.cose_sign1_bytes, pub_pem)
        assert result.chain_link_valid is True


class TestWORMStore:
    def test_write_returns_worm_record(self, tmp_path, checkpoint_signer):
        e = CheckpointEngine(stream_id="worm-test", signer=checkpoint_signer)
        e.add_receipt_digest("7" * 64)
        cp = e.issue_checkpoint()
        store = WORMStore(tmp_path / "worm")
        record = store.write(cp)
        assert isinstance(record, WORMRecord)

    def test_write_creates_file(self, tmp_path, checkpoint_signer):
        e = CheckpointEngine(stream_id="worm-file", signer=checkpoint_signer)
        e.add_receipt_digest("8" * 64)
        cp = e.issue_checkpoint()
        store = WORMStore(tmp_path / "worm2")
        record = store.write(cp)
        # File exists and is read-only
        import os
        path = (tmp_path / "worm2") / record.object_key
        assert path.exists()
        assert oct(os.stat(path).st_mode)[-3:] == "444"

    def test_write_twice_raises(self, tmp_path, checkpoint_signer):
        e = CheckpointEngine(stream_id="worm-once", signer=checkpoint_signer)
        e.add_receipt_digest("9" * 64)
        cp = e.issue_checkpoint()
        store = WORMStore(tmp_path / "worm3")
        store.write(cp)
        with pytest.raises(FileExistsError):
            store.write(cp)

    def test_verify_integrity_passes(self, tmp_path, checkpoint_signer):
        e = CheckpointEngine(stream_id="integrity", signer=checkpoint_signer)
        e.add_receipt_digest("a" * 64)
        cp = e.issue_checkpoint()
        store = WORMStore(tmp_path / "worm4")
        record = store.write(cp)
        assert store.verify_integrity(record)

    def test_verify_integrity_fails_on_tamper(self, tmp_path, checkpoint_signer):
        e = CheckpointEngine(stream_id="tamper", signer=checkpoint_signer)
        e.add_receipt_digest("b" * 64)
        cp = e.issue_checkpoint()
        store = WORMStore(tmp_path / "worm5")
        record = store.write(cp)
        # Tamper: make writable, modify, restore read-only
        path = (tmp_path / "worm5") / record.object_key
        path.chmod(0o644)
        path.write_text('{"tampered": true}')
        path.chmod(0o444)
        assert not store.verify_integrity(record)


class TestTimestamps:
    def test_returns_timestamp_token(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="ts-test", signer=checkpoint_signer)
        e.add_receipt_digest("c" * 64)
        cp = e.issue_checkpoint()
        token = timestamp_checkpoint(cp)
        assert isinstance(token, TimestampToken)

    def test_mock_token_flagged(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="ts-mock", signer=checkpoint_signer)
        e.add_receipt_digest("d" * 64)
        cp = e.issue_checkpoint()
        token = timestamp_checkpoint(cp)
        assert token.is_mock

    def test_token_has_checkpoint_digest(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="ts-dig", signer=checkpoint_signer)
        e.add_receipt_digest("e" * 64)
        cp = e.issue_checkpoint()
        token = timestamp_checkpoint(cp)
        assert token.checkpoint_digest == cp.checkpoint_digest

    def test_token_to_dict(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="ts-dict", signer=checkpoint_signer)
        e.add_receipt_digest("f" * 64)
        cp = e.issue_checkpoint()
        d = timestamp_checkpoint(cp).to_dict()
        assert "checkpoint_digest" in d
        assert "gen_time" in d
        assert "is_mock" in d


class TestSCITT:
    def test_returns_scitt_receipt(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="scitt-test", signer=checkpoint_signer)
        e.add_receipt_digest("0" * 64)
        cp = e.issue_checkpoint()
        receipt = register_with_scitt(cp)
        assert isinstance(receipt, SCITTReceipt)

    def test_stub_flagged(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="scitt-stub", signer=checkpoint_signer)
        e.add_receipt_digest("1" * 64)
        cp = e.issue_checkpoint()
        receipt = register_with_scitt(cp)
        assert receipt.is_stub

    def test_stub_has_merkle_root(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="scitt-root", signer=checkpoint_signer)
        e.add_receipt_digest("2" * 64)
        cp = e.issue_checkpoint()
        receipt = register_with_scitt(cp)
        assert receipt.merkle_root == cp.merkle_root

    def test_scitt_to_dict(self, checkpoint_signer):
        e = CheckpointEngine(stream_id="scitt-dict", signer=checkpoint_signer)
        e.add_receipt_digest("3" * 64)
        cp = e.issue_checkpoint()
        d = register_with_scitt(cp).to_dict()
        assert "checkpoint_id" in d
        assert "merkle_root" in d
        assert "is_stub" in d
