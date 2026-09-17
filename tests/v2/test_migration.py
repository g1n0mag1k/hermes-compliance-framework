"""
tests/v2/test_migration.py — V1 → V2 bridge record tests.
"""

import hashlib
import pytest

from hermes.attestation import AttestationChain
from hermes.receipts.v2.builder import ReceiptV2
from hermes.receipts.v2.migration import create_v1_bridge
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519
from hermes.receipts.v2.verifier import verify_receipt


@pytest.fixture
def fresh_v1_chain(tmp_path):
    """A fresh V1 chain with a few receipts, using a temp DB."""
    chain = AttestationChain(db_path=str(tmp_path / "test_v1.db"))
    chain.issue(
        transaction_id="tx001",
        flags_triggered={"SSN": 1},
        flags_redacted={"SSN": 1},
        char_count_in=100,
        char_count_out=95,
    )
    chain.issue(
        transaction_id="tx002",
        flags_triggered={},
        flags_redacted={},
        char_count_in=50,
        char_count_out=50,
    )
    return chain


@pytest.fixture
def signer():
    return SoftwareSignerEd25519.generate()


class TestGetChainHead:
    def test_returns_dict(self, fresh_v1_chain):
        head = fresh_v1_chain.get_chain_head()
        assert isinstance(head, dict)

    def test_has_required_fields(self, fresh_v1_chain):
        head = fresh_v1_chain.get_chain_head()
        for field in ("head_hash", "chain_position", "issued_at", "record_count"):
            assert field in head, f"Missing field: {field}"

    def test_record_count_correct(self, fresh_v1_chain):
        head = fresh_v1_chain.get_chain_head()
        assert head["record_count"] == 2

    def test_chain_position_is_tail(self, fresh_v1_chain):
        head = fresh_v1_chain.get_chain_head()
        assert head["chain_position"] == 1  # 0-indexed, 2 records → tail at 1

    def test_empty_chain_raises(self, tmp_path):
        empty = AttestationChain(db_path=str(tmp_path / "empty.db"))
        with pytest.raises(RuntimeError, match="empty"):
            empty.get_chain_head()

    def test_does_not_modify_chain(self, fresh_v1_chain):
        before = fresh_v1_chain.chain_length()
        fresh_v1_chain.get_chain_head()
        after = fresh_v1_chain.chain_length()
        assert before == after


class TestCreateV1Bridge:
    def test_returns_receipt_v2(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        assert isinstance(bridge, ReceiptV2)

    def test_event_type_is_v1_algorithm_transition(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        assert bridge.payload.get("event_type") == "v1_algorithm_transition"

    def test_payload_contains_required_fields(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        required_keys = {
            "event_type",
            "v1_hmac_head",
            "v1_record_count",
            "v1_db_sha256",
            "v1_schema_version",
            "v2_first_key_id",
            "v2_profile",
            "transition_note",
            "limitation_note",
        }
        for key in required_keys:
            assert key in bridge.payload, f"Missing payload key: {key}"

    def test_v1_hmac_head_stored_correctly(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        assert bridge.payload["v1_hmac_head"] == head["head_hash"]

    def test_bridge_is_v2_genesis_no_prev(self, fresh_v1_chain, signer):
        """Bridge record has no V2 predecessor — it IS the V2 genesis."""
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        assert bridge.prev_receipt_digest is None

    def test_bridge_signature_verifies(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        pub_pem = signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(bridge.cose_sign1_bytes, pub_pem)
        assert result.signature_valid
        assert not result.errors

    def test_v1_chain_untouched_after_bridge(self, fresh_v1_chain, signer):
        """Bridge creation must never modify V1 records."""
        before_len = fresh_v1_chain.chain_length()
        before_head = fresh_v1_chain.get_chain_head()

        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )

        after_len = fresh_v1_chain.chain_length()
        after_head = fresh_v1_chain.get_chain_head()

        assert before_len == after_len
        assert before_head["head_hash"] == after_head["head_hash"]

    def test_v2_key_id_matches_signer(self, fresh_v1_chain, signer):
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )
        assert bridge.payload["v2_first_key_id"] == signer.key_id.hex()

    def test_v1_chain_verify_still_passes_after_bridge(self, fresh_v1_chain, signer):
        """The V1 chain's own verify_chain must still return True after bridge creation."""
        assert fresh_v1_chain.verify_chain()

        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )

        assert fresh_v1_chain.verify_chain()

    def test_v2_chain_extends_from_bridge(self, fresh_v1_chain, signer):
        """After the bridge, subsequent V2 receipts link to it correctly."""
        from hermes.receipts.v2.builder import ReceiptV2Builder
        head = fresh_v1_chain.get_chain_head()
        db_sha256 = hashlib.sha256(b"fake-db-export").hexdigest()
        bridge = create_v1_bridge(
            v1_hmac_head=head["head_hash"],
            v1_record_count=head["record_count"],
            v1_db_sha256=db_sha256,
            v2_signer=signer,
        )

        builder = ReceiptV2Builder(signer)
        r2 = builder.build({"event_type": "phi_scan", "result": "clean"},
                           prev_receipt_digest=bridge.receipt_digest)
        assert r2.prev_receipt_digest == bridge.receipt_digest
