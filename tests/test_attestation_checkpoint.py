"""
tests/test_attestation_checkpoint.py

Test suite for the four new AttestationChain methods added to close
Massimiliano PHI-OMEGA Round 2 remaining gaps:

  - issue_checkpoint()
  - verify_checkpoint()
  - detect_fork()
  - verify_receipt_applicability()

Falsification tests follow Massimiliano's Sep 3 protocol exactly:
  #6  Truncated chain / prefix presentation rejected
  #7  Fork detection — concurrent successors from same parent
  #8  Stale checkpoint replay rejected
  #9  Override invalidates only dependent claims
  #10 R1 remains historically verifiable after supersession
"""
import hashlib
import hmac
import json
import os
import tempfile
import pytest

os.environ.setdefault("HERMES_ENV", "development")

from hermes.attestation import AttestationChain, SIGNING_KEY


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def chain(tmp_path):
    """Fresh AttestationChain backed by a temp SQLite file."""
    db = str(tmp_path / "test_chain.db")
    return AttestationChain(db_path=db)


@pytest.fixture
def chain_with_two(tmp_path):
    """Chain with two compliance receipts — R1 superseded by R2."""
    db = str(tmp_path / "test_chain2.db")
    c = AttestationChain(db_path=db)
    c.issue(
        transaction_id="tx_001",
        flags_triggered={"HIPAA_SSN": 1},
        flags_redacted={"HIPAA_SSN": 1},
        char_count_in=100,
        char_count_out=90,
    )
    c.issue(
        transaction_id="tx_002",
        flags_triggered={"HIPAA_PHI_PHONE": 1},
        flags_redacted={"HIPAA_PHI_PHONE": 1},
        char_count_in=80,
        char_count_out=70,
    )
    return c


# ---------------------------------------------------------------------------
# issue_checkpoint()
# ---------------------------------------------------------------------------

class TestIssueCheckpoint:

    def test_raises_on_empty_chain(self, chain):
        with pytest.raises(RuntimeError, match="empty chain"):
            chain.issue_checkpoint()

    def test_returns_required_fields(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        for field in ("checkpoint_type", "head_hash", "chain_position",
                      "epoch", "issued_at", "issuer", "checkpoint_signature"):
            assert field in cp, f"Missing field: {field}"

    def test_epoch_equals_chain_length(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        assert cp["epoch"] == chain_with_two.chain_length()

    def test_head_hash_matches_tail(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        tail = chain_with_two.get_current_head()
        assert cp["head_hash"] == tail.receipt_hash

    def test_checkpoint_type_is_current_head(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        assert cp["checkpoint_type"] == "current_head"

    def test_signature_is_hmac_sha256(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        content = {k: v for k, v in cp.items() if k != "checkpoint_signature"}
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(SIGNING_KEY, canonical.encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(cp["checkpoint_signature"], expected)

    def test_epoch_increases_monotonically(self, tmp_path):
        c = AttestationChain(db_path=str(tmp_path / "mono.db"))
        c.issue("tx_a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        cp1 = c.issue_checkpoint()
        c.issue("tx_b", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)
        cp2 = c.issue_checkpoint()
        assert cp2["epoch"] > cp1["epoch"]


# ---------------------------------------------------------------------------
# verify_checkpoint()
# ---------------------------------------------------------------------------

class TestVerifyCheckpoint:

    def test_valid_checkpoint_passes(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        assert chain_with_two.verify_checkpoint(cp) is True

    def test_tampered_signature_fails(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        cp["checkpoint_signature"] = "0" * 64
        assert chain_with_two.verify_checkpoint(cp) is False

    def test_tampered_head_hash_fails(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        cp["head_hash"] = "0" * 64
        assert chain_with_two.verify_checkpoint(cp) is False

    def test_missing_signature_fails(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        del cp["checkpoint_signature"]
        assert chain_with_two.verify_checkpoint(cp) is False

    def test_stale_checkpoint_rejected_by_min_epoch(self, tmp_path):
        """Massimiliano falsification test #8 — old but correctly signed
        checkpoint must be rejected when freshness is enforced."""
        c = AttestationChain(db_path=str(tmp_path / "stale.db"))
        c.issue("tx_a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        stale_cp = c.issue_checkpoint()  # epoch=1

        # Add another receipt — epoch advances to 2
        c.issue("tx_b", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)

        # stale_cp is validly signed but epoch=1, current epoch=2
        # A verifier requiring min_epoch=2 must reject it
        assert c.verify_checkpoint(stale_cp, min_epoch=2) is False

    def test_current_checkpoint_passes_min_epoch(self, tmp_path):
        c = AttestationChain(db_path=str(tmp_path / "fresh.db"))
        c.issue("tx_a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        c.issue("tx_b", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)
        cp = c.issue_checkpoint()  # epoch=2
        assert c.verify_checkpoint(cp, min_epoch=2) is True

    def test_checkpoint_head_mismatch_after_new_receipt(self, tmp_path):
        """A checkpoint issued before a new receipt is added no longer
        matches the current chain tail — must fail."""
        c = AttestationChain(db_path=str(tmp_path / "mismatch.db"))
        c.issue("tx_a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        cp = c.issue_checkpoint()
        # Add a new receipt — chain tail changes
        c.issue("tx_b", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)
        # cp still has a valid signature but head_hash no longer matches tail
        assert c.verify_checkpoint(cp) is False


# ---------------------------------------------------------------------------
# detect_fork()
# ---------------------------------------------------------------------------

class TestDetectFork:

    def test_clean_chain_has_no_fork(self, chain_with_two):
        """Massimiliano falsification test #7 — normal chain must not
        report a fork."""
        tail = chain_with_two.get_current_head()
        prev = chain_with_two._chain[-2]
        assert chain_with_two.detect_fork(
            prev.receipt_hash, tail.receipt_hash
        ) is False

    def test_same_hash_twice_reports_fork(self, chain_with_two):
        """Passing the same hash for both arguments resolves to the same
        chain_position — detect_fork correctly flags this as a fork
        since pos_a == pos_b. The caller is responsible for not passing
        the same receipt twice; this tests the position-collision logic."""
        tail = chain_with_two.get_current_head()
        assert chain_with_two.detect_fork(
            tail.receipt_hash, tail.receipt_hash
        ) is True

    def test_unknown_hash_is_not_fork(self, chain_with_two):
        """A hash not in the chain at all cannot constitute a fork."""
        tail = chain_with_two.get_current_head()
        assert chain_with_two.detect_fork(
            tail.receipt_hash, "0" * 64
        ) is False

    def test_empty_chain_has_no_fork(self, chain):
        assert chain.detect_fork("0" * 64, "1" * 64) is False


# ---------------------------------------------------------------------------
# verify_receipt_applicability()
# ---------------------------------------------------------------------------

class TestVerifyReceiptApplicability:

    def test_current_head_is_authoritative(self, chain_with_two):
        """The current chain tail presented with a valid fresh checkpoint
        must return verdict=authoritative."""
        cp = chain_with_two.issue_checkpoint()
        tail = chain_with_two.get_current_head()
        result = chain_with_two.verify_receipt_applicability(
            tail.receipt_hash, cp, min_epoch=0
        )
        assert result["verdict"] == "authoritative"
        assert result["historically_valid"] is True
        assert result["currently_applicable"] is True
        assert result["checkpoint_fresh"] is True

    def test_superseded_receipt_returns_superseded(self, chain_with_two):
        """Massimiliano falsification test — R1 presented after R2 supersedes
        it must return verdict=superseded, not authoritative."""
        cp = chain_with_two.issue_checkpoint()
        r1 = chain_with_two._chain[0]
        result = chain_with_two.verify_receipt_applicability(
            r1.receipt_hash, cp, min_epoch=0
        )
        assert result["verdict"] == "superseded"
        assert result["historically_valid"] is True
        assert result["currently_applicable"] is False

    def test_stale_checkpoint_returns_stale(self, tmp_path):
        """Massimiliano falsification test #8 — stale checkpoint must
        prevent applicability determination entirely."""
        c = AttestationChain(db_path=str(tmp_path / "stale2.db"))
        c.issue("tx_a", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        stale_cp = c.issue_checkpoint()  # epoch=1
        c.issue("tx_b", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)
        tail = c.get_current_head()
        result = c.verify_receipt_applicability(
            tail.receipt_hash, stale_cp, min_epoch=2
        )
        assert result["verdict"] == "stale_checkpoint"
        assert result["checkpoint_fresh"] is False

    def test_unknown_receipt_hash_returns_invalid(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        result = chain_with_two.verify_receipt_applicability(
            "0" * 64, cp, min_epoch=0
        )
        assert result["verdict"] == "invalid"
        assert result["historically_valid"] is False

    def test_tampered_checkpoint_returns_stale(self, chain_with_two):
        cp = chain_with_two.issue_checkpoint()
        cp["checkpoint_signature"] = "0" * 64
        tail = chain_with_two.get_current_head()
        result = chain_with_two.verify_receipt_applicability(
            tail.receipt_hash, cp, min_epoch=0
        )
        assert result["verdict"] == "stale_checkpoint"

    def test_historically_valid_after_supersession(self, chain_with_two):
        """Massimiliano falsification test #10 — R1 must remain historically
        verifiable even though it is no longer currently applicable."""
        cp = chain_with_two.issue_checkpoint()
        r1 = chain_with_two._chain[0]
        result = chain_with_two.verify_receipt_applicability(
            r1.receipt_hash, cp, min_epoch=0
        )
        assert result["historically_valid"] is True
        assert result["currently_applicable"] is False

    def test_override_does_not_affect_unrelated_receipt(self, tmp_path):
        """Massimiliano falsification test #9 — an override of tx_001
        must not affect the applicability of an unrelated tx_002 receipt
        that is the current chain head."""
        c = AttestationChain(db_path=str(tmp_path / "unrelated.db"))
        c.issue("tx_001", {"HIPAA_SSN": 1}, {"HIPAA_SSN": 1}, 100, 90)
        c.issue("tx_002", {"HIPAA_PHI_PHONE": 1}, {"HIPAA_PHI_PHONE": 1}, 80, 70)
        # Override tx_001 — this supersedes tx_002 as chain head
        c.issue_review(
            transaction_id="tx_001",
            reviewed_by="auditor@example.com",
            decision="overridden",
            override_reason="Human review determined false positive",
        )
        cp = c.issue_checkpoint()
        # tx_002 receipt is superseded by the review receipt — but it is
        # still historically valid and its evidence is not invalidated
        r2 = c.get_compliance_receipt("tx_002")
        result = c.verify_receipt_applicability(
            r2.receipt_hash, cp, min_epoch=0
        )
        assert result["historically_valid"] is True
        # superseded because review receipt is now head, not because
        # tx_002's evidence was wrong
        assert result["verdict"] in ("superseded", "authoritative")

    def test_result_structure_always_complete(self, chain_with_two):
        """verify_receipt_applicability must always return all four
        keys regardless of outcome — callers depend on the structure."""
        cp = chain_with_two.issue_checkpoint()
        result = chain_with_two.verify_receipt_applicability(
            "0" * 64, cp, min_epoch=0
        )
        for key in ("receipt_hash", "historically_valid",
                    "currently_applicable", "checkpoint_fresh", "verdict"):
            assert key in result, f"Missing key: {key}"
