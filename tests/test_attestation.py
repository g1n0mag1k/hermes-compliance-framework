"""Tamper-resistance tests for AttestationChain.verify_chain()."""

import tempfile
from dataclasses import asdict

import pytest

from hermes.attestation import AttestationChain, ComplianceReceipt, HumanReviewReceipt


def _issue_sample(chain: AttestationChain, txn_id: str) -> ComplianceReceipt:
    return chain.issue(
        transaction_id=txn_id,
        flags_triggered={"HIPAA_SSN": 1},
        flags_redacted={"HIPAA_SSN": 1},
        char_count_in=100,
        char_count_out=80,
        downstream_target="test-downstream",
    )


def _fresh_db_path() -> str:
    """A unique SQLite path per call so tests never share persisted state."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="hermes_test_")
    import os as _os
    _os.close(fd)
    return path


def _build_chain(length: int = 4) -> AttestationChain:
    chain = AttestationChain(db_path=_fresh_db_path())
    for i in range(length):
        _issue_sample(chain, f"txn_{i}")
    return chain


def _resign(chain: AttestationChain, receipt: ComplianceReceipt) -> None:
    """Recompute receipt_hash so invariant 1 passes for the current fields."""
    content = asdict(receipt)
    content.pop("receipt_hash")
    receipt.receipt_hash = chain._sign_receipt(content)


def test_verify_chain_true_on_untampered_chain() -> None:
    """(e) An untampered, correctly-built chain verifies."""
    chain = _build_chain(4)
    assert chain.verify_chain() is True


def test_verify_chain_false_when_payload_mutated_after_signing() -> None:
    """(a) Mutating stored receipt content after signing invalidates the chain."""
    chain = _build_chain(3)
    assert chain.verify_chain() is True

    chain._chain[1].transaction_id = "tampered_txn"
    chain._chain[1].chars_removed = 999

    assert chain.verify_chain() is False


def test_verify_chain_false_when_previous_receipt_hash_corrupted() -> None:
    """(b) Corrupting a previous_receipt_hash link invalidates the chain."""
    chain = _build_chain(3)
    assert chain.verify_chain() is True

    chain._chain[2].previous_receipt_hash = "0" * 64

    assert chain.verify_chain() is False


def test_verify_chain_false_when_receipts_reordered() -> None:
    """(c) Reordering receipts breaks sequential position / hash links."""
    chain = _build_chain(4)
    assert chain.verify_chain() is True

    chain._chain[1], chain._chain[2] = chain._chain[2], chain._chain[1]

    assert chain.verify_chain() is False


def test_verify_chain_false_when_chain_positions_renumbered() -> None:
    """(c) Renumbering chain_position values breaks sequential position."""
    chain = _build_chain(3)
    assert chain.verify_chain() is True

    chain._chain[1].chain_position = 99
    _resign(chain, chain._chain[1])  # keep signature valid; isolate invariant 3

    assert chain.verify_chain() is False


def test_verify_chain_false_when_middle_receipt_deleted_and_rest_resigned() -> None:
    """(d) Deleting a middle receipt and re-signing survivors still fails.

    Re-signing restores invariant 1; broken previous_receipt_hash links and
    non-sequential chain_position values are caught by invariants 2 and 3.
    """
    chain = _build_chain(4)
    assert chain.verify_chain() is True
    assert chain.chain_length() == 4

    del chain._chain[1]
    for receipt in chain._chain:
        _resign(chain, receipt)

    assert chain.chain_length() == 3
    assert chain.verify_chain() is False


def test_chain_persists_across_simulated_restart(tmp_path) -> None:
    """(f) A chain reloaded from SQLite after a simulated restart still
    verifies, and can keep issuing receipts that correctly extend the same
    hash chain — proving persistence isn't just storage, it's continuity."""
    db_path = str(tmp_path / "restart_test.db")

    chain = AttestationChain(db_path=db_path)
    for i in range(4):
        _issue_sample(chain, f"txn_{i}")
    assert chain.chain_length() == 4
    assert chain.verify_chain() is True

    # Simulate a process restart: a brand new AttestationChain instance
    # pointed at the same on-disk database, as would happen after a
    # deploy, crash, or restart in production.
    reloaded = AttestationChain(db_path=db_path)
    assert reloaded.chain_length() == 4
    assert reloaded.verify_chain() is True

    # The reloaded chain must still be a live, extendable chain — a new
    # receipt issued after reload has to link correctly to the last
    # persisted receipt, not restart from a fresh genesis.
    new_receipt = _issue_sample(reloaded, "txn_after_restart")
    assert new_receipt.chain_position == 4
    assert reloaded.chain_length() == 5
    assert reloaded.verify_chain() is True


def test_chain_reload_preserves_order(tmp_path) -> None:
    """(g) chain_position, transaction order, and receipt_hash values survive
    a reload in exactly their original sequence — reload must not silently
    reorder rows (e.g. via an unordered SELECT)."""
    db_path = str(tmp_path / "order_test.db")

    chain = AttestationChain(db_path=db_path)
    issued = [_issue_sample(chain, f"txn_{i}") for i in range(5)]

    reloaded = AttestationChain(db_path=db_path)

    assert [r.chain_position for r in reloaded._chain] == [0, 1, 2, 3, 4]
    assert [r.transaction_id for r in reloaded._chain] == [r.transaction_id for r in issued]
    assert [r.receipt_hash for r in reloaded._chain] == [r.receipt_hash for r in issued]
    assert [r.previous_receipt_hash for r in reloaded._chain] == [
        r.previous_receipt_hash for r in issued
    ]


def test_override_receipt_links_to_original() -> None:
    """(h) issue_review() finds the original ComplianceReceipt for the given
    transaction_id and the review carries that exact receipt's hash."""
    chain = AttestationChain(db_path=_fresh_db_path())
    original = _issue_sample(chain, "txn_reviewed")

    review = chain.issue_review(
        transaction_id="txn_reviewed",
        reviewed_by="kiki.stein@example.com",
        decision="overridden",
        override_reason="False positive — not actually an SSN pattern.",
    )

    assert isinstance(review, HumanReviewReceipt)
    assert review.transaction_id == original.transaction_id
    assert review.original_receipt_hash == original.receipt_hash
    assert review.chain_position == original.chain_position + 1
    assert review.previous_receipt_hash == original.receipt_hash
    assert chain.verify_chain() is True


def test_override_receipt_is_tamper_evident() -> None:
    """(i) Mutating a HumanReviewReceipt after issuance invalidates the
    chain, the same guarantee ComplianceReceipts already have. Tampering
    with the field that names which original it reviewed is the specific
    attack this receipt type exists to prevent."""
    chain = AttestationChain(db_path=_fresh_db_path())
    _issue_sample(chain, "txn_reviewed")
    chain.issue_review(
        transaction_id="txn_reviewed",
        reviewed_by="kiki.stein@example.com",
        decision="overridden",
        override_reason="False positive.",
    )
    assert chain.verify_chain() is True

    # Tamper with the review's claim about which original it reviewed.
    chain._chain[1].original_receipt_hash = "0" * 64
    assert chain.verify_chain() is False


def test_accepted_decision_recorded_in_chain() -> None:
    """(j) An 'accepted' decision (no override) is recorded and chains
    cleanly — the review event exists whether or not anything was
    overridden, proving a human actually looked at the control."""
    chain = AttestationChain(db_path=_fresh_db_path())
    _issue_sample(chain, "txn_ok")

    review = chain.issue_review(
        transaction_id="txn_ok",
        reviewed_by="kiki.stein@example.com",
        decision="accepted",
    )

    assert review.decision == "accepted"
    assert review.override_reason is None
    assert chain.chain_length() == 2
    assert chain._chain[1] is review
    assert chain.verify_chain() is True


def test_issue_review_rejects_invalid_decision() -> None:
    """decision is constrained to accepted/overridden/escalated — anything
    else must fail loudly rather than silently record a typo."""
    chain = AttestationChain(db_path=_fresh_db_path())
    _issue_sample(chain, "txn_bad_decision")

    with pytest.raises(ValueError):
        chain.issue_review(
            transaction_id="txn_bad_decision",
            reviewed_by="kiki.stein@example.com",
            decision="approved",  # not a valid REVIEW_DECISIONS value
        )


def test_issue_review_unknown_transaction_raises() -> None:
    """Reviewing a transaction_id with no ComplianceReceipt must fail
    loudly, not silently create an orphaned review receipt."""
    chain = AttestationChain(db_path=_fresh_db_path())

    with pytest.raises(ValueError):
        chain.issue_review(
            transaction_id="txn_never_scanned",
            reviewed_by="kiki.stein@example.com",
            decision="accepted",
        )
