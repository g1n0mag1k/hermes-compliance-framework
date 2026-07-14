"""Tamper-resistance tests for AttestationChain.verify_chain()."""

from dataclasses import asdict

from hermes.attestation import AttestationChain, ComplianceReceipt


def _issue_sample(chain: AttestationChain, txn_id: str) -> ComplianceReceipt:
    return chain.issue(
        transaction_id=txn_id,
        flags_triggered={"HIPAA_SSN": 1},
        flags_redacted={"HIPAA_SSN": 1},
        char_count_in=100,
        char_count_out=80,
        downstream_target="test-downstream",
    )


def _build_chain(length: int = 4) -> AttestationChain:
    chain = AttestationChain()
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
