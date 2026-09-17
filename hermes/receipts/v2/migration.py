"""
hermes/receipts/v2/migration.py — V1 → V2 algorithm transition bridge.

Creates a signed V2 receipt that anchors the final V1 HMAC chain head,
record count, and database digest. This record is the cryptographic
handoff: everything before it has HMAC-only integrity; everything after
it has asymmetric non-repudiation.

V1 records are NEVER modified, deleted, or rewritten.
"""

from __future__ import annotations

from hermes.receipts.v2.builder import ReceiptV2Builder, ReceiptV2
from hermes.receipts.v2.signer import Signer


def create_v1_bridge(
    v1_hmac_head: str,
    v1_record_count: int,
    v1_db_sha256: str,
    v2_signer: Signer,
) -> ReceiptV2:
    """
    Create a signed V2 bridge record anchoring the frozen V1 HMAC chain.

    Args:
        v1_hmac_head:    Hex HMAC digest of the final V1 chain receipt.
        v1_record_count: Total number of records in the V1 chain.
        v1_db_sha256:    SHA-256 hex of the exported V1 database at freeze time.
        v2_signer:       The V2 Signer to use for this receipt.

    Returns:
        A signed ReceiptV2 with event_type "v1_algorithm_transition".
        This receipt is the first record in the new V2 chain
        (prev_receipt_digest is None — it is the V2 genesis).

    Notes:
        - Does NOT modify, delete, or read any V1 receipt_json.
        - The bridge record is the V2 genesis — prev_receipt_digest is None.
        - After this record, all new receipts are V2 only.
        - V1 receipts retain HMAC integrity but cannot provide third-party
          non-repudiation; that property begins with this bridge record.
    """
    bridge_payload = {
        "event_type": "v1_algorithm_transition",
        "v1_hmac_head": v1_hmac_head,
        "v1_record_count": v1_record_count,
        "v1_db_sha256": v1_db_sha256,
        "v1_schema_version": "1.0",
        "v2_first_key_id": v2_signer.key_id.hex(),
        "v2_profile": "hermes-receipt-v2",
        "transition_note": (
            "V1 HMAC chain frozen. V2 asymmetric signing begins after this record."
        ),
        "limitation_note": (
            "V1 receipts retain HMAC integrity only. "
            "Third-party non-repudiation applies to V2 receipts from this point forward."
        ),
    }

    builder = ReceiptV2Builder(v2_signer)
    # Bridge record is the V2 genesis — no V2 predecessor
    return builder.build(bridge_payload, prev_receipt_digest=None)
