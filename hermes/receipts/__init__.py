"""
hermes/receipts — unified receipt facade.

Use this package for all receipt creation and verification.  Do NOT
import from ``hermes.attestation`` (V1 HMAC chain) or
``hermes.receipts.v2`` directly in application code; import from here
so that callers are insulated from version details.

V1 — HMAC-SHA256 chain (SQLite-backed, backward-compatible)
    Primary class:  ComplianceReceipt  (from hermes.attestation)
    Chain store:    HermesChain         (from hermes.attestation)

V2 — Ed25519/ES256 signed verifiable receipts (Merkle-anchored)
    Builder:  ReceiptV2Builder          (from hermes.receipts.v2)
    Signer:   SoftwareSignerEd25519     (from hermes.receipts.v2)
    Verify:   verify_receipt            (from hermes.receipts.v2)

Migration helper:
    create_v1_bridge — anchor the frozen V1 HMAC chain into a V2
                        genesis receipt (from hermes.receipts.v2)

Quick-start
-----------
    # V1 (existing integrations)
    from hermes.receipts import ComplianceReceipt, HermesChain

    # V2 (new integrations)
    from hermes.receipts import (
        ReceiptV2Builder, SoftwareSignerEd25519, verify_receipt,
    )

    # Migration
    from hermes.receipts import create_v1_bridge
"""

# V1 — HMAC chain
from hermes.attestation import AttestationChain as HermesChain, ComplianceReceipt

# V2 — verifiable receipts
from hermes.receipts.v2 import (
    ReceiptV2,
    ReceiptV2Builder,
    SoftwareSigner,
    SoftwareSignerEd25519,
    SoftwareSignerES256,
    VerificationResult,
    create_v1_bridge,
    verify_receipt,
)

__all__ = [  # noqa: RUF022  # grouped by version for readability
    # V1
    "ComplianceReceipt",
    "HermesChain",
    # V2
    "ReceiptV2",
    "ReceiptV2Builder",
    "SoftwareSigner",
    "SoftwareSignerEd25519",
    "SoftwareSignerES256",
    "VerificationResult",
    "create_v1_bridge",
    "verify_receipt",
]
