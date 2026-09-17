"""
hermes/receipts/v2 — Hermes Relay V2 verifiable receipt architecture.

Public API:

    from hermes.receipts.v2 import (
        ReceiptV2,
        ReceiptV2Builder,
        SoftwareSigner,
        SoftwareSignerEd25519,
        SoftwareSignerES256,
        verify_receipt,
        VerificationResult,
        create_v1_bridge,
    )

Key hierarchy and design notes:
  - ReceiptV2Builder accepts any Signer implementation.
  - SoftwareSignerEd25519 is the default for development and on-prem deployments.
  - SoftwareSignerES256 is available for deployments requiring P-256 / FIPS 140 hardware.
  - verify_receipt requires only a public key PEM — no signing dependencies.
  - create_v1_bridge anchors the frozen V1 HMAC chain into the V2 genesis receipt.
"""

from hermes.receipts.v2.builder import ReceiptV2, ReceiptV2Builder
from hermes.receipts.v2.software_signer import (
    SoftwareSigner,
    SoftwareSignerEd25519,
    SoftwareSignerES256,
)
from hermes.receipts.v2.verifier import VerificationResult, verify_receipt
from hermes.receipts.v2.migration import create_v1_bridge
from hermes.receipts.v2.key_manifest import KeyManifestDocument, ManifestEntry
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.key_ceremony import run_ceremony, rotate_operational_key
from hermes.receipts.v2.merkle_tree import MerkleTree, InclusionProof, ConsistencyProof
from hermes.receipts.v2.checkpoint import CheckpointEngine, CheckpointRecord, verify_checkpoint
from hermes.receipts.v2.anchoring import WORMStore, timestamp_checkpoint, register_with_scitt

__all__ = [
    "ReceiptV2",
    "ReceiptV2Builder",
    "SoftwareSigner",
    "SoftwareSignerEd25519",
    "SoftwareSignerES256",
    "VerificationResult",
    "verify_receipt",
    "create_v1_bridge",
    # Release B — key governance
    "KeyManifestDocument",
    "ManifestEntry",
    "KeyStore",
    "run_ceremony",
    "rotate_operational_key",
    # Release C — Merkle checkpoints
    "MerkleTree", "InclusionProof", "ConsistencyProof",
    "CheckpointEngine", "CheckpointRecord", "verify_checkpoint",
    # Release D — external anchoring
    "WORMStore", "timestamp_checkpoint", "register_with_scitt",
]
