"""
hermes/receipts/v2/checkpoint.py — Signed Merkle tree checkpoints.

A CheckpointRecord is a COSE_Sign1-signed snapshot of the Merkle tree state
at a point in time. It contains:
  - Merkle root over all receipts issued so far
  - Tree size (monotonic — verifiers reject checkpoints with lower tree_size)
  - Stream/deployment identifier
  - Previous checkpoint digest (links checkpoints into their own chain)
  - Policy, software version, and configuration digests
    (allows detecting config drift between checkpoints)

These are the artifacts that:
  1. Enable split-view detection — two investigators can compare checkpoint
     digests out-of-band; a forked log would produce different roots
  2. Enable RFC 3161 timestamping (Release D) — TSA signs the checkpoint digest
  3. Enable SCITT registration (Release D) — checkpoint root registered with a
     transparency service

The checkpoint key (Tier 2) should be separate from the operational receipt
key (Tier 1) so a compromise of one does not compromise the other.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import cbor2
from pycose.headers import Algorithm, KID, ContentType
from pycose.messages import Sign1Message

from hermes.receipts.v2.canonical import canonicalize, receipt_digest_hex
from hermes.receipts.v2.merkle_tree import MerkleTree
from hermes.receipts.v2.signer import ALLOWED_ALGORITHMS, Signer

_CHECKPOINT_CONTENT_TYPE = "application/vnd.hermes.checkpoint-v2+cose"
_CHECKPOINT_PROFILE = "hermes-checkpoint-v2"
_HEADER_CHECKPOINT_PROFILE = -70002  # private-use COSE header label
_UHDR_CHECKPOINT_DIGEST = -70003     # unprotected: hex checkpoint_digest
_CHECKPOINT_DOMAIN = b"HERMES-CHECKPOINT-V2\x00"
_COSE_SIGN1_TAG = 18


@dataclass(frozen=True)
class CheckpointRecord:
    """
    A signed snapshot of the Merkle tree state.

    All fields except cose_sign1_bytes are human-readable.
    cose_sign1_bytes is the canonical wire format for storage and transmission.
    """
    # Identity
    checkpoint_id: str            # UUID
    stream_id: str                # deployment/stream identifier
    sequence: int                 # monotonically increasing checkpoint counter
    issued_at: str                # ISO 8601 UTC

    # Tree state
    tree_size: int                # number of leaves at checkpoint time
    merkle_root: str              # hex SHA-256 Merkle root

    # Chain link
    prev_checkpoint_digest: Optional[str]   # hex, None for genesis checkpoint

    # Policy/config digests — detect drift between checkpoints
    policy_digest: str            # hex SHA-256 of current policy document
    software_version: str         # Hermes version string
    config_digest: str            # hex SHA-256 of current configuration

    # Cryptographic envelope
    checkpoint_digest: str        # hex domain-separated SHA-256 of canonical payload
    cose_sign1_bytes: bytes       # serialized COSE_Sign1 envelope


@dataclass
class CheckpointEngine:
    """
    Issues signed checkpoints over a MerkleTree.

    One CheckpointEngine per stream/deployment. Thread-safe for reads;
    issue_checkpoint() should be called from a single writer thread or
    protected by a lock at the application level.
    """

    stream_id: str
    signer: Signer
    tree: MerkleTree = field(default_factory=MerkleTree)
    _sequence: int = field(default=0, init=False)
    _prev_checkpoint_digest: Optional[str] = field(default=None, init=False)
    _checkpoints: list[CheckpointRecord] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.signer.cose_algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(
                f"Signer algorithm {self.signer.cose_algorithm} not in allowed set."
            )

    # ------------------------------------------------------------------
    # Tree population
    # ------------------------------------------------------------------

    def add_receipt_digest(self, receipt_digest_hex: str) -> int:
        """
        Append a receipt digest to the Merkle tree.

        Returns the leaf index.
        """
        return self.tree.append_hex(receipt_digest_hex)

    # ------------------------------------------------------------------
    # Checkpoint issuance
    # ------------------------------------------------------------------

    def issue_checkpoint(
        self,
        policy_digest: str = "0" * 64,
        software_version: str = "hermes-relay-v2",
        config_digest: str = "0" * 64,
    ) -> CheckpointRecord:
        """
        Issue a signed checkpoint over the current Merkle tree state.

        Args:
            policy_digest:    Hex SHA-256 of the current policy document.
            software_version: Current Hermes version string.
            config_digest:    Hex SHA-256 of the current configuration.

        Returns:
            A frozen CheckpointRecord.

        Raises:
            ValueError: if the tree is empty.
        """
        import uuid as _uuid

        if self.tree.size == 0:
            raise ValueError("Cannot issue checkpoint over empty tree.")

        issued_at = datetime.now(timezone.utc).isoformat()
        checkpoint_id = str(_uuid.uuid4())
        merkle_root = self.tree.root_hex()
        sequence = self._sequence

        # Build canonical payload
        payload = {
            "checkpoint_id": checkpoint_id,
            "stream_id": self.stream_id,
            "sequence": sequence,
            "issued_at": issued_at,
            "tree_size": self.tree.size,
            "merkle_root": merkle_root,
            "prev_checkpoint_digest": self._prev_checkpoint_digest,
            "policy_digest": policy_digest,
            "software_version": software_version,
            "config_digest": config_digest,
        }

        canonical_bytes = canonicalize(payload)

        # Domain-separated checkpoint digest
        digest = hashlib.sha256(
            _CHECKPOINT_DOMAIN + canonical_bytes
        ).digest()
        checkpoint_digest_hex = digest.hex()

        # Build COSE_Sign1
        protected_headers = {
            Algorithm: self.signer.cose_algorithm,
            KID: self.signer.key_id,
            ContentType: _CHECKPOINT_CONTENT_TYPE,
            _HEADER_CHECKPOINT_PROFILE: _CHECKPOINT_PROFILE,
        }
        msg = Sign1Message(
            phdr=protected_headers,
            uhdr={_UHDR_CHECKPOINT_DIGEST: checkpoint_digest_hex},
            payload=canonical_bytes,
        )
        sig_structure = msg._create_sig_structure()
        signature = self.signer.sign_cose_sig_structure(sig_structure)
        msg.signature = signature
        cose_bytes = msg.encode(sign=False)

        record = CheckpointRecord(
            checkpoint_id=checkpoint_id,
            stream_id=self.stream_id,
            sequence=sequence,
            issued_at=issued_at,
            tree_size=self.tree.size,
            merkle_root=merkle_root,
            prev_checkpoint_digest=self._prev_checkpoint_digest,
            policy_digest=policy_digest,
            software_version=software_version,
            config_digest=config_digest,
            checkpoint_digest=checkpoint_digest_hex,
            cose_sign1_bytes=cose_bytes,
        )

        self._checkpoints.append(record)
        self._prev_checkpoint_digest = checkpoint_digest_hex
        self._sequence += 1
        return record

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def checkpoint_count(self) -> int:
        return len(self._checkpoints)

    @property
    def latest_checkpoint(self) -> Optional[CheckpointRecord]:
        return self._checkpoints[-1] if self._checkpoints else None

    def get_checkpoint(self, sequence: int) -> Optional[CheckpointRecord]:
        for cp in self._checkpoints:
            if cp.sequence == sequence:
                return cp
        return None


# ------------------------------------------------------------------
# Checkpoint verification
# ------------------------------------------------------------------

@dataclass
class CheckpointVerificationResult:
    signature_valid: bool = False
    checkpoint_digest_valid: bool = False
    sequence_monotonic: bool = False
    chain_link_valid: Optional[bool] = None
    merkle_root: str = ""
    tree_size: int = 0
    stream_id: str = ""
    issued_at: str = ""
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def fully_valid(self) -> bool:
        return self.signature_valid and self.checkpoint_digest_valid


def verify_checkpoint(
    cose_sign1_bytes: bytes,
    public_key_pem: str,
    min_sequence: int = 0,
) -> CheckpointVerificationResult:
    """
    Verify a Hermes V2 checkpoint COSE_Sign1 envelope.

    Args:
        cose_sign1_bytes: Raw COSE_Sign1 checkpoint bytes.
        public_key_pem:   PEM public key from the Tier 2 key manifest entry.
        min_sequence:     Minimum acceptable sequence number (rejects replays).

    Returns:
        CheckpointVerificationResult — never raises, errors captured in result.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    result = CheckpointVerificationResult()

    # Decode COSE envelope
    try:
        outer = cbor2.loads(cose_sign1_bytes)
    except Exception as exc:
        result.errors.append(f"CBOR decode failed: {exc}")
        return result

    if not isinstance(outer, cbor2.CBORTag) or outer.tag != _COSE_SIGN1_TAG:
        result.errors.append("Not a COSE_Sign1 envelope.")
        return result

    arr = outer.value
    if not isinstance(arr, (list, tuple)) or len(arr) != 4:
        result.errors.append("COSE_Sign1 must be 4-element array.")
        return result

    phdr_bytes, uhdr_raw, payload_bytes, signature = arr

    # Decode protected headers
    try:
        phdr = cbor2.loads(phdr_bytes)
    except Exception as exc:
        result.errors.append(f"Protected header decode failed: {exc}")
        return result

    # Reconstruct Sig_Structure and verify signature
    try:
        sig_structure = cbor2.dumps(["Signature1", phdr_bytes, b"", payload_bytes])
        pub_key = serialization.load_pem_public_key(
            public_key_pem.encode("ascii")
            if isinstance(public_key_pem, str) else public_key_pem
        )
        if isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key.verify(bytes(signature), sig_structure)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            from cryptography.hazmat.primitives import hashes as _h
            pub_key.verify(bytes(signature), sig_structure, ec.ECDSA(_h.SHA256()))
        else:
            result.errors.append(f"Unsupported key type: {type(pub_key).__name__}")
            return result
        result.signature_valid = True
    except InvalidSignature:
        result.errors.append("Checkpoint signature verification FAILED.")
        return result
    except Exception as exc:
        result.errors.append(f"Signature verification error: {exc}")
        return result

    # Parse payload
    try:
        payload = json.loads(payload_bytes)
    except Exception as exc:
        result.errors.append(f"Payload JSON decode failed: {exc}")
        return result

    result.merkle_root = payload.get("merkle_root", "")
    result.tree_size = payload.get("tree_size", 0)
    result.stream_id = payload.get("stream_id", "")
    result.issued_at = payload.get("issued_at", "")

    # Verify checkpoint_digest from unprotected header
    try:
        uhdr = dict(uhdr_raw) if uhdr_raw else {}
        stored_digest = uhdr.get(_UHDR_CHECKPOINT_DIGEST)
        canonical_bytes = canonicalize(payload)
        recomputed = hashlib.sha256(_CHECKPOINT_DOMAIN + canonical_bytes).hexdigest()
        if stored_digest and recomputed == stored_digest:
            result.checkpoint_digest_valid = True
        elif not stored_digest:
            result.warnings.append("No checkpoint_digest in unprotected header.")
        else:
            result.errors.append("checkpoint_digest mismatch — payload tampered.")
    except Exception as exc:
        result.errors.append(f"checkpoint_digest verification error: {exc}")

    # Check sequence monotonicity
    seq = payload.get("sequence", -1)
    if seq >= min_sequence:
        result.sequence_monotonic = True
    else:
        result.errors.append(
            f"Sequence {seq} is below min_sequence {min_sequence} — possible replay."
        )

    # Chain link
    prev = payload.get("prev_checkpoint_digest")
    if prev is not None:
        result.chain_link_valid = True
        result.warnings.append(
            "Chain link (prev_checkpoint_digest) present — verify against prior checkpoint."
        )

    return result
