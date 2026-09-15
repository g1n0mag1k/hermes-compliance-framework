"""
hermes/receipts/v2/signer.py — Signer Protocol and KeyManifest type.

The Signer Protocol is the single seam between receipt-building logic and
the key-management backend. Swap in AWS KMS, Azure Key Vault, an HSM, or
a YubiKey — the builder never changes. Only software-key-based signers are
implemented here; KMS backends live in separate modules.

No signing happens in this file. Only the interface contract is defined.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, TypedDict, runtime_checkable


class KeyManifest(TypedDict):
    """
    Public-only key manifest — safe to publish and distribute to verifiers.
    Contains everything a verifier needs; never contains a private key.
    """
    key_id: str                # hex — first 8 bytes of SHA-256(SPKI)
    algorithm: str             # "ES256" (ECDSA P-256) or "EdDSA" (Ed25519)
    public_key_spki_sha256: str  # hex — SHA-256 of the DER-encoded SPKI blob
    public_key_pem: str        # PEM-encoded SubjectPublicKeyInfo
    valid_from: str            # ISO 8601 UTC
    valid_until: str | None    # ISO 8601 UTC, or None if unbounded
    status: str                # "active" | "rotated" | "revoked"
    purpose: str               # "receipt-signing"


# COSE algorithm integers (RFC 8152 §8)
COSE_ALG_ES256 = -7    # ECDSA P-256 with SHA-256
COSE_ALG_EDDSA = -8    # EdDSA (Ed25519 in Hermes context)
COSE_ALG_EdDSA = COSE_ALG_EDDSA  # alias — matches Cursor-generated code

ALLOWED_ALGORITHMS = frozenset({COSE_ALG_ES256, COSE_ALG_EDDSA})


@runtime_checkable
class Signer(Protocol):
    """
    Signing backend contract.

    Implementations must be safe to call from concurrent request handlers.
    The private key must never be exported or passed to any other module.
    sign_cose_sig_structure receives the exact bytes produced by the COSE
    Sig_Structure — the signer must not re-canonicalize or re-wrap them.
    """

    @property
    def key_id(self) -> bytes:
        """8-byte key identifier — derived from the public key, not secret."""
        ...

    @property
    def cose_algorithm(self) -> int:
        """COSE algorithm integer (COSE_ALG_ES256 or COSE_ALG_EDDSA)."""
        ...

    def public_key_manifest(self) -> KeyManifest:
        """Return the public KeyManifest for this key."""
        ...

    def sign_cose_sig_structure(self, message: bytes) -> bytes:
        """
        Sign exactly the bytes passed.

        The caller (ReceiptV2Builder) produces the COSE Sig_Structure bytes
        and passes them here. The signer signs and returns the raw signature
        bytes. It must not modify, re-encode, or re-canonicalize the message.

        Raises:
            ValueError: if message is empty
        """
        ...


def derive_key_id(public_key_spki_der: bytes) -> bytes:
    """Derive an 8-byte key identifier from the DER-encoded SPKI blob."""
    return hashlib.sha256(public_key_spki_der).digest()[:8]


def spki_sha256(public_key_spki_der: bytes) -> str:
    """Return hex SHA-256 of the DER-encoded SPKI blob."""
    return hashlib.sha256(public_key_spki_der).hexdigest()
