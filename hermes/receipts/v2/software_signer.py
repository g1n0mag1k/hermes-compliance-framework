"""In-memory Ed25519 SoftwareSigner for Hermes Relay V2."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hermes.receipts.v2.signer import KeyManifest

# COSE algorithm identifier for EdDSA (RFC 8152).
COSE_ALG_EdDSA = -8


class SoftwareSigner:
    """Ed25519 signer that keeps the private key in process memory only.

    The private key is never written to disk in plaintext by this class.
    ``sign_cose_sig_structure`` signs the exact bytes passed with no
    re-canonicalization inside the signer.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        status: str = "active",
    ) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._spki_der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._spki_sha256 = hashlib.sha256(self._spki_der).digest()
        self._key_id = self._spki_sha256[:8]
        self._valid_from = valid_from or datetime.now(timezone.utc)
        self._valid_until = valid_until
        self._status = status

    @classmethod
    def generate(cls) -> SoftwareSigner:
        """Create a new SoftwareSigner with a freshly generated Ed25519 key."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_from_pem(cls, private_key_pem: bytes) -> SoftwareSigner:
        """Load an existing Ed25519 private key from PEM bytes into memory."""
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError(
                "private_key_pem must decode to an Ed25519 private key, "
                f"got {type(private_key).__name__}"
            )
        return cls(private_key)

    @property
    def key_id(self) -> bytes:
        """First 8 bytes of SHA-256(SPKI DER) of the public key."""
        return self._key_id

    @property
    def cose_algorithm(self) -> int:
        """COSE algorithm integer for EdDSA."""
        return COSE_ALG_EdDSA

    def public_key_manifest(self) -> KeyManifest:
        """Return a complete KeyManifest for this signing key."""
        public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        valid_until: str | None = None
        if self._valid_until is not None:
            valid_until = self._valid_until.astimezone(timezone.utc).isoformat()
        return KeyManifest(
            key_id=self._key_id.hex(),
            algorithm="EdDSA",
            public_key_spki_sha256=self._spki_sha256.hex(),
            public_key_pem=public_key_pem,
            valid_from=self._valid_from.astimezone(timezone.utc).isoformat(),
            valid_until=valid_until,
            status=self._status,
            purpose="receipt-signing",
        )

    def sign_cose_sig_structure(self, message: bytes) -> bytes:
        """Sign ``message`` exactly as provided — no re-canonicalization.

        Raises:
            ValueError: if ``message`` is empty.
        """
        if not message:
            raise ValueError("message must be non-empty bytes")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify a signature over ``message`` with this signer's public key.

        Raises cryptography's InvalidSignature on failure.
        """
        self._public_key.verify(signature, message)
