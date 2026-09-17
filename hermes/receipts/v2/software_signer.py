"""
hermes/receipts/v2/software_signer.py — In-memory software key signers.

Two implementations:
  SoftwareSignerEd25519 — Ed25519 (default; COSE alg -8 / EdDSA)
  SoftwareSignerES256   — ECDSA P-256 SHA-256 (COSE alg -7 / ES256)

Both are thread-safe (the private key is immutable after construction).
The private key is never written to disk here — callers are responsible
for serialization if they need persistence.

For production deployments, swap these for a KMSSigner that delegates
sign_cose_sig_structure to AWS KMS / Azure Key Vault.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from hermes.receipts.v2.signer import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    KeyManifest,
    Signer,
    derive_key_id,
    spki_sha256,
)


class SoftwareSignerEd25519:
    """
    Ed25519 signer — private key lives in memory only.

    Ed25519 signatures are deterministic (RFC 8032), so signing the same
    message twice produces identical signatures. This is fine and expected.
    """

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        *,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        status: str = "active",
    ) -> None:
        self._private_key = private_key
        self._pub_key = private_key.public_key()
        spki_der = self._pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id: bytes = derive_key_id(spki_der)
        self._spki_sha256: str = spki_sha256(spki_der)
        self._public_key_pem: str = self._pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self._created_at: str = (valid_from or datetime.now(timezone.utc)).isoformat()
        self._valid_until: str | None = (
            valid_until.astimezone(timezone.utc).isoformat() if valid_until else None
        )
        self._status: str = status

    # --- Signer protocol ---

    @property
    def key_id(self) -> bytes:
        return self._key_id

    @property
    def cose_algorithm(self) -> int:
        return COSE_ALG_EDDSA

    def public_key_manifest(self) -> KeyManifest:
        return KeyManifest(
            key_id=self._key_id.hex(),
            algorithm="EdDSA",
            public_key_spki_sha256=self._spki_sha256,
            public_key_pem=self._public_key_pem,
            valid_from=self._created_at,
            valid_until=self._valid_until,
            status=self._status,
            purpose="receipt-signing",
        )

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify a signature against this key's public key.

        Raises cryptography.exceptions.InvalidSignature on failure.
        Useful in tests and for receipt chain validation.
        """
        self._pub_key.verify(signature, message)

    def sign_cose_sig_structure(self, message: bytes) -> bytes:
        if not message:
            raise ValueError("sign_cose_sig_structure: message must not be empty")
        return self._private_key.sign(message)

    # --- Constructors ---

    @classmethod
    def generate(cls) -> "SoftwareSignerEd25519":
        """Generate a new Ed25519 key pair."""
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def load_from_pem(cls, private_key_pem: bytes) -> "SoftwareSignerEd25519":
        """Load an Ed25519 private key from PEM bytes (no passphrase)."""
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TypeError(
                f"Expected Ed25519PrivateKey, got {type(key).__name__}"
            )
        return cls(key)

    def private_key_pem(self) -> bytes:
        """
        Export the private key as PEM for safe storage.
        Callers are responsible for encrypting this before writing to disk.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


class SoftwareSignerES256:
    """
    ECDSA P-256 (ES256) signer — private key lives in memory only.

    ECDSA signatures are probabilistic — the same message signed twice
    produces different (but both valid) signatures.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise TypeError(
                f"ES256 requires P-256 (SECP256R1), got {type(private_key.curve).__name__}"
            )
        self._private_key = private_key
        pub = private_key.public_key()
        spki_der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._key_id: bytes = derive_key_id(spki_der)
        self._spki_sha256: str = spki_sha256(spki_der)
        self._public_key_pem: str = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self._created_at: str = datetime.now(timezone.utc).isoformat()

    # --- Signer protocol ---

    @property
    def key_id(self) -> bytes:
        return self._key_id

    @property
    def cose_algorithm(self) -> int:
        return COSE_ALG_ES256

    def public_key_manifest(self) -> KeyManifest:
        return KeyManifest(
            key_id=self._key_id.hex(),
            algorithm="ES256",
            public_key_spki_sha256=self._spki_sha256,
            public_key_pem=self._public_key_pem,
            valid_from=self._created_at,
            valid_until=None,
            status="active",
            purpose="receipt-signing",
        )

    def sign_cose_sig_structure(self, message: bytes) -> bytes:
        if not message:
            raise ValueError("sign_cose_sig_structure: message must not be empty")
        # ES256 signs the raw bytes with ECDSA+SHA-256
        # The COSE Sig_Structure already includes the protected headers and
        # payload — we sign its raw bytes, NOT a pre-hashed digest, because
        # ECDSA with hash=SHA256 takes the message and hashes internally.
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    # --- Constructors ---

    @classmethod
    def generate(cls) -> "SoftwareSignerES256":
        """Generate a new P-256 key pair."""
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def load_from_pem(cls, private_key_pem: bytes) -> "SoftwareSignerES256":
        """Load a P-256 private key from PEM bytes (no passphrase)."""
        key = serialization.load_pem_private_key(private_key_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                f"Expected EllipticCurvePrivateKey, got {type(key).__name__}"
            )
        return cls(key)

    def private_key_pem(self) -> bytes:
        """Export the private key as PEM. Encrypt before writing to disk."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


# Convenience alias — default signer is Ed25519
SoftwareSigner = SoftwareSignerEd25519


# Runtime check that both implementations satisfy the Protocol
assert isinstance(SoftwareSignerEd25519.generate(), Signer), \
    "SoftwareSignerEd25519 does not implement Signer protocol"
assert isinstance(SoftwareSignerES256.generate(), Signer), \
    "SoftwareSignerES256 does not implement Signer protocol"
