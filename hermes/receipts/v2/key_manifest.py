"""
hermes/receipts/v2/key_manifest.py — Root-signed key manifests for Hermes V2.

A KeyManifestDocument is a JSON-serializable object that:
  - Lists all active, rotated, and revoked keys for a deployment
  - Is signed by the root key so external verifiers can authenticate it
  - Contains no private key material — public SPKI and metadata only

Three key tiers (from the architecture spec):
  Tier 0 — offline_root:   Customer-controlled, offline trust root
  Tier 1 — operational:    Non-exportable per-deployment receipt signing key
  Tier 2 — checkpoint:     Separately controlled checkpoint/anchor key

External verifiers receive the manifest and can verify any receipt or
checkpoint signature by looking up the appropriate public key by key_id.

The manifest itself is signed by the Tier 0 root so verifiers can confirm
that the operational keys were legitimately installed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal

from hermes.receipts.v2.canonical import canonicalize


KeyTier = Literal["offline_root", "operational", "checkpoint"]
KeyStatus = Literal["active", "rotated", "revoked"]


@dataclass
class ManifestEntry:
    """A single key entry in a KeyManifestDocument."""
    key_id: str                    # hex — first 8 bytes of SHA-256(SPKI)
    tier: KeyTier                  # "offline_root" | "operational" | "checkpoint"
    algorithm: str                 # "EdDSA" | "ES256"
    public_key_pem: str            # PEM-encoded SubjectPublicKeyInfo
    public_key_spki_sha256: str    # hex — SHA-256 of DER-encoded SPKI
    purpose: str                   # human-readable description
    valid_from: str                # ISO 8601 UTC
    valid_until: str | None        # ISO 8601 UTC, or None if unbounded
    status: KeyStatus              # "active" | "rotated" | "revoked"
    rotated_at: str | None = None  # ISO 8601 UTC — when rotation occurred
    revoked_at: str | None = None  # ISO 8601 UTC — when revocation occurred
    revocation_reason: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None or k in (
            "valid_until", "rotated_at", "revoked_at", "revocation_reason"
        )}


@dataclass
class KeyManifestDocument:
    """
    A root-signed collection of public keys for a Hermes deployment.

    The manifest_digest covers all entries canonically so any modification
    is detectable. The root_signature signs the manifest_digest using the
    Tier 0 offline root key — verifiers confirm the root public key
    out-of-band (e.g. printed at key ceremony, pinned in their config).

    Fields:
        deployment_id:    Unique identifier for this Hermes installation
        issued_at:        ISO 8601 UTC timestamp
        entries:          All keys (all tiers, all statuses)
        manifest_digest:  SHA-256 hex over RFC 8785 canonical entries
        root_signature:   Ed25519/ECDSA signature by the offline root key
        root_key_id:      hex key_id of the root key that signed this
    """
    deployment_id: str
    issued_at: str
    entries: list[ManifestEntry]
    manifest_digest: str = field(default="")   # filled by sign()
    root_signature: str = field(default="")    # hex, filled by sign()
    root_key_id: str = field(default="")       # filled by sign()

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, root_signer: object) -> "KeyManifestDocument":
        """
        Sign the manifest with the Tier 0 root signer.

        Computes manifest_digest over the canonical entries payload, then
        signs the digest bytes with root_signer.sign_cose_sig_structure.
        Returns self (mutates in place) for chaining.

        Args:
            root_signer: Any object implementing the Signer protocol.
        """
        entries_payload = [e.to_dict() for e in self.entries]
        canonical = canonicalize({
            "deployment_id": self.deployment_id,
            "issued_at": self.issued_at,
            "entries": entries_payload,
        })
        digest = hashlib.sha256(b"HERMES-KEY-MANIFEST-V1\x00" + canonical).digest()
        self.manifest_digest = digest.hex()
        self.root_signature = root_signer.sign_cose_sig_structure(digest).hex()
        self.root_key_id = root_signer.key_id.hex()
        return self

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self, root_public_key_pem: str) -> "ManifestVerificationResult":
        """
        Verify the manifest signature using the root public key PEM.

        Does NOT require any private key or access to the Hermes database.
        The root public key should be pinned by the verifier out-of-band.

        Returns a ManifestVerificationResult with claim-by-claim output.
        """
        result = ManifestVerificationResult()

        if not self.manifest_digest or not self.root_signature or not self.root_key_id:
            result.errors.append("Manifest is unsigned — call sign() first.")
            return result

        # Recompute digest
        entries_payload = [e.to_dict() for e in self.entries]
        canonical = canonicalize({
            "deployment_id": self.deployment_id,
            "issued_at": self.issued_at,
            "entries": entries_payload,
        })
        expected_digest = hashlib.sha256(
            b"HERMES-KEY-MANIFEST-V1\x00" + canonical
        ).digest()

        if expected_digest.hex() != self.manifest_digest:
            result.errors.append(
                "manifest_digest mismatch — entries have been tampered with."
            )
            return result

        result.digest_valid = True

        # Verify signature
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519, ec
            from cryptography.hazmat.primitives import hashes

            pub_key = serialization.load_pem_public_key(
                root_public_key_pem.encode("ascii")
                if isinstance(root_public_key_pem, str)
                else root_public_key_pem
            )
            sig_bytes = bytes.fromhex(self.root_signature)
            digest_bytes = bytes.fromhex(self.manifest_digest)

            if isinstance(pub_key, ed25519.Ed25519PublicKey):
                pub_key.verify(sig_bytes, digest_bytes)
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(sig_bytes, digest_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                result.errors.append(
                    f"Unsupported root key type: {type(pub_key).__name__}"
                )
                return result

            result.signature_valid = True

        except Exception as exc:
            result.errors.append(f"Root signature verification failed: {exc}")
            return result

        result.root_key_id = self.root_key_id
        result.active_keys = [e for e in self.entries if e.status == "active"]
        return result

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def get_key(self, key_id: str) -> ManifestEntry | None:
        """Return the manifest entry for a given key_id, or None."""
        for entry in self.entries:
            if entry.key_id == key_id:
                return entry
        return None

    def active_operational_keys(self) -> list[ManifestEntry]:
        """Return all active Tier 1 operational signing keys."""
        return [
            e for e in self.entries
            if e.tier == "operational" and e.status == "active"
        ]

    def active_checkpoint_keys(self) -> list[ManifestEntry]:
        """Return all active Tier 2 checkpoint/anchor keys."""
        return [
            e for e in self.entries
            if e.tier == "checkpoint" and e.status == "active"
        ]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "deployment_id": self.deployment_id,
            "issued_at": self.issued_at,
            "entries": [e.to_dict() for e in self.entries],
            "manifest_digest": self.manifest_digest,
            "root_signature": self.root_signature,
            "root_key_id": self.root_key_id,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "KeyManifestDocument":
        entries = [ManifestEntry(**e) for e in data.get("entries", [])]
        return cls(
            deployment_id=data["deployment_id"],
            issued_at=data["issued_at"],
            entries=entries,
            manifest_digest=data.get("manifest_digest", ""),
            root_signature=data.get("root_signature", ""),
            root_key_id=data.get("root_key_id", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "KeyManifestDocument":
        return cls.from_dict(json.loads(json_str))


@dataclass
class ManifestVerificationResult:
    """Claim-by-claim result from KeyManifestDocument.verify()."""
    digest_valid: bool = False
    signature_valid: bool = False
    root_key_id: str = ""
    active_keys: list[ManifestEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def fully_valid(self) -> bool:
        return self.digest_valid and self.signature_valid
