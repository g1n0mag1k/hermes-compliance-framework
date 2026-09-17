"""
hermes/receipts/v2/verifier.py — Hermes V2 public receipt verifier.

Verifies a COSE_Sign1 receipt using ONLY public material:
  - A PEM-encoded public key (from the published key manifest)
  - The raw COSE_Sign1 bytes

No private key, no Hermes database, no signing code is required.
This module has ZERO imports from hermes/attestation.py or any V1 module.

The verifier produces claim-by-claim output in a VerificationResult
dataclass — never a single pass/fail flag. Each claim is independently
verified and independently reportable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from hermes.receipts.v2.canonical import canonicalize, receipt_digest_hex
from hermes.receipts.v2.signer import COSE_ALG_EDDSA, COSE_ALG_ES256

# COSE header labels (RFC 8152)
_COSE_SIGN1_TAG = 18
_COSE_CONTEXT = "Signature1"  # RFC 8152 §4.4: text string, not bytes
_COSE_ALG_LABEL = 1
_COSE_KID_LABEL = 4
_COSE_CONTENT_TYPE_LABEL = 3
_HERMES_PROFILE_LABEL = -70000

REQUIRED_CONTENT_TYPE = "application/vnd.hermes.receipt-v2+cose"
REQUIRED_PROFILE = "hermes-receipt-v2"
SUPPORTED_ALGORITHMS = {COSE_ALG_ES256, COSE_ALG_EDDSA}  # -7, -8
_UHDR_RECEIPT_DIGEST = -70001  # unprotected header: hex receipt_digest


@dataclass
class VerificationResult:
    """
    Claim-by-claim verification output.

    A receipt may be historically valid (signature_valid=True,
    receipt_digest_valid=True) but still superseded in the broader chain.
    Always obtain a fresh checkpoint to determine current applicability.
    """
    # Core cryptographic claims
    signature_valid: bool = False
    signer_key_id: str = ""        # hex key_id extracted from KID header
    algorithm: str = ""             # "ES256" or "EdDSA"

    # Payload integrity
    receipt_digest_valid: bool = False

    # Chain linkage (None when no prev_receipt_digest was present)
    chain_link_valid: Optional[bool] = None

    # Metadata
    issued_at: str = ""
    claims: dict = field(default_factory=dict)

    # Diagnostics
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def fully_valid(self) -> bool:
        """True only when signature AND receipt_digest are both valid."""
        return self.signature_valid and self.receipt_digest_valid


def verify_receipt(
    cose_sign1_bytes: bytes,
    public_key_pem: str,
) -> VerificationResult:
    """
    Verify a Hermes V2 COSE_Sign1 receipt.

    Args:
        cose_sign1_bytes:  Raw COSE_Sign1 envelope bytes.
        public_key_pem:    PEM-encoded public key from the published key manifest.

    Returns:
        VerificationResult with all claims populated.
        Never raises — errors are captured in result.errors.
    """
    result = VerificationResult()

    # --- Step 1: Deserialize COSE_Sign1 envelope ---
    try:
        outer = cbor2.loads(cose_sign1_bytes)
    except Exception as exc:
        result.errors.append(f"CBOR decode failed: {exc}")
        return result

    if not isinstance(outer, cbor2.CBORTag):
        result.errors.append(
            f"Expected CBOR tag, got {type(outer).__name__}. "
            "Bytes may not be a COSE_Sign1 envelope."
        )
        return result

    if outer.tag != _COSE_SIGN1_TAG:
        result.errors.append(
            f"Expected COSE_Sign1 tag (18), got tag {outer.tag}."
        )
        return result

    arr = outer.value
    if not isinstance(arr, (list, tuple)) or len(arr) != 4:
        result.errors.append(
            f"COSE_Sign1 must be a 4-element CBOR array, got {len(arr) if isinstance(arr, (list, tuple)) else type(arr).__name__}."
        )
        return result

    phdr_bytes, uhdr_raw, payload_bytes, signature = arr

    # Decode unprotected headers (cbor2 returns frozendict for CBOR maps)
    try:
        uhdr = dict(uhdr_raw) if uhdr_raw else {}
    except Exception:
        uhdr = {}

    # --- Step 2: Decode protected headers ---
    try:
        phdr = cbor2.loads(phdr_bytes)
    except Exception as exc:
        result.errors.append(f"Failed to decode protected headers: {exc}")
        return result

    # Extract algorithm
    alg = phdr.get(_COSE_ALG_LABEL)
    if alg is None:
        result.errors.append("Protected headers missing Algorithm (label 1).")
    elif alg not in SUPPORTED_ALGORITHMS:
        result.errors.append(
            f"Unsupported algorithm {alg}. Supported: {SUPPORTED_ALGORITHMS}."
        )
    else:
        result.algorithm = "EdDSA" if alg == COSE_ALG_EDDSA else "ES256"

    # Extract KID
    kid = phdr.get(_COSE_KID_LABEL)
    if kid is None:
        result.errors.append("Protected headers missing KID (label 4).")
    else:
        result.signer_key_id = kid.hex() if isinstance(kid, bytes) else str(kid)

    # Validate content-type
    ct = phdr.get(_COSE_CONTENT_TYPE_LABEL)
    if ct != REQUIRED_CONTENT_TYPE:
        result.warnings.append(
            f"content_type is {ct!r}, expected {REQUIRED_CONTENT_TYPE!r}."
        )

    # Validate profile
    profile = phdr.get(_HERMES_PROFILE_LABEL)
    if profile != REQUIRED_PROFILE:
        result.warnings.append(
            f"profile header is {profile!r}, expected {REQUIRED_PROFILE!r}."
        )

    if result.errors:
        return result

    # --- Step 3: Reconstruct COSE Sig_Structure ---
    # Sig_Structure = ["Signature1", protected_header_bytes, b"", payload]
    try:
        sig_structure = cbor2.dumps([
            _COSE_CONTEXT,
            phdr_bytes,
            b"",           # external AAD — Hermes V2 uses empty
            payload_bytes,
        ])
    except Exception as exc:
        result.errors.append(f"Failed to build Sig_Structure: {exc}")
        return result

    # --- Step 4: Load public key and verify signature ---
    try:
        pub_key = serialization.load_pem_public_key(
            public_key_pem.encode("ascii") if isinstance(public_key_pem, str)
            else public_key_pem
        )
    except Exception as exc:
        result.errors.append(f"Failed to load public key: {exc}")
        return result

    try:
        if isinstance(pub_key, ed25519.Ed25519PublicKey):
            if alg != COSE_ALG_EDDSA:
                result.errors.append(
                    "Public key is Ed25519 but algorithm header says ES256."
                )
                return result
            pub_key.verify(signature, sig_structure)
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            if alg != COSE_ALG_ES256:
                result.errors.append(
                    "Public key is EC but algorithm header says EdDSA."
                )
                return result
            pub_key.verify(signature, sig_structure, ec.ECDSA(hashes.SHA256()))
        else:
            result.errors.append(
                f"Unsupported public key type: {type(pub_key).__name__}."
            )
            return result

        result.signature_valid = True

    except InvalidSignature:
        result.errors.append(
            "Signature verification FAILED — receipt may be tampered or key mismatch."
        )
        return result
    except Exception as exc:
        result.errors.append(f"Signature verification error: {exc}")
        return result

    # --- Step 5: Parse and validate payload ---
    try:
        payload_dict = json.loads(payload_bytes)
    except Exception as exc:
        result.errors.append(f"Payload is not valid JSON: {exc}")
        return result

    result.claims = payload_dict
    result.issued_at = payload_dict.get("issued_at", "")

    # --- Step 6: Verify receipt_digest ---
    # The builder stores receipt_digest in the COSE unprotected header
    # (label -70001) because the digest is computed over the payload and
    # cannot be embedded inside it (circular).  Re-derive from the
    # canonical payload bytes we already have.
    try:
        recomputed = receipt_digest_hex(payload_dict)
        stored = uhdr.get(_UHDR_RECEIPT_DIGEST)
        if stored is None:
            result.warnings.append(
                "Unprotected header missing receipt_digest (label -70001) — cannot verify digest claim."
            )
        elif recomputed == stored:
            result.receipt_digest_valid = True
        else:
            result.errors.append(
                f"receipt_digest mismatch — stored={stored[:16]}…, "
                f"recomputed={recomputed[:16]}…"
            )
    except Exception as exc:
        result.errors.append(f"receipt_digest verification error: {exc}")

    # --- Step 7: Check chain linkage presence ---
    prev = payload_dict.get("_hermes_prev_receipt_digest")
    if prev is not None:
        result.chain_link_valid = True
        result.warnings.append(
            "Chain link (_hermes_prev_receipt_digest) is present. "
            "Full chain traversal requires the prior receipt."
        )
    # else: chain_link_valid stays None (chain head / no link present)

    return result
