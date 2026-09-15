"""Tests for Hermes Relay V2 Signer protocol and SoftwareSigner."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes.receipts.v2.software_signer import COSE_ALG_EdDSA, SoftwareSigner


REQUIRED_MANIFEST_FIELDS = {
    "key_id",
    "algorithm",
    "public_key_spki_sha256",
    "public_key_pem",
    "valid_from",
    "valid_until",
    "status",
    "purpose",
}


def test_generated_key_signs_and_verifies():
    signer = SoftwareSigner.generate()
    message = b"cose-sig-structure-payload"
    signature = signer.sign_cose_sig_structure(message)
    assert isinstance(signature, bytes)
    assert len(signature) == 64
    signer.verify(message, signature)


def test_key_id_is_stable_across_calls():
    signer = SoftwareSigner.generate()
    first = signer.key_id
    second = signer.key_id
    assert first == second
    assert isinstance(first, bytes)
    assert len(first) == 8
    assert signer.public_key_manifest()["key_id"] == first.hex()


def test_signing_twice_produces_valid_signatures():
    """Ed25519 is deterministic — both signatures must verify (may be equal)."""
    signer = SoftwareSigner.generate()
    message = b"same-message-twice"
    sig1 = signer.sign_cose_sig_structure(message)
    sig2 = signer.sign_cose_sig_structure(message)
    signer.verify(message, sig1)
    signer.verify(message, sig2)
    # Deterministic Ed25519: signatures are equal; still both valid.
    assert sig1 == sig2


def test_public_key_manifest_contains_all_required_fields():
    signer = SoftwareSigner.generate()
    manifest = signer.public_key_manifest()
    assert set(manifest.keys()) == REQUIRED_MANIFEST_FIELDS
    assert manifest["algorithm"] == "EdDSA"
    assert manifest["status"] == "active"
    assert manifest["purpose"] == "receipt-signing"
    assert manifest["valid_until"] is None
    assert isinstance(manifest["valid_from"], str)
    assert "BEGIN PUBLIC KEY" in manifest["public_key_pem"]
    assert len(bytes.fromhex(manifest["key_id"])) == 8
    assert len(bytes.fromhex(manifest["public_key_spki_sha256"])) == 32
    assert signer.cose_algorithm == COSE_ALG_EdDSA
    assert signer.cose_algorithm == -8


def test_sign_cose_sig_structure_rejects_empty_bytes():
    signer = SoftwareSigner.generate()
    with pytest.raises(ValueError, match="non-empty"):
        signer.sign_cose_sig_structure(b"")


def test_load_from_pem_roundtrip():
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    loaded = SoftwareSigner.load_from_pem(private_pem)
    message = b"roundtrip-message"
    signature = loaded.sign_cose_sig_structure(message)
    private_key.public_key().verify(signature, message)
    # Same PEM loads to the same key_id.
    assert SoftwareSigner.load_from_pem(private_pem).key_id == loaded.key_id


def test_tampered_signature_fails_verification():
    signer = SoftwareSigner.generate()
    message = b"integrity-check"
    signature = bytearray(signer.sign_cose_sig_structure(message))
    signature[0] ^= 0xFF
    with pytest.raises(InvalidSignature):
        signer.verify(message, bytes(signature))


def test_load_from_pem_rejects_non_ed25519():
    # Generate a throwaway RSA key would be heavy; use Ed25519 but assert type
    # guard by constructing via raw wrong type path — generate RSA via crypto.
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(TypeError, match="Ed25519"):
        SoftwareSigner.load_from_pem(pem)
