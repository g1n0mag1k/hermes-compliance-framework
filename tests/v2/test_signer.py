"""
tests/v2/test_signer.py — Signer protocol and software key implementation tests.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from hermes.receipts.v2.signer import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    Signer,
)
from hermes.receipts.v2.software_signer import (
    SoftwareSignerEd25519,
    SoftwareSignerES256,
    SoftwareSigner,
)


class TestSoftwareSignerEd25519:
    def test_generate_returns_instance(self):
        s = SoftwareSignerEd25519.generate()
        assert isinstance(s, SoftwareSignerEd25519)

    def test_satisfies_signer_protocol(self):
        s = SoftwareSignerEd25519.generate()
        assert isinstance(s, Signer)

    def test_key_id_is_8_bytes(self):
        s = SoftwareSignerEd25519.generate()
        assert isinstance(s.key_id, bytes)
        assert len(s.key_id) == 8

    def test_key_id_stable_across_calls(self):
        s = SoftwareSignerEd25519.generate()
        assert s.key_id == s.key_id

    def test_different_keys_different_ids(self):
        a = SoftwareSignerEd25519.generate()
        b = SoftwareSignerEd25519.generate()
        assert a.key_id != b.key_id

    def test_cose_algorithm(self):
        s = SoftwareSignerEd25519.generate()
        assert s.cose_algorithm == COSE_ALG_EDDSA  # -8

    def test_sign_returns_bytes(self):
        s = SoftwareSignerEd25519.generate()
        sig = s.sign_cose_sig_structure(b"test message")
        assert isinstance(sig, bytes)
        assert len(sig) == 64  # Ed25519 signatures are always 64 bytes

    def test_sign_deterministic(self):
        """Ed25519 is deterministic — same message, same signature."""
        s = SoftwareSignerEd25519.generate()
        msg = b"same message every time"
        sig1 = s.sign_cose_sig_structure(msg)
        sig2 = s.sign_cose_sig_structure(msg)
        assert sig1 == sig2

    def test_sign_verifies_correctly(self):
        s = SoftwareSignerEd25519.generate()
        msg = b"audit receipt payload bytes"
        sig = s.sign_cose_sig_structure(msg)
        pub_pem = s.public_key_manifest()["public_key_pem"].encode("ascii")
        pub_key = serialization.load_pem_public_key(pub_pem)
        # Ed25519 verify — raises if invalid
        pub_key.verify(sig, msg)

    def test_sign_empty_raises(self):
        s = SoftwareSignerEd25519.generate()
        with pytest.raises(ValueError, match="empty"):
            s.sign_cose_sig_structure(b"")

    def test_public_key_manifest_fields(self):
        s = SoftwareSignerEd25519.generate()
        m = s.public_key_manifest()
        assert m["algorithm"] == "EdDSA"
        assert m["status"] == "active"
        assert m["purpose"] == "receipt-signing"
        assert m["valid_until"] is None
        assert m["key_id"] == s.key_id.hex()
        assert "BEGIN PUBLIC KEY" in m["public_key_pem"]
        assert len(m["public_key_spki_sha256"]) == 64

    def test_round_trip_pem(self):
        s = SoftwareSignerEd25519.generate()
        pem = s.private_key_pem()
        s2 = SoftwareSignerEd25519.load_from_pem(pem)
        assert s.key_id == s2.key_id

    def test_load_from_pem_wrong_type_raises(self):
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pem = ec_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(TypeError):
            SoftwareSignerEd25519.load_from_pem(ec_pem)


class TestSoftwareSignerES256:
    def test_generate_returns_instance(self):
        s = SoftwareSignerES256.generate()
        assert isinstance(s, SoftwareSignerES256)

    def test_satisfies_signer_protocol(self):
        s = SoftwareSignerES256.generate()
        assert isinstance(s, Signer)

    def test_cose_algorithm(self):
        s = SoftwareSignerES256.generate()
        assert s.cose_algorithm == COSE_ALG_ES256  # -7

    def test_key_id_is_8_bytes(self):
        s = SoftwareSignerES256.generate()
        assert isinstance(s.key_id, bytes)
        assert len(s.key_id) == 8

    def test_sign_returns_bytes(self):
        s = SoftwareSignerES256.generate()
        sig = s.sign_cose_sig_structure(b"test message")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_sign_probabilistic_both_valid(self):
        """ECDSA is probabilistic — two signatures differ but both verify."""
        s = SoftwareSignerES256.generate()
        msg = b"same message every time"
        sig1 = s.sign_cose_sig_structure(msg)
        sig2 = s.sign_cose_sig_structure(msg)
        # They may be different (probabilistic)
        # Both must verify against the public key
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import hashes as _h, serialization as _s
        pub_pem = s.public_key_manifest()["public_key_pem"].encode("ascii")
        pub_key = _s.load_pem_public_key(pub_pem)
        pub_key.verify(sig1, msg, _ec.ECDSA(_h.SHA256()))
        pub_key.verify(sig2, msg, _ec.ECDSA(_h.SHA256()))

    def test_sign_empty_raises(self):
        s = SoftwareSignerES256.generate()
        with pytest.raises(ValueError, match="empty"):
            s.sign_cose_sig_structure(b"")

    def test_public_key_manifest_fields(self):
        s = SoftwareSignerES256.generate()
        m = s.public_key_manifest()
        assert m["algorithm"] == "ES256"
        assert m["status"] == "active"
        assert m["purpose"] == "receipt-signing"

    def test_wrong_curve_raises(self):
        p384_key = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(TypeError, match="P-256"):
            SoftwareSignerES256(p384_key)

    def test_round_trip_pem(self):
        s = SoftwareSignerES256.generate()
        pem = s.private_key_pem()
        s2 = SoftwareSignerES256.load_from_pem(pem)
        assert s.key_id == s2.key_id


class TestSoftwareSignerAlias:
    def test_default_alias_is_ed25519(self):
        assert SoftwareSigner is SoftwareSignerEd25519


class TestSoftwareSignerExtended:
    """Tests for valid_from/valid_until/status params and verify() method.
    Pulled from Cursor's Prompt 2 output and merged here."""

    def test_verify_method_succeeds(self):
        s = SoftwareSignerEd25519.generate()
        msg = b"verify-method-test"
        sig = s.sign_cose_sig_structure(msg)
        s.verify(msg, sig)  # must not raise

    def test_verify_method_fails_on_tamper(self):
        from cryptography.exceptions import InvalidSignature
        s = SoftwareSignerEd25519.generate()
        msg = b"verify-method-test"
        sig = bytearray(s.sign_cose_sig_structure(msg))
        sig[0] ^= 0xFF
        with pytest.raises(InvalidSignature):
            s.verify(msg, bytes(sig))

    def test_valid_from_param(self):
        from datetime import datetime, timezone
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        s = SoftwareSignerEd25519(
            __import__('cryptography.hazmat.primitives.asymmetric.ed25519', fromlist=['Ed25519PrivateKey']).Ed25519PrivateKey.generate(),
            valid_from=ts,
        )
        assert "2025-01-01" in s.public_key_manifest()["valid_from"]

    def test_valid_until_param(self):
        from datetime import datetime, timezone
        ts = datetime(2030, 12, 31, tzinfo=timezone.utc)
        s = SoftwareSignerEd25519(
            __import__('cryptography.hazmat.primitives.asymmetric.ed25519', fromlist=['Ed25519PrivateKey']).Ed25519PrivateKey.generate(),
            valid_until=ts,
        )
        assert "2030-12-31" in s.public_key_manifest()["valid_until"]

    def test_status_param(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        s = SoftwareSignerEd25519(Ed25519PrivateKey.generate(), status="rotated")
        assert s.public_key_manifest()["status"] == "rotated"

    def test_load_from_pem_rejects_rsa(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(TypeError, match="Ed25519"):
            SoftwareSignerEd25519.load_from_pem(pem)

    def test_cose_alg_eddsa_alias(self):
        from hermes.receipts.v2.signer import COSE_ALG_EdDSA, COSE_ALG_EDDSA
        assert COSE_ALG_EdDSA == COSE_ALG_EDDSA == -8
