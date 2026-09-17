"""
tests/v2/test_verifier.py — Public verifier tests.
"""

import json
import os
import tempfile
import pytest

from hermes.receipts.v2.builder import ReceiptV2Builder
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519, SoftwareSignerES256
from hermes.receipts.v2.verifier import VerificationResult, verify_receipt


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ed25519_signer():
    return SoftwareSignerEd25519.generate()


@pytest.fixture(scope="module")
def es256_signer():
    return SoftwareSignerES256.generate()


@pytest.fixture(scope="module")
def ed25519_builder(ed25519_signer):
    return ReceiptV2Builder(ed25519_signer)


@pytest.fixture(scope="module")
def es256_builder(es256_signer):
    return ReceiptV2Builder(es256_signer)


SAMPLE_PAYLOAD = {
    "event_type": "phi_scan",
    "scan_id": "test-001",
    "zero_phi_egress": True,
}


def build_receipt_with_embedded_digest(builder, payload):
    """Build a receipt normally — receipt_digest now lives in the COSE
    unprotected header, not in the payload, so no special embedding needed."""
    return builder.build(payload)


# ---------------------------------------------------------------------------
# Basic verification tests
# ---------------------------------------------------------------------------

class TestVerifyValid:
    def test_valid_ed25519_receipt(self, ed25519_signer, ed25519_builder):
        receipt = build_receipt_with_embedded_digest(ed25519_builder, SAMPLE_PAYLOAD)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.signature_valid
        assert result.receipt_digest_valid
        assert result.fully_valid
        assert result.errors == []

    def test_valid_es256_receipt(self, es256_signer, es256_builder):
        receipt = build_receipt_with_embedded_digest(es256_builder, SAMPLE_PAYLOAD)
        pub_pem = es256_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.signature_valid
        assert result.receipt_digest_valid
        assert result.fully_valid

    def test_algorithm_field_ed25519(self, ed25519_signer, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.algorithm == "EdDSA"

    def test_algorithm_field_es256(self, es256_signer, es256_builder):
        receipt = es256_builder.build(SAMPLE_PAYLOAD)
        pub_pem = es256_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.algorithm == "ES256"

    def test_signer_key_id_matches(self, ed25519_signer, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.signer_key_id == ed25519_signer.key_id.hex()

    def test_claims_contain_payload(self, ed25519_signer, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        for key in SAMPLE_PAYLOAD:
            assert key in result.claims

    def test_chain_link_none_for_first_receipt(self, ed25519_signer, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, pub_pem)
        assert result.chain_link_valid is None  # no prev_receipt_digest

    def test_chain_link_present_for_chained_receipt(self, ed25519_signer, ed25519_builder):
        r1 = ed25519_builder.build({"seq": 1})
        r2 = ed25519_builder.build({"seq": 2}, prev_receipt_digest=r1.receipt_digest)
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(r2.cose_sign1_bytes, pub_pem)
        assert result.chain_link_valid is True


class TestTampering:
    def test_tampered_payload_fails(self, ed25519_signer, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        # Flip a byte in the middle of the COSE envelope (payload region)
        raw = bytearray(receipt.cose_sign1_bytes)
        raw[len(raw) // 2] ^= 0xFF
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(bytes(raw), pub_pem)
        assert not result.signature_valid or result.errors

    def test_tampered_signature_fails(self, ed25519_signer, ed25519_builder):
        import cbor2 as _cbor2
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        decoded = _cbor2.loads(receipt.cose_sign1_bytes)
        arr = list(decoded.value)
        # Corrupt the signature (last element)
        sig = bytearray(arr[3])
        sig[0] ^= 0xFF
        arr[3] = bytes(sig)
        tampered = _cbor2.dumps(_cbor2.CBORTag(18, arr))
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(tampered, pub_pem)
        assert not result.signature_valid
        assert any("FAILED" in e for e in result.errors)

    def test_wrong_public_key_fails(self, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        # Use a different signer's public key
        wrong_signer = SoftwareSignerEd25519.generate()
        wrong_pem = wrong_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(receipt.cose_sign1_bytes, wrong_pem)
        assert not result.signature_valid
        assert result.errors


class TestMalformedInput:
    def test_empty_bytes(self, ed25519_signer):
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(b"", pub_pem)
        assert result.errors
        assert not result.signature_valid

    def test_random_bytes(self, ed25519_signer):
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(b"\xff\xfe\xfd" * 100, pub_pem)
        assert result.errors
        assert not result.signature_valid

    def test_plain_json_not_cose(self, ed25519_signer):
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        result = verify_receipt(json.dumps({"hello": "world"}).encode(), pub_pem)
        assert result.errors

    def test_bad_public_key_pem(self, ed25519_builder):
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        result = verify_receipt(receipt.cose_sign1_bytes, "not a valid pem")
        assert result.errors
        assert not result.signature_valid

    def test_never_raises_exception(self, ed25519_signer):
        """verify_receipt must return VerificationResult, never raise."""
        pub_pem = ed25519_signer.public_key_manifest()["public_key_pem"]
        for bad_input in [b"", b"\x00" * 10, b"not cbor", b"\xff" * 50]:
            result = verify_receipt(bad_input, pub_pem)
            assert isinstance(result, VerificationResult)


class TestNoV1Imports:
    def test_verifier_has_no_v1_imports(self):
        import inspect
        import hermes.receipts.v2.verifier as verifier_mod
        src = inspect.getsource(verifier_mod)
        assert "hermes.attestation" not in src
        assert "from hermes.attestation" not in src

    def test_cli_has_no_v1_imports(self):
        import inspect
        import hermes.receipts.v2.cli as cli_mod
        src = inspect.getsource(cli_mod)
        assert "hermes.attestation" not in src
        assert "from hermes.attestation" not in src


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def _write_temp(self, content: bytes | str, suffix: str) -> str:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        if isinstance(content, str):
            f.write(content.encode("ascii"))
        else:
            f.write(content)
        f.close()
        return f.name

    def test_cli_exit_0_on_valid(self, ed25519_signer, ed25519_builder):
        from hermes.receipts.v2.cli import main
        receipt = build_receipt_with_embedded_digest(ed25519_builder, SAMPLE_PAYLOAD)
        cose_path = self._write_temp(receipt.cose_sign1_bytes, ".cose")
        key_path = self._write_temp(
            ed25519_signer.public_key_manifest()["public_key_pem"], ".pem"
        )
        try:
            code = main(["receipt", cose_path, "--public-key", key_path])
            assert code == 0
        finally:
            os.unlink(cose_path)
            os.unlink(key_path)

    def test_cli_exit_1_on_wrong_key(self, ed25519_builder):
        from hermes.receipts.v2.cli import main
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        wrong = SoftwareSignerEd25519.generate()
        cose_path = self._write_temp(receipt.cose_sign1_bytes, ".cose")
        key_path = self._write_temp(
            wrong.public_key_manifest()["public_key_pem"], ".pem"
        )
        try:
            code = main(["receipt", cose_path, "--public-key", key_path])
            assert code == 1
        finally:
            os.unlink(cose_path)
            os.unlink(key_path)

    def test_cli_exit_2_on_missing_file(self, ed25519_signer):
        from hermes.receipts.v2.cli import main
        key_path = self._write_temp(
            ed25519_signer.public_key_manifest()["public_key_pem"], ".pem"
        )
        try:
            code = main(["receipt", "/nonexistent.cose", "--public-key", key_path])
            assert code == 2
        finally:
            os.unlink(key_path)

    def test_cli_outputs_json(self, ed25519_signer, ed25519_builder, capsys):
        from hermes.receipts.v2.cli import main
        receipt = ed25519_builder.build(SAMPLE_PAYLOAD)
        cose_path = self._write_temp(receipt.cose_sign1_bytes, ".cose")
        key_path = self._write_temp(
            ed25519_signer.public_key_manifest()["public_key_pem"], ".pem"
        )
        try:
            main(["receipt", cose_path, "--public-key", key_path])
            captured = capsys.readouterr()
            parsed = json.loads(captured.out)
            assert "signature_valid" in parsed
            assert "receipt_digest_valid" in parsed
            assert "errors" in parsed
        finally:
            os.unlink(cose_path)
            os.unlink(key_path)
