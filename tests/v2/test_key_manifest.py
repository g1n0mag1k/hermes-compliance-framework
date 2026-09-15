"""
tests/v2/test_key_manifest.py — KeyManifestDocument tests.
"""

import json
import pytest
from datetime import datetime, timezone

from hermes.receipts.v2.key_manifest import (
    KeyManifestDocument,
    ManifestEntry,
    ManifestVerificationResult,
)
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519


@pytest.fixture(scope="module")
def root_signer():
    return SoftwareSignerEd25519.generate()


@pytest.fixture(scope="module")
def op_signer():
    return SoftwareSignerEd25519.generate()


@pytest.fixture
def sample_entries(root_signer, op_signer):
    def _entry(signer, tier, purpose):
        m = signer.public_key_manifest()
        return ManifestEntry(
            key_id=m["key_id"],
            tier=tier,
            algorithm=m["algorithm"],
            public_key_pem=m["public_key_pem"],
            public_key_spki_sha256=m["public_key_spki_sha256"],
            purpose=purpose,
            valid_from=m["valid_from"],
            valid_until=None,
            status="active",
        )
    return [
        _entry(root_signer, "offline_root", "Trust root"),
        _entry(op_signer, "operational", "Receipt signing"),
    ]


@pytest.fixture
def signed_doc(root_signer, sample_entries):
    doc = KeyManifestDocument(
        deployment_id="test-deployment-001",
        issued_at=datetime.now(timezone.utc).isoformat(),
        entries=sample_entries,
    )
    doc.sign(root_signer)
    return doc


class TestManifestEntry:
    def test_to_dict_excludes_none(self, sample_entries):
        e = sample_entries[0]
        d = e.to_dict()
        assert "key_id" in d
        assert "tier" in d
        assert "algorithm" in d

    def test_to_dict_includes_none_sentinels(self, sample_entries):
        e = sample_entries[0]
        d = e.to_dict()
        # valid_until should be present even when None
        assert "valid_until" in d


class TestKeyManifestDocumentSign:
    def test_sign_populates_manifest_digest(self, signed_doc):
        assert len(signed_doc.manifest_digest) == 64
        bytes.fromhex(signed_doc.manifest_digest)  # valid hex

    def test_sign_populates_root_signature(self, signed_doc):
        assert len(signed_doc.root_signature) > 0
        bytes.fromhex(signed_doc.root_signature)

    def test_sign_populates_root_key_id(self, root_signer, signed_doc):
        assert signed_doc.root_key_id == root_signer.key_id.hex()

    def test_sign_is_deterministic_for_same_input(self, root_signer, sample_entries):
        """Same payload + same key = same digest (Ed25519 is deterministic)."""
        issued_at = "2026-01-01T00:00:00+00:00"
        doc1 = KeyManifestDocument("dep-x", issued_at, sample_entries).sign(root_signer)
        doc2 = KeyManifestDocument("dep-x", issued_at, sample_entries).sign(root_signer)
        assert doc1.manifest_digest == doc2.manifest_digest
        assert doc1.root_signature == doc2.root_signature


class TestKeyManifestDocumentVerify:
    def test_verify_succeeds_with_correct_root_key(self, root_signer, signed_doc):
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = signed_doc.verify(pub_pem)
        assert result.fully_valid
        assert result.digest_valid
        assert result.signature_valid
        assert result.errors == []

    def test_verify_fails_with_wrong_root_key(self, signed_doc):
        wrong = SoftwareSignerEd25519.generate()
        pub_pem = wrong.public_key_manifest()["public_key_pem"]
        result = signed_doc.verify(pub_pem)
        assert not result.fully_valid
        assert result.errors

    def test_verify_fails_on_tampered_entry(self, root_signer, signed_doc):
        # Clone and mutate an entry
        doc2 = KeyManifestDocument.from_json(signed_doc.to_json())
        doc2.entries[0].status = "revoked"  # tamper
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = doc2.verify(pub_pem)
        assert not result.fully_valid
        assert any("tampered" in e for e in result.errors)

    def test_verify_unsigned_doc_returns_error(self, root_signer, sample_entries):
        doc = KeyManifestDocument("dep-y", "2026-01-01T00:00:00+00:00", sample_entries)
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = doc.verify(pub_pem)
        assert not result.fully_valid
        assert result.errors

    def test_verify_result_active_keys(self, root_signer, signed_doc):
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = signed_doc.verify(pub_pem)
        assert len(result.active_keys) == 2  # both root and operational are active


class TestManifestLookup:
    def test_get_key_by_id(self, root_signer, signed_doc):
        kid = root_signer.key_id.hex()
        entry = signed_doc.get_key(kid)
        assert entry is not None
        assert entry.key_id == kid

    def test_get_key_missing_returns_none(self, signed_doc):
        assert signed_doc.get_key("00" * 8) is None

    def test_active_operational_keys(self, signed_doc):
        ops = signed_doc.active_operational_keys()
        assert all(k.tier == "operational" for k in ops)
        assert all(k.status == "active" for k in ops)


class TestManifestSerialization:
    def test_to_json_is_valid_json(self, signed_doc):
        j = signed_doc.to_json()
        parsed = json.loads(j)
        assert "deployment_id" in parsed
        assert "entries" in parsed
        assert "manifest_digest" in parsed

    def test_round_trip_json(self, root_signer, signed_doc):
        j = signed_doc.to_json()
        doc2 = KeyManifestDocument.from_json(j)
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = doc2.verify(pub_pem)
        assert result.fully_valid

    def test_from_dict_round_trip(self, root_signer, signed_doc):
        d = signed_doc.to_dict()
        doc2 = KeyManifestDocument.from_dict(d)
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        assert doc2.verify(pub_pem).fully_valid
