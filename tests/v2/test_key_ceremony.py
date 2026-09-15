"""
tests/v2/test_key_ceremony.py — Three-tier key ceremony tests.
"""

import json
import pytest

from hermes.receipts.v2.key_ceremony import run_ceremony, rotate_operational_key, CeremonyResult
from hermes.receipts.v2.key_manifest import KeyManifestDocument
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.builder import ReceiptV2Builder

ROOT_PW = b"root-passphrase-tier0"
OP_PW = b"operational-passphrase-tier1"
CK_PW = b"checkpoint-passphrase-tier2"
DEPLOYMENT_ID = "test-deployment-ceremony"


@pytest.fixture(scope="module")
def ceremony(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ceremony")
    return run_ceremony(
        deployment_id=DEPLOYMENT_ID,
        output_dir=tmp,
        root_passphrase=ROOT_PW,
        operational_passphrase=OP_PW,
        checkpoint_passphrase=CK_PW,
    )


class TestCeremonyResult:
    def test_returns_ceremony_result(self, ceremony):
        assert isinstance(ceremony, CeremonyResult)

    def test_deployment_id_matches(self, ceremony):
        assert ceremony.deployment_id == DEPLOYMENT_ID

    def test_all_key_ids_populated(self, ceremony):
        assert len(ceremony.root_key_id) == 16
        assert len(ceremony.operational_key_id) == 16
        assert len(ceremony.checkpoint_key_id) == 16

    def test_three_distinct_key_ids(self, ceremony):
        ids = {ceremony.root_key_id, ceremony.operational_key_id, ceremony.checkpoint_key_id}
        assert len(ids) == 3

    def test_transcript_has_entries(self, ceremony):
        assert len(ceremony.transcript) > 0
        steps = [e["step"] for e in ceremony.transcript]
        assert "ceremony_start" in steps
        assert "ceremony_complete" in steps


class TestCeremonyFiles:
    def test_all_keystore_files_exist(self, ceremony):
        assert ceremony.paths.root_store.exists()
        assert ceremony.paths.operational_store.exists()
        assert ceremony.paths.checkpoint_store.exists()

    def test_manifest_file_exists(self, ceremony):
        assert ceremony.paths.manifest.exists()

    def test_transcript_file_exists(self, ceremony):
        assert ceremony.paths.transcript.exists()

    def test_transcript_is_valid_json(self, ceremony):
        data = json.loads(ceremony.paths.transcript.read_text())
        assert isinstance(data, list)
        assert len(data) > 0


class TestCeremonyManifest:
    def test_manifest_is_signed(self, ceremony):
        assert ceremony.manifest.root_signature != ""
        assert ceremony.manifest.manifest_digest != ""

    def test_manifest_has_three_entries(self, ceremony):
        assert len(ceremony.manifest.entries) == 3

    def test_manifest_tiers(self, ceremony):
        tiers = {e.tier for e in ceremony.manifest.entries}
        assert tiers == {"offline_root", "operational", "checkpoint"}

    def test_all_entries_active(self, ceremony):
        assert all(e.status == "active" for e in ceremony.manifest.entries)

    def test_manifest_verifies_with_root_key(self, ceremony):
        root_store = KeyStore.open(ceremony.paths.root_store, ROOT_PW)
        root_signer = root_store.load_signer()
        pub_pem = root_signer.public_key_manifest()["public_key_pem"]
        result = ceremony.manifest.verify(pub_pem)
        assert result.fully_valid
        assert result.errors == []

    def test_manifest_round_trip_from_file(self, ceremony):
        doc = KeyManifestDocument.from_json(
            ceremony.paths.manifest.read_text()
        )
        root_store = KeyStore.open(ceremony.paths.root_store, ROOT_PW)
        pub_pem = root_store.load_signer().public_key_manifest()["public_key_pem"]
        assert doc.verify(pub_pem).fully_valid

    def test_manifest_root_key_id_matches_store(self, ceremony):
        root_store = KeyStore.open(ceremony.paths.root_store, ROOT_PW)
        assert ceremony.manifest.root_key_id == root_store.key_id

    def test_idempotency_guard(self, ceremony):
        """Re-running ceremony on existing paths raises FileExistsError."""
        with pytest.raises(FileExistsError):
            run_ceremony(
                deployment_id=DEPLOYMENT_ID,
                output_dir=ceremony.paths.root_store.parent.parent,
                root_passphrase=ROOT_PW,
                operational_passphrase=OP_PW,
                checkpoint_passphrase=CK_PW,
            )


class TestCeremonyIntegrationWithBuilder:
    def test_operational_key_can_build_receipt(self, ceremony):
        op_store = KeyStore.open(ceremony.paths.operational_store, OP_PW)
        signer = op_store.load_signer()
        builder = ReceiptV2Builder(signer)
        receipt = builder.build({"event_type": "phi_scan", "result": "clean"})
        assert receipt.cose_sign1_bytes
        assert receipt.receipt_digest

    def test_receipt_verifies_against_manifest_public_key(self, ceremony):
        from hermes.receipts.v2.verifier import verify_receipt
        op_store = KeyStore.open(ceremony.paths.operational_store, OP_PW)
        signer = op_store.load_signer()
        builder = ReceiptV2Builder(signer)
        receipt = builder.build({"event_type": "phi_scan", "result": "clean"})

        # Verifier uses the public key from the manifest
        op_entry = next(
            e for e in ceremony.manifest.entries if e.tier == "operational"
        )
        result = verify_receipt(receipt.cose_sign1_bytes, op_entry.public_key_pem)
        assert result.signature_valid
        assert not result.errors


class TestKeyRotation:
    def test_rotate_operational_key(self, tmp_path):
        NEW_OP_PW = b"new-operational-passphrase"
        dep_id = "rotation-test-deployment"

        # Initial ceremony
        result = run_ceremony(
            deployment_id=dep_id,
            output_dir=tmp_path,
            root_passphrase=ROOT_PW,
            operational_passphrase=OP_PW,
            checkpoint_passphrase=CK_PW,
        )
        old_op_key_id = result.operational_key_id

        # Rotate
        rotated = rotate_operational_key(
            ceremony_dir=tmp_path,
            deployment_id=dep_id,
            root_passphrase=ROOT_PW,
            old_operational_passphrase=OP_PW,
            new_operational_passphrase=NEW_OP_PW,
        )

        assert rotated.operational_key_id != old_op_key_id

    def test_rotated_manifest_has_two_operational_entries(self, tmp_path):
        NEW_OP_PW = b"new-op-pw-rotate-2"
        dep_id = "rotation-test-2"
        run_ceremony(dep_id, tmp_path, ROOT_PW, OP_PW, CK_PW)
        rotated = rotate_operational_key(tmp_path, dep_id, ROOT_PW, OP_PW, NEW_OP_PW)

        op_entries = [e for e in rotated.manifest.entries if e.tier == "operational"]
        assert len(op_entries) == 2
        statuses = {e.status for e in op_entries}
        assert "rotated" in statuses
        assert "active" in statuses

    def test_rotated_manifest_still_verifies(self, tmp_path):
        NEW_OP_PW = b"new-op-pw-rotate-3"
        dep_id = "rotation-test-3"
        run_ceremony(dep_id, tmp_path, ROOT_PW, OP_PW, CK_PW)
        rotated = rotate_operational_key(tmp_path, dep_id, ROOT_PW, OP_PW, NEW_OP_PW)

        root_store = KeyStore.open(rotated.paths.root_store, ROOT_PW)
        pub_pem = root_store.load_signer().public_key_manifest()["public_key_pem"]
        assert rotated.manifest.verify(pub_pem).fully_valid

    def test_new_operational_key_signs_receipts(self, tmp_path):
        from hermes.receipts.v2.verifier import verify_receipt
        NEW_OP_PW = b"new-op-pw-rotate-4"
        dep_id = "rotation-test-4"
        run_ceremony(dep_id, tmp_path, ROOT_PW, OP_PW, CK_PW)
        rotated = rotate_operational_key(tmp_path, dep_id, ROOT_PW, OP_PW, NEW_OP_PW)

        new_op_store = KeyStore.open(rotated.paths.operational_store, NEW_OP_PW)
        signer = new_op_store.load_signer()
        builder = ReceiptV2Builder(signer)
        receipt = builder.build({"event": "post_rotation_scan"})

        # Verify against new key in manifest
        new_op_entry = next(
            e for e in rotated.manifest.entries
            if e.tier == "operational" and e.status == "active"
        )
        result = verify_receipt(receipt.cose_sign1_bytes, new_op_entry.public_key_pem)
        assert result.signature_valid
