"""
hermes/receipts/v2/key_ceremony.py — Three-tier key ceremony for Hermes V2.

Initializes a deployment's full key hierarchy:

  Tier 0 — offline_root:   Customer-controlled, used only to sign the manifest.
                           Should be generated on an air-gapped machine and stored
                           offline (hardware token, printed backup, etc.).

  Tier 1 — operational:   Non-exportable per-deployment receipt signing key.
                           Lives in an encrypted KeyStore on the server. Used for
                           every COSE_Sign1 receipt. Rotated on schedule.

  Tier 2 — checkpoint:    Separately controlled key for signing Merkle checkpoints.
                           Distinct from the operational key so a compromise of one
                           does not compromise the other.

The ceremony produces:
  - Three encrypted KeyStore files (one per tier)
  - A signed KeyManifestDocument containing all three public keys
  - A ceremony transcript (JSON) for audit purposes

Offline root usage:
  The Tier 0 root key should only be brought online to:
    1. Sign a new manifest after key rotation or revocation
    2. Initialize a new deployment

After ceremony completion, the root KeyStore passphrase should be stored
separately from the operational and checkpoint passphrases.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from hermes.receipts.v2.key_manifest import (
    KeyManifestDocument,
    ManifestEntry,
)
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.signer import derive_key_id, spki_sha256
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519

from cryptography.hazmat.primitives import serialization


@dataclass
class CeremonyPaths:
    """Filesystem paths for a ceremony's output artifacts."""
    root_store: Path
    operational_store: Path
    checkpoint_store: Path
    manifest: Path
    transcript: Path

    @classmethod
    def under(cls, base_dir: str | Path, deployment_id: str) -> "CeremonyPaths":
        base = Path(base_dir) / deployment_id
        base.mkdir(parents=True, exist_ok=True)
        return cls(
            root_store=base / "root.keystore",
            operational_store=base / "operational.keystore",
            checkpoint_store=base / "checkpoint.keystore",
            manifest=base / "key_manifest.json",
            transcript=base / "ceremony_transcript.json",
        )


@dataclass
class CeremonyResult:
    """
    Output of a completed key ceremony.

    manifest:          Signed KeyManifestDocument — publish this to verifiers.
    paths:             Filesystem locations of all artifacts.
    deployment_id:     Deployment identifier used across all artifacts.
    root_key_id:       Tier 0 key_id (hex) — pin this in verifier config.
    operational_key_id: Tier 1 key_id (hex) — used on every receipt.
    checkpoint_key_id:  Tier 2 key_id (hex) — used on every checkpoint.
    transcript:        Full audit log of the ceremony steps.
    """
    manifest: KeyManifestDocument
    paths: CeremonyPaths
    deployment_id: str
    root_key_id: str
    operational_key_id: str
    checkpoint_key_id: str
    transcript: list[dict] = field(default_factory=list)


def run_ceremony(
    deployment_id: str,
    output_dir: str | Path,
    root_passphrase: bytes,
    operational_passphrase: bytes,
    checkpoint_passphrase: bytes,
    algorithm: str = "EdDSA",
    log: Callable[[str], None] | None = None,
) -> CeremonyResult:
    """
    Execute the full three-tier key ceremony.

    Creates three KeyStore files plus a signed manifest.  Idempotent in the
    sense that it will raise FileExistsError if any keystore already exists,
    protecting against accidental re-generation.

    Args:
        deployment_id:           Unique identifier for this Hermes installation.
        output_dir:              Directory to write all artifacts under.
        root_passphrase:         Tier 0 offline root key encryption passphrase.
        operational_passphrase:  Tier 1 operational key encryption passphrase.
        checkpoint_passphrase:   Tier 2 checkpoint key encryption passphrase.
        algorithm:               "EdDSA" (default) or "ES256" for all three keys.
        log:                     Optional callback for progress messages.

    Returns:
        CeremonyResult with the signed manifest and paths to all artifacts.

    Raises:
        FileExistsError: if any keystore already exists at the target path.
        ValueError:      if algorithm is unsupported.
    """
    def _log(msg: str) -> None:
        if log:
            log(msg)

    transcript: list[dict] = []

    def _record(step: str, detail: dict | None = None) -> None:
        entry = {
            "step": step,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if detail:
            entry.update(detail)
        transcript.append(entry)
        _log(f"[ceremony] {step}")

    paths = CeremonyPaths.under(output_dir, deployment_id)
    _record("ceremony_start", {"deployment_id": deployment_id, "algorithm": algorithm})

    # ------------------------------------------------------------------
    # Tier 0: offline root key
    # ------------------------------------------------------------------
    _record("generating_tier0_root_key")
    root_store = KeyStore.create(paths.root_store, root_passphrase, algorithm=algorithm)
    _record("tier0_root_key_created", {"key_id": root_store.key_id, "path": str(paths.root_store)})

    # ------------------------------------------------------------------
    # Tier 1: operational receipt signing key
    # ------------------------------------------------------------------
    _record("generating_tier1_operational_key")
    op_store = KeyStore.create(paths.operational_store, operational_passphrase, algorithm=algorithm)
    _record("tier1_operational_key_created", {"key_id": op_store.key_id, "path": str(paths.operational_store)})

    # ------------------------------------------------------------------
    # Tier 2: checkpoint anchor key
    # ------------------------------------------------------------------
    _record("generating_tier2_checkpoint_key")
    ck_store = KeyStore.create(paths.checkpoint_store, checkpoint_passphrase, algorithm=algorithm)
    _record("tier2_checkpoint_key_created", {"key_id": ck_store.key_id, "path": str(paths.checkpoint_store)})

    # ------------------------------------------------------------------
    # Build manifest entries from the three signers' public manifests
    # ------------------------------------------------------------------
    _record("building_key_manifest")
    issued_at = datetime.now(timezone.utc).isoformat()
    root_signer = root_store.load_signer(root_passphrase)
    op_signer = op_store.load_signer(operational_passphrase)
    ck_signer = ck_store.load_signer(checkpoint_passphrase)

    def _to_manifest_entry(signer, tier: str, purpose: str) -> ManifestEntry:
        m = signer.public_key_manifest()
        return ManifestEntry(
            key_id=m["key_id"],
            tier=tier,
            algorithm=m["algorithm"],
            public_key_pem=m["public_key_pem"],
            public_key_spki_sha256=m["public_key_spki_sha256"],
            purpose=purpose,
            valid_from=m["valid_from"],
            valid_until=m["valid_until"],
            status="active",
        )

    entries = [
        _to_manifest_entry(root_signer, "offline_root",
                           "Tier 0 offline trust root — signs key manifests only"),
        _to_manifest_entry(op_signer, "operational",
                           "Tier 1 operational receipt signing key — signs every COSE_Sign1 receipt"),
        _to_manifest_entry(ck_signer, "checkpoint",
                           "Tier 2 checkpoint anchor key — signs Merkle tree checkpoints"),
    ]

    doc = KeyManifestDocument(
        deployment_id=deployment_id,
        issued_at=issued_at,
        entries=entries,
    )

    # Sign manifest with root key
    _record("signing_manifest_with_root_key", {"root_key_id": root_signer.key_id.hex()})
    doc.sign(root_signer)
    _record("manifest_signed", {"manifest_digest": doc.manifest_digest})

    # Save manifest
    paths.manifest.write_text(doc.to_json(), encoding="utf-8")
    _record("manifest_saved", {"path": str(paths.manifest)})

    # Save transcript
    _record("ceremony_complete", {
        "root_key_id": root_store.key_id,
        "operational_key_id": op_store.key_id,
        "checkpoint_key_id": ck_store.key_id,
    })
    paths.transcript.write_text(json.dumps(transcript, indent=2), encoding="utf-8")

    return CeremonyResult(
        manifest=doc,
        paths=paths,
        deployment_id=deployment_id,
        root_key_id=root_store.key_id,
        operational_key_id=op_store.key_id,
        checkpoint_key_id=ck_store.key_id,
        transcript=transcript,
    )


def rotate_operational_key(
    ceremony_dir: str | Path,
    deployment_id: str,
    root_passphrase: bytes,
    old_operational_passphrase: bytes,
    new_operational_passphrase: bytes,
    algorithm: str = "EdDSA",
    log: Callable[[str], None] | None = None,
) -> CeremonyResult:
    """
    Rotate the Tier 1 operational key.

    Steps:
      1. Load the current manifest and mark the old operational key as "rotated"
      2. Generate a new operational KeyStore
      3. Add the new key as "active" in the manifest
      4. Re-sign the manifest with the root key
      5. Write the updated manifest and a new transcript

    The old keystore file is renamed to <name>.rotated_<timestamp> so
    historical receipts signed with it can still be verified.

    Raises:
        FileNotFoundError: if existing keystores or manifest not found.
        ValueError:        if root passphrase is wrong.
    """
    def _log(msg: str) -> None:
        if log:
            log(msg)

    transcript: list[dict] = []

    def _record(step: str, detail: dict | None = None) -> None:
        entry = {"step": step, "timestamp": datetime.now(timezone.utc).isoformat()}
        if detail:
            entry.update(detail)
        transcript.append(entry)
        _log(f"[rotation] {step}")

    paths = CeremonyPaths.under(ceremony_dir, deployment_id)
    _record("rotation_start", {"deployment_id": deployment_id})

    # Load current manifest
    if not paths.manifest.exists():
        raise FileNotFoundError(f"Manifest not found at {paths.manifest}")
    doc = KeyManifestDocument.from_json(paths.manifest.read_text())
    _record("manifest_loaded", {"deployment_id": doc.deployment_id})

    # Verify old operational key
    old_op_store = KeyStore.open(paths.operational_store, old_operational_passphrase)
    _record("old_operational_key_verified", {"key_id": old_op_store.key_id})

    # Mark old operational key as rotated in manifest
    rotated_at = datetime.now(timezone.utc).isoformat()
    for entry in doc.entries:
        if entry.key_id == old_op_store.key_id and entry.tier == "operational":
            entry.status = "rotated"
            entry.rotated_at = rotated_at
    _record("old_key_marked_rotated")

    # Archive the old keystore
    archived = paths.operational_store.with_suffix(
        f".rotated_{rotated_at.replace(':', '-').replace('.', '-')}"
    )
    paths.operational_store.rename(archived)
    _record("old_keystore_archived", {"path": str(archived)})

    # Generate new operational key
    new_op_store = KeyStore.create(
        paths.operational_store, new_operational_passphrase, algorithm=algorithm
    )
    _record("new_operational_key_created", {"key_id": new_op_store.key_id})

    # Add new key to manifest
    new_op_signer = new_op_store.load_signer(new_operational_passphrase)
    new_manifest_entry = new_op_signer.public_key_manifest()
    doc.entries.append(ManifestEntry(
        key_id=new_manifest_entry["key_id"],
        tier="operational",
        algorithm=new_manifest_entry["algorithm"],
        public_key_pem=new_manifest_entry["public_key_pem"],
        public_key_spki_sha256=new_manifest_entry["public_key_spki_sha256"],
        purpose="Tier 1 operational receipt signing key — signs every COSE_Sign1 receipt",
        valid_from=new_manifest_entry["valid_from"],
        valid_until=new_manifest_entry["valid_until"],
        status="active",
    ))
    doc.issued_at = datetime.now(timezone.utc).isoformat()

    # Re-sign manifest with root key
    root_store = KeyStore.open(paths.root_store, root_passphrase)
    root_signer = root_store.load_signer(root_passphrase)
    doc.sign(root_signer)
    _record("manifest_re_signed", {"manifest_digest": doc.manifest_digest})

    paths.manifest.write_text(doc.to_json())
    _record("manifest_saved")

    _record("rotation_complete", {"new_key_id": new_op_store.key_id})
    rotation_transcript_path = paths.transcript.with_suffix(
        f".rotation_{rotated_at.replace(':', '-').replace('.', '-')}.json"
    )
    rotation_transcript_path.write_text(json.dumps(transcript, indent=2))

    return CeremonyResult(
        manifest=doc,
        paths=paths,
        deployment_id=deployment_id,
        root_key_id=root_store.key_id,
        operational_key_id=new_op_store.key_id,
        checkpoint_key_id="",   # unchanged
        transcript=transcript,
    )
