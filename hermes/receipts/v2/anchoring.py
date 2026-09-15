"""
hermes/receipts/v2/anchoring.py — External anchoring for Hermes V2 checkpoints.

Three anchoring mechanisms, in increasing strength:

  1. WORM storage (local simulation + S3/Azure Blob production path)
     Write-once checkpoint bundles: the checkpoint COSE bytes + a manifest
     are written to an object store with object lock enabled. The object
     version ID is recorded so immutability can be verified.

  2. RFC 3161 trusted timestamps (TSA)
     A Timestamp Authority signs the checkpoint_digest, producing a TST
     (TimeStampToken). This provides legally admissible proof of existence
     before a point in time, independent of Hermes infrastructure.
     Production: use Sectigo, DigiCert, or Let's Encrypt TSA endpoints.
     This module ships a MOCK TSA for development; swap for a real endpoint
     via HERMES_TSA_URL environment variable.

  3. SCITT transparency service (RFC 9943) — stub
     Registers the checkpoint Merkle root with a SCITT-compliant
     transparency service. Returns an inclusion receipt (COSE_Sign1 from
     the SCITT log operator) plus a consistency proof handle.
     The stub records the intent and returns a placeholder until a real
     SCITT endpoint is configured via HERMES_SCITT_URL.

None of these mechanisms are required for Release C functionality.
They are additive anchoring layers for the enterprise/gov tier.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hermes.receipts.v2.checkpoint import CheckpointRecord


# ------------------------------------------------------------------
# 1. WORM Storage
# ------------------------------------------------------------------

@dataclass
class WORMRecord:
    """
    Record of a checkpoint written to WORM storage.

    In production, object_version_id is the S3 Object Lock version ID
    or Azure Blob immutability policy token. In local simulation it is
    a SHA-256 of the written bytes.
    """
    checkpoint_id: str
    stream_id: str
    written_at: str             # ISO 8601 UTC
    object_key: str             # storage path / object key
    object_version_id: str      # immutability handle
    bundle_sha256: str          # SHA-256 of the written bundle bytes
    storage_backend: str        # "local_simulation" | "s3" | "azure_blob"


class WORMStore:
    """
    Write-once checkpoint store.

    write() accepts a CheckpointRecord and writes a JSON bundle to the
    configured backend. Once written, the bundle is never modified.

    For local simulation (development/CI): writes to a local directory.
    For production: subclass and override _write_bundle() to use S3/Azure.
    """

    def __init__(self, store_dir: str | Path, backend: str = "local_simulation") -> None:
        self._store_dir = Path(store_dir)
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._backend = backend
        self._records: list[WORMRecord] = []

    def write(self, checkpoint: CheckpointRecord) -> WORMRecord:
        """
        Write a checkpoint bundle to WORM storage.

        The bundle contains:
          - The raw COSE_Sign1 bytes (hex-encoded)
          - The checkpoint metadata as JSON
          - A SHA-256 integrity check over both

        Returns:
            WORMRecord with the object version ID and integrity hash.

        Raises:
            FileExistsError: if a bundle for this checkpoint_id already exists
                             (enforces write-once at the application layer).
        """
        bundle = self._build_bundle(checkpoint)
        bundle_bytes = json.dumps(bundle, indent=2).encode("utf-8")
        bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()

        object_key = (
            f"{checkpoint.stream_id}/"
            f"{checkpoint.sequence:08d}/"
            f"{checkpoint.checkpoint_id}.checkpoint.json"
        )
        written_at = datetime.now(timezone.utc).isoformat()
        object_version_id = self._write_bundle(object_key, bundle_bytes)

        record = WORMRecord(
            checkpoint_id=checkpoint.checkpoint_id,
            stream_id=checkpoint.stream_id,
            written_at=written_at,
            object_key=object_key,
            object_version_id=object_version_id,
            bundle_sha256=bundle_sha256,
            storage_backend=self._backend,
        )
        self._records.append(record)
        return record

    def read(self, object_key: str) -> bytes:
        """Read a bundle by object key. Raises FileNotFoundError if absent."""
        path = self._store_dir / object_key
        if not path.exists():
            raise FileNotFoundError(f"WORM bundle not found: {object_key}")
        return path.read_bytes()

    def verify_integrity(self, record: WORMRecord) -> bool:
        """
        Verify that a stored bundle's SHA-256 still matches.

        A mismatch means the stored bytes were modified after writing —
        a WORM violation.
        """
        try:
            bundle_bytes = self.read(record.object_key)
            return hashlib.sha256(bundle_bytes).hexdigest() == record.bundle_sha256
        except FileNotFoundError:
            return False

    @property
    def records(self) -> list[WORMRecord]:
        return list(self._records)

    def _build_bundle(self, checkpoint: CheckpointRecord) -> dict:
        return {
            "bundle_version": 1,
            "checkpoint_id": checkpoint.checkpoint_id,
            "stream_id": checkpoint.stream_id,
            "sequence": checkpoint.sequence,
            "issued_at": checkpoint.issued_at,
            "tree_size": checkpoint.tree_size,
            "merkle_root": checkpoint.merkle_root,
            "checkpoint_digest": checkpoint.checkpoint_digest,
            "prev_checkpoint_digest": checkpoint.prev_checkpoint_digest,
            "policy_digest": checkpoint.policy_digest,
            "software_version": checkpoint.software_version,
            "config_digest": checkpoint.config_digest,
            "cose_sign1_hex": checkpoint.cose_sign1_bytes.hex(),
        }

    def _write_bundle(self, object_key: str, bundle_bytes: bytes) -> str:
        """
        Write bundle bytes to the local filesystem.

        Returns a version_id (SHA-256 of written bytes for local sim).
        Override this method for S3/Azure production backends.
        """
        path = self._store_dir / object_key
        if path.exists():
            raise FileExistsError(
                f"WORM bundle already exists at {object_key}. "
                "WORM storage is write-once."
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bundle_bytes)
        # Make file read-only to simulate object lock
        path.chmod(0o444)
        # Version ID is SHA-256 of written bytes (in production: S3 version ID)
        return hashlib.sha256(bundle_bytes).hexdigest()[:16]


# ------------------------------------------------------------------
# 2. RFC 3161 Timestamps
# ------------------------------------------------------------------

@dataclass
class TimestampToken:
    """
    RFC 3161 Timestamp Token (or mock equivalent for development).

    In production: tst_der is the DER-encoded TimeStampToken from the TSA.
    In mock mode: tst_der contains a signed JSON blob identifying this as mock.
    """
    checkpoint_digest: str    # hex — the digest that was timestamped
    tsa_url: str              # URL of the TSA that issued the token
    serial_number: int        # TSA-assigned serial
    gen_time: str             # ISO 8601 UTC — TSA's asserted time
    tst_der: bytes            # DER-encoded TimeStampToken (or mock bytes)
    is_mock: bool = False     # True if this is a development mock token

    def to_dict(self) -> dict:
        return {
            "checkpoint_digest": self.checkpoint_digest,
            "tsa_url": self.tsa_url,
            "serial_number": self.serial_number,
            "gen_time": self.gen_time,
            "tst_der_hex": self.tst_der.hex(),
            "is_mock": self.is_mock,
        }


_MOCK_TSA_URL = "https://tsa.hermes-relay.dev/mock"
_PROD_TSA_URL = os.environ.get("HERMES_TSA_URL", "")


def timestamp_checkpoint(
    checkpoint: CheckpointRecord,
    tsa_url: str | None = None,
) -> TimestampToken:
    """
    Obtain an RFC 3161 timestamp over a checkpoint's digest.

    In production, set HERMES_TSA_URL to a real TSA endpoint
    (e.g. http://timestamp.sectigo.com or http://timestamp.digicert.com).

    In development/CI, a mock token is returned. Mock tokens are clearly
    labelled is_mock=True and must never be presented as production evidence.

    Args:
        checkpoint: The CheckpointRecord to timestamp.
        tsa_url:    TSA endpoint URL. Defaults to HERMES_TSA_URL env var,
                    or the mock TSA if not set.

    Returns:
        TimestampToken — real or mock depending on configuration.
    """
    url = tsa_url or _PROD_TSA_URL or _MOCK_TSA_URL

    if url == _MOCK_TSA_URL or not _PROD_TSA_URL:
        return _mock_timestamp(checkpoint, url)

    return _real_timestamp(checkpoint, url)


def _mock_timestamp(checkpoint: CheckpointRecord, tsa_url: str) -> TimestampToken:
    """Issue a mock RFC 3161-shaped timestamp for development and testing."""
    gen_time = datetime.now(timezone.utc).isoformat()
    serial = int(time.time() * 1000) & 0xFFFFFFFF

    mock_tst = json.dumps({
        "_mock_warning": "NOT A REAL RFC 3161 TOKEN — development use only",
        "checkpoint_digest": checkpoint.checkpoint_digest,
        "gen_time": gen_time,
        "serial_number": serial,
        "tsa_url": tsa_url,
    }).encode("utf-8")

    return TimestampToken(
        checkpoint_digest=checkpoint.checkpoint_digest,
        tsa_url=tsa_url,
        serial_number=serial,
        gen_time=gen_time,
        tst_der=mock_tst,
        is_mock=True,
    )


def _real_timestamp(checkpoint: CheckpointRecord, tsa_url: str) -> TimestampToken:
    """
    Send a TimeStampRequest to a real RFC 3161 TSA and parse the response.

    Requires the `rfc3161ng` package (optional dependency).
    Falls back to mock if the package is not installed.
    """
    try:
        import rfc3161ng
    except ImportError:
        # Graceful fallback — log a warning and return mock
        import warnings
        warnings.warn(
            "rfc3161ng not installed — falling back to mock timestamp. "
            "Install with: pip install rfc3161ng",
            stacklevel=2,
        )
        return _mock_timestamp(checkpoint, tsa_url)

    digest_bytes = bytes.fromhex(checkpoint.checkpoint_digest)
    try:
        tst = rfc3161ng.get_timestamp(
            data=digest_bytes,
            url=tsa_url,
            hash_algorithm="sha256",
        )
        gen_time = datetime.fromtimestamp(
            tst.tst_info["gen_time"].native, tz=timezone.utc
        ).isoformat()
        serial = int(tst.tst_info["serial_number"].native)

        return TimestampToken(
            checkpoint_digest=checkpoint.checkpoint_digest,
            tsa_url=tsa_url,
            serial_number=serial,
            gen_time=gen_time,
            tst_der=tst.dump(),
            is_mock=False,
        )
    except Exception as exc:
        import warnings
        warnings.warn(f"TSA request failed ({exc}) — falling back to mock.", stacklevel=2)
        return _mock_timestamp(checkpoint, tsa_url)


# ------------------------------------------------------------------
# 3. SCITT Transparency Service (RFC 9943) — stub
# ------------------------------------------------------------------

@dataclass
class SCITTReceipt:
    """
    Record of a SCITT registration for a checkpoint Merkle root.

    In production: inclusion_receipt_cose is the COSE_Sign1 from the
    SCITT log operator, and consistency_proof_handle is a handle to
    retrieve a consistency proof against a later tree state.

    The stub always returns is_stub=True until a real SCITT endpoint
    is configured via HERMES_SCITT_URL.
    """
    checkpoint_id: str
    merkle_root: str                    # hex — the value registered
    scitt_url: str
    registered_at: str                  # ISO 8601 UTC
    log_entry_id: str                   # SCITT-assigned entry identifier
    inclusion_receipt_cose: bytes       # COSE_Sign1 from SCITT operator (or stub)
    consistency_proof_handle: str       # handle for future consistency proof
    is_stub: bool = True

    def to_dict(self) -> dict:
        return {
            "checkpoint_id": self.checkpoint_id,
            "merkle_root": self.merkle_root,
            "scitt_url": self.scitt_url,
            "registered_at": self.registered_at,
            "log_entry_id": self.log_entry_id,
            "inclusion_receipt_cose_hex": self.inclusion_receipt_cose.hex(),
            "consistency_proof_handle": self.consistency_proof_handle,
            "is_stub": self.is_stub,
        }


_SCITT_URL = os.environ.get("HERMES_SCITT_URL", "")


def register_with_scitt(checkpoint: CheckpointRecord) -> SCITTReceipt:
    """
    Register a checkpoint Merkle root with a SCITT transparency service.

    Set HERMES_SCITT_URL to a real RFC 9943-compliant endpoint to activate.
    Returns a stub receipt in development until configured.

    Args:
        checkpoint: The CheckpointRecord whose Merkle root to register.

    Returns:
        SCITTReceipt — real or stub depending on HERMES_SCITT_URL.
    """
    if not _SCITT_URL:
        return _stub_scitt_receipt(checkpoint)

    try:
        import httpx
        return _real_scitt_registration(checkpoint, _SCITT_URL)
    except ImportError:
        import warnings
        warnings.warn("httpx not installed — returning stub SCITT receipt.", stacklevel=2)
        return _stub_scitt_receipt(checkpoint)
    except Exception as exc:
        import warnings
        warnings.warn(f"SCITT registration failed ({exc}) — returning stub.", stacklevel=2)
        return _stub_scitt_receipt(checkpoint)


def _stub_scitt_receipt(checkpoint: CheckpointRecord) -> SCITTReceipt:
    """Return a clearly-marked stub SCITT receipt for development."""
    stub_payload = json.dumps({
        "_stub_warning": "NOT A REAL SCITT RECEIPT — set HERMES_SCITT_URL to activate",
        "checkpoint_id": checkpoint.checkpoint_id,
        "merkle_root": checkpoint.merkle_root,
    }).encode("utf-8")

    return SCITTReceipt(
        checkpoint_id=checkpoint.checkpoint_id,
        merkle_root=checkpoint.merkle_root,
        scitt_url="stub://not-configured",
        registered_at=datetime.now(timezone.utc).isoformat(),
        log_entry_id=f"stub-{checkpoint.checkpoint_id[:8]}",
        inclusion_receipt_cose=stub_payload,
        consistency_proof_handle=f"stub-handle-{checkpoint.checkpoint_id[:8]}",
        is_stub=True,
    )


def _real_scitt_registration(checkpoint: CheckpointRecord, scitt_url: str) -> SCITTReceipt:
    """
    Submit a checkpoint to a real SCITT endpoint (RFC 9943).

    The payload is the checkpoint's COSE_Sign1 bytes submitted as a SCITT
    statement. The SCITT service issues a signed inclusion receipt.
    """
    import httpx

    resp = httpx.post(
        f"{scitt_url}/entries",
        content=checkpoint.cose_sign1_bytes,
        headers={"Content-Type": "application/cose"},
        timeout=30.0,
    )
    resp.raise_for_status()

    log_entry_id = resp.headers.get("Location", "").split("/")[-1]
    inclusion_receipt_cose = resp.content

    return SCITTReceipt(
        checkpoint_id=checkpoint.checkpoint_id,
        merkle_root=checkpoint.merkle_root,
        scitt_url=scitt_url,
        registered_at=datetime.now(timezone.utc).isoformat(),
        log_entry_id=log_entry_id,
        inclusion_receipt_cose=inclusion_receipt_cose,
        consistency_proof_handle=log_entry_id,
        is_stub=False,
    )
