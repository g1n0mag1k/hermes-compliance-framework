"""
hermes/demo_receipts.py — V2 receipt signing oracle for the procurement demo.

DEMO ONLY — THIS IS A SIGNING ORACLE.

POST /v2/receipts signs whatever JSON payload the caller hands it. In
production, V2 receipts are issued by the gateway enforcement path
(issue_gateway_receipt in gateway/evidence.py), where the payload is built
from an enforcement decision the gateway observed itself and cannot be chosen
by the client. An endpoint that signs a client-supplied payload will attest to
anything, including a statement about an action that never happened, and must
never be exposed outside a demo deployment.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import cbor2

from hermes.attestation import DEFAULT_DB_PATH
from hermes.receipts.v2.builder import ReceiptV2Builder
from hermes.receipts.v2.canonical import canonicalize
from hermes.receipts.v2.key_store import KeyStore
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519

KEYSTORE_PATH_ENV_VAR = "HERMES_GATEWAY_KEYSTORE_PATH"
KEYSTORE_PASSPHRASE_ENV_VAR = "HERMES_GATEWAY_KEYSTORE_PASSPHRASE"

EPHEMERAL_KEY_WARNING = (
    f"{KEYSTORE_PATH_ENV_VAR} / {KEYSTORE_PASSPHRASE_ENV_VAR} are not set. This "
    "receipt was signed with an ephemeral in-process key from "
    "SoftwareSignerEd25519.generate(). The key is discarded when the process "
    "exits and appears in no published key manifest, so this receipt is not "
    "independently verifiable. Demo only."
)

_COSE_SIGN1_TAG = 18

_signer_lock = threading.Lock()
_SIGNER: Optional[SoftwareSignerEd25519] = None
_SIGNER_WARNING: Optional[str] = None


def _load_signer() -> tuple[SoftwareSignerEd25519, Optional[str]]:
    """Open the configured keystore, or fall back to an ephemeral key.

    Never raises on a missing or unreadable keystore. The returned warning is
    surfaced in the API response so the operator sees why the receipt is not
    independently verifiable instead of getting a silent ephemeral key.
    """
    path = os.environ.get(KEYSTORE_PATH_ENV_VAR)
    passphrase = os.environ.get(KEYSTORE_PASSPHRASE_ENV_VAR)
    if path and passphrase:
        try:
            store = KeyStore.open(path, passphrase.encode("utf-8"))
            return store.load_signer(), None
        except (FileNotFoundError, ValueError, OSError, KeyError) as exc:
            return (
                SoftwareSignerEd25519.generate(),
                f"Keystore at {path} could not be opened ({exc}). "
                + EPHEMERAL_KEY_WARNING,
            )
    return SoftwareSignerEd25519.generate(), EPHEMERAL_KEY_WARNING


def get_signer() -> tuple[SoftwareSignerEd25519, Optional[str]]:
    global _SIGNER, _SIGNER_WARNING
    with _signer_lock:
        if _SIGNER is None:
            _SIGNER, _SIGNER_WARNING = _load_signer()
        return _SIGNER, _SIGNER_WARNING


def reset_signer() -> None:
    """Drop the cached signer. Used by tests and by keystore changes mid-demo."""
    global _SIGNER, _SIGNER_WARNING
    with _signer_lock:
        _SIGNER = None
        _SIGNER_WARNING = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS demo_v2_receipts (
    receipt_id     TEXT PRIMARY KEY,
    workspace_id   TEXT NOT NULL,
    action_digest  TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    algorithm      TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    cose_sign1_hex TEXT NOT NULL,
    payload        TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    ephemeral_key  INTEGER NOT NULL
);
"""


def demo_receipt_db_path(workspace_id: str, chain_db_path: Optional[str] = None) -> str:
    if chain_db_path:
        return str(Path(chain_db_path).parent / "demo_v2_receipts.db")
    base = os.environ.get("HERMES_DB_PATH", DEFAULT_DB_PATH)
    if workspace_id != "default":
        from hermes.workspaces import _data_dir

        return str(_data_dir() / workspace_id / "demo_v2_receipts.db")
    return str(Path(base).parent / "demo_v2_receipts.db")


def _connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


@dataclass(frozen=True)
class IssuedDemoReceipt:
    receipt_id: str
    action_digest: str
    issued_at: str
    key_id: str
    algorithm: str
    ephemeral_key: bool
    warning: Optional[str]


@dataclass(frozen=True)
class StoredDemoReceipt:
    receipt_id: str
    action_digest: str
    issued_at: str
    key_id: str
    algorithm: str
    public_key_pem: str
    cose_sign1_bytes: bytes
    payload: dict
    ephemeral_key: bool


def issue_demo_receipt(
    payload: dict[str, Any],
    workspace_id: str,
    db_path: str,
) -> IssuedDemoReceipt:
    """Sign `payload` as a V2 COSE_Sign1 receipt and persist it.

    action_digest is the receipt's domain-separated SHA-256 over the canonical
    signed payload — the same value ReceiptV2 calls receipt_digest.
    """
    signer, warning = get_signer()
    manifest = signer.public_key_manifest()
    receipt = ReceiptV2Builder(signer).build(payload)

    conn = _connect(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO demo_v2_receipts (
                    receipt_id, workspace_id, action_digest, key_id, algorithm,
                    public_key_pem, cose_sign1_hex, payload, issued_at,
                    ephemeral_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    workspace_id,
                    receipt.receipt_digest,
                    manifest["key_id"],
                    manifest["algorithm"],
                    manifest["public_key_pem"],
                    receipt.cose_sign1_bytes.hex(),
                    json.dumps(receipt.payload, sort_keys=True),
                    receipt.issued_at,
                    1 if warning else 0,
                ),
            )
    finally:
        conn.close()

    return IssuedDemoReceipt(
        receipt_id=receipt.receipt_id,
        action_digest=receipt.receipt_digest,
        issued_at=receipt.issued_at,
        key_id=manifest["key_id"],
        algorithm=manifest["algorithm"],
        ephemeral_key=bool(warning),
        warning=warning,
    )


def get_demo_receipt(receipt_id: str, db_path: str) -> Optional[StoredDemoReceipt]:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT receipt_id, action_digest, issued_at, key_id, algorithm,
                   public_key_pem, cose_sign1_hex, payload, ephemeral_key
            FROM demo_v2_receipts WHERE receipt_id = ?
            """,
            (receipt_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return StoredDemoReceipt(
        receipt_id=row[0],
        action_digest=row[1],
        issued_at=row[2],
        key_id=row[3],
        algorithm=row[4],
        public_key_pem=row[5],
        cose_sign1_bytes=bytes.fromhex(row[6]),
        payload=json.loads(row[7]),
        ephemeral_key=bool(row[8]),
    )


def splice_payload(cose_sign1_bytes: bytes, replacement_payload: dict) -> bytes:
    """Swap the COSE_Sign1 payload, keeping the headers and original signature.

    This is exactly what someone editing a stored receipt can do: the payload
    changes, the signature does not. verify_receipt then rebuilds Sig_Structure
    over the new payload and the signature check fails for real — the verifier
    has no simulated failure path.
    """
    outer = cbor2.loads(cose_sign1_bytes)
    if not isinstance(outer, cbor2.CBORTag) or outer.tag != _COSE_SIGN1_TAG:
        raise ValueError("Stored receipt is not a COSE_Sign1 envelope.")
    phdr_bytes, uhdr, _payload, signature = outer.value
    return cbor2.dumps(
        cbor2.CBORTag(
            _COSE_SIGN1_TAG,
            [
                phdr_bytes,
                dict(uhdr) if uhdr else {},
                canonicalize(replacement_payload),
                signature,
            ],
        )
    )
