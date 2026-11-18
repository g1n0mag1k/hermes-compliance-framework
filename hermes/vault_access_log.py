"""
hermes/vault_access_log.py — Tamper-Evident Vault Access Log

Every retrieval of an original (un-redacted) value from the reversible
redaction token vault (hermes/vault.py) is recorded here as a hash-chained,
HMAC-signed, append-only entry — this is the "who looked at the real PHI,
and when" trail a HIPAA-covered entity needs for an accounting of
disclosures.

Deliberately independent of hermes.attestation.AttestationChain: that
chain's signing and verification code is frozen after two rounds of
independent audit (PHI-OMEGA), so this additive feature has its own small,
self-contained hash chain rather than extending a third item type into
code that is not supposed to change. Same cryptographic pattern (HMAC-SHA256
over a canonical JSON content dict, chained via previous-hash linkage,
sequential chain_position), applied to a different, smaller record shape.

Regulatory alignment:
- HIPAA Security Rule 45 CFR 164.312(b) — audit controls: record and
  examine activity in systems containing ePHI, in particular any
  disclosure of a previously redacted value back to a human or a
  downstream system.
- HIPAA Privacy Rule 45 CFR 164.528 — accounting of disclosures.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

_GENESIS = hashlib.sha256(b"hermes-vault-access-genesis").hexdigest()
_SIGN_EXCLUDE = {"record_hash"}


@dataclass
class VaultAccessRecord:
    # --- Immutable signed fields ---
    access_id: str
    token: str
    transaction_id: str
    workspace_id: str
    accessed_by: str
    issued_at: str
    previous_record_hash: str
    chain_position: int
    record_hash: str


class VaultAccessLog:
    """Hash-chained, HMAC-signed, append-only record of every original-value
    retrieval from a TokenVault. One instance per vault — pass the same
    signing_key convention used elsewhere in this codebase (a deployment-wide
    key for legacy single-tenant use, or a per-workspace derived key)."""

    def __init__(self, db_path: str, signing_key: bytes) -> None:
        self._db_path = db_path
        self._signing_key = signing_key
        self._lock = threading.Lock()
        self._chain: list[VaultAccessRecord] = []
        conn = sqlite3.connect(self._db_path)
        try:
            self._init_db(conn)
            self._load(conn)
        finally:
            conn.close()

    @staticmethod
    def _init_db(conn: sqlite3.Connection) -> None:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_access_log (
                chain_position       INTEGER PRIMARY KEY,
                access_id            TEXT NOT NULL,
                token                TEXT NOT NULL,
                transaction_id       TEXT NOT NULL,
                workspace_id         TEXT NOT NULL,
                accessed_by          TEXT NOT NULL,
                issued_at            TEXT NOT NULL,
                previous_record_hash TEXT NOT NULL,
                record_hash          TEXT NOT NULL
            )
        """)
        conn.commit()

    def _load(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT chain_position, access_id, token, transaction_id, "
            "workspace_id, accessed_by, issued_at, previous_record_hash, "
            "record_hash FROM vault_access_log ORDER BY chain_position ASC"
        ).fetchall()
        for row in rows:
            self._chain.append(VaultAccessRecord(
                chain_position=row[0], access_id=row[1], token=row[2],
                transaction_id=row[3], workspace_id=row[4], accessed_by=row[5],
                issued_at=row[6], previous_record_hash=row[7], record_hash=row[8],
            ))

    def _sign(self, content: dict) -> str:
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            self._signing_key, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def log_access(
        self,
        token: str,
        transaction_id: str,
        workspace_id: str,
        accessed_by: str,
    ) -> VaultAccessRecord:
        """Append one tamper-evident record of an un-redaction event.
        Call this every time an API caller resolves a vault token back to
        its original value."""
        with self._lock:
            position = len(self._chain)
            prev_hash = self._chain[-1].record_hash if self._chain else _GENESIS
            access_id = f"vault_access_{position:08d}"
            issued_at = datetime.now(UTC).isoformat()
            sign_content = {
                "access_id": access_id,
                "token": token,
                "transaction_id": transaction_id,
                "workspace_id": workspace_id,
                "accessed_by": accessed_by,
                "issued_at": issued_at,
                "previous_record_hash": prev_hash,
                "chain_position": position,
            }
            record_hash = self._sign(sign_content)
            record = VaultAccessRecord(
                access_id=access_id,
                token=token,
                transaction_id=transaction_id,
                workspace_id=workspace_id,
                accessed_by=accessed_by,
                issued_at=issued_at,
                previous_record_hash=prev_hash,
                chain_position=position,
                record_hash=record_hash,
            )
            self._persist(record)
            self._chain.append(record)
        return record

    def _persist(self, record: VaultAccessRecord) -> None:
        conn = sqlite3.connect(self._db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO vault_access_log
                        (chain_position, access_id, token, transaction_id,
                         workspace_id, accessed_by, issued_at,
                         previous_record_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.chain_position, record.access_id, record.token,
                        record.transaction_id, record.workspace_id,
                        record.accessed_by, record.issued_at,
                        record.previous_record_hash, record.record_hash,
                    ),
                )
        finally:
            conn.close()

    def verify(self) -> bool:
        """Walk the full log and confirm every signature and hash link.
        Same invariant shape as AttestationChain.verify_chain(), scoped to
        this independent log: (1) signature validity, (2) hash-chain
        linkage, (3) sequential chain_position."""
        expected_prev = _GENESIS
        with self._lock:
            for i, r in enumerate(self._chain):
                sign_content = {
                    k: v for k, v in asdict(r).items() if k not in _SIGN_EXCLUDE
                }
                if not hmac.compare_digest(self._sign(sign_content), r.record_hash):
                    return False
                if not hmac.compare_digest(r.previous_record_hash, expected_prev):
                    return False
                if r.chain_position != i:
                    return False
                expected_prev = r.record_hash
        return True

    def export_log(self, workspace_id: str | None = None) -> list[VaultAccessRecord]:
        with self._lock:
            if workspace_id is None:
                return list(self._chain)
            return [r for r in self._chain if r.workspace_id == workspace_id]


def _legacy_db_path() -> str:
    return os.environ.get(
        "HERMES_VAULT_ACCESS_LOG_DB_PATH", "hermes_vault_access_log.db"
    )


_legacy_log: VaultAccessLog | None = None
_legacy_lock = threading.Lock()


def get_legacy_vault_access_log() -> VaultAccessLog:
    """Global, deployment-wide log for legacy single-tenant deployments
    (HERMES_API_KEY auth, no workspace registry) — mirrors hermes.vault.VAULT
    and hermes.attestation.ATTESTATION_CHAIN being module-level singletons."""
    global _legacy_log
    with _legacy_lock:
        if _legacy_log is None:
            from hermes.vault import VAULT_KEY
            _legacy_log = VaultAccessLog(
                db_path=_legacy_db_path(), signing_key=VAULT_KEY
            )
        return _legacy_log
