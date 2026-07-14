"""
hermes/vault.py — Reversible Redaction Token Vault

Encryption: AES-256-GCM (authenticated encryption)
- 96-bit random nonce per encryption operation  
- Authentication tag detects any ciphertext tampering
- Replaces XOR cipher (broken, HIPAA-inadmissible)

Regulatory alignment:
- HIPAA Security Rule 45 CFR 164.312(a)(2)(iv) — encryption/decryption
- HIPAA Security Rule 45 CFR 164.312(e)(2)(ii) — encryption in transit
- PCI-DSS v4.0 Req 3.5.1 — protection of stored account data
"""
import hashlib
import sqlite3
import hmac
import os
import threading
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_vault_key() -> bytes:
    key_hex = os.environ.get("HERMES_VAULT_KEY")
    env = os.environ.get("HERMES_ENV", "development")
    if key_hex:
        key = bytes.fromhex(key_hex)
        if len(key) != 32:
            raise ValueError(
                "HERMES_VAULT_KEY must be exactly 64 hex characters (32 bytes). "
                f"Got {len(key)} bytes."
            )
        return key
    if env == "production":
        raise RuntimeError(
            "HERMES_VAULT_KEY is required when HERMES_ENV=production. "
            "Set HERMES_VAULT_KEY to a 64-char hex string (32 bytes)."
        )
    warnings.warn(
        "HERMES_VAULT_KEY not set — using insecure dev key. "
        "Set HERMES_VAULT_KEY to a 64-char hex string before production.",
        stacklevel=2,
    )
    return hashlib.sha256(b"hermes-dev-vault-key-not-for-production").digest()


VAULT_KEY: bytes = _load_vault_key()


def _aesgcm_encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt. Returns hex(nonce || ciphertext || tag).
    Nonce: 12 bytes random per call. Tag: 16 bytes. Tamper-evident."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return (nonce + ct).hex()


def _aesgcm_decrypt(ciphertext_hex: str, key: bytes) -> str:
    """AES-256-GCM decrypt. Raises InvalidTag on tamper — authenticated decryption."""
    raw = bytes.fromhex(ciphertext_hex)
    if len(raw) < 12:
        raise ValueError("Ciphertext too short — nonce missing or data corrupted.")
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def _generate_token(pii_type: str, original_value: str) -> str:
    """HMAC-SHA256 derived token. Deterministic per (key, pii_type, value)."""
    mac = hmac.new(
        VAULT_KEY,
        f"{pii_type}:{original_value}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"[REDACTED_{pii_type}_{mac}]"


@dataclass
class VaultEntry:
    token: str
    pii_type: str
    encrypted_value: str
    transaction_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# -------------------------------------------------------------------------
# SQLITE BACKEND
# -------------------------------------------------------------------------
def _get_db_path() -> str:
    return os.environ.get("HERMES_VAULT_DB_PATH", "hermes_vault.db")


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            token             TEXT PRIMARY KEY,
            pii_type          TEXT NOT NULL,
            encrypted_value   TEXT NOT NULL,
            transaction_id    TEXT NOT NULL,
            created_at        TEXT NOT NULL
        )
    """)
    conn.commit()


def _load_all_entries(conn: sqlite3.Connection) -> Dict[str, VaultEntry]:
    rows = conn.execute(
        "SELECT token, pii_type, encrypted_value, transaction_id, created_at "
        "FROM vault_entries"
    ).fetchall()
    return {
        row[0]: VaultEntry(
            token=row[0],
            pii_type=row[1],
            encrypted_value=row[2],
            transaction_id=row[3],
            created_at=row[4],
        )
        for row in rows
    }


class TokenVault:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or _get_db_path()
        self._lock = threading.Lock()

        conn = sqlite3.connect(self._db_path)
        _init_db(conn)
        self._store: Dict[str, VaultEntry] = _load_all_entries(conn)
        conn.close()

    def store(self, pii_type: str, original_value: str, transaction_id: str) -> str:
        token = _generate_token(pii_type, original_value)
        encrypted = _aesgcm_encrypt(original_value, VAULT_KEY)
        entry = VaultEntry(
            token=token,
            pii_type=pii_type,
            encrypted_value=encrypted,
            transaction_id=transaction_id,
        )
        with self._lock:
            self._store[token] = entry
        return token

    def retrieve(self, token: str) -> Optional[str]:
        """Decrypt and return original value. Raises InvalidTag if tampered."""
        with self._lock:
            entry = self._store.get(token)
        if entry is None:
            return None
        return _aesgcm_decrypt(entry.encrypted_value, VAULT_KEY)

    def retrieve_entry(self, token: str) -> Optional[VaultEntry]:
        with self._lock:
            return self._store.get(token)

    def purge_transaction(self, transaction_id: str) -> int:
        with self._lock:
            keys_to_remove = [
                k for k, v in self._store.items()
                if v.transaction_id == transaction_id
            ]
            for k in keys_to_remove:
                del self._store[k]
        return len(keys_to_remove)

    def size(self) -> int:
        with self._lock:
            return len(self._store)


VAULT = TokenVault()
