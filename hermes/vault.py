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
import hmac
import os
import sqlite3
import threading
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hermes.tenant_keys import (
    KEY_SCHEME_GLOBAL,
    KEY_SCHEME_PER_WORKSPACE,
    resolve_key_scheme,
)


def _load_vault_key() -> bytes:
    key_hex = os.environ.get("HERMES_VAULT_KEY")
    env = os.environ.get("HERMES_ENV", "development")
    if key_hex:
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            if env == "production":
                raise RuntimeError(
                    "HERMES_VAULT_KEY is invalid when HERMES_ENV=production. "
                    "Set HERMES_VAULT_KEY to a 64-char hex string (32 bytes)."
                ) from exc
            raise
        if len(key) != 32:
            msg = (
                "HERMES_VAULT_KEY must be exactly 64 hex characters (32 bytes). "
                f"Got {len(key)} bytes."
            )
            if env == "production":
                raise RuntimeError(msg)
            raise ValueError(msg)
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


def _generate_token(
    pii_type: str, original_value: str, key: bytes | None = None
) -> str:
    """HMAC-SHA256 derived token. Deterministic per (key, pii_type, value).

    key defaults to the deployment-wide VAULT_KEY. Per-workspace vaults pass
    their derived key so the same value yields different tokens in different
    workspaces (no cross-tenant correlation by token).
    """
    mac = hmac.new(
        key if key is not None else VAULT_KEY,
        f"{pii_type}:{original_value}".encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"[REDACTED_{pii_type}_{mac}]"


@dataclass
class VaultEntry:
    token: str
    pii_type: str
    encrypted_value: str
    transaction_id: str
    workspace_id: str = "default"
    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
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
            created_at        TEXT NOT NULL,
            workspace_id      TEXT NOT NULL DEFAULT 'default'
        )
    """)
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(vault_entries)")
    }
    if "workspace_id" not in columns:
        conn.execute("""
            ALTER TABLE vault_entries
            ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'
        """)
    conn.commit()


def _load_all_entries(conn: sqlite3.Connection) -> dict[str, VaultEntry]:
    rows = conn.execute(
        "SELECT token, pii_type, encrypted_value, transaction_id, "
        "created_at, workspace_id "
        "FROM vault_entries"
    ).fetchall()
    return {
        row[0]: VaultEntry(
            token=row[0],
            pii_type=row[1],
            encrypted_value=row[2],
            transaction_id=row[3],
            created_at=row[4],
            workspace_id=row[5],
        )
        for row in rows
    }


class TokenVault:
    def __init__(
        self,
        db_path: str | None = None,
        vault_key: bytes | None = None,
    ) -> None:
        """
        vault_key: per-workspace key (see hermes.tenant_keys). When omitted the
        deployment-wide VAULT_KEY is used (legacy single-tenant).

        The key scheme is recorded in the vault_meta table. A vault that already
        holds entries encrypted with the global key keeps using it, so existing
        tokens stay decryptable; a vault created with a per-workspace key
        refuses to open without one.
        """
        self._db_path = db_path or _get_db_path()
        self._lock = threading.Lock()

        conn = sqlite3.connect(self._db_path)
        try:
            _init_db(conn)
            self._key_scheme = resolve_key_scheme(
                conn, "vault_meta", "vault_entries", vault_key
            )
            if self._key_scheme == KEY_SCHEME_PER_WORKSPACE:
                if vault_key is None:
                    raise ValueError(
                        f"Vault at {self._db_path!r} was created with a per-workspace "
                        "key. Open it via hermes.workspaces.get_vault_for_workspace()."
                    )
                if len(vault_key) != 32:
                    raise ValueError("vault_key must be exactly 32 bytes")
                self._key = vault_key
            elif self._key_scheme == KEY_SCHEME_GLOBAL:
                if vault_key is not None:
                    warnings.warn(
                        f"Vault at {self._db_path!r} predates per-workspace keys; "
                        "continuing with HERMES_VAULT_KEY so existing tokens decrypt.",
                        stacklevel=2,
                    )
                self._key = VAULT_KEY
            else:
                raise ValueError(
                    f"Unknown key_scheme {self._key_scheme!r} in {self._db_path!r}"
                )
            self._store: dict[str, VaultEntry] = _load_all_entries(conn)
        finally:
            conn.close()

    @property
    def key_scheme(self) -> str:
        """'global' (deployment-wide key) or 'per_workspace_v1'."""
        return self._key_scheme

    def store(
        self,
        pii_type: str,
        original_value: str,
        transaction_id: str,
        workspace_id: str = "default",
    ) -> str:
        token = _generate_token(pii_type, original_value, self._key)
        encrypted = _aesgcm_encrypt(original_value, self._key)
        entry = VaultEntry(
            token=token,
            pii_type=pii_type,
            encrypted_value=encrypted,
            transaction_id=transaction_id,
            workspace_id=workspace_id,
        )
        with self._lock:
            self._store[token] = entry
            self._persist(entry)
        return token

    def _persist(self, entry: VaultEntry) -> None:
        """Write a vault entry to SQLite. Called while holding self._lock."""
        conn = sqlite3.connect(self._db_path)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vault_entries
                        (token, pii_type, encrypted_value, transaction_id,
                         created_at, workspace_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (entry.token, entry.pii_type, entry.encrypted_value,
                     entry.transaction_id, entry.created_at, entry.workspace_id),
                )
        finally:
            conn.close()

    def retrieve(self, token: str, workspace_id: str = "default") -> str | None:
        """Decrypt and return original value. Raises InvalidTag if tampered."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                row = conn.execute(
                    "SELECT encrypted_value FROM vault_entries "
                    "WHERE token = ? AND workspace_id = ?",
                    (token, workspace_id),
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return _aesgcm_decrypt(row[0], self._key)

    def retrieve_entry(
        self, token: str, workspace_id: str = "default"
    ) -> VaultEntry | None:
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                row = conn.execute(
                    "SELECT token, pii_type, encrypted_value, transaction_id, "
                    "created_at, workspace_id FROM vault_entries "
                    "WHERE token = ? AND workspace_id = ?",
                    (token, workspace_id),
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        return VaultEntry(
            token=row[0],
            pii_type=row[1],
            encrypted_value=row[2],
            transaction_id=row[3],
            created_at=row[4],
            workspace_id=row[5],
        )

    def purge_transaction(
        self, transaction_id: str, workspace_id: str = "default"
    ) -> int:
        with self._lock:
            keys_to_remove = [
                k for k, v in self._store.items()
                if v.transaction_id == transaction_id
                and v.workspace_id == workspace_id
            ]
            for k in keys_to_remove:
                del self._store[k]
            conn = sqlite3.connect(self._db_path)
            try:
                with conn:
                    conn.execute(
                        "DELETE FROM vault_entries "
                        "WHERE transaction_id = ? AND workspace_id = ?",
                        (transaction_id, workspace_id),
                    )
            finally:
                conn.close()
        return len(keys_to_remove)

    def size(self) -> int:
        with self._lock:
            return len(self._store)


VAULT = TokenVault()
