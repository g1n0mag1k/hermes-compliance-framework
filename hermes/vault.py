"""
hermes/vault.py — Reversible Redaction Token Vault
"""
import hashlib
import hmac
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

def _load_vault_key() -> bytes:
    key_hex = os.environ.get("HERMES_VAULT_KEY")
    if key_hex:
        return bytes.fromhex(key_hex)
    return hashlib.sha256(b"hermes-dev-vault-key-not-for-production").digest()

VAULT_KEY: bytes = _load_vault_key()

def _xor_encrypt(plaintext: str, key: bytes) -> str:
    pt_bytes = plaintext.encode("utf-8")
    key_stream = (key * (len(pt_bytes) // len(key) + 1))[:len(pt_bytes)]
    ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, key_stream))
    return ct_bytes.hex()

def _xor_decrypt(ciphertext_hex: str, key: bytes) -> str:
    ct_bytes = bytes.fromhex(ciphertext_hex)
    key_stream = (key * (len(ct_bytes) // len(key) + 1))[:len(ct_bytes)]
    pt_bytes = bytes(a ^ b for a, b in zip(ct_bytes, key_stream))
    return pt_bytes.decode("utf-8")

def _generate_token(pii_type: str, original_value: str) -> str:
    mac = hmac.new(VAULT_KEY, original_value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
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

class TokenVault:
    def __init__(self) -> None:
        self._store: Dict[str, VaultEntry] = {}
        self._lock = threading.Lock()

    def store(self, pii_type: str, original_value: str, transaction_id: str) -> str:
        token = _generate_token(pii_type, original_value)
        encrypted = _xor_encrypt(original_value, VAULT_KEY)
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
        with self._lock:
            entry = self._store.get(token)
        if entry is None:
            return None
        return _xor_decrypt(entry.encrypted_value, VAULT_KEY)

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
