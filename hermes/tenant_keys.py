"""
hermes/tenant_keys.py — Per-workspace key derivation.

Every workspace gets its own HMAC signing key and its own vault key, derived
from the deployment's root keys (HERMES_SIGNING_KEY / HERMES_VAULT_KEY):

    workspace_key = HMAC-SHA256(root_key, "hermes-relay:<purpose>:v1:<workspace_id>")

Properties:
  - Deterministic: the same root key + workspace_id always yields the same key,
    so nothing secret has to be stored per workspace.
  - Isolated: knowing one workspace's derived key reveals nothing about another
    workspace's key or about the root key.
  - Domain-separated: the purpose label keeps the attestation key and the vault
    key distinct even when an operator reuses the same root value for both.

Root keys are taken from the already-validated module globals
(hermes.attestation.SIGNING_KEY, hermes.vault.VAULT_KEY) so production
validation of HERMES_SIGNING_KEY / HERMES_VAULT_KEY happens in exactly one place.
"""
from __future__ import annotations

import hashlib
import hmac

PURPOSE_ATTESTATION = "attestation"
PURPOSE_VAULT = "vault"
PURPOSE_PROVIDER_CREDENTIALS = "provider-credentials"

_VALID_PURPOSES = frozenset(
    {PURPOSE_ATTESTATION, PURPOSE_VAULT, PURPOSE_PROVIDER_CREDENTIALS}
)

# Key scheme markers written into each per-workspace SQLite DB (chain_meta /
# vault_meta tables) so a DB is always opened with the key it was written with.
KEY_SCHEME_GLOBAL = "global"
KEY_SCHEME_PER_WORKSPACE = "per_workspace_v1"


def derive_workspace_key(root_key: bytes, purpose: str, workspace_id: str) -> bytes:
    """Return a 32-byte key for (purpose, workspace_id) derived from root_key."""
    if purpose not in _VALID_PURPOSES:
        raise ValueError(f"Unknown key purpose {purpose!r}")
    if not workspace_id:
        raise ValueError("workspace_id is required for key derivation")
    if not root_key:
        raise ValueError("root_key must be non-empty")
    label = f"hermes-relay:{purpose}:v1:{workspace_id}".encode()
    return hmac.new(root_key, label, hashlib.sha256).digest()


def workspace_signing_key(workspace_id: str) -> bytes:
    """Per-workspace HMAC key for the V1 attestation chain."""
    from hermes.attestation import SIGNING_KEY

    return derive_workspace_key(SIGNING_KEY, PURPOSE_ATTESTATION, workspace_id)


def workspace_vault_key(workspace_id: str) -> bytes:
    """Per-workspace AES-256-GCM / token-HMAC key for the token vault."""
    from hermes.vault import VAULT_KEY

    return derive_workspace_key(VAULT_KEY, PURPOSE_VAULT, workspace_id)


def workspace_credential_key(workspace_id: str) -> bytes:
    """Per-workspace AES-256-GCM key for encrypting stored AI provider credentials."""
    from hermes.vault import VAULT_KEY

    return derive_workspace_key(
        VAULT_KEY, PURPOSE_PROVIDER_CREDENTIALS, workspace_id
    )


# Fixed SQL per (meta_table, data_table) pair. No table names are interpolated
# at runtime, so there is no string-built SQL for a scanner (or reviewer) to doubt.
_KEY_SCHEME_SQL = {
    ("chain_meta", "receipts"): {
        "create": "CREATE TABLE IF NOT EXISTS chain_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "select": "SELECT value FROM chain_meta WHERE key = 'key_scheme'",
        "has_data": "SELECT 1 FROM receipts LIMIT 1",
        "insert": "INSERT OR IGNORE INTO chain_meta (key, value) VALUES ('key_scheme', ?)",
    },
    ("vault_meta", "vault_entries"): {
        "create": "CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        "select": "SELECT value FROM vault_meta WHERE key = 'key_scheme'",
        "has_data": "SELECT 1 FROM vault_entries LIMIT 1",
        "insert": "INSERT OR IGNORE INTO vault_meta (key, value) VALUES ('key_scheme', ?)",
    },
}


def resolve_key_scheme(
    conn,
    meta_table: str,
    data_table: str,
    requested_key: bytes | None,
) -> str:
    """
    Decide which key scheme an existing (or new) SQLite DB uses and record it.

    - meta row present          -> honor it
    - no meta, data rows exist  -> 'global' (DB predates per-workspace keys;
                                   it was written with the root key)
    - no meta, no data rows     -> 'per_workspace_v1' if a key was requested,
                                   else 'global'

    The caller decides what to do with the result. This never rewrites or
    re-signs existing rows.
    """
    sql = _KEY_SCHEME_SQL.get((meta_table, data_table))
    if sql is None:
        raise ValueError(f"Unexpected table pair {(meta_table, data_table)!r}")

    with conn:
        conn.execute(sql["create"])
        row = conn.execute(sql["select"]).fetchone()
        if row is not None:
            return row[0]

        has_data = conn.execute(sql["has_data"]).fetchone()
        if has_data is not None or requested_key is None:
            scheme = KEY_SCHEME_GLOBAL
        else:
            scheme = KEY_SCHEME_PER_WORKSPACE
        conn.execute(sql["insert"], (scheme,))
        # Re-read in case a concurrent opener won the INSERT race.
        return conn.execute(sql["select"]).fetchone()[0]
