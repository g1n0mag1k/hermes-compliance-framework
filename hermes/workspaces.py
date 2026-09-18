"""
hermes/workspaces.py — Multi-tenant workspace model for Hermes Relay.

A workspace is a fully isolated tenant: its own API key, its own
attestation chain DB, its own vault DB, its own trial quota.

The MSP use case:
  - The MSP signs up → one workspace per MSP (their "management" workspace)
  - They add clients → one workspace per HIPAA-covered client
  - The MSP dashboard shows all their client workspaces in a table
  - Each workspace has its own receipt chain, independent of every other

Design decisions:
  - SQLite-backed: one central workspaces.db, separate per-workspace chain/vault DBs
  - API key is a 32-byte random token, stored as hex (64 chars), never shown again
  - Workspace ID is a slug: alphanumeric + hyphens, max 64 chars
  - All workspace DBs live in a configurable DATA_DIR (default: ./data/workspaces/)
  - Thread-safe: short-lived connections + a threading.Lock for the registry table
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_DATA_DIR = os.environ.get("HERMES_DATA_DIR", "data/workspaces")
_DEFAULT_REGISTRY_DB = os.environ.get(
    "HERMES_REGISTRY_DB",
    os.path.join(_DEFAULT_DATA_DIR, "registry.db"),
)

_registry_lock = threading.Lock()


def _data_dir() -> Path:
    p = Path(_DEFAULT_DATA_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _registry_db_path() -> str:
    return _DEFAULT_REGISTRY_DB


# ---------------------------------------------------------------------------
# Workspace dataclass
# ---------------------------------------------------------------------------

@dataclass
class Workspace:
    workspace_id: str
    name: str                      # human-readable display name
    owner_email: str
    api_key_hash: str              # SHA-256 of the raw API key — never store raw
    created_at: str
    plan: str                      # "trial" | "production" | "enterprise"
    parent_workspace_id: Optional[str]  # set when this workspace belongs to an MSP

    @property
    def chain_db_path(self) -> str:
        return str(_data_dir() / self.workspace_id / "chain.db")

    @property
    def vault_db_path(self) -> str:
        return str(_data_dir() / self.workspace_id / "vault.db")

    @property
    def canary_db_path(self) -> str:
        return str(_data_dir() / self.workspace_id / "canary.db")


# ---------------------------------------------------------------------------
# Registry DB init
# ---------------------------------------------------------------------------

def _init_registry(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id        TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            owner_email         TEXT NOT NULL,
            api_key_hash        TEXT NOT NULL UNIQUE,
            created_at          TEXT NOT NULL,
            plan                TEXT NOT NULL DEFAULT 'trial',
            parent_workspace_id TEXT
        );

        CREATE TABLE IF NOT EXISTS trial_quota (
            workspace_id   TEXT PRIMARY KEY,
            scans_used     INTEGER NOT NULL DEFAULT 0,
            first_scan_at  TEXT,
            extended_by    INTEGER NOT NULL DEFAULT 0
        );
    """)
    conn.commit()


def _get_registry_conn() -> sqlite3.Connection:
    # Ensure directory exists
    p = Path(_registry_db_path()).parent
    p.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_registry_db_path(), check_same_thread=False)
    _init_registry(conn)
    return conn


# ---------------------------------------------------------------------------
# API key helpers
# ---------------------------------------------------------------------------

def _generate_api_key() -> str:
    """Return a 32-byte random API key as a 64-char hex string."""
    return secrets.token_hex(32)


def _hash_api_key(raw_key: str) -> str:
    """SHA-256 of the raw API key. Only this is stored."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _api_key_matches(raw_key: str, stored_hash: str) -> bool:
    """Constant-time comparison of a raw key against a stored hash."""
    candidate_hash = _hash_api_key(raw_key)
    return hmac.compare_digest(candidate_hash, stored_hash)


# ---------------------------------------------------------------------------
# Workspace CRUD
# ---------------------------------------------------------------------------

def create_workspace(
    workspace_id: str,
    name: str,
    owner_email: str,
    plan: str = "trial",
    parent_workspace_id: Optional[str] = None,
) -> tuple[Workspace, str]:
    """
    Create a new workspace and return (Workspace, raw_api_key).

    The raw_api_key is shown ONCE to the caller and never stored.
    All subsequent auth uses api_key_hash.

    Raises:
        ValueError: if workspace_id already exists or is invalid.
    """
    _validate_workspace_id(workspace_id)

    raw_key = _generate_api_key()
    key_hash = _hash_api_key(raw_key)
    created_at = datetime.now(timezone.utc).isoformat()

    workspace = Workspace(
        workspace_id=workspace_id,
        name=name,
        owner_email=owner_email,
        api_key_hash=key_hash,
        created_at=created_at,
        plan=plan,
        parent_workspace_id=parent_workspace_id,
    )

    # Create the workspace data directory
    ws_dir = _data_dir() / workspace_id
    ws_dir.mkdir(parents=True, exist_ok=True)

    with _registry_lock:
        conn = _get_registry_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO workspaces
                        (workspace_id, name, owner_email, api_key_hash,
                         created_at, plan, parent_workspace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        workspace.workspace_id,
                        workspace.name,
                        workspace.owner_email,
                        workspace.api_key_hash,
                        workspace.created_at,
                        workspace.plan,
                        workspace.parent_workspace_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Workspace '{workspace_id}' already exists."
            ) from exc
        finally:
            conn.close()

    return workspace, raw_key


def get_workspace_by_api_key(raw_api_key: str) -> Optional[Workspace]:
    """
    Look up a workspace by its raw API key.
    Returns None if no matching workspace exists.
    """
    key_hash = _hash_api_key(raw_api_key)
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            row = conn.execute(
                """
                SELECT workspace_id, name, owner_email, api_key_hash,
                       created_at, plan, parent_workspace_id
                FROM workspaces
                WHERE api_key_hash = ?
                """,
                (key_hash,),
            ).fetchone()
        finally:
            conn.close()

    if row is None:
        return None
    return Workspace(
        workspace_id=row[0],
        name=row[1],
        owner_email=row[2],
        api_key_hash=row[3],
        created_at=row[4],
        plan=row[5],
        parent_workspace_id=row[6],
    )


def can_access_workspace(caller: Workspace, target: Workspace) -> bool:
    """
    Return True when caller may act on target's resources.

    A workspace may access itself. A parent may access its direct children.
    All other combinations (child→parent, siblings, unrelated) are denied.
    """
    if caller.workspace_id == target.workspace_id:
        return True
    if target.parent_workspace_id == caller.workspace_id:
        return True
    return False


def get_workspace(workspace_id: str) -> Optional[Workspace]:
    """Look up a workspace by its ID."""
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            row = conn.execute(
                """
                SELECT workspace_id, name, owner_email, api_key_hash,
                       created_at, plan, parent_workspace_id
                FROM workspaces WHERE workspace_id = ?
                """,
                (workspace_id,),
            ).fetchone()
        finally:
            conn.close()

    if row is None:
        return None
    return Workspace(
        workspace_id=row[0], name=row[1], owner_email=row[2],
        api_key_hash=row[3], created_at=row[4], plan=row[5],
        parent_workspace_id=row[6],
    )


def list_workspaces(parent_workspace_id: Optional[str] = None) -> list[Workspace]:
    """
    List all workspaces, optionally filtered to children of a parent.
    MSPs use this to list their client workspaces.
    """
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            if parent_workspace_id is not None:
                rows = conn.execute(
                    "SELECT workspace_id, name, owner_email, api_key_hash, "
                    "created_at, plan, parent_workspace_id "
                    "FROM workspaces WHERE parent_workspace_id = ? "
                    "ORDER BY created_at DESC",
                    (parent_workspace_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT workspace_id, name, owner_email, api_key_hash, "
                    "created_at, plan, parent_workspace_id "
                    "FROM workspaces ORDER BY created_at DESC"
                ).fetchall()
        finally:
            conn.close()

    return [
        Workspace(
            workspace_id=r[0], name=r[1], owner_email=r[2],
            api_key_hash=r[3], created_at=r[4], plan=r[5],
            parent_workspace_id=r[6],
        )
        for r in rows
    ]


def rotate_api_key(workspace_id: str) -> str:
    """
    Generate a new API key for a workspace. Returns the raw new key.
    The old key is immediately invalidated.
    """
    raw_key = _generate_api_key()
    key_hash = _hash_api_key(raw_key)
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            with conn:
                result = conn.execute(
                    "UPDATE workspaces SET api_key_hash = ? WHERE workspace_id = ?",
                    (key_hash, workspace_id),
                )
                if result.rowcount == 0:
                    raise ValueError(f"Workspace '{workspace_id}' not found.")
        finally:
            conn.close()
    return raw_key


def update_plan(workspace_id: str, plan: str) -> None:
    """Update the plan for a workspace (trial → production → enterprise)."""
    valid_plans = {"trial", "production", "enterprise"}
    if plan not in valid_plans:
        raise ValueError(f"plan must be one of {valid_plans}, got {plan!r}")
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            with conn:
                conn.execute(
                    "UPDATE workspaces SET plan = ? WHERE workspace_id = ?",
                    (plan, workspace_id),
                )
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Per-workspace trial quota
# ---------------------------------------------------------------------------

TRIAL_SCAN_LIMIT = 5
TRIAL_WINDOW_DAYS = 14


def get_trial_quota(workspace_id: str) -> tuple[int, Optional[str], int]:
    """Return (scans_used, first_scan_at, extended_by) for a workspace."""
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            row = conn.execute(
                "SELECT scans_used, first_scan_at, extended_by "
                "FROM trial_quota WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
        finally:
            conn.close()
    if row is None:
        return 0, None, 0
    return int(row[0] or 0), row[1], int(row[2] or 0)


def increment_trial_quota(workspace_id: str) -> tuple[int, str]:
    """Increment scans_used after a successful trial scan."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with _registry_lock:
        conn = _get_registry_conn()
        try:
            row = conn.execute(
                "SELECT scans_used, first_scan_at FROM trial_quota WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            with conn:
                if row is None:
                    conn.execute(
                        "INSERT INTO trial_quota (workspace_id, scans_used, first_scan_at) "
                        "VALUES (?, 1, ?)",
                        (workspace_id, now_iso),
                    )
                    return 1, now_iso
                scans_used = int(row[0] or 0) + 1
                first_scan_at = row[1] or now_iso
                conn.execute(
                    "UPDATE trial_quota SET scans_used = ? WHERE workspace_id = ?",
                    (scans_used, workspace_id),
                )
                return scans_used, first_scan_at
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Per-workspace chain/vault instances
# ---------------------------------------------------------------------------

_chain_cache: dict[str, object] = {}
_vault_cache: dict[str, object] = {}
_cache_lock = threading.Lock()


def get_chain_for_workspace(workspace: Workspace):
    """
    Return the AttestationChain for a workspace, creating it if needed.
    Instances are cached per workspace_id for the lifetime of the process.
    """
    from hermes.attestation import AttestationChain
    with _cache_lock:
        if workspace.workspace_id not in _chain_cache:
            # Ensure directory exists
            Path(workspace.chain_db_path).parent.mkdir(parents=True, exist_ok=True)
            _chain_cache[workspace.workspace_id] = AttestationChain(
                db_path=workspace.chain_db_path
            )
        return _chain_cache[workspace.workspace_id]


def get_vault_for_workspace(workspace: Workspace):
    """
    Return the TokenVault for a workspace, creating it if needed.
    Instances are cached per workspace_id for the lifetime of the process.
    """
    from hermes.vault import TokenVault
    with _cache_lock:
        if workspace.workspace_id not in _vault_cache:
            Path(workspace.vault_db_path).parent.mkdir(parents=True, exist_ok=True)
            _vault_cache[workspace.workspace_id] = TokenVault(
                db_path=workspace.vault_db_path
            )
        return _vault_cache[workspace.workspace_id]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

import re
_WORKSPACE_ID_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$')


def _validate_workspace_id(workspace_id: str) -> None:
    if not _WORKSPACE_ID_RE.match(workspace_id):
        raise ValueError(
            f"workspace_id must be 3–64 lowercase alphanumeric chars and hyphens, "
            f"starting and ending with alphanumeric. Got: {workspace_id!r}"
        )
