import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

PolicyDecision = Literal["ALLOW", "REDACT", "BLOCK"]


@dataclass
class Policy:
    policy_id: str
    policy_version: str
    text_action: PolicyDecision
    binary_action: PolicyDecision
    on_detector_error: PolicyDecision
    on_parse_error: PolicyDecision
    approved_providers: list[str]

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            {
                k: getattr(self, k)
                for k in [
                    "policy_id",
                    "policy_version",
                    "text_action",
                    "binary_action",
                    "on_detector_error",
                    "on_parse_error",
                    "approved_providers",
                ]
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


_workspace_policies: dict[str, Policy] = {}

HIPAA_STRICT = Policy(
    policy_id="HIPAA_STRICT",
    policy_version="1.0.0",
    text_action="REDACT",
    binary_action="BLOCK",
    on_detector_error="BLOCK",
    on_parse_error="BLOCK",
    approved_providers=["openai", "azure_openai", "anthropic"],
)

# Explicit production blocking profile — PHI detected → BLOCK (never silent REDACT).
HIPAA_PRODUCTION_BLOCK = Policy(
    policy_id="HIPAA_PRODUCTION_BLOCK",
    policy_version="1.0.0",
    text_action="BLOCK",
    binary_action="BLOCK",
    on_detector_error="BLOCK",
    on_parse_error="BLOCK",
    approved_providers=["openai", "azure_openai", "anthropic"],
)

_POLICY_BY_ID = {
    "HIPAA_STRICT": HIPAA_STRICT,
    "HIPAA_PRODUCTION_BLOCK": HIPAA_PRODUCTION_BLOCK,
}


def _policy_from_env() -> Policy:
    policy_id = os.environ.get("HERMES_GATEWAY_POLICY", "HIPAA_STRICT")
    policy = _POLICY_BY_ID.get(policy_id)
    if policy is None:
        raise RuntimeError(
            f"Unknown HERMES_GATEWAY_POLICY {policy_id!r}. "
            f"Supported: {sorted(_POLICY_BY_ID)}"
        )
    return policy


_active_policy: Policy = _policy_from_env()


@dataclass
class EnforcementDecision:
    decision: PolicyDecision
    reasons: list[str]
    policy_id: str
    policy_version: str
    policy_digest: str
    content_types_inspected: list[str]
    content_types_not_inspected: list[str]
    all_detectors_clean: bool


# ---------------------------------------------------------------------------
# Persisted per-workspace policy assignments (multi-tenant)
# ---------------------------------------------------------------------------
# The API process writes assignments; the gateway process reads them on every
# request, so a change made through the API takes effect on the next gateway
# request with no restart and no cross-process cache to invalidate.
#
# Precedence in PolicyEngine: in-process override (set_workspace_policy, used by
# tests/admin) > persisted assignment > deployment default (_active_policy).

_policy_db_lock = threading.Lock()


def _policy_db_path() -> str:
    explicit = os.environ.get("HERMES_POLICY_DB")
    if explicit:
        return explicit
    from hermes.workspaces import _data_dir

    return str(_data_dir() / "workspace_policies.db")


def _policy_conn() -> sqlite3.Connection:
    from pathlib import Path

    path = _policy_db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workspace_policies (
            workspace_id TEXT PRIMARY KEY,
            policy_id    TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        )
        """
    )
    return conn


def get_policy_by_id(policy_id: str) -> Policy:
    policy = _POLICY_BY_ID.get(policy_id)
    if policy is None:
        raise ValueError(
            f"Unknown policy_id {policy_id!r}. Supported: {sorted(_POLICY_BY_ID)}"
        )
    return policy


def available_policy_ids() -> list[str]:
    return sorted(_POLICY_BY_ID)


def save_workspace_policy(workspace_id: str, policy_id: str) -> Policy:
    """Persist a policy assignment for a workspace. Raises ValueError if unknown."""
    policy = get_policy_by_id(policy_id)
    with _policy_db_lock:
        conn = _policy_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO workspace_policies (workspace_id, policy_id, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(workspace_id) DO UPDATE SET
                        policy_id = excluded.policy_id,
                        updated_at = excluded.updated_at
                    """,
                    (workspace_id, policy_id, datetime.now(UTC).isoformat()),
                )
        finally:
            conn.close()
    return policy


def delete_workspace_policy(workspace_id: str) -> bool:
    """Remove a persisted assignment (workspace reverts to the default)."""
    with _policy_db_lock:
        conn = _policy_conn()
        try:
            with conn:
                cur = conn.execute(
                    "DELETE FROM workspace_policies WHERE workspace_id = ?",
                    (workspace_id,),
                )
        finally:
            conn.close()
    return cur.rowcount > 0


def load_persisted_policy(workspace_id: str) -> Policy | None:
    """
    Return the persisted policy for a workspace, or None if none is assigned.

    Fails closed: if the store cannot be read, or holds a policy_id this build
    does not know, raises RuntimeError rather than silently applying a weaker
    default policy. The gateway turns RuntimeError into a 503.
    """
    try:
        with _policy_db_lock:
            conn = _policy_conn()
            try:
                row = conn.execute(
                    "SELECT policy_id FROM workspace_policies WHERE workspace_id = ?",
                    (workspace_id,),
                ).fetchone()
            finally:
                conn.close()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Workspace policy store unavailable: {exc}") from exc
    if row is None:
        return None
    policy = _POLICY_BY_ID.get(row[0])
    if policy is None:
        raise RuntimeError(
            f"Workspace {workspace_id!r} is assigned unknown policy {row[0]!r}"
        )
    return policy


def resolve_workspace_policy(workspace_id: str) -> tuple[Policy, str]:
    """Return (policy, source) where source is 'override', 'workspace' or 'default'."""
    override = _workspace_policies.get(workspace_id)
    if override is not None:
        return override, "override"
    persisted = load_persisted_policy(workspace_id)
    if persisted is not None:
        return persisted, "workspace"
    return _active_policy, "default"


class PolicyEngine:
    def __init__(self, workspace_id: str) -> None:
        self._workspace_id = workspace_id
        self._policy, self._policy_source = resolve_workspace_policy(workspace_id)

    def get_policy(self) -> Policy:
        return self._policy

    def decide(
        self,
        flags_triggered: dict[str, int],
        flags_redacted: dict[str, int],
        all_detectors_clean: bool,
        content_type: str,
        parse_error: bool = False,
        has_binary_content: bool = False,
    ) -> EnforcementDecision:
        policy = self._policy
        reasons: list[str] = []
        content_types_inspected: list[str] = []
        content_types_not_inspected: list[str] = []

        if content_type:
            if has_binary_content:
                content_types_not_inspected.append(content_type)
            else:
                content_types_inspected.append(content_type)

        if parse_error:
            return EnforcementDecision(
                decision=policy.on_parse_error,
                reasons=["JSON parse error"],
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_digest=policy.digest,
                content_types_inspected=content_types_inspected,
                content_types_not_inspected=content_types_not_inspected,
                all_detectors_clean=all_detectors_clean,
            )

        if not all_detectors_clean:
            return EnforcementDecision(
                decision=policy.on_detector_error,
                reasons=["Detector failure during inspection"],
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_digest=policy.digest,
                content_types_inspected=content_types_inspected,
                content_types_not_inspected=content_types_not_inspected,
                all_detectors_clean=False,
            )

        if has_binary_content:
            return EnforcementDecision(
                decision=policy.binary_action,
                reasons=["Binary content not inspected"],
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_digest=policy.digest,
                content_types_inspected=content_types_inspected,
                content_types_not_inspected=content_types_not_inspected,
                all_detectors_clean=all_detectors_clean,
            )

        if flags_triggered:
            action = policy.text_action
            reasons.append("PHI detected in request content")
            return EnforcementDecision(
                decision=action,
                reasons=reasons,
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_digest=policy.digest,
                content_types_inspected=content_types_inspected,
                content_types_not_inspected=content_types_not_inspected,
                all_detectors_clean=all_detectors_clean,
            )

        return EnforcementDecision(
            decision="ALLOW",
            reasons=["No PHI detected"],
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            policy_digest=policy.digest,
            content_types_inspected=content_types_inspected,
            content_types_not_inspected=content_types_not_inspected,
            all_detectors_clean=all_detectors_clean,
        )


def reload_policy() -> None:
    """Hot-reload the active gateway policy from environment defaults."""
    global _active_policy
    _active_policy = _policy_from_env()


def set_workspace_policy(workspace_id: str, policy: Policy) -> None:
    """Assign a workspace-specific policy override (used in tests/admin)."""
    _workspace_policies[workspace_id] = policy


def clear_workspace_policy(workspace_id: str) -> None:
    _workspace_policies.pop(workspace_id, None)


def set_active_policy(policy: Policy) -> None:
    global _active_policy
    _active_policy = policy
