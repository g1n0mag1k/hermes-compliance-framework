import hashlib
import json
import os
from dataclasses import dataclass
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


class PolicyEngine:
    def __init__(self, workspace_id: str) -> None:
        self._workspace_id = workspace_id
        self._policy = _workspace_policies.get(workspace_id, _active_policy)

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
