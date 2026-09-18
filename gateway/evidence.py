from __future__ import annotations

import threading
from typing import Optional

from hermes.receipts.v2.builder import ReceiptV2, ReceiptV2Builder
from hermes.receipts.v2.software_signer import SoftwareSignerEd25519
from hermes.workspaces import Workspace, get_chain_for_workspace

from gateway import __version__
from gateway.policy import EnforcementDecision, PolicyDecision

_GATEWAY_SIGNER = SoftwareSignerEd25519.generate()
_v2_chain_heads: dict[str, Optional[str]] = {}
_chain_lock = threading.Lock()


def _decision_label(decision: PolicyDecision) -> str:
    return {
        "ALLOW": "allowed",
        "REDACT": "redacted",
        "BLOCK": "blocked",
    }[decision]


def issue_gateway_receipt(
    workspace: Workspace,
    transaction_id: str,
    decision: EnforcementDecision,
    provider_id: str,
    endpoint_path: str,
    flags_triggered: dict[str, int],
    flags_redacted: dict[str, int],
    detectors_executed: dict[str, str],
) -> ReceiptV2:
    """Issue a V2 COSE_Sign1 receipt linked to the workspace receipt chain."""
    get_chain_for_workspace(workspace)

    with _chain_lock:
        prev_digest = _v2_chain_heads.get(workspace.workspace_id)

    payload = {
        "transaction_id": transaction_id,
        "gateway_decision": _decision_label(decision.decision),
        "upstream_provider": provider_id,
        "endpoint_path": endpoint_path,
        "phi_categories_detected": sorted(flags_triggered.keys()),
        "phi_categories_redacted": sorted(flags_redacted.keys()),
        "content_types_inspected": decision.content_types_inspected,
        "content_types_not_inspected": decision.content_types_not_inspected,
        "detector_states": detectors_executed,
        "policy_version": decision.policy_version,
        "policy_digest": decision.policy_digest,
        "policy_id": decision.policy_id,
        "gateway_version": __version__,
        "workspace_id": workspace.workspace_id,
        "all_detectors_clean": decision.all_detectors_clean,
    }

    builder = ReceiptV2Builder(_GATEWAY_SIGNER)
    receipt = builder.build(payload, prev_receipt_digest=prev_digest)

    with _chain_lock:
        _v2_chain_heads[workspace.workspace_id] = receipt.receipt_digest

    return receipt


def get_v2_chain_head(workspace_id: str) -> Optional[str]:
    with _chain_lock:
        return _v2_chain_heads.get(workspace_id)


def reset_v2_chains() -> None:
    with _chain_lock:
        _v2_chain_heads.clear()
