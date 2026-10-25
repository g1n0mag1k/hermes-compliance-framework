"""
hermes/gateway_integration.py — bridge module for hermes→gateway calls.

ARCHITECTURE NOTE
-----------------
The canonical dependency direction is:

    hermes  (core PHI/scrub/receipt domain)
      ↑
    gateway (AI proxy, evidence export, Drata CCT)

``hermes`` must NOT import ``gateway`` at the module level because that
would create a circular dependency (gateway already imports hermes
classifiers and receipt types).

Endpoints in ``hermes.api`` that need gateway capabilities (Drata CCT
status, outbox stats, PSA ticket dispatch) MUST call the helpers in
this module rather than importing gateway packages directly.  This
module is the single permitted bridging point.  All imports here are
lazy (inside functions) so that ``import hermes`` never triggers
``import gateway`` at startup.

When the hermes/gateway split is eventually formalised into separate
services or packages, replace these helpers with HTTP client calls or
remove them; do not add new direct ``from gateway.*`` imports elsewhere
in the ``hermes`` package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gateway.evidence_export.drata_connector import ConnectionResult


# ---------------------------------------------------------------------------
# Drata / CCT helpers
# ---------------------------------------------------------------------------


def drata_test_connection() -> ConnectionResult:
    """Return the offline structural connection result for the Drata CCT connector."""
    from gateway.evidence_export.drata_connector import DrataConnector

    return DrataConnector().test_connection()


def drata_outbox_stats(workspace_id: str) -> dict:
    """Return evidence outbox counters for *workspace_id*."""
    from gateway.evidence_export.outbox import outbox_stats

    return outbox_stats(workspace_id)


def drata_sanitize_error(message: str) -> str:
    """Redact any PHI-like tokens from an outbox error string."""
    from gateway.evidence_export.outbox import sanitize_error

    return sanitize_error(message)


def dispatch_psa_ticket(workspace_id: str, failed_category: str, evidence_url: str) -> None:
    """Open a PSA ticket for a drift event (background-task safe)."""
    import asyncio

    from gateway.evidence_export.dispatch import dispatch_psa_ticket as _dispatch

    asyncio.run(_dispatch(workspace_id, failed_category, evidence_url))


# ---------------------------------------------------------------------------
# Gateway evidence / receipt helpers
# ---------------------------------------------------------------------------


def list_gateway_receipts(workspace) -> list:
    """Return all gateway receipts for *workspace* as ordered dicts."""
    from gateway.evidence import list_gateway_receipts as _list

    return _list(workspace)


# ---------------------------------------------------------------------------
# Multi-tenant gateway configuration helpers (policy + provider credentials)
# ---------------------------------------------------------------------------


def gateway_available_policy_ids() -> list[str]:
    from gateway.policy import available_policy_ids

    return available_policy_ids()


def gateway_resolve_workspace_policy(workspace_id: str) -> dict:
    """Return the effective gateway policy for a workspace as a plain dict."""
    from gateway.policy import resolve_workspace_policy

    policy, source = resolve_workspace_policy(workspace_id)
    return {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_digest": policy.digest,
        "source": source,
    }


def gateway_save_workspace_policy(workspace_id: str, policy_id: str) -> None:
    """Persist a policy assignment. Raises ValueError for unknown policy_id."""
    from gateway.policy import save_workspace_policy

    save_workspace_policy(workspace_id, policy_id)


def gateway_delete_workspace_policy(workspace_id: str) -> bool:
    from gateway.policy import delete_workspace_policy

    return delete_workspace_policy(workspace_id)


def gateway_set_provider_credential(
    workspace_id: str, provider_id: str, credential: str, base_url: str | None
) -> None:
    """Store an encrypted provider credential. Raises ValueError on bad input."""
    from gateway.credentials import ProviderCredentialStore

    ProviderCredentialStore().set_credential(
        workspace_id, provider_id, credential, base_url
    )


def gateway_list_provider_credentials(workspace_id: str) -> list[dict]:
    """Metadata only — never returns credential values."""
    from gateway.credentials import ProviderCredentialStore

    return ProviderCredentialStore().list_configured(workspace_id)


def gateway_delete_provider_credential(workspace_id: str, provider_id: str) -> bool:
    from gateway.credentials import ProviderCredentialStore

    return ProviderCredentialStore().delete_credential(workspace_id, provider_id)


def gateway_provider_ids() -> list[str]:
    from gateway.providers import PROVIDER_REGISTRY

    return sorted(PROVIDER_REGISTRY)
