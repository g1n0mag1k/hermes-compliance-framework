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
    from gateway.evidence_export.drata_connector import ConnectionResult, DrataConnector
    from gateway.evidence_export.outbox import OutboxStats


# ---------------------------------------------------------------------------
# Drata / CCT helpers
# ---------------------------------------------------------------------------


def drata_test_connection() -> "ConnectionResult":
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
    from gateway.evidence_export.dispatch import dispatch_psa_ticket as _dispatch

    _dispatch(workspace_id, failed_category, evidence_url)


# ---------------------------------------------------------------------------
# Gateway evidence / receipt helpers
# ---------------------------------------------------------------------------


def list_gateway_receipts(workspace) -> list:
    """Return all gateway receipts for *workspace* as ordered dicts."""
    from gateway.evidence import list_gateway_receipts as _list

    return _list(workspace)
