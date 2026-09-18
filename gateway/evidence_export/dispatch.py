from __future__ import annotations

import logging
from typing import Optional

from gateway.evidence_export.event import EvidenceEvent, build_evidence_event
from gateway.evidence_export.exporters import ExportResult, get_configured_exporters
from hermes.receipts.v2.builder import ReceiptV2

logger = logging.getLogger("hermes.gateway.evidence_export")


def dispatch_evidence_export(event: EvidenceEvent) -> list[ExportResult]:
    """
    Export evidence to all configured exporters.

    Best-effort only — failures are logged and returned but never raised.
    """
    event.assert_phi_safe()
    results: list[ExportResult] = []
    for exporter in get_configured_exporters():
        try:
            results.append(exporter.export(event))
        except Exception as exc:
            logger.warning(
                "Gateway evidence exporter %s raised unexpectedly: %s",
                exporter.name,
                exc,
            )
            results.append(
                ExportResult(
                    exporter=exporter.name,
                    success=False,
                    error=str(exc),
                )
            )
    return results


def try_export_evidence(receipt: ReceiptV2, workspace_id: str) -> Optional[list[ExportResult]]:
    """
    Build and export gateway evidence after receipt persistence.

    Returns None when no exporters are configured. Never raises.
    """
    exporters = get_configured_exporters()
    if not exporters:
        return None

    try:
        event = build_evidence_event(receipt, workspace_id)
        return dispatch_evidence_export(event)
    except Exception as exc:
        logger.warning("Gateway evidence export skipped due to error: %s", exc)
        return []
