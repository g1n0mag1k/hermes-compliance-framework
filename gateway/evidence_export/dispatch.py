from __future__ import annotations

import logging

import httpx

from gateway.credentials import CredentialManager
from gateway.evidence_export.drata_connector import (
    CONNECTOR_NAME as DRATA_CONNECTOR_NAME,
)
from gateway.evidence_export.event import EvidenceEvent, build_evidence_event
from gateway.evidence_export.exporters import (
    EvidenceExporter,
    ExportResult,
    get_configured_exporters,
)
from gateway.evidence_export.outbox import enqueue_event, sanitize_error
from hermes.receipts.v2.builder import ReceiptV2

logger = logging.getLogger("hermes.gateway.evidence_export")


def dispatch_evidence_export(
    event: EvidenceEvent,
    exporters: list[EvidenceExporter] | None = None,
) -> list[ExportResult]:
    """
    Export evidence to all configured exporters.

    Best-effort only — failures are logged and returned but never raised.
    """
    event.assert_phi_safe()
    results: list[ExportResult] = []
    if exporters is None:
        exporters = get_configured_exporters()
    for exporter in exporters:
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


def try_export_evidence(receipt: ReceiptV2, workspace_id: str) -> list[ExportResult] | None:
    """
    Build and export gateway evidence after receipt persistence.

    Drata evidence is only written to the local outbox here; the Drata network
    call happens later in ``outbox.flush_outbox``. Results cover inline
    exporters only. Returns None when no exporters are configured. Never raises.
    """
    exporters = get_configured_exporters()
    if not exporters:
        return None

    try:
        event = build_evidence_event(receipt, workspace_id)
    except Exception as exc:
        logger.warning("Gateway evidence export skipped due to error: %s", exc)
        return []

    inline_exporters = [e for e in exporters if e.name != DRATA_CONNECTOR_NAME]
    if len(inline_exporters) != len(exporters):
        try:
            enqueue_event(event)
        except Exception as exc:
            logger.warning(
                "Gateway evidence outbox write failed for event %s: %s",
                event.event_id,
                sanitize_error(str(exc)),
            )

    if not inline_exporters:
        return []
    try:
        return dispatch_evidence_export(event, inline_exporters)
    except Exception as exc:
        logger.warning("Gateway evidence export skipped due to error: %s", exc)
        return []


async def dispatch_psa_ticket(
    tenant_id: str,
    failed_category: str,
    evidence_url: str,
    drift_detected: bool = True,
) -> None:
    """
    Open a PSA ticket for detected canary drift.

    Best-effort only — missing config and network failures are swallowed.
    """
    try:
        manager = CredentialManager()
        config = manager.get_psa_config(tenant_id)
        if config is None:
            return

        psa_type = config["psa_type"]
        base_url = config["base_url"].rstrip("/")
        api_token = config["api_token"]
        client_id = config.get("client_id") or ""

        if psa_type == "halopsa":
            url = f"{base_url}/api/Tickets"
            payload = {
                "summary": f"Hermes Relay Drift Detected: {failed_category}",
                "details": f"Audit evidence: {evidence_url}",
                "client_id": tenant_id,
                "tickettype_id": 1,
            }
            headers = {"Authorization": f"Bearer {api_token}"}
        elif psa_type == "connectwise":
            url = f"{base_url}/v4_6_release/apis/3.0/service/tickets"
            payload = {
                "summary": f"Hermes Relay Alert: {failed_category} Drift",
                "company": {"identifier": tenant_id},
                "initialDescription": f"Audit evidence: {evidence_url}",
                "recordType": "ServiceTicket",
            }
            headers = {
                "Authorization": f"Basic {api_token}",
                "clientId": client_id,
            }
        else:
            return

        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, headers=headers)
    except Exception as exc:
        logger.warning("PSA ticket dispatch failed silently: %s", exc)
