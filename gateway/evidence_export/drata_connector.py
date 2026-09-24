"""
gateway/evidence_export/drata_connector.py — canonical Drata connector.

This is the single Drata implementation used by gateway evidence export.
``DrataExporter`` in ``exporters.py`` is a thin wrapper around it, and the
legacy ``/v1/scrub`` path (``hermes.webhooks.dispatch_drata_cct``) is kept
only for backward compatibility.

STATUS: CONTRACT-TESTED against mocks only. NOT live-validated against a real
Drata tenant. Only behavior already present in this repository is implemented;
anything else returns UNSUPPORTED rather than guessing at Drata API contracts.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from gateway.evidence_export import exporters as _transport
from gateway.evidence_export.event import EvidenceEvent
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    ExportResult,
)
from hermes.drata_state import DrataConfigState, get_drata_config_state

logger = logging.getLogger("hermes.gateway.evidence_export")

CONNECTOR_NAME = "drata_cct"
USER_AGENT = "hermes-gateway-drata-cct/1.0"

UNSUPPORTED = "UNSUPPORTED"
NOT_CONFIGURED_ERROR = "not_configured"
PHI_SAFETY_ERROR = "phi_safety_check_failed"

TEST_CONNECTION_UNSUPPORTED_REASON = (
    "No verified read-only Drata endpoint exists in this repository to test "
    "connectivity or credentials. A real connection test will be implemented "
    "only once a safe method is confirmed (planned for Session 4)."
)


@dataclass(frozen=True)
class ConnectionResult:
    state: str
    success: bool
    reason: Optional[str] = None


class DrataConnector:
    name = CONNECTOR_NAME

    def is_configured(self) -> bool:
        return bool(os.environ.get(DRATA_CCT_URL_ENV))

    def status(self) -> dict:
        state = get_drata_config_state()
        return {
            "connector": self.name,
            "state": state.value,
            "cct_url_configured": state is not DrataConfigState.NOT_CONFIGURED,
            "api_key_configured": bool(os.environ.get(DRATA_API_KEY_ENV)),
            "connection_tested": False,
        }

    @staticmethod
    def build_drata_record(event: EvidenceEvent) -> dict:
        """Map EvidenceEvent to a Drata Custom Data Record (metadata-only fields)."""
        return {
            "id": event.event_id,
            "timestamp": event.timestamp,
            "transaction_id": event.transaction_id,
            "receipt_id": event.receipt_id,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "source": event.source,
            "workspace_id": event.workspace_id,
            "gateway_decision": event.decision,
            "upstream_contacted": event.upstream_contacted,
            "upstream_provider": event.upstream_provider,
            "endpoint_path": event.endpoint_path,
            "phi_categories_detected": event.phi_categories_detected,
            "phi_categories_redacted": event.phi_categories_redacted,
            "policy_id": event.policy_id,
            "policy_version": event.policy_version,
            "policy_digest": event.policy_digest,
            "receipt_digest": event.receipt_digest,
            "prev_receipt_digest": event.prev_receipt_digest,
            "gateway_sequence": event.gateway_sequence,
            "failure_class": event.failure_class,
            "gateway_version": event.gateway_version,
            "signature_algorithm": event.signature_algorithm,
        }

    @staticmethod
    def build_drata_payload(event: EvidenceEvent) -> dict:
        """
        Wrap the record in Drata v2 Custom Data Records request body.

        POST /custom-connections/{connectionId}/resources/{resourceId}/records
        requires a top-level ``data`` key (object or array).
        """
        return {"data": DrataConnector.build_drata_record(event)}

    def send_evidence(self, event: EvidenceEvent) -> ExportResult:
        url = os.environ.get(DRATA_CCT_URL_ENV)
        if not url:
            return ExportResult(exporter=self.name, success=False, error=NOT_CONFIGURED_ERROR)

        try:
            event.assert_phi_safe()
        except ValueError:
            logger.warning("Gateway Drata CCT evidence export refused: PHI safety check failed")
            return ExportResult(
                exporter=self.name,
                success=False,
                attempts=0,
                error=PHI_SAFETY_ERROR,
            )

        headers = {"User-Agent": USER_AGENT}
        api_key = os.environ.get(DRATA_API_KEY_ENV)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = self.build_drata_payload(event)
        # Looked up on the module at call time so exporters share one HTTP helper.
        success, attempts, error = _transport._post_json(
            url,
            payload,
            headers,
            idempotency_key=event.event_id,
        )
        if not success:
            logger.warning(
                "Gateway Drata CCT evidence export failed after %s attempt(s): %s",
                attempts,
                error,
            )
        return ExportResult(
            exporter=self.name,
            success=success,
            attempts=attempts,
            error=error,
        )

    def export(self, event: EvidenceEvent) -> ExportResult:
        return self.send_evidence(event)

    def send_test_evidence(self) -> ExportResult:
        """
        UNSUPPORTED: no safe Drata connection-test endpoint is known. Posting a
        synthetic record to HERMES_DRATA_CCT_URL would write test data into a
        real customer's Drata evidence, so no request is made.
        """
        return ExportResult(
            exporter=self.name,
            success=False,
            attempts=0,
            error=UNSUPPORTED,
        )

    def test_connection(self) -> ConnectionResult:
        """UNSUPPORTED until a safe connection-test method is confirmed. No network call."""
        return ConnectionResult(
            state=UNSUPPORTED,
            success=False,
            reason=TEST_CONNECTION_UNSUPPORTED_REASON,
        )
