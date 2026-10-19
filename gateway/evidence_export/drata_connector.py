"""
gateway/evidence_export/drata_connector.py — canonical Drata connector.

This is the single Drata implementation used by gateway evidence export.
``DrataExporter`` in ``exporters.py`` is a thin wrapper around it, and the
legacy ``/v1/scrub`` path (``hermes.webhooks.dispatch_drata_cct``) is kept
only for backward compatibility.

STATUS: CONTRACT-TESTED against mocks only. NOT live-validated against a real
Drata tenant. Only behavior already present in this repository is implemented;
anything else returns UNSUPPORTED rather than guessing at Drata API contracts.
``test_connection()`` is an offline structural check, not a live test.
``send_evidence()`` refuses to send to a non-https HERMES_DRATA_CCT_URL.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from gateway.evidence_export import exporters as _transport
from gateway.evidence_export.event import EvidenceEvent
from gateway.evidence_export.exporters import (
    DRATA_API_KEY_ENV,
    DRATA_CCT_URL_ENV,
    ExportResult,
)
from hermes.drata_state import (
    DrataConfigState,
    DrataConnectionState,
    check_drata_config,
    get_drata_config_state,
    is_https_url,
)

logger = logging.getLogger("hermes.gateway.evidence_export")

CONNECTOR_NAME = "drata_cct"
USER_AGENT = "hermes-gateway-drata-cct/1.0"

UNSUPPORTED = "UNSUPPORTED"
NOT_CONFIGURED_ERROR = "not_configured"
PHI_SAFETY_ERROR = "phi_safety_check_failed"
INSECURE_URL_ERROR = "insecure_url_refused"

INSECURE_URL_WARNING = (
    "HERMES_DRATA_CCT_URL is set but does not use https://; Drata credentials "
    "and evidence will not be sent over an insecure transport"
)

TEST_CONNECTION_UNSUPPORTED_REASON = (
    "Live Drata connection validation is not supported. No verified read-only "
    "Drata endpoint exists in this repository, and posting to the CCT URL would "
    "write a record into a real Drata tenant. Only a structural configuration "
    "check is available, and it does NOT prove Drata accepts these credentials "
    "or this URL."
)

SEND_TEST_EVIDENCE_UNSUPPORTED_REASON = (
    "Sending test evidence to Drata is not supported. The only verified Drata "
    "transport is the CCT POST URL, which writes records into a real customer's "
    "Drata tenant, and no Drata sandbox or test endpoint is known. No request "
    "was made."
)


@dataclass(frozen=True)
class ConnectionResult:
    """
    success is True only when the structural config check passed. It never
    means Drata accepted anything: live_validated is False on every result
    because no network call is ever made.
    """

    state: str
    success: bool
    reason: str | None = None
    live_validated: bool = False


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

        if not is_https_url(url):
            logger.warning(INSECURE_URL_WARNING)
            return ExportResult(
                exporter=self.name,
                success=False,
                attempts=0,
                error=INSECURE_URL_ERROR,
            )

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
            reason=SEND_TEST_EVIDENCE_UNSUPPORTED_REASON,
        )

    def test_connection(self, live: bool = False) -> ConnectionResult:
        """
        Offline structural check of the Drata CCT configuration. No network call.

        Returns NOT_CONFIGURED, CONFIG_INVALID, or CONFIGURED. A URL without an
        API key is CONFIG_INVALID: the URL alone decides NOT_CONFIGURED vs.
        not, but CONFIGURED requires the key. live=True requests live
        validation, which is UNSUPPORTED; CONNECTION_SUCCESS and
        CONNECTION_FAILED are reserved for it and never returned today.
        """
        # IMPORTANT: A structural config check is not a live connection test.
        # It proves only that the connector is minimally configured.
        # It does NOT prove Drata accepts these credentials or this URL.
        # Live validation remains pending until a real Drata tenant is tested.
        if live:
            return ConnectionResult(
                state=DrataConnectionState.UNSUPPORTED.value,
                success=False,
                reason=TEST_CONNECTION_UNSUPPORTED_REASON,
                live_validated=False,
            )

        state, reason = check_drata_config()
        url = os.environ.get(DRATA_CCT_URL_ENV)
        if url and not is_https_url(url):
            logger.warning(INSECURE_URL_WARNING)
        return ConnectionResult(
            state=state.value,
            success=state is DrataConnectionState.CONFIGURED,
            reason=reason,
            live_validated=False,
        )
