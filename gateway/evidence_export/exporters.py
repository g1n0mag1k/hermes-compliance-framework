from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional, Protocol

from gateway.evidence_export.event import EvidenceEvent

logger = logging.getLogger("hermes.gateway.evidence_export")

WEBHOOK_URL_ENV = "HERMES_WEBHOOK_URL"
WEBHOOK_AUTH_HEADER_ENV = "HERMES_WEBHOOK_AUTH_HEADER"
WEBHOOK_AUTH_VALUE_ENV = "HERMES_WEBHOOK_AUTH_VALUE"
DRATA_CCT_URL_ENV = "HERMES_DRATA_CCT_URL"
DRATA_API_KEY_ENV = "HERMES_DRATA_API_KEY"

DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_RETRIES = 2
RETRY_BACKOFF_SECONDS = 0.25


@dataclass(frozen=True)
class ExportResult:
    exporter: str
    success: bool
    attempts: int = 1
    error: Optional[str] = None


class EvidenceExporter(Protocol):
    name: str

    def is_configured(self) -> bool: ...

    def export(self, event: EvidenceEvent) -> ExportResult: ...


def _post_json(
    url: str,
    payload: dict,
    headers: dict[str, str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    idempotency_key: Optional[str] = None,
) -> tuple[bool, int, Optional[str]]:
    """POST JSON with bounded retries on 5xx and transient network errors."""
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    request_headers = {
        "Content-Type": "application/json",
        **headers,
    }
    if idempotency_key:
        request_headers["X-Idempotency-Key"] = idempotency_key

    last_error: Optional[str] = None
    attempts = 0

    for attempt in range(MAX_RETRIES + 1):
        attempts = attempt + 1
        req = urllib.request.Request(url, data=data, headers=request_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if 200 <= resp.status < 300:
                    return True, attempts, None
                last_error = f"HTTP {resp.status}"
                if resp.status < 500 or attempt >= MAX_RETRIES:
                    return False, attempts, last_error
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code < 500 or attempt >= MAX_RETRIES:
                return False, attempts, last_error
        except urllib.error.URLError as exc:
            last_error = str(exc.reason)
            if attempt >= MAX_RETRIES:
                return False, attempts, last_error
        except Exception as exc:
            last_error = str(exc)
            if attempt >= MAX_RETRIES:
                return False, attempts, last_error

        time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))

    return False, attempts, last_error


class WebhookExporter:
    name = "webhook"

    def is_configured(self) -> bool:
        return bool(os.environ.get(WEBHOOK_URL_ENV))

    def export(self, event: EvidenceEvent) -> ExportResult:
        url = os.environ.get(WEBHOOK_URL_ENV)
        if not url:
            return ExportResult(exporter=self.name, success=False, error="not_configured")

        headers = {"User-Agent": "hermes-gateway-evidence/1.0"}
        auth_header = os.environ.get(WEBHOOK_AUTH_HEADER_ENV)
        auth_value = os.environ.get(WEBHOOK_AUTH_VALUE_ENV)
        if auth_header and auth_value:
            headers[auth_header] = auth_value

        success, attempts, error = _post_json(
            url,
            event.to_dict(),
            headers,
            idempotency_key=event.event_id,
        )
        if not success:
            logger.warning(
                "Gateway webhook evidence export failed after %s attempt(s): %s",
                attempts,
                error,
            )
        return ExportResult(
            exporter=self.name,
            success=success,
            attempts=attempts,
            error=error,
        )


class DrataExporter:
    name = "drata_cct"

    def is_configured(self) -> bool:
        return bool(os.environ.get(DRATA_CCT_URL_ENV))

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
        return {"data": DrataExporter.build_drata_record(event)}

    def export(self, event: EvidenceEvent) -> ExportResult:
        url = os.environ.get(DRATA_CCT_URL_ENV)
        if not url:
            return ExportResult(exporter=self.name, success=False, error="not_configured")

        headers = {"User-Agent": "hermes-gateway-drata-cct/1.0"}
        api_key = os.environ.get(DRATA_API_KEY_ENV)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = self.build_drata_payload(event)
        success, attempts, error = _post_json(
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


def get_configured_exporters() -> list[EvidenceExporter]:
    exporters: list[EvidenceExporter] = [WebhookExporter(), DrataExporter()]
    return [exporter for exporter in exporters if exporter.is_configured()]
