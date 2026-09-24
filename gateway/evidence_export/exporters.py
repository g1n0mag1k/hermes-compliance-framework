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


def _drata_connector_cls():
    # Deferred: drata_connector imports this module for ExportResult and _post_json.
    from gateway.evidence_export.drata_connector import DrataConnector

    return DrataConnector


class DrataExporter:
    """Thin wrapper around the canonical DrataConnector (drata_connector.py)."""

    name = "drata_cct"

    def __init__(self) -> None:
        self._connector = _drata_connector_cls()()

    def is_configured(self) -> bool:
        return self._connector.is_configured()

    @staticmethod
    def build_drata_record(event: EvidenceEvent) -> dict:
        return _drata_connector_cls().build_drata_record(event)

    @staticmethod
    def build_drata_payload(event: EvidenceEvent) -> dict:
        return _drata_connector_cls().build_drata_payload(event)

    def export(self, event: EvidenceEvent) -> ExportResult:
        return self._connector.send_evidence(event)


def get_configured_exporters() -> list[EvidenceExporter]:
    exporters: list[EvidenceExporter] = [WebhookExporter(), _drata_connector_cls()()]
    return [exporter for exporter in exporters if exporter.is_configured()]
