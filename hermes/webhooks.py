"""
hermes/webhooks.py — Generic JSON webhook dispatcher for SIEM/DLP event export.

Fires a structured JSON event to a configured HTTP endpoint whenever a scrub
occurs. This is the real implementation behind the "JSON event export / HTTP
ingest" and "REST webhook / synthetic alert" claims on hermesrelay.dev's
Integrations section -- one generic exporter, any destination that accepts a
JSON POST (Splunk HTTP Event Collector, generic SIEM webhook intake, DLP
platform custom actions, etc.).

Uses only the Python standard library (urllib) -- no new dependency required.

Configuration (all via environment variables, unset = disabled):
    HERMES_WEBHOOK_URL          Destination URL. If unset, dispatch is a no-op.
    HERMES_WEBHOOK_AUTH_HEADER  Optional header name (e.g. "Authorization").
    HERMES_WEBHOOK_AUTH_VALUE   Optional header value (e.g. "Splunk abc123...").

Explicitly out of scope today: platforms requiring per-request HMAC-signed
auth (e.g. Azure Sentinel's Log Analytics Data Collector API) are not yet
supported -- that requires a signing implementation beyond a static header
and is tracked as follow-up work, not claimed as shipped.
"""
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Optional

from hermes.attestation import ComplianceReceipt

logger = logging.getLogger("hermes.webhooks")

WEBHOOK_URL_ENV_VAR = "HERMES_WEBHOOK_URL"
WEBHOOK_AUTH_HEADER_ENV_VAR = "HERMES_WEBHOOK_AUTH_HEADER"
WEBHOOK_AUTH_VALUE_ENV_VAR = "HERMES_WEBHOOK_AUTH_VALUE"
WEBHOOK_TIMEOUT_SECONDS = 3.0


def build_event_payload(receipt: ComplianceReceipt, event_type: str = "scrub") -> dict:
    """
    Build the platform-agnostic JSON event Hermes exports for every scrubbing
    decision: field-level PHI classes, compliance frameworks, hash chain
    position, and timestamp.
    """
    return {
        "event_type": event_type,
        "source": "hermes-relay",
        "receipt_id": receipt.receipt_id,
        "transaction_id": receipt.transaction_id,
        "issued_at": receipt.issued_at,
        "compliance_frameworks": receipt.compliance_frameworks,
        "pii_classes_detected": receipt.pii_classes_detected,
        "pii_classes_redacted": receipt.pii_classes_redacted,
        "count_detected": receipt.count_detected,
        "count_redacted": receipt.count_redacted,
        "zero_pii_egress_confirmed": receipt.zero_pii_egress_confirmed,
        "chain_position": receipt.chain_position,
        "receipt_hash": receipt.receipt_hash,
        "previous_receipt_hash": receipt.previous_receipt_hash,
    }


def dispatch_webhook(receipt: ComplianceReceipt, event_type: str = "scrub") -> bool:
    """
    POST a structured JSON event to HERMES_WEBHOOK_URL, if configured.

    Intentionally best-effort: a webhook/SIEM outage must never raise,
    retry indefinitely, or block the caller. Returns True only if the POST
    was attempted and returned a 2xx status; False in every other case,
    including when no webhook URL is configured.
    """
    webhook_url = os.environ.get(WEBHOOK_URL_ENV_VAR)
    if not webhook_url:
        return False

    payload = build_event_payload(receipt, event_type=event_type)
    data = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "hermes-relay-webhook/1.0",
    }
    auth_header = os.environ.get(WEBHOOK_AUTH_HEADER_ENV_VAR)
    auth_value = os.environ.get(WEBHOOK_AUTH_VALUE_ENV_VAR)
    if auth_header and auth_value:
        headers[auth_header] = auth_value

    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as resp:
            success = 200 <= resp.status < 300
            if not success:
                logger.warning(
                    "Hermes webhook dispatch returned non-2xx status: %s", resp.status
                )
            return success
    except urllib.error.URLError as exc:
        logger.warning("Hermes webhook dispatch failed: %s", exc)
        return False
    except Exception as exc:
        logger.warning("Hermes webhook dispatch raised unexpected error: %s", exc)
        return False


def dispatch_drata_cct(receipt: ComplianceReceipt) -> bool:
    """
    POST a Hermes compliance receipt to Drata's Custom Connections
    and Tests (CCT) API as structured evidence.

    Configuration (environment variables):
        HERMES_DRATA_CCT_URL    Full Drata CCT endpoint URL.
                                If unset, this function is a no-op.
        HERMES_DRATA_API_KEY    Drata API key for Authorization header.
                                If unset, no auth header is added.
    """
    cct_url = os.environ.get("HERMES_DRATA_CCT_URL")
    if not cct_url:
        return False

    payload = {
        "timestamp": receipt.issued_at,
        "transaction_id": receipt.transaction_id,
        "receipt_id": receipt.receipt_id,
        "zero_phi_egress_confirmed": receipt.zero_pii_egress_confirmed,
        "phi_classes_detected": receipt.pii_classes_detected,
        "phi_classes_redacted": receipt.pii_classes_redacted,
        "count_detected": receipt.count_detected,
        "count_redacted": receipt.count_redacted,
        "compliance_frameworks": receipt.compliance_frameworks,
        "chain_position": receipt.chain_position,
        "receipt_hash": receipt.receipt_hash,
        "declared_scope": receipt.declared_scope,
        "evidence_incomplete_categories": receipt.evidence_incomplete_categories,
        "issuer": receipt.issuer,
        "source": "hermes-relay",
    }

    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "hermes-relay-drata-cct/1.0",
    }

    api_key = os.environ.get("HERMES_DRATA_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(
        cct_url,
        data=data,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_SECONDS) as resp:
            success = 200 <= resp.status < 300
            if not success:
                logger.warning(
                    "Hermes Drata CCT dispatch returned non-2xx: %s", resp.status
                )
            return success
    except urllib.error.URLError as exc:
        logger.warning("Hermes Drata CCT dispatch failed: %s", exc)
        return False
    except Exception as exc:
        logger.warning("Hermes Drata CCT dispatch unexpected error: %s", exc)
        return False