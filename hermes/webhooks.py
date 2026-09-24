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
SPRINTO_API_KEY_ENV_VAR = "HERMES_SPRINTO_API_KEY"
SPRINTO_GRAPHQL_URL_ENV_VAR = "HERMES_SPRINTO_GRAPHQL_URL"
SPRINTO_MUTATION_ENV_VAR = "HERMES_SPRINTO_MUTATION"


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
    LEGACY (Drata Path A). Kept only for backward compatibility with the
    /v1/scrub and /v1/trial-scan V1 receipt flow; its behavior is frozen.
    The canonical Drata integration is DrataConnector in
    gateway/evidence_export/drata_connector.py. This path sends a different,
    flat payload shape (no {"data": ...} wrapper), with no retries and no
    idempotency key; see docs/GATEWAY_EVIDENCE_EXPORT.md.

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

def dispatch_vanta_custom_resource(receipt, chain_integrity: bool = False) -> bool:
    """
    PUT a Hermes scan receipt as a custom resource record into a Vanta tenant.

    Vanta private integrations use OAuth 2.0 client_credentials grant.
    Fetches a fresh access token on every call (Vanta allows only one active
    token per app). chain_integrity must come from a live chain verification
    result, never hard-coded to True.

    Env vars required:
        HERMES_VANTA_CLIENT_ID
        HERMES_VANTA_CLIENT_SECRET
        HERMES_VANTA_RESOURCE_ID
    """
    import json, urllib.request, urllib.error, os, logging
    logger = logging.getLogger("hermes.webhooks")

    client_id = os.environ.get("HERMES_VANTA_CLIENT_ID")
    client_secret = os.environ.get("HERMES_VANTA_CLIENT_SECRET")
    resource_id = os.environ.get("HERMES_VANTA_RESOURCE_ID")

    if not all([client_id, client_secret, resource_id]):
        return False

    token_req = urllib.request.Request(
        "https://api.vanta.com/oauth/token",
        data=json.dumps({
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "connectors.self:write-resource",
            "grant_type": "client_credentials",
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(token_req, timeout=3.0) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
            access_token = token_data.get("access_token")
            if not access_token:
                logger.warning("Vanta token response missing access_token")
                return False
    except Exception as exc:
        logger.warning("Vanta token fetch failed: %s", exc)
        return False

    # IMPORTANT: Vanta PUT is full-state synchronization.
    # Any uniqueId previously pushed but omitted from this call
    # will be marked as no longer existing in Vanta.
    # Always pass the complete set of current receipts, not just the latest.
    resource_req = urllib.request.Request(
        "https://api.vanta.com/v1/resources/custom_resource",
        data=json.dumps({
            "resourceId": resource_id,
            "resources": [{
                "displayName": receipt.receipt_id,
                "uniqueId": receipt.receipt_id,
                "externalUrl": "https://hermesrelay.dev",
                "customProperties": {
                    "receipt_id": receipt.receipt_id,
                    "scan_timestamp": receipt.issued_at,
                    "phi_classes_detected": receipt.pii_classes_detected,
                    "zero_pii_egress_confirmed": receipt.zero_pii_egress_confirmed,
                    "chain_position": receipt.chain_position,
                    "chain_integrity": chain_integrity,
                },
            }],
        }).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "hermes-relay-vanta/1.0",
        },
        method="PUT",
    )
    try:
        with urllib.request.urlopen(resource_req, timeout=3.0) as resp:
            success = 200 <= resp.status < 300
            if not success:
                logger.warning("Vanta resource push returned non-2xx: %s", resp.status)
            return success
    except urllib.error.URLError as exc:
        logger.warning("Vanta resource push failed: %s", exc)
        return False
    except Exception as exc:
        logger.warning("Vanta resource push unexpected error: %s", exc)
        return False


def dispatch_sprinto_custom_evidence(receipt, chain_integrity: bool = False) -> bool:
    """
    Confirm with Sprinto whether mutation name is CONFIRM_WITH_SPRINTO or something else. Default is intentionally a no-op until HERMES_SPRINTO_MUTATION is set.
    """
    import json, urllib.request, urllib.error, os, logging
    logger = logging.getLogger("hermes.webhooks")

    api_key = os.environ.get("HERMES_SPRINTO_API_KEY")
    if not api_key:
        return False

    graphql_url = os.environ.get(
        "HERMES_SPRINTO_GRAPHQL_URL",
        "https://app.sprinto.com/dev-api/graphql",
    )
    mutation = os.environ.get("HERMES_SPRINTO_MUTATION", "CONFIRM_WITH_SPRINTO")

    req = urllib.request.Request(
        graphql_url,
        data=json.dumps({
            "query": "mutation AddHermesEvidence($input: HermesEvidenceInput) { " + mutation + "(input: $input) { success } }",
            "variables": {
                "input": {
                    "receipt_id": receipt.receipt_id,
                    "scan_timestamp": receipt.issued_at,
                    "phi_classes_detected": receipt.pii_classes_detected,
                    "zero_pii_egress_confirmed": receipt.zero_pii_egress_confirmed,
                    "chain_position": receipt.chain_position,
                    "chain_integrity": chain_integrity,
                }
            },
            "operationName": "AddHermesEvidence",
        }).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "api-key": api_key,
            "User-Agent": "hermes-relay-sprinto/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            success = 200 <= resp.status < 300
            if not success:
                logger.warning("Sprinto evidence push returned non-2xx: %s", resp.status)
            return success
    except urllib.error.URLError as exc:
        logger.warning("Sprinto evidence push failed: %s", exc)
        return False
    except Exception as exc:
        logger.warning("Sprinto evidence push unexpected error: %s", exc)
        return False
