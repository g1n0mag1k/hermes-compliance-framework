import base64
import json
import re
import urllib.parse
from typing import Any

from hermes.classifier import (
    DETECTOR_RAN_ERROR,
    DetectorFailureError,
    FlagEntry,
    scrub_payload,
)

_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

_BINARY_PREFIXES = ("image/", "audio/", "application/octet-stream")


def _empty_accumulators() -> tuple[dict[str, int], dict[str, int], dict[str, str]]:
    return {}, {}, {}


def _merge_flags(
    flags_triggered: dict[str, int],
    flags_redacted: dict[str, int],
    detectors_executed: dict[str, str],
    new_triggered: dict[str, int],
    new_redacted: dict[str, int],
    new_detectors: dict[str, str],
) -> None:
    for key, count in new_triggered.items():
        flags_triggered[key] = flags_triggered.get(key, 0) + count
    for key, count in new_redacted.items():
        flags_redacted[key] = flags_redacted.get(key, 0) + count
    _STATE_PRIORITY = {"ran_error": 2, "not_run": 1, "ran_clean": 0}
    for key, state in new_detectors.items():
        existing = detectors_executed.get(key, "ran_clean")
        if _STATE_PRIORITY.get(state, 0) > _STATE_PRIORITY.get(existing, 0):
            detectors_executed[key] = state


def _extract_scrub_result(result) -> tuple[str, dict[str, int], dict[str, int], dict[str, str]]:
    flags_triggered: dict[str, int] = {}
    flags_redacted: dict[str, int] = {}
    for key, entry in result.audit_log.flags_triggered.items():
        count = entry.count if isinstance(entry, FlagEntry) else entry["count"]
        flags_triggered[key] = flags_triggered.get(key, 0) + count
    for key, entry in result.audit_log.flags_redacted.items():
        count = entry.count if isinstance(entry, FlagEntry) else entry["count"]
        flags_redacted[key] = flags_redacted.get(key, 0) + count
    detectors_executed = dict(result.detectors_executed)
    if any(state == DETECTOR_RAN_ERROR for state in detectors_executed.values()):
        raise DetectorFailureError("One or more PHI detectors failed during inspection")
    return result.clean_text, flags_triggered, flags_redacted, detectors_executed


def inspect_string_value(text: str, transaction_id: str) -> tuple[str, dict, dict, dict]:
    """Inspect a single string value for PHI. Raises DetectorFailureError on detector error.

    When `text` is itself a JSON-encoded object/array (a JSON body that
    arrived as a string value, e.g. a webhook payload embedded in a log
    field), it is inspected exactly once: recursively, via
    inspect_json_recursive(). It is NOT also scanned as raw text first —
    doing both double-counted every PHI occurrence inside the embedded
    JSON (once from the raw-text scrub, once from the recursive walk).
    """
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            parsed_clean, flags_triggered, flags_redacted, detectors_executed = (
                inspect_json_recursive(parsed, transaction_id)
            )
            clean_text = json.dumps(parsed_clean, separators=(",", ":"), ensure_ascii=False)
            return clean_text, flags_triggered, flags_redacted, detectors_executed

    result = scrub_payload(transaction_id=transaction_id, text=text)
    return _extract_scrub_result(result)


def inspect_json_recursive(
    obj: Any,
    transaction_id: str,
) -> tuple[Any, dict, dict, dict]:
    """Recursively inspect every string value in a JSON tree."""
    flags_triggered, flags_redacted, detectors_executed = _empty_accumulators()

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            cleaned: dict[Any, Any] = {}
            for k, v in node.items():
                clean_key = k
                if isinstance(k, str):
                    clean_key, k_trig, k_red, k_det = inspect_string_value(k, transaction_id)
                    _merge_flags(flags_triggered, flags_redacted, detectors_executed, k_trig, k_red, k_det)
                cleaned[clean_key] = _walk(v)
            return cleaned
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, str):
            clean, trig, red, det = inspect_string_value(node, transaction_id)
            _merge_flags(flags_triggered, flags_redacted, detectors_executed, trig, red, det)
            return clean
        return node

    return _walk(obj), flags_triggered, flags_redacted, detectors_executed


def inspect_query_string(query: str, transaction_id: str) -> tuple[str, dict, dict, dict]:
    """URL-decode and inspect each query parameter value."""
    if not query:
        return query, *_empty_accumulators()

    flags_triggered, flags_redacted, detectors_executed = _empty_accumulators()
    params = urllib.parse.parse_qsl(query, keep_blank_values=True)
    rebuilt: list[tuple[str, str]] = []

    for key, value in params:
        decoded = urllib.parse.unquote_plus(value)
        clean, trig, red, det = inspect_string_value(decoded, transaction_id)
        _merge_flags(flags_triggered, flags_redacted, detectors_executed, trig, red, det)
        rebuilt.append((key, clean))

    return urllib.parse.urlencode(rebuilt), flags_triggered, flags_redacted, detectors_executed


def inspect_base64_field(value: str, transaction_id: str) -> tuple[str, dict, dict, dict]:
    """Inspect base64-encoded content and the original value."""
    flags_triggered, flags_redacted, detectors_executed = _empty_accumulators()

    clean_original, trig, red, det = inspect_string_value(value, transaction_id)
    _merge_flags(flags_triggered, flags_redacted, detectors_executed, trig, red, det)

    if _BASE64_PATTERN.match(value):
        try:
            decoded_bytes = base64.b64decode(value, validate=True)
            decoded_text = decoded_bytes.decode("utf-8")
            decoded_clean, d_trig, d_red, d_det = inspect_string_value(decoded_text, transaction_id)
            _merge_flags(flags_triggered, flags_redacted, detectors_executed, d_trig, d_red, d_det)
            if decoded_clean != decoded_text:
                return "[REDACTED_BASE64]", flags_triggered, flags_redacted, detectors_executed
        except (ValueError, UnicodeDecodeError):
            pass

    return clean_original, flags_triggered, flags_redacted, detectors_executed


def is_binary_content_type(content_type: str) -> bool:
    lower = content_type.lower().split(";")[0].strip()
    return any(lower.startswith(prefix) for prefix in _BINARY_PREFIXES)
