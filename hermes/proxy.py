"""
hermes/proxy.py — Zero-Trust LLM Scrub Proxy
"""
import httpx
import json
import os
import uuid
from typing import Any, Dict, Optional, Tuple

from hermes.classifier import scrub_payload
from hermes.attestation import ATTESTATION_CHAIN

PROXY_TARGETS: Dict[str, str] = {
    "openai":    "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "ollama":    os.environ.get("HERMES_OLLAMA_BASE", "http://localhost:11434"),
    "custom":    os.environ.get("HERMES_CUSTOM_TARGET", ""),
}

_TEXT_FIELDS = {"content", "text", "prompt", "input", "query", "message", "instructions"}


def _scrub_str(text: str, transaction_id: str, flags: Dict[str, int]) -> str:
    result = scrub_payload(transaction_id=transaction_id, text=text)
    for k, v in result.audit_log.flags_triggered.items():
        flags[k] = flags.get(k, 0) + v
    return result.clean_text


def _deep_scrub(obj: Any, transaction_id: str) -> Tuple[Any, Dict[str, int]]:
    flags: Dict[str, int] = {}

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                k: (_scrub_str(v, transaction_id, flags)
                    if isinstance(v, str) and k.lower() in _TEXT_FIELDS
                    else _walk(v))
                for k, v in node.items()
            }
        elif isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    return _walk(obj), flags


class ProxyRelay:
    def __init__(self, timeout: float = 30.0) -> None:
        self._client = httpx.Client(timeout=timeout)

    def relay(
        self,
        target: str,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: Optional[bytes],
    ) -> Tuple[httpx.Response, str, Dict[str, int]]:
        transaction_id = f"proxy_{uuid.uuid4().hex[:12]}"

        base_url = PROXY_TARGETS.get(target, target)
        if not base_url:
            raise ValueError(f"Unknown proxy target: {target}")

        upstream_url = f"{base_url}{path}"
        original_size = len(body) if body else 0
        scrubbed_body = body
        flags: Dict[str, int] = {}

        if body:
            try:
                payload_obj = json.loads(body)
                scrubbed_obj, flags = _deep_scrub(payload_obj, transaction_id)
                scrubbed_body = json.dumps(scrubbed_obj).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                text = body.decode("utf-8", errors="replace")
                result = scrub_payload(transaction_id=transaction_id, text=text)
                scrubbed_body = result.clean_text.encode("utf-8")
                flags = result.audit_log.flags_triggered

        scrubbed_size = len(scrubbed_body) if scrubbed_body else 0

        ATTESTATION_CHAIN.issue(
            transaction_id=transaction_id,
            flags_triggered=flags,
            char_count_in=original_size,
            char_count_out=scrubbed_size,
            downstream_target=base_url,
        )

        forward_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in {"host", "content-length", "transfer-encoding"}
        }
        if scrubbed_body:
            forward_headers["content-length"] = str(len(scrubbed_body))

        response = self._client.request(
            method=method,
            url=upstream_url,
            headers=forward_headers,
            content=scrubbed_body,
        )

        return response, transaction_id, flags

    def close(self) -> None:
        self._client.close()


PROXY_RELAY = ProxyRelay()
