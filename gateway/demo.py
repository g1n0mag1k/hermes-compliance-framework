#!/usr/bin/env python3
"""
Hermes Gateway — outreach demo (synthetic data only).

Demonstrates four enforcement scenarios with visible upstream request counts:
  A) CLEAN  → ALLOW  → upstream contacted
  B) PHI    → BLOCK  → upstream NOT contacted
  C) DETECTOR FAILURE → BLOCK/503 → upstream NOT contacted
  D) PHI    → REDACT → sanitized upstream forward

Run (self-contained, no live gateway required):
    .venv/bin/python gateway/demo.py

Run against a live gateway (requires mock upstream or provider credentials):
    export GATEWAY_API_KEY=<workspace X-API-Key>
    .venv/bin/python gateway/demo.py --live --base-url http://127.0.0.1:8788
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

# Allow running as: .venv/bin/python gateway/demo.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import gateway.evidence as gateway_evidence
import gateway.policy as gateway_policy
from gateway.app import app
from gateway.pipeline import GatewayPipeline
from gateway.policy import (
    HIPAA_STRICT,
    Policy,
    clear_workspace_policy,
    set_workspace_policy,
)
from hermes.classifier import DetectorFailureError
from hermes.workspaces import create_workspace


BLOCK_POLICY = Policy(
    policy_id="HIPAA_PRODUCTION_BLOCK",
    policy_version="1.0.0",
    text_action="BLOCK",
    binary_action="BLOCK",
    on_detector_error="BLOCK",
    on_parse_error="BLOCK",
    approved_providers=["openai", "azure_openai", "anthropic"],
)

DIVIDER = "-" * 64


def _chat(content: str) -> dict[str, Any]:
    return {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": content}],
    }


def _print_scenario(title: str, response_status: int, body: dict, upstream_count: int) -> None:
    print(DIVIDER)
    print(title)
    print(DIVIDER)
    print(f"HTTP status:           {response_status}")
    print(f"upstream.request_count: {upstream_count}")
    if "receipt_digest" in body:
        print(f"receipt_digest:        {body['receipt_digest'][:32]}...")
    if "error" in body:
        print(f"error.type:            {body['error'].get('type')}")
    if "forwarded" in body:
        print(f"forwarded:             {body['forwarded']}")
    print()


def _setup_embedded_demo() -> tuple[TestClient, str, dict[str, Any], Any]:
    tmp = tempfile.mkdtemp(prefix="hermes-gateway-demo-")
    os.environ["HERMES_DATA_DIR"] = tmp
    os.environ["HERMES_REGISTRY_DB"] = os.path.join(tmp, "registry.db")
    os.environ["HERMES_ENV"] = "development"
    os.environ["HERMES_OPENAI_API_KEY"] = "demo-openai-key-not-real"

    import hermes.workspaces as ws_mod

    ws_mod._chain_cache.clear()
    ws_mod._vault_cache.clear()
    ws_mod._DEFAULT_DATA_DIR = tmp
    ws_mod._DEFAULT_REGISTRY_DB = os.path.join(tmp, "registry.db")

    gateway_evidence.reset_v2_chains()
    gateway_policy.reload_policy()

    ws, api_key = create_workspace("demo-gw", "Outreach Demo", "demo@example.com")
    upstream_state: dict[str, Any] = {
        "requests": [],
        "response": {"id": "chatcmpl-demo", "choices": [{"message": {"content": "ok"}}]},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else ""
        upstream_state["requests"].append(
            {"method": request.method, "url": str(request.url), "body": body}
        )
        return httpx.Response(200, json=upstream_state["response"])

    gateway_app._pipeline = GatewayPipeline(
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )
    return TestClient(app), api_key, upstream_state, ws


def run_embedded_demo() -> None:
    client, api_key, upstream_state, ws = _setup_embedded_demo()
    headers = {"X-API-Key": api_key}

    print()
    print("=" * 64)
    print(" HERMES GATEWAY — Outreach Demo (embedded mock upstream)")
    print(" Synthetic data only — no real PHI")
    print("=" * 64)
    print()

    # Scenario A — CLEAN / ALLOW
    upstream_state["requests"].clear()
    set_workspace_policy(ws.workspace_id, HIPAA_STRICT)
    gateway_policy.reload_policy()
    resp = client.post(
        "/gateway/openai/v1/chat/completions",
        headers=headers,
        json=_chat("Explain HIPAA minimum necessary in one sentence."),
    )
    _print_scenario(
        "A) CLEAN REQUEST → ALLOW → upstream contacted",
        resp.status_code,
        resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {},
        len(upstream_state["requests"]),
    )

    # Scenario B — PHI / BLOCK
    upstream_state["requests"].clear()
    set_workspace_policy(ws.workspace_id, BLOCK_POLICY)
    resp = client.post(
        "/gateway/openai/v1/chat/completions",
        headers=headers,
        json=_chat("Patient SSN is 123-45-6789"),
    )
    _print_scenario(
        "B) PHI REQUEST → BLOCK → upstream NOT contacted",
        resp.status_code,
        resp.json(),
        len(upstream_state["requests"]),
    )

    # Scenario C — DETECTOR FAILURE
    upstream_state["requests"].clear()

    def _fail_scrub(*args, **kwargs):
        raise DetectorFailureError("demo detector failure")

    import gateway.inspector as inspector_mod

    original_scrub = inspector_mod.scrub_payload
    inspector_mod.scrub_payload = _fail_scrub
    try:
        resp = client.post(
            "/gateway/openai/v1/chat/completions",
            headers=headers,
            json=_chat("hello"),
        )
    finally:
        inspector_mod.scrub_payload = original_scrub

    _print_scenario(
        "C) DETECTOR FAILURE → BLOCK/503 → upstream NOT contacted",
        resp.status_code,
        resp.json(),
        len(upstream_state["requests"]),
    )

    # Scenario D — PHI / REDACT
    upstream_state["requests"].clear()
    clear_workspace_policy(ws.workspace_id)
    gateway_policy.reload_policy()
    resp = client.post(
        "/gateway/openai/v1/chat/completions",
        headers=headers,
        json=_chat("Patient SSN is 123-45-6789"),
    )
    forwarded_body = upstream_state["requests"][0]["body"] if upstream_state["requests"] else ""
    _print_scenario(
        "D) PHI REQUEST → REDACT → sanitized upstream forward",
        resp.status_code,
        {"receipt_digest": "n/a-live-response"},
        len(upstream_state["requests"]),
    )
    if forwarded_body:
        print("Upstream body contains [REDACTED_SSN]:", "[REDACTED_SSN]" in forwarded_body)
        print("Upstream body contains raw SSN:", "123-45-6789" in forwarded_body)
        print()

    print("=" * 64)
    print(" Demo complete. Verify receipts with: hermes-verify receipt <file.cose>")
    print("=" * 64)
    print()


def run_live_demo(base_url: str, api_key: str) -> None:
    print()
    print("=" * 64)
    print(f" HERMES GATEWAY — Live demo @ {base_url}")
    print(" Requires gateway running with provider credentials configured.")
    print(" Upstream count inferred from HTTP status + receipt forwarded field.")
    print("=" * 64)
    print()

    scenarios = [
        (
            "A) CLEAN REQUEST",
            _chat("Explain HIPAA minimum necessary in one sentence."),
            "ALLOW",
        ),
        (
            "B) PHI + BLOCK (set HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK)",
            _chat("Patient SSN is 123-45-6789"),
            "BLOCK",
        ),
        (
            "D) PHI + REDACT (default HIPAA_STRICT)",
            _chat("Patient SSN is 987-65-4321"),
            "REDACT",
        ),
    ]

    with httpx.Client(timeout=30.0) as client:
        for title, payload, expected in scenarios:
            resp = client.post(
                f"{base_url}/gateway/openai/v1/chat/completions",
                headers={"X-API-Key": api_key, "Content-Type": "application/json"},
                json=payload,
            )
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            upstream_contacted = resp.status_code == 200
            if "forwarded" in body:
                upstream_contacted = bool(body["forwarded"])
            print(DIVIDER)
            print(title)
            print(DIVIDER)
            print(f"HTTP status:            {resp.status_code}")
            print(f"expected decision:      {expected}")
            print(f"upstream_contacted:     {upstream_contacted}")
            if "receipt_digest" in body:
                print(f"receipt_digest:         {body['receipt_digest'][:32]}...")
            print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Hermes Gateway outreach demo")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run against a live gateway instead of embedded mock",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("GATEWAY_BASE_URL", "http://127.0.0.1:8788"),
        help="Live gateway base URL (default: http://127.0.0.1:8788)",
    )
    args = parser.parse_args()

    if args.live:
        api_key = os.environ.get("GATEWAY_API_KEY") or os.environ.get("HERMES_API_KEY")
        if not api_key:
            print("Set GATEWAY_API_KEY (workspace X-API-Key) for live demo.", file=sys.stderr)
            sys.exit(1)
        run_live_demo(args.base_url.rstrip("/"), api_key)
    else:
        run_embedded_demo()


if __name__ == "__main__":
    main()
