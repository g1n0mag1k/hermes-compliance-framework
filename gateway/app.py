from __future__ import annotations

import hmac
import os
import time
from collections import defaultdict
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from hermes.classifier import DetectorFailureError, scrub_payload
from hermes.workspaces import Workspace, get_workspace_by_api_key

from gateway import __version__
from gateway.evidence import get_v2_chain_head, validate_gateway_signing_config
from gateway.pipeline import GatewayPipeline, GatewayRequest
from gateway.policy import PolicyEngine, reload_policy
from gateway.providers import PROVIDER_REGISTRY, resolve_provider, validate_path

app = FastAPI(
    title="Hermes Relay Gateway",
    description="Fail-closed AI PHI enforcement gateway",
    version=__version__,
)

_start_time = time.time()


def _empty_stats() -> dict:
    return {
        "requests_total": 0,
        "requests_allowed": 0,
        "requests_redacted": 0,
        "requests_blocked": 0,
        "phi_events_total": 0,
        "detector_errors_total": 0,
    }


_stats: defaultdict = defaultdict(_empty_stats)
_pipeline = GatewayPipeline()


@app.on_event("startup")
async def _validate_production_gateway_config() -> None:
    validate_gateway_signing_config()


def _authenticate(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> Workspace:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    workspace = get_workspace_by_api_key(x_api_key)
    if workspace is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return workspace


def _record_stats(
    workspace_id: str,
    decision: str,
    phi_detected: bool,
    detector_error: bool,
) -> None:
    stats = _stats[workspace_id]
    stats["requests_total"] += 1
    if decision == "ALLOW":
        stats["requests_allowed"] += 1
    elif decision == "REDACT":
        stats["requests_redacted"] += 1
    elif decision == "BLOCK":
        stats["requests_blocked"] += 1
    if phi_detected:
        stats["phi_events_total"] += 1
    if detector_error:
        stats["detector_errors_total"] += 1


@app.post("/gateway/policy/reload")
async def gateway_policy_reload(
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> dict:
    expected = os.environ.get("HERMES_ADMIN_TOKEN")
    if not expected or not hmac.compare_digest(x_admin_token or "", expected):
        raise HTTPException(status_code=401, detail="Invalid admin token")
    reload_policy()
    return {"status": "reloaded"}


@app.post("/gateway/{provider_id}/{path:path}")
async def gateway_relay(
    provider_id: str,
    path: str,
    request: Request,
    workspace: Workspace = Depends(_authenticate),
) -> Response:
    try:
        resolve_provider(provider_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    provider = resolve_provider(provider_id)
    full_path = path if path.startswith("/") else f"/{path}"

    if not validate_path(provider, full_path):
        raise HTTPException(
            status_code=400,
            detail=f"Path {full_path!r} not allowed for provider {provider_id!r}",
        )

    body_bytes = await request.body()
    query_string = str(request.url.query)
    headers = {k: v for k, v in request.headers.items()}
    content_type = headers.get("content-type", "")

    gateway_request = GatewayRequest(
        workspace_id=workspace.workspace_id,
        provider_id=provider_id,
        method=request.method,
        path=full_path,
        query_string=query_string,
        headers=headers,
        body_bytes=body_bytes,
        content_type=content_type,
    )

    try:
        result = _pipeline.process(gateway_request, workspace)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    phi_detected = bool(result.receipt.payload.get("phi_categories_detected"))
    _record_stats(
        workspace.workspace_id,
        result.decision.decision,
        phi_detected,
        result.detector_error,
    )

    if result.receipt_persistence_failed:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "message": (
                        "Enforcement completed but evidence persistence failed. "
                        "Receipt signature was computed but not stored."
                    ),
                    "type": "receipt_persistence_failure",
                    "code": "evidence_persistence_error",
                },
                "transaction_id": result.transaction_id,
                "receipt_digest": result.receipt.receipt_digest,
                "forwarded": result.receipt.payload.get("forwarded", False),
            },
        )

    if result.upstream_failure is not None:
        failure = result.upstream_failure
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": failure.message,
                    "type": failure.kind,
                    "code": "upstream_transport_failure",
                },
                "transaction_id": result.transaction_id,
                "receipt_digest": result.receipt.receipt_digest,
                "forwarded": True,
                "upstream_status": failure.upstream_status,
            },
        )

    if result.detector_error:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "message": "Request blocked — detector failure.",
                    "type": "detector_failure",
                    "code": "detector_error",
                },
                "transaction_id": result.transaction_id,
                "receipt_digest": result.receipt.receipt_digest,
            },
        )

    if result.decision.decision == "BLOCK":
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked — PHI policy violation.",
                    "type": "policy_violation",
                    "code": "phi_detected",
                },
                "transaction_id": result.transaction_id,
                "receipt_digest": result.receipt.receipt_digest,
            },
        )

    upstream = result.upstream_response
    if upstream is None:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "message": "Gateway completed without an upstream response.",
                    "type": "gateway_internal_error",
                    "code": "missing_upstream_response",
                },
                "transaction_id": result.transaction_id,
                "receipt_digest": result.receipt.receipt_digest,
            },
        )

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
        media_type=upstream.headers.get("content-type"),
    )


@app.get("/gateway/health")
async def gateway_health() -> JSONResponse:
    components = {
        "gateway_service": "healthy",
        "policy_engine": "healthy",
        "detector_state": "healthy",
        "evidence_chain": "healthy",
    }

    try:
        PolicyEngine("health-check").get_policy()
    except Exception:
        components["policy_engine"] = "degraded"

    try:
        scrub_payload("health_check", "test")
    except DetectorFailureError:
        components["detector_state"] = "degraded"

    try:
        get_v2_chain_head("__health_probe__")
        components["evidence_chain"] = "healthy"
    except Exception:
        components["evidence_chain"] = "degraded"

    provider_connectivity = {
        provider_id: bool(os.environ.get(provider.credential_env))
        for provider_id, provider in PROVIDER_REGISTRY.items()
    }

    all_healthy = (
        all(status == "healthy" for status in components.values())
        and all(provider_connectivity.values())
    )

    body = {
        "gateway_service": components["gateway_service"],
        "policy_engine": components["policy_engine"],
        "detector_state": components["detector_state"],
        "evidence_chain": components["evidence_chain"],
        "provider_connectivity": provider_connectivity,
    }
    return JSONResponse(status_code=200 if all_healthy else 503, content=body)


@app.get("/gateway/stats")
async def gateway_stats(workspace: Workspace = Depends(_authenticate)) -> dict:
    return {
        **_stats[workspace.workspace_id],
        "uptime_seconds": time.time() - _start_time,
    }
