from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

from hermes.classifier import DetectorFailureError
from hermes.receipts.v2.builder import ReceiptV2
from hermes.workspaces import Workspace

from gateway.credentials import inject_provider_credentials, strip_client_auth_headers
from gateway.evidence import issue_gateway_receipt
from gateway.inspector import (
    inspect_json_recursive,
    inspect_query_string,
    inspect_string_value,
    is_binary_content_type,
)
from gateway.policy import EnforcementDecision, PolicyEngine
from gateway.providers import PROVIDER_REGISTRY, resolve_provider, validate_path
from gateway.response_headers import filter_response_headers


@dataclass
class GatewayRequest:
    workspace_id: str
    provider_id: str
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body_bytes: bytes
    content_type: str


@dataclass
class GatewayResponse:
    decision: EnforcementDecision
    sanitized_body: Optional[bytes]
    upstream_response: Optional[httpx.Response]
    receipt: ReceiptV2
    transaction_id: str
    gateway_request_id: str
    detector_error: bool = False


class GatewayPipeline:
    def __init__(
        self,
        timeout: float = 30.0,
        client_factory: Optional[Callable[[], httpx.Client]] = None,
    ) -> None:
        self._timeout = timeout
        self._client_factory = client_factory or (lambda: httpx.Client(timeout=timeout))

    def process(self, request: GatewayRequest, workspace: Workspace) -> GatewayResponse:
        transaction_id = f"gw_{uuid.uuid4().hex[:12]}"
        gateway_request_id = str(uuid.uuid4())
        policy_engine = PolicyEngine(workspace.workspace_id)
        policy = policy_engine.get_policy()

        flags_triggered: dict[str, int] = {}
        flags_redacted: dict[str, int] = {}
        detectors_executed: dict[str, str] = {}
        all_detectors_clean = True
        detector_error = False

        def _merge(
            trig: dict[str, int],
            red: dict[str, int],
            det: dict[str, str],
        ) -> None:
            nonlocal all_detectors_clean
            for key, count in trig.items():
                flags_triggered[key] = flags_triggered.get(key, 0) + count
            for key, count in red.items():
                flags_redacted[key] = flags_redacted.get(key, 0) + count
            for key, state in det.items():
                existing = detectors_executed.get(key, "ran_clean")
                priority = {"ran_error": 2, "not_run": 1, "ran_clean": 0}
                if priority.get(state, 0) > priority.get(existing, 0):
                    detectors_executed[key] = state
                if state == "ran_error":
                    all_detectors_clean = False

        # 1. Validate provider is in PROVIDER_REGISTRY
        provider = resolve_provider(request.provider_id)
        if request.provider_id not in policy.approved_providers:
            decision = EnforcementDecision(
                decision="BLOCK",
                reasons=[f"Provider {request.provider_id!r} not approved by policy"],
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_digest=policy.digest,
                content_types_inspected=[],
                content_types_not_inspected=[],
                all_detectors_clean=True,
            )
            receipt = issue_gateway_receipt(
                workspace,
                transaction_id,
                decision,
                request.provider_id,
                request.path,
                flags_triggered,
                flags_redacted,
                detectors_executed,
            )
            return GatewayResponse(
                decision=decision,
                sanitized_body=None,
                upstream_response=None,
                receipt=receipt,
                transaction_id=transaction_id,
                gateway_request_id=gateway_request_id,
            )

        if not validate_path(provider, request.path):
            raise ValueError(f"Path {request.path!r} not allowed for provider {request.provider_id!r}")

        content_type = request.content_type or ""
        has_binary = is_binary_content_type(content_type)

        # 2. Check content-type — if binary apply binary_action immediately
        if has_binary:
            decision = policy_engine.decide(
                flags_triggered,
                flags_redacted,
                all_detectors_clean,
                content_type,
                has_binary_content=True,
            )
            receipt = issue_gateway_receipt(
                workspace,
                transaction_id,
                decision,
                request.provider_id,
                request.path,
                flags_triggered,
                flags_redacted,
                detectors_executed,
            )
            return GatewayResponse(
                decision=decision,
                sanitized_body=None,
                upstream_response=None,
                receipt=receipt,
                transaction_id=transaction_id,
                gateway_request_id=gateway_request_id,
            )

        parsed_body: Optional[object] = None
        parse_error = False

        # 3. Parse JSON body — if parse fails apply on_parse_error immediately
        if request.body_bytes:
            try:
                parsed_body = json.loads(request.body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parse_error = True

        if parse_error:
            decision = policy_engine.decide(
                flags_triggered,
                flags_redacted,
                all_detectors_clean,
                content_type,
                parse_error=True,
            )
            receipt = issue_gateway_receipt(
                workspace,
                transaction_id,
                decision,
                request.provider_id,
                request.path,
                flags_triggered,
                flags_redacted,
                detectors_executed,
            )
            return GatewayResponse(
                decision=decision,
                sanitized_body=None,
                upstream_response=None,
                receipt=receipt,
                transaction_id=transaction_id,
                gateway_request_id=gateway_request_id,
            )

        # 4. Inspect query string
        sanitized_query = request.query_string
        if request.query_string:
            try:
                sanitized_query, q_trig, q_red, q_det = inspect_query_string(
                    request.query_string,
                    transaction_id,
                )
                _merge(q_trig, q_red, q_det)
            except DetectorFailureError:
                all_detectors_clean = False
                detector_error = True
                decision = policy_engine.decide(
                    flags_triggered,
                    flags_redacted,
                    False,
                    content_type,
                )
                receipt = issue_gateway_receipt(
                    workspace,
                    transaction_id,
                    decision,
                    request.provider_id,
                    request.path,
                    flags_triggered,
                    flags_redacted,
                    detectors_executed,
                )
                return GatewayResponse(
                    decision=decision,
                    sanitized_body=None,
                    upstream_response=None,
                    receipt=receipt,
                    transaction_id=transaction_id,
                    gateway_request_id=gateway_request_id,
                    detector_error=True,
                )

        # 5. Inspect ALL string values in JSON body
        sanitized_obj = parsed_body
        if parsed_body is not None:
            try:
                sanitized_obj, b_trig, b_red, b_det = inspect_json_recursive(
                    parsed_body,
                    transaction_id,
                )
                _merge(b_trig, b_red, b_det)
            except DetectorFailureError:
                all_detectors_clean = False
                detector_error = True
                decision = policy_engine.decide(
                    flags_triggered,
                    flags_redacted,
                    False,
                    content_type,
                )
                receipt = issue_gateway_receipt(
                    workspace,
                    transaction_id,
                    decision,
                    request.provider_id,
                    request.path,
                    flags_triggered,
                    flags_redacted,
                    detectors_executed,
                )
                return GatewayResponse(
                    decision=decision,
                    sanitized_body=None,
                    upstream_response=None,
                    receipt=receipt,
                    transaction_id=transaction_id,
                    gateway_request_id=gateway_request_id,
                    detector_error=True,
                )

        # 6. Inspect path for PHI
        try:
            _, p_trig, p_red, p_det = inspect_string_value(request.path, transaction_id)
            _merge(p_trig, p_red, p_det)
        except DetectorFailureError:
            all_detectors_clean = False
            detector_error = True
            decision = policy_engine.decide(
                flags_triggered,
                flags_redacted,
                False,
                content_type,
            )
            receipt = issue_gateway_receipt(
                workspace,
                transaction_id,
                decision,
                request.provider_id,
                request.path,
                flags_triggered,
                flags_redacted,
                detectors_executed,
            )
            return GatewayResponse(
                decision=decision,
                sanitized_body=None,
                upstream_response=None,
                receipt=receipt,
                transaction_id=transaction_id,
                gateway_request_id=gateway_request_id,
                detector_error=True,
            )

        # 7. Apply PolicyEngine.decide()
        decision = policy_engine.decide(
            flags_triggered,
            flags_redacted,
            all_detectors_clean,
            content_type,
        )

        # 8. If BLOCK: issue receipt, return WITHOUT forwarding
        if decision.decision == "BLOCK":
            receipt = issue_gateway_receipt(
                workspace,
                transaction_id,
                decision,
                request.provider_id,
                request.path,
                flags_triggered,
                flags_redacted,
                detectors_executed,
            )
            return GatewayResponse(
                decision=decision,
                sanitized_body=None,
                upstream_response=None,
                receipt=receipt,
                transaction_id=transaction_id,
                gateway_request_id=gateway_request_id,
                detector_error=detector_error,
            )

        # 9. If REDACT: rebuild sanitized JSON body
        # 10. If ALLOW: use original body
        if decision.decision == "REDACT" and sanitized_obj is not None:
            forward_body = json.dumps(sanitized_obj).encode("utf-8")
        else:
            forward_body = request.body_bytes

        # 11. strip_client_auth_headers()
        forward_headers = strip_client_auth_headers(dict(request.headers))

        # 12. inject_provider_credentials()
        forward_headers = inject_provider_credentials(forward_headers, provider)

        # 13. Filter request headers
        forward_headers = {
            k: v
            for k, v in forward_headers.items()
            if k.lower() not in {"host", "content-length", "transfer-encoding"}
        }
        if forward_body:
            forward_headers["content-length"] = str(len(forward_body))

        upstream_url = provider.effective_base_url()
        if request.query_string:
            upstream_url = f"{upstream_url}{request.path}?{sanitized_query}"
        else:
            upstream_url = f"{upstream_url}{request.path}"

        # 14. Forward to provider via httpx
        with self._client_factory() as client:
            upstream_response = client.request(
                method=request.method,
                url=upstream_url,
                headers=forward_headers,
                content=forward_body,
            )

        # 15. Receive upstream response
        response_body = upstream_response.content
        response_content_type = upstream_response.headers.get("content-type", "")

        # 16. filter_response_headers()
        filtered_headers = filter_response_headers(
            dict(upstream_response.headers),
            gateway_request_id,
        )

        # 17. Inspect response body with inspect_json_recursive()
        if response_body and "json" in response_content_type.lower():
            try:
                response_obj = json.loads(response_body)
                sanitized_response, r_trig, r_red, r_det = inspect_json_recursive(
                    response_obj,
                    transaction_id,
                )
                _merge(r_trig, r_red, r_det)
                response_body = json.dumps(sanitized_response).encode("utf-8")
            except (json.JSONDecodeError, DetectorFailureError):
                pass

        upstream_response.headers = httpx.Headers(filtered_headers)
        upstream_response._content = response_body

        # 18. issue_gateway_receipt()
        receipt = issue_gateway_receipt(
            workspace,
            transaction_id,
            decision,
            request.provider_id,
            request.path,
            flags_triggered,
            flags_redacted,
            detectors_executed,
        )

        # 19. Return GatewayResponse
        return GatewayResponse(
            decision=decision,
            sanitized_body=forward_body,
            upstream_response=upstream_response,
            receipt=receipt,
            transaction_id=transaction_id,
            gateway_request_id=gateway_request_id,
            detector_error=detector_error,
        )
