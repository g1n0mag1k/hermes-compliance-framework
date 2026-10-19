from __future__ import annotations

import json
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gateway import __version__
from hermes.receipts.v2.builder import ReceiptV2

DecisionType = Literal["ALLOW", "REDACT", "BLOCK"]

# Representative PHI patterns that must never appear in serialized evidence.
_PHI_FORBIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\bMRN\s*\d+\b", re.IGNORECASE),
    re.compile(r"\bPatient\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"),
    re.compile(r"\b\d{3}-\d{3}-\d{4}\b"),  # phone
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
)

_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "raw_request_body",
        "raw_response_body",
        "request_body",
        "response_body",
        "prompt",
        "completion",
        "source_text",
        "redacted_text",
        "detector_snippet",
        "payload",
        "content",
        "messages",
    }
)


class EvidenceEvent(BaseModel):
    """
    Metadata-only gateway enforcement evidence contract.

    Deliberately excludes raw request/response bodies and any PHI values.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(description="Unique idempotency key for this export")
    event_type: str = Field(default="gateway_enforcement")
    source: str = Field(default="hermes-gateway")
    transaction_id: str
    workspace_id: str
    timestamp: str
    gateway_version: str
    upstream_provider: str
    endpoint_path: str
    decision: DecisionType
    policy_id: str
    policy_version: str
    policy_digest: str
    phi_categories_detected: list[str]
    phi_categories_redacted: list[str]
    content_types_inspected: list[str]
    content_types_not_inspected: list[str]
    detector_states: dict[str, str]
    upstream_contacted: bool
    all_detectors_clean: bool
    failure_class: str | None = None
    upstream_status: int | None = None
    receipt_id: str
    receipt_digest: str
    prev_receipt_digest: str | None = None
    gateway_sequence: int
    signature_algorithm: str
    cose_sign1_hex: str

    @field_validator("decision")
    @classmethod
    def _validate_decision(cls, value: str) -> str:
        if value not in ("ALLOW", "REDACT", "BLOCK"):
            raise ValueError(f"Invalid gateway decision: {value!r}")
        return value

    @field_validator("phi_categories_detected", "phi_categories_redacted", mode="before")
    @classmethod
    def _ensure_sorted_unique(cls, value: list[str]) -> list[str]:
        return sorted(set(value))

    def to_dict(self) -> dict:
        return self.model_dump(mode="json", exclude_none=True)

    def serialize(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def assert_phi_safe(self) -> None:
        """Raise ValueError if serialized evidence contains forbidden PHI patterns."""
        serialized = self.serialize()
        for pattern in _PHI_FORBIDDEN_PATTERNS:
            if pattern.search(serialized):
                raise ValueError(
                    f"EvidenceEvent serialization contains forbidden PHI pattern: "
                    f"{pattern.pattern}"
                )
        for forbidden in _FORBIDDEN_FIELD_NAMES:
            if f'"{forbidden}"' in serialized:
                raise ValueError(
                    f"EvidenceEvent serialization contains forbidden field: {forbidden}"
                )


def build_evidence_event(receipt: ReceiptV2, workspace_id: str) -> EvidenceEvent:
    """Build a validated EvidenceEvent from a persisted V2 gateway receipt."""
    payload = receipt.payload
    decision = payload.get("decision")
    if decision not in ("ALLOW", "REDACT", "BLOCK"):
        raise ValueError(f"Receipt payload missing valid decision: {decision!r}")

    event = EvidenceEvent(
        event_id=str(uuid.uuid4()),
        transaction_id=payload.get("transaction_id", receipt.receipt_id),
        workspace_id=workspace_id,
        timestamp=receipt.issued_at,
        gateway_version=payload.get("gateway_version", __version__),
        upstream_provider=payload.get("upstream_provider", "unknown"),
        endpoint_path=payload.get("endpoint_path", "/"),
        decision=decision,
        policy_id=payload.get("policy_id", "unknown"),
        policy_version=payload.get("policy_version", "0.0.0"),
        policy_digest=payload.get("policy_digest", ""),
        phi_categories_detected=list(payload.get("phi_categories_detected", [])),
        phi_categories_redacted=list(payload.get("phi_categories_redacted", [])),
        content_types_inspected=list(payload.get("content_types_inspected", [])),
        content_types_not_inspected=list(payload.get("content_types_not_inspected", [])),
        detector_states=dict(payload.get("detector_states", {})),
        upstream_contacted=bool(payload.get("forwarded", False)),
        all_detectors_clean=bool(payload.get("all_detectors_clean", True)),
        failure_class=payload.get("failure_class"),
        upstream_status=payload.get("upstream_status"),
        receipt_id=receipt.receipt_id,
        receipt_digest=receipt.receipt_digest,
        prev_receipt_digest=receipt.prev_receipt_digest,
        gateway_sequence=int(payload.get("gateway_sequence", 0)),
        signature_algorithm="EdDSA",
        cose_sign1_hex=receipt.cose_sign1_bytes.hex(),
    )
    event.assert_phi_safe()
    return event
