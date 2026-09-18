"""Gateway-specific exceptions with customer-safe semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from hermes.receipts.v2.builder import ReceiptV2


class ReceiptPersistenceError(RuntimeError):
    """Receipt was built but could not be persisted to storage."""

    def __init__(self, receipt: ReceiptV2, message: str) -> None:
        super().__init__(message)
        self.receipt = receipt


@dataclass
class UpstreamTransportFailure:
    """Upstream provider transport or HTTP failure after forward was attempted."""

    kind: str
    message: str
    upstream_status: Optional[int] = None
