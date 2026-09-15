"""
hermes/receipts/v2/builder.py — COSE_Sign1 receipt builder for Hermes V2.

Produces a ReceiptV2 containing:
  - receipt_id:          random UUID
  - receipt_digest:      domain-separated SHA-256 of canonical payload (hex)
  - prev_receipt_digest: hex link to prior receipt (None for chain head)
  - cose_sign1_bytes:    serialized COSE_Sign1 envelope (CBOR-tagged)
  - payload:             original payload dict
  - canonical_bytes:     RFC 8785 canonical form used for digest + COSE payload
  - issued_at:           ISO 8601 UTC

The builder calls signer.sign_cose_sig_structure with the exact COSE
Sig_Structure bytes — it never re-canonicalizes inside the signer.

V1 records are never touched.  prev_receipt_digest links V2 receipts only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import cbor2
from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID, ContentType

from hermes.receipts.v2.canonical import canonicalize, receipt_digest_hex
from hermes.receipts.v2.signer import ALLOWED_ALGORITHMS, Signer

# Custom protected header integers for Hermes-specific fields
# Using private-use range (negative integers not assigned by IANA)
_HEADER_PROFILE = -70000  # "hermes-receipt-v2"

HERMES_RECEIPT_CONTENT_TYPE = "application/vnd.hermes.receipt-v2+cose"
HERMES_RECEIPT_PROFILE = "hermes-receipt-v2"


@dataclass(frozen=True)
class ReceiptV2:
    """
    Immutable V2 receipt — all fields are set at construction and never mutated.

    cose_sign1_bytes is the canonical wire format — store and transmit this.
    payload and canonical_bytes are retained for downstream convenience.
    """
    receipt_id: str
    receipt_digest: str        # hex SHA-256 over "HERMES-RECEIPT-V2\0" + canonical
    prev_receipt_digest: Optional[str]  # hex, links to previous V2 receipt
    cose_sign1_bytes: bytes    # CBOR-tagged COSE_Sign1 envelope
    payload: dict              # original payload dict (not re-serialized)
    canonical_bytes: bytes     # RFC 8785 canonical bytes (matches COSE payload)
    issued_at: str             # ISO 8601 UTC


class ReceiptV2Builder:
    """
    Builds V2 receipts using a provided Signer backend.

    Thread-safety: instances are stateless — all parameters are passed per call.
    Safe to share across threads.
    """

    def __init__(self, signer: Signer) -> None:
        if signer.cose_algorithm not in ALLOWED_ALGORITHMS:
            raise ValueError(
                f"Algorithm {signer.cose_algorithm} is not in the allowed set "
                f"{ALLOWED_ALGORITHMS}. Blocked algorithms (HMAC, 'none', etc.) "
                "are never permitted in V2 receipts."
            )
        self._signer = signer

    def build(
        self,
        payload: dict,
        prev_receipt_digest: Optional[str] = None,
    ) -> ReceiptV2:
        """
        Build and sign a single V2 receipt.

        Args:
            payload:             The receipt payload dict. Must be RFC 8785 safe.
            prev_receipt_digest: Hex digest of the preceding V2 receipt, or None
                                 for the first receipt in a new V2 chain.

        Returns:
            A frozen ReceiptV2 dataclass.

        Raises:
            ValueError: if payload contains NaN/Infinity, the algorithm is blocked,
                        or signer.sign_cose_sig_structure returns empty bytes.
        """
        issued_at = datetime.now(timezone.utc).isoformat()
        receipt_id = str(uuid.uuid4())

        # Step 1: Build the full signed payload dict.
        # Chain link (prev_receipt_digest), issued_at, and receipt_id are
        # embedded so the verifier can read them from the COSE payload
        # without any side channel.  Caller-supplied fields must not use
        # these reserved keys.
        full_payload = dict(payload)
        full_payload["_hermes_receipt_id"] = receipt_id
        full_payload["_hermes_issued_at"] = issued_at
        if prev_receipt_digest is not None:
            full_payload["_hermes_prev_receipt_digest"] = prev_receipt_digest

        # Step 2: RFC 8785 canonicalization (validates full_payload too)
        canonical_bytes = canonicalize(full_payload)

        # Step 3: Domain-separated receipt digest over canonical full_payload
        digest_hex = receipt_digest_hex(full_payload)

        # Step 4: Build COSE_Sign1 protected headers
        protected_headers = {
            Algorithm: self._signer.cose_algorithm,
            KID: self._signer.key_id,
            ContentType: HERMES_RECEIPT_CONTENT_TYPE,
            _HEADER_PROFILE: HERMES_RECEIPT_PROFILE,
        }

        # Step 5: Construct Sign1Message with canonical bytes as payload.
        # receipt_digest goes in the UNPROTECTED header — it is computed over
        # the canonical payload, so it cannot be inside the payload itself
        # (that would be circular). Unprotected headers are readable by the
        # verifier without breaking the signature.
        _UHDR_RECEIPT_DIGEST = -70001  # private-use label
        msg = Sign1Message(
            phdr=protected_headers,
            uhdr={_UHDR_RECEIPT_DIGEST: digest_hex},
            payload=canonical_bytes,
        )

        # Step 6: Extract the COSE Sig_Structure bytes and hand to signer.
        # The signer sees exactly what RFC 8152 §4.4 specifies — no
        # re-canonicalization, no wrapping, no modification.
        sig_structure_bytes = msg._create_sig_structure()
        signature = self._signer.sign_cose_sig_structure(sig_structure_bytes)

        if not signature:
            raise ValueError(
                "Signer returned empty signature — refusing to produce receipt."
            )

        # Step 7: Attach signature and serialize
        msg.signature = signature
        cose_sign1_bytes = msg.encode(sign=False)  # sign=False: use pre-computed sig

        return ReceiptV2(
            receipt_id=receipt_id,
            receipt_digest=digest_hex,
            prev_receipt_digest=prev_receipt_digest,
            cose_sign1_bytes=cose_sign1_bytes,
            payload=full_payload,
            canonical_bytes=canonical_bytes,
            issued_at=issued_at,
        )

    def build_chain(
        self,
        payloads: list[dict],
        first_prev_digest: Optional[str] = None,
    ) -> list[ReceiptV2]:
        """
        Build a chain of receipts, each linked to the previous.

        Args:
            payloads:          List of payload dicts in chain order.
            first_prev_digest: Hex digest of the receipt preceding this chain,
                               or None if this is the start of the V2 chain.

        Returns:
            List of ReceiptV2 in the same order as payloads.
        """
        receipts: list[ReceiptV2] = []
        prev = first_prev_digest
        for payload in payloads:
            r = self.build(payload, prev_receipt_digest=prev)
            receipts.append(r)
            prev = r.receipt_digest
        return receipts
