"""
hermes/attestation.py — Cryptographically Signed Compliance Attestation Receipts
"""
import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

def _load_signing_key() -> bytes:
    key_hex = os.environ.get("HERMES_SIGNING_KEY")
    if key_hex:
        return bytes.fromhex(key_hex)
    return hashlib.sha256(b"hermes-dev-signing-key-not-for-production").digest()

SIGNING_KEY: bytes = _load_signing_key()

@dataclass
class ComplianceReceipt:
    receipt_id: str
    transaction_id: str
    issued_at: str
    issuer: str
    compliance_frameworks: List[str]
    pii_classes_detected: List[str]
    pii_classes_redacted: List[str]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    zero_pii_egress_confirmed: bool
    downstream_target: Optional[str]
    previous_receipt_hash: str
    receipt_hash: str
    chain_position: int

class AttestationChain:
    ISSUER = "Hermes Relay v1.0.0 — hermesrelay.dev"
    COMPLIANCE_FRAMEWORKS = ["HIPAA", "PCI-DSS"]

    def __init__(self) -> None:
        self._chain: List[ComplianceReceipt] = []
        self._lock = threading.Lock()
        self._genesis_hash = hashlib.sha256(b"hermes-genesis-block").hexdigest()

    def _sign_receipt(self, content: Dict) -> str:
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            SIGNING_KEY,
            canonical.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def _previous_hash(self) -> str:
        if not self._chain:
            return self._genesis_hash
        return self._chain[-1].receipt_hash

    def issue(
        self,
        transaction_id: str,
        flags_triggered: Dict[str, int],
        flags_redacted: Dict[str, int],
        char_count_in: int,
        char_count_out: int,
        downstream_target: Optional[str] = None,
    ) -> ComplianceReceipt:
        pii_detected = list(flags_triggered.keys())
        pii_redacted = list(flags_redacted.keys())
        zero_egress = set(pii_detected) == set(pii_redacted)

        with self._lock:
            position = len(self._chain)
            prev_hash = self._previous_hash()
            receipt_id = f"rcpt_{transaction_id}_{position:06d}"
            issued_at = datetime.now(timezone.utc).isoformat()

            content = {
                "receipt_id": receipt_id,
                "transaction_id": transaction_id,
                "issued_at": issued_at,
                "issuer": self.ISSUER,
                "compliance_frameworks": self.COMPLIANCE_FRAMEWORKS,
                "pii_classes_detected": pii_detected,
                "pii_classes_redacted": pii_redacted,
                "payload_char_count_in": char_count_in,
                "payload_char_count_out": char_count_out,
                "chars_removed": char_count_in - char_count_out,
                "zero_pii_egress_confirmed": zero_egress,
                "downstream_target": downstream_target,
                "previous_receipt_hash": prev_hash,
                "chain_position": position,
            }

            signature = self._sign_receipt(content)
            receipt = ComplianceReceipt(
                receipt_id=receipt_id,
                transaction_id=transaction_id,
                issued_at=issued_at,
                issuer=self.ISSUER,
                compliance_frameworks=self.COMPLIANCE_FRAMEWORKS,
                pii_classes_detected=pii_detected,
                pii_classes_redacted=pii_redacted,
                payload_char_count_in=char_count_in,
                payload_char_count_out=char_count_out,
                chars_removed=char_count_in - char_count_out,
                zero_pii_egress_confirmed=zero_egress,
                downstream_target=downstream_target,
                previous_receipt_hash=prev_hash,
                chain_position=position,
                receipt_hash=signature,
            )
            self._chain.append(receipt)

        return receipt

    def verify_chain(self) -> bool:
        with self._lock:
            for receipt in self._chain:
                content = asdict(receipt)
                stored_hash = content.pop("receipt_hash")
                expected = self._sign_receipt(content)
                if not hmac.compare_digest(stored_hash, expected):
                    return False
        return True

    def get_receipt(self, transaction_id: str) -> Optional[ComplianceReceipt]:
        with self._lock:
            for r in reversed(self._chain):
                if r.transaction_id == transaction_id:
                    return r
        return None

    def export_chain(self) -> List[Dict]:
        with self._lock:
            return [asdict(r) for r in self._chain]

    def chain_length(self) -> int:
        with self._lock:
            return len(self._chain)

ATTESTATION_CHAIN = AttestationChain()
