"""
hermes/attestation.py — Cryptographically Signed Compliance Attestation Receipts
"""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
from hermes.classifier import COVERED_CFRS, NOT_COVERED_CFRS

REVIEW_DECISIONS = ("accepted", "overridden", "escalated")

DEFAULT_DB_PATH = "hermes_chain.db"

def _load_signing_key() -> bytes:
    key_hex = os.environ.get("HERMES_SIGNING_KEY")
    env = os.environ.get("HERMES_ENV", "development")
    if key_hex:
        try:
            return bytes.fromhex(key_hex)
        except ValueError as exc:
            if env == "production":
                raise RuntimeError(
                    "HERMES_SIGNING_KEY is invalid when HERMES_ENV=production. "
                    "Set HERMES_SIGNING_KEY to a valid hex string."
                ) from exc
            raise
    if env == "production":
        raise RuntimeError(
            "HERMES_SIGNING_KEY is required when HERMES_ENV=production. "
            "Set HERMES_SIGNING_KEY to a secure hex string."
        )
    warnings.warn(
        "HERMES_SIGNING_KEY not set — using insecure dev key. "
        "Set HERMES_SIGNING_KEY to a hex string before production.",
        stacklevel=2,
    )
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
    count_detected: Dict[str, int]
    count_redacted: Dict[str, int]
    payload_char_count_in: int
    payload_char_count_out: int
    chars_removed: int
    zero_pii_egress_confirmed: bool
    zero_pii_egress_scope_note: str
    downstream_target: Optional[str]
    previous_receipt_hash: str
    receipt_hash: str
    chain_position: int
    declared_scope: List[str]
    evidence_incomplete_categories: List[str]
    detectors_executed: Dict[str, bool]


@dataclass
class HumanReviewReceipt:
    """A human review/override event, chained alongside ComplianceReceipts
    in the same AttestationChain — same signing scheme, same chain_position
    sequence, same tamper-evidence guarantees.

    previous_receipt_hash is not part of the originally specified field list
    but is required for this to actually be "linked into the same hash
    chain": without it there is no way for verify_chain() to prove a review
    receipt hasn't been reordered or inserted after the fact, the same
    invariant that already protects every ComplianceReceipt.
    """
    review_id: str
    transaction_id: str
    reviewed_by: str
    issued_at: str
    decision: str  # one of REVIEW_DECISIONS: "accepted" | "overridden" | "escalated"
    override_reason: Optional[str]
    original_receipt_hash: str
    previous_receipt_hash: str
    review_receipt_hash: str
    chain_position: int


ChainItem = Union[ComplianceReceipt, HumanReviewReceipt]


class AttestationChain:
    ISSUER = "Hermes Relay v1.0.0 — hermesrelay.dev"
    COMPLIANCE_FRAMEWORKS = ["HIPAA", "PCI-DSS"]

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._chain: List[ChainItem] = []
        self._lock = threading.Lock()
        self._genesis_hash = hashlib.sha256(b"hermes-genesis-block").hexdigest()

        # SQLite persistence — survives process restarts. Path resolution
        # order: explicit constructor arg > HERMES_DB_PATH env var > default
        # "hermes_chain.db" in the working directory.
        self._db_path = db_path or os.environ.get("HERMES_DB_PATH", DEFAULT_DB_PATH)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_db()
        self._load_from_db()

    def _init_db(self) -> None:
        # item_type distinguishes ComplianceReceipt ("compliance") from
        # HumanReviewReceipt ("review") rows so _load_from_db knows which
        # dataclass to reconstruct. Added alongside item_type in the same
        # patch cycle that introduces HumanReviewReceipt — there is no
        # pre-existing production data to migrate yet.
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    chain_position INTEGER PRIMARY KEY,
                    transaction_id TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    item_type TEXT NOT NULL DEFAULT 'compliance',
                    receipt_json TEXT NOT NULL
                )
                """
            )

    def _load_from_db(self) -> None:
        """Reconstruct the in-memory chain from SQLite in chain order.

        Runs once at construction time, before any issue()/issue_review()
        call, so the loaded items become the prefix of self._chain exactly
        as if the process had never restarted.
        """
        cursor = self._conn.execute(
            "SELECT item_type, receipt_json FROM receipts ORDER BY chain_position ASC"
        )
        for item_type, receipt_json in cursor.fetchall():
            data = json.loads(receipt_json)
            if item_type == "review":
                self._chain.append(HumanReviewReceipt(**data))
            else:
                self._chain.append(ComplianceReceipt(**data))

    def _persist_item(self, item: ChainItem) -> None:
        """Write a newly-issued chain item (receipt or review) to SQLite
        immediately. Called while still holding self._lock so the in-memory
        chain and the on-disk chain can never observe different lengths."""
        if isinstance(item, HumanReviewReceipt):
            item_type = "review"
            item_hash = item.review_receipt_hash
        else:
            item_type = "compliance"
            item_hash = item.receipt_hash
        with self._conn:
            self._conn.execute(
                "INSERT INTO receipts (chain_position, transaction_id, receipt_hash, item_type, receipt_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    item.chain_position,
                    item.transaction_id,
                    item_hash,
                    item_type,
                    json.dumps(asdict(item)),
                ),
            )

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
        last = self._chain[-1]
        return last.review_receipt_hash if isinstance(last, HumanReviewReceipt) else last.receipt_hash

    def issue(
        self,
        transaction_id: str,
        flags_triggered: Dict[str, int],
        flags_redacted: Dict[str, int],
        char_count_in: int,
        char_count_out: int,
        downstream_target: Optional[str] = None,
        detectors_executed: Optional[Dict[str, bool]] = None,
    ) -> ComplianceReceipt:
        # Compute evidence_incomplete: not_covered CFR categories
        evidence_incomplete = list(NOT_COVERED_CFRS)
        detectors_executed = detectors_executed or {}
        pii_detected = list(flags_triggered.keys())
        pii_redacted = list(flags_redacted.keys())
        # COUNT PARITY (not just class-set parity): a class present in both
        # key-sets can still have detected=2 / redacted=1 — a real PHI leak
        # that a set-equality check cannot see. Comparing the full dicts
        # (keys AND per-class counts) is what actually proves zero egress.
        zero_egress = flags_triggered == flags_redacted

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
                "count_detected": dict(flags_triggered),
                "count_redacted": dict(flags_redacted),
                "payload_char_count_in": char_count_in,
                "payload_char_count_out": char_count_out,
                "chars_removed": abs(char_count_in - char_count_out),
                "zero_pii_egress_confirmed": zero_egress,
                "zero_pii_egress_scope_note": "Confirmed within declared_scope only. evidence_incomplete_categories were not checked.",
                "downstream_target": downstream_target,
                "previous_receipt_hash": prev_hash,
                "chain_position": position,
                "declared_scope": COVERED_CFRS,
                "evidence_incomplete_categories": evidence_incomplete,
                "detectors_executed": detectors_executed,
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
                count_detected=dict(flags_triggered),
                count_redacted=dict(flags_redacted),
                payload_char_count_in=char_count_in,
                payload_char_count_out=char_count_out,
                chars_removed=abs(char_count_in - char_count_out),
                zero_pii_egress_confirmed=zero_egress,
                zero_pii_egress_scope_note="Confirmed within declared_scope only. evidence_incomplete_categories were not checked.",
                downstream_target=downstream_target,
                previous_receipt_hash=prev_hash,
                chain_position=position,
                receipt_hash=signature,
                declared_scope=COVERED_CFRS,
                evidence_incomplete_categories=evidence_incomplete,
                detectors_executed=detectors_executed,
            )
            self._chain.append(receipt)
            self._persist_item(receipt)

        return receipt

    def issue_review(
        self,
        transaction_id: str,
        reviewed_by: str,
        decision: str,
        override_reason: Optional[str] = None,
    ) -> HumanReviewReceipt:
        """Issue a human review/override event for an existing transaction,
        chained into the same AttestationChain as the ComplianceReceipt it
        reviews. original_receipt_hash is captured from the located
        ComplianceReceipt and included in the signed content, so tampering
        with a review's record of which original it reviewed invalidates
        that review's own signature (invariant 1 below)."""
        if decision not in REVIEW_DECISIONS:
            raise ValueError(
                f"decision must be one of {REVIEW_DECISIONS} — got {decision!r}"
            )

        with self._lock:
            original: Optional[ComplianceReceipt] = None
            for item in reversed(self._chain):
                if isinstance(item, ComplianceReceipt) and item.transaction_id == transaction_id:
                    original = item
                    break
            if original is None:
                raise ValueError(
                    f"No ComplianceReceipt found for transaction_id={transaction_id!r}"
                )

            position = len(self._chain)
            prev_hash = self._previous_hash()
            review_id = f"review_{transaction_id}_{position:06d}"
            issued_at = datetime.now(timezone.utc).isoformat()

            content = {
                "review_id": review_id,
                "transaction_id": transaction_id,
                "reviewed_by": reviewed_by,
                "issued_at": issued_at,
                "decision": decision,
                "override_reason": override_reason,
                "original_receipt_hash": original.receipt_hash,
                "previous_receipt_hash": prev_hash,
                "chain_position": position,
            }
            signature = self._sign_receipt(content)
            review = HumanReviewReceipt(
                review_id=review_id,
                transaction_id=transaction_id,
                reviewed_by=reviewed_by,
                issued_at=issued_at,
                decision=decision,
                override_reason=override_reason,
                original_receipt_hash=original.receipt_hash,
                previous_receipt_hash=prev_hash,
                review_receipt_hash=signature,
                chain_position=position,
            )
            self._chain.append(review)
            self._persist_item(review)

        return review

    def verify_chain(self) -> bool:
        """
        Full chain verification — three invariants must hold, uniformly
        across ComplianceReceipts and HumanReviewReceipts sharing this chain:

        1. Every item's signature is valid (HMAC matches signed content)
        2. Every item.previous_receipt_hash equals the prior item's hash
        3. chain_position values are strictly sequential with no gaps or duplicates

        A chain that passes only invariant 1 is forgeable by deleting items
        and re-signing the survivors. Invariants 2 and 3 close that attack
        vector. For a HumanReviewReceipt, invariant 1 also transitively
        covers original_receipt_hash — since it's part of the signed
        content, tampering with which original a review claims to have
        reviewed invalidates that review's own signature.
        """
        with self._lock:
            expected_prev = self._genesis_hash

            for i, item in enumerate(self._chain):
                is_review = isinstance(item, HumanReviewReceipt)
                hash_field = "review_receipt_hash" if is_review else "receipt_hash"

                # Invariant 1: signature valid
                content = asdict(item)
                stored_hash = content.pop(hash_field)
                expected_sig = self._sign_receipt(content)
                if not hmac.compare_digest(stored_hash, expected_sig):
                    return False

                # Invariant 2: previous_receipt_hash links to prior item
                if not hmac.compare_digest(item.previous_receipt_hash, expected_prev):
                    return False

                # Invariant 3: chain_position is strictly sequential
                if item.chain_position != i:
                    return False

                expected_prev = stored_hash

        return True

    def get_receipt(self, transaction_id: str) -> Optional[ComplianceReceipt]:
        """Most recent chain item (of either type) matching transaction_id.
        Unchanged behavior from before HumanReviewReceipt existed — kept
        type-agnostic so existing callers are unaffected."""
        with self._lock:
            for r in reversed(self._chain):
                if r.transaction_id == transaction_id:
                    return r
        return None

    def get_compliance_receipt(self, transaction_id: str) -> Optional[ComplianceReceipt]:
        """Most recent ComplianceReceipt (never a review) matching
        transaction_id — used by issue_review() and available for callers
        that specifically need the original scan record, not a review."""
        with self._lock:
            for r in reversed(self._chain):
                if isinstance(r, ComplianceReceipt) and r.transaction_id == transaction_id:
                    return r
        return None

    def export_chain(self) -> List[Dict]:
        with self._lock:
            return [asdict(r) for r in self._chain]

    def chain_length(self) -> int:
        with self._lock:
            return len(self._chain)

ATTESTATION_CHAIN = AttestationChain()
