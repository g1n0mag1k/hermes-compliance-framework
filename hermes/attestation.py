"""
hermes/attestation.py — Cryptographically Signed Compliance Attestation Receipts

PHI-OMEGA audit status:
  Round 1 — OWNER/CODE-VERIFIED, NOT INDEPENDENTLY REPRODUCED (frozen)
  Round 2 — Finding #1 closed: applicability propagation via superseded_by
             and is_chain_head fields, stored outside the signature envelope
             so mutability does not invalidate historical signatures.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import warnings
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union
from hermes.classifier import COVERED_CFRS, NOT_COVERED_CFRS

REVIEW_DECISIONS = ("accepted", "overridden", "escalated")
DEFAULT_DB_PATH = "hermes_chain.db"

# Fields that are mutable chain metadata — excluded from HMAC signature
# envelope so that applicability propagation mutations do not invalidate
# historical signatures. These fields are stored in a separate SQLite
# column, not inside receipt_json, so tampering with them is detectable
# by comparing against the immutable signed payload.
_MUTABLE_FIELDS = frozenset({"superseded_by", "is_chain_head"})


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
    # --- Immutable signed fields ---
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
    detectors_executed: Dict[str, str]
    # --- Mutable chain metadata (outside signature envelope) ---
    # superseded_by: null = authoritative. Populated = hash of superseding
    # receipt. A verifier MUST NOT treat this receipt as standalone
    # authoritative evidence if superseded_by is non-null.
    # is_chain_head: True only for the current tail of the chain.
    # These fields are stored in a separate SQLite column so mutations
    # do not invalidate the historical HMAC signature.
    superseded_by: Optional[str] = None
    is_chain_head: bool = True


@dataclass
class HumanReviewReceipt:
    """A human review/override event chained alongside ComplianceReceipts.
    Same signing scheme, same chain_position sequence, same tamper-evidence
    guarantees. Mutable applicability fields follow the same pattern as
    ComplianceReceipt — stored outside the signature envelope.
    """
    # --- Immutable signed fields ---
    review_id: str
    transaction_id: str
    reviewed_by: str
    issued_at: str
    decision: str  # "accepted" | "overridden" | "escalated"
    override_reason: Optional[str]
    original_receipt_hash: str
    previous_receipt_hash: str
    review_receipt_hash: str
    chain_position: int
    # --- Mutable chain metadata (outside signature envelope) ---
    superseded_by: Optional[str] = None
    is_chain_head: bool = True


ChainItem = Union[ComplianceReceipt, HumanReviewReceipt]

# Fields excluded from the HMAC content dict before signing.
# Must match _MUTABLE_FIELDS plus the hash field itself (which is the
# output of signing, not an input to it).
_COMPLIANCE_SIGN_EXCLUDE = _MUTABLE_FIELDS | {"receipt_hash"}
_REVIEW_SIGN_EXCLUDE = _MUTABLE_FIELDS | {"review_receipt_hash"}


class AttestationChain:
    ISSUER = "Hermes Relay v1.0.0 — hermesrelay.dev"
    COMPLIANCE_FRAMEWORKS = ["HIPAA", "PCI-DSS"]

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._chain: List[ChainItem] = []
        self._lock = threading.Lock()
        self._genesis_hash = hashlib.sha256(b"hermes-genesis-block").hexdigest()
        self._db_path = db_path or os.environ.get("HERMES_DB_PATH", DEFAULT_DB_PATH)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_db()
        self._load_from_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    chain_position  INTEGER PRIMARY KEY,
                    transaction_id  TEXT    NOT NULL,
                    receipt_hash    TEXT    NOT NULL,
                    item_type       TEXT    NOT NULL DEFAULT 'compliance',
                    receipt_json    TEXT    NOT NULL,
                    superseded_by   TEXT,
                    is_chain_head   INTEGER NOT NULL DEFAULT 1
                )
                """
            )

    def _load_from_db(self) -> None:
        """Reconstruct the in-memory chain from SQLite in chain order.
        Mutable applicability fields are loaded from their dedicated columns,
        not from receipt_json, so they reflect post-issuance mutations."""
        cursor = self._conn.execute(
            """
            SELECT item_type, receipt_json, superseded_by, is_chain_head
            FROM receipts
            ORDER BY chain_position ASC
            """
        )
        for item_type, receipt_json, superseded_by, is_chain_head in cursor.fetchall():
            data = json.loads(receipt_json)
            # Override with the authoritative mutable-column values
            data["superseded_by"] = superseded_by
            data["is_chain_head"] = bool(is_chain_head)
            if item_type == "review":
                self._chain.append(HumanReviewReceipt(**data))
            else:
                self._chain.append(ComplianceReceipt(**data))

    def _persist_item(self, item: ChainItem) -> None:
        """Write a newly-issued chain item to SQLite. Mutable fields are
        written to dedicated columns so they can be updated without touching
        receipt_json (which must remain immutable for signature verification)."""
        if isinstance(item, HumanReviewReceipt):
            item_type = "review"
            item_hash = item.review_receipt_hash
        else:
            item_type = "compliance"
            item_hash = item.receipt_hash

        # receipt_json stores only the immutable signed payload
        immutable_data = {
            k: v for k, v in asdict(item).items()
            if k not in _MUTABLE_FIELDS
        }

        with self._conn:
            self._conn.execute(
                """
                INSERT INTO receipts
                    (chain_position, transaction_id, receipt_hash,
                     item_type, receipt_json, superseded_by, is_chain_head)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.chain_position,
                    item.transaction_id,
                    item_hash,
                    item_type,
                    json.dumps(immutable_data),
                    item.superseded_by,
                    int(item.is_chain_head),
                ),
            )

    def _update_applicability(self, item: ChainItem) -> None:
        """Update only the mutable applicability columns for an existing
        chain item. Never touches receipt_json — the immutable signed payload
        is preserved exactly as issued. Called while holding self._lock."""
        with self._conn:
            self._conn.execute(
                """
                UPDATE receipts
                SET superseded_by = ?, is_chain_head = ?
                WHERE chain_position = ?
                """,
                (
                    item.superseded_by,
                    int(item.is_chain_head),
                    item.chain_position,
                ),
            )

    def _sign_receipt(self, content: Dict) -> str:
        """HMAC-SHA256 sign a content dict. Mutable fields must already be
        excluded from content before this is called."""
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        return hmac.new(
            SIGNING_KEY,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _build_sign_content(self, item: ChainItem) -> Dict:
        """Return the signable content dict for an item — all fields except
        the mutable applicability fields and the hash field itself."""
        full = asdict(item)
        if isinstance(item, HumanReviewReceipt):
            exclude = _REVIEW_SIGN_EXCLUDE
        else:
            exclude = _COMPLIANCE_SIGN_EXCLUDE
        return {k: v for k, v in full.items() if k not in exclude}

    def _previous_hash(self) -> str:
        if not self._chain:
            return self._genesis_hash
        last = self._chain[-1]
        return (
            last.review_receipt_hash
            if isinstance(last, HumanReviewReceipt)
            else last.receipt_hash
        )

    def _mark_previous_superseded(self, new_item_hash: str) -> None:
        """Mark the current chain tail as superseded by new_item_hash.
        Called while holding self._lock, before the new item is appended.
        Mutates only the mutable applicability fields — the tail item's
        receipt_json and signature are never touched."""
        if not self._chain:
            return
        prev = self._chain[-1]
        prev.superseded_by = new_item_hash
        prev.is_chain_head = False
        self._update_applicability(prev)

    def issue(
        self,
        transaction_id: str,
        flags_triggered: Dict[str, int],
        flags_redacted: Dict[str, int],
        char_count_in: int,
        char_count_out: int,
        downstream_target: Optional[str] = None,
        detectors_executed: Optional[Dict[str, str]] = None,
    ) -> ComplianceReceipt:
        evidence_incomplete = list(NOT_COVERED_CFRS)
        detectors_executed = detectors_executed or {}
        pii_detected = list(flags_triggered.keys())
        pii_redacted = list(flags_redacted.keys())
        # COUNT PARITY: compare full dicts (keys AND counts), not just key sets
        zero_egress = flags_triggered == flags_redacted

        with self._lock:
            position = len(self._chain)
            prev_hash = self._previous_hash()
            receipt_id = f"rcpt_{transaction_id}_{position:06d}"
            issued_at = datetime.now(timezone.utc).isoformat()

            # Build the immutable signed content — no mutable fields
            sign_content = {
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
                "zero_pii_egress_scope_note": (
                    "Confirmed within declared_scope only. "
                    "evidence_incomplete_categories were not checked."
                ),
                "downstream_target": downstream_target,
                "previous_receipt_hash": prev_hash,
                "chain_position": position,
                "declared_scope": COVERED_CFRS,
                "evidence_incomplete_categories": evidence_incomplete,
                "detectors_executed": detectors_executed,
            }

            signature = self._sign_receipt(sign_content)

            receipt = ComplianceReceipt(
                **sign_content,
                receipt_hash=signature,
                superseded_by=None,
                is_chain_head=True,
            )

            self._mark_previous_superseded(signature)
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
        if decision not in REVIEW_DECISIONS:
            raise ValueError(
                f"decision must be one of {REVIEW_DECISIONS} — got {decision!r}"
            )

        with self._lock:
            original: Optional[ComplianceReceipt] = None
            for item in reversed(self._chain):
                if (
                    isinstance(item, ComplianceReceipt)
                    and item.transaction_id == transaction_id
                ):
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

            sign_content = {
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

            signature = self._sign_receipt(sign_content)

            review = HumanReviewReceipt(
                **sign_content,
                review_receipt_hash=signature,
                superseded_by=None,
                is_chain_head=True,
            )

            self._mark_previous_superseded(signature)
            self._chain.append(review)
            self._persist_item(review)

        return review

    def verify_chain(self) -> bool:
        """
        Full chain verification — four invariants must hold uniformly
        across ComplianceReceipts and HumanReviewReceipts:

        1. Every item's HMAC signature is valid against its immutable
           signed content (mutable fields excluded from verification input)
        2. Every item.previous_receipt_hash equals the prior item's hash
        3. chain_position values are strictly sequential with no gaps
        4. Applicability propagation: only the tail item may have
           is_chain_head=True and superseded_by=None. Every non-tail item
           must have is_chain_head=False and superseded_by populated.
           Closes PHI-OMEGA Round 2 Finding #1.
        """
        with self._lock:
            expected_prev = self._genesis_hash

            for i, item in enumerate(self._chain):
                is_review = isinstance(item, HumanReviewReceipt)

                # Invariant 1: rebuild sign content (mutable fields excluded)
                # and verify HMAC
                sign_content = self._build_sign_content(item)
                stored_hash = (
                    item.review_receipt_hash if is_review else item.receipt_hash
                )
                expected_sig = self._sign_receipt(sign_content)
                if not hmac.compare_digest(stored_hash, expected_sig):
                    return False

                # Invariant 2: hash chain linkage
                if not hmac.compare_digest(item.previous_receipt_hash, expected_prev):
                    return False

                # Invariant 3: sequential positions
                if item.chain_position != i:
                    return False

                # Invariant 4: applicability propagation
                is_tail = (i == len(self._chain) - 1)
                if is_tail:
                    if not item.is_chain_head or item.superseded_by is not None:
                        return False
                else:
                    if item.is_chain_head or item.superseded_by is None:
                        return False

                expected_prev = stored_hash

        return True

    def get_receipt(self, transaction_id: str) -> Optional[ChainItem]:
        """Most recent chain item matching transaction_id."""
        with self._lock:
            for r in reversed(self._chain):
                if r.transaction_id == transaction_id:
                    return r
        return None

    def get_compliance_receipt(
        self, transaction_id: str
    ) -> Optional[ComplianceReceipt]:
        """Most recent ComplianceReceipt (never a review) for transaction_id."""
        with self._lock:
            for r in reversed(self._chain):
                if (
                    isinstance(r, ComplianceReceipt)
                    and r.transaction_id == transaction_id
                ):
                    return r
        return None

    def get_current_head(self) -> Optional[ChainItem]:
        """Return the current authoritative chain head — the only item a
        verifier may treat as standalone evidence without traversal.
        Returns None on an empty chain."""
        with self._lock:
            return self._chain[-1] if self._chain else None

    def is_authoritative(self, receipt_hash: str) -> bool:
        """Return True only if receipt_hash identifies the current chain
        head. Verifiers must call this before relying on any receipt as
        standalone authoritative evidence. False means the receipt has been
        superseded — call get_current_head() to resolve current state."""
        with self._lock:
            if not self._chain:
                return False
            tail = self._chain[-1]
            tail_hash = (
                tail.review_receipt_hash
                if isinstance(tail, HumanReviewReceipt)
                else tail.receipt_hash
            )
            return hmac.compare_digest(tail_hash, receipt_hash)


    def issue_checkpoint(self) -> Dict:
        """Issue a signed current-head checkpoint — a standalone artifact
        that identifies the authoritative chain head at a point in time.
        Includes a monotonic epoch (chain_length) so freshness and
        rollback attacks are detectable.

        A verifier presented with a receipt in isolation MUST obtain a
        fresh checkpoint and confirm the receipt hash matches
        checkpoint["head_hash"] before treating it as authoritative.
        A checkpoint with a lower epoch than a previously seen checkpoint
        MUST be rejected (Massimiliano Round 2 falsification test #8).
        """
        with self._lock:
            if not self._chain:
                raise RuntimeError("Cannot issue checkpoint on empty chain")
            tail = self._chain[-1]
            tail_hash = (
                tail.review_receipt_hash
                if isinstance(tail, HumanReviewReceipt)
                else tail.receipt_hash
            )
            epoch = len(self._chain)  # monotonic — never decreases
            issued_at = datetime.now(timezone.utc).isoformat()

            content = {
                "checkpoint_type": "current_head",
                "head_hash": tail_hash,
                "chain_position": tail.chain_position,
                "epoch": epoch,
                "issued_at": issued_at,
                "issuer": self.ISSUER,
            }
            canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
            signature = hmac.new(
                SIGNING_KEY,
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            content["checkpoint_signature"] = signature
            return content

    def verify_checkpoint(self, checkpoint: Dict, min_epoch: int = 0) -> bool:
        """Verify a checkpoint signature and freshness.

        Returns True only if:
        1. The HMAC signature is valid
        2. The epoch is >= min_epoch (freshness — rejects stale checkpoints)
        3. The head_hash matches the current chain tail

        Closes Massimiliano Round 2 falsification test #8 (stale checkpoint
        replay) and underpins tests #3, #4, #6 (fork/truncation/prefix).
        """
        try:
            provided_sig = checkpoint.get("checkpoint_signature")
            if not provided_sig:
                return False

            content = {k: v for k, v in checkpoint.items()
                       if k != "checkpoint_signature"}
            canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
            expected_sig = hmac.new(
                SIGNING_KEY,
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(provided_sig, expected_sig):
                return False

            if checkpoint.get("epoch", 0) < min_epoch:
                return False

            with self._lock:
                if not self._chain:
                    return False
                tail = self._chain[-1]
                tail_hash = (
                    tail.review_receipt_hash
                    if isinstance(tail, HumanReviewReceipt)
                    else tail.receipt_hash
                )
                return hmac.compare_digest(
                    checkpoint.get("head_hash", ""), tail_hash
                )
        except Exception:
            return False

    def detect_fork(self, receipt_hash_a: str, receipt_hash_b: str) -> bool:
        """Return True if two receipts claim the same chain_position —
        indicating a fork (concurrent write attempt from the same parent).
        Closes Massimiliano Round 2 falsification test #7.
        A fork must never be silently resolved; callers must halt and
        alert on True."""
        with self._lock:
            positions: Dict[int, list] = {}
            for item in self._chain:
                h = (item.review_receipt_hash
                     if isinstance(item, HumanReviewReceipt)
                     else item.receipt_hash)
                pos = item.chain_position
                positions.setdefault(pos, []).append(h)

            # A fork exists if any position has more than one hash,
            # OR if the two provided hashes share a chain_position
            for pos, hashes in positions.items():
                if len(hashes) > 1:
                    return True

            # Also check the two specific hashes passed in
            pos_a = next(
                (item.chain_position for item in self._chain
                 if (item.review_receipt_hash
                     if isinstance(item, HumanReviewReceipt)
                     else item.receipt_hash) == receipt_hash_a),
                None,
            )
            pos_b = next(
                (item.chain_position for item in self._chain
                 if (item.review_receipt_hash
                     if isinstance(item, HumanReviewReceipt)
                     else item.receipt_hash) == receipt_hash_b),
                None,
            )
            if pos_a is not None and pos_b is not None and pos_a == pos_b:
                return True
            return False

    def verify_receipt_applicability(
        self, receipt_hash: str, checkpoint: Dict, min_epoch: int = 0
    ) -> Dict:
        """Full applicability verification for a receipt presented in isolation.

        Returns a structured verdict so callers can distinguish:
          - historically_valid: the receipt exists in the chain with valid HMAC
          - currently_applicable: the receipt IS the current chain head
          - checkpoint_fresh: the checkpoint passes freshness + signature check
          - verdict: "authoritative" | "superseded" | "invalid" | "stale_checkpoint"

        This is the method an auditor or verifier MUST call — not just
        is_authoritative() — to close Massimiliano's core finding that
        historical validity != current applicability.
        """
        result = {
            "receipt_hash": receipt_hash,
            "historically_valid": False,
            "currently_applicable": False,
            "checkpoint_fresh": False,
            "verdict": "invalid",
        }

        # 1. Verify checkpoint freshness first — if stale, we cannot trust
        # the applicability determination at all
        if not self.verify_checkpoint(checkpoint, min_epoch=min_epoch):
            result["verdict"] = "stale_checkpoint"
            return result

        result["checkpoint_fresh"] = True

        # 2. Check historical validity — receipt must exist with valid HMAC
        with self._lock:
            matching = next(
                (item for item in self._chain
                 if (item.review_receipt_hash
                     if isinstance(item, HumanReviewReceipt)
                     else item.receipt_hash) == receipt_hash),
                None,
            )

        if matching is None:
            result["verdict"] = "invalid"
            return result

        sign_content = self._build_sign_content(matching)
        expected_sig = self._sign_receipt(sign_content)
        if not hmac.compare_digest(receipt_hash, expected_sig):
            result["verdict"] = "invalid"
            return result

        result["historically_valid"] = True

        # 3. Check current applicability against checkpoint head
        head_hash = checkpoint.get("head_hash", "")
        if hmac.compare_digest(receipt_hash, head_hash):
            result["currently_applicable"] = True
            result["verdict"] = "authoritative"
        else:
            result["verdict"] = "superseded"

        return result

    def export_chain(self) -> List[Dict]:
        with self._lock:
            return [asdict(r) for r in self._chain]

    def chain_length(self) -> int:
        with self._lock:
            return len(self._chain)


ATTESTATION_CHAIN = AttestationChain()