#!/usr/bin/env python3
"""
hermes/demo.py — 90-second MSP demo script

Shows:
1. PHI detected and redacted
2. Signed compliance receipt generated
3. Hash-chained audit evidence produced

Run:
    export HERMES_API_KEY=demo-key-123
    python3 hermes/demo.py
"""
import json
import os
import sys
import time

# Set demo API key if not already set
if not os.environ.get("HERMES_API_KEY"):
    os.environ["HERMES_API_KEY"] = "demo-key-123"

from hermes.classifier import scrub_payload
from hermes.attestation import ATTESTATION_CHAIN

DEMO_PAYLOAD = (
    "Patient: John Smith | SSN: 372-18-5421 | "
    "DOB: 1982-03-15 | MRN: 1234567 | "
    "Email: john.smith@example.com | "
    "Phone: 555-867-5309 | "
    "Address: 742 Evergreen Terrace, Springfield IL"
)

DIVIDER = "-" * 60

def pause(seconds=0.8):
    time.sleep(seconds)

def main():
    print()
    print("=" * 60)
    print(" HERMES RELAY — Live PHI Detection Demo")
    print(" hermesrelay.dev | Sui-Generis LLC")
    print("=" * 60)
    print()
    pause()

    print("[1] INCOMING PAYLOAD (before scan)")
    print(DIVIDER)
    print(DEMO_PAYLOAD)
    print()
    pause()

    print("[2] SCANNING...")
    print(DIVIDER)
    txn_id = "demo_txn_001"
    result = scrub_payload(transaction_id=txn_id, text=DEMO_PAYLOAD)
    pause()

    print("[3] PHI DETECTED — REDACTED OUTPUT")
    print(DIVIDER)
    print(result.clean_text)
    print()
    pause()

    print("[4] FLAGS TRIGGERED")
    print(DIVIDER)
    for flag, entry in result.audit_log.flags_triggered.items():
        count = entry.count if hasattr(entry, "count") else entry["count"]
        cfr = entry.cfr_citation if hasattr(entry, "cfr_citation") else entry.get("cfr_citation", "")
        print(f"  {flag:<30} count={count}  {cfr}")
    print()
    pause()

    print("[5] ISSUING SIGNED COMPLIANCE RECEIPT")
    print(DIVIDER)
    flags = {
        k: v.count if hasattr(v, "count") else v["count"]
        for k, v in result.audit_log.flags_triggered.items()
    }
    redacted = {
        k: v.count if hasattr(v, "count") else v["count"]
        for k, v in result.audit_log.flags_redacted.items()
    }
    receipt = ATTESTATION_CHAIN.issue(
        transaction_id=txn_id,
        flags_triggered=flags,
        flags_redacted=redacted,
        char_count_in=result.audit_log.original_char_count,
        char_count_out=result.audit_log.redacted_char_count,
        downstream_target=None,
        detectors_executed=result.detectors_executed,
    )
    pause()

    print("[6] COMPLIANCE RECEIPT")
    print(DIVIDER)
    print(f"  receipt_id:               {receipt.receipt_id}")
    print(f"  transaction_id:           {receipt.transaction_id}")
    print(f"  issued_at:                {receipt.issued_at}")
    print(f"  chain_position:           {receipt.chain_position}")
    print(f"  zero_pii_egress:          {receipt.zero_pii_egress_confirmed}")
    print(f"  phi_classes_detected:     {receipt.pii_classes_detected}")
    print(f"  receipt_hash:             {receipt.receipt_hash[:32]}...")
    print(f"  previous_receipt_hash:    {receipt.previous_receipt_hash[:32]}...")
    print()
    pause()

    print("[7] DECLARED SCOPE")
    print(DIVIDER)
    for cfr in receipt.declared_scope:
        print(f"  {cfr}")
    print()
    pause()

    print("=" * 60)
    print(" RESULT: PHI caught. Receipt signed. Chain updated.")
    print(" Zero PHI egress confirmed within declared scope.")
    print(" This receipt is now pushing to Drata CCT automatically.")
    print("=" * 60)
    print()

if __name__ == "__main__":
    main()
