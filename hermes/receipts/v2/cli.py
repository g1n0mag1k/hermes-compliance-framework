"""
hermes/receipts/v2/cli.py — hermes-verify CLI entry point.

Usage:
    hermes-verify receipt <receipt.cose> --public-key <key.pem>

Exit codes:
    0 — signature_valid AND receipt_digest_valid
    1 — verification failure (signature invalid, digest mismatch, etc.)
    2 — malformed input (bad file, CBOR decode error, etc.)

The verifier has ZERO imports from hermes/attestation.py or any V1 module.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hermes.receipts.v2.verifier import verify_receipt


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hermes-verify",
        description="Verify a Hermes Relay V2 COSE_Sign1 audit receipt.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0  Both signature and receipt digest are valid.
  1  Verification failed (tampered, wrong key, digest mismatch).
  2  Malformed input (file not found, unreadable, or CBOR error).
""",
    )
    sub = parser.add_subparsers(dest="command")

    receipt_cmd = sub.add_parser(
        "receipt",
        help="Verify a COSE_Sign1 receipt file.",
    )
    receipt_cmd.add_argument(
        "receipt_file",
        type=Path,
        help="Path to the .cose file containing the COSE_Sign1 receipt.",
    )
    receipt_cmd.add_argument(
        "--public-key",
        required=True,
        type=Path,
        dest="public_key_file",
        help="Path to the PEM-encoded public key from the key manifest.",
    )
    receipt_cmd.add_argument(
        "--json",
        action="store_true",
        default=False,
        dest="output_json",
        help="Output verification result as JSON (default is human-readable).",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """
    CLI entry point. Returns exit code (0, 1, or 2).
    Prints JSON result to stdout. Errors to stderr.
    """
    args = _parse_args(argv)

    if args.command != "receipt":
        print("Usage: hermes-verify receipt <receipt.cose> --public-key <key.pem>",
              file=sys.stderr)
        return 2

    # --- Load receipt bytes ---
    try:
        cose_bytes = args.receipt_file.read_bytes()
    except FileNotFoundError:
        print(f"Error: Receipt file not found: {args.receipt_file}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"Error: Cannot read receipt file: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: Failed to read receipt file: {exc}", file=sys.stderr)
        return 2

    # --- Load public key ---
    try:
        public_key_pem = args.public_key_file.read_text(encoding="ascii")
    except FileNotFoundError:
        print(f"Error: Public key file not found: {args.public_key_file}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Error: Failed to read public key file: {exc}", file=sys.stderr)
        return 2

    # --- Verify ---
    result = verify_receipt(cose_bytes, public_key_pem)

    claims = result.claims

    if not args.output_json:
        status = "VALID" if result.fully_valid else "INVALID"
        print(status)
        print(f"signature_valid: {result.signature_valid}")
        print(f"receipt_digest_valid: {result.receipt_digest_valid}")
        print(f"chain_link_valid: {result.chain_link_valid}")
        print(f"signer_key_id: {result.signer_key_id or 'n/a'}")
        print(f"algorithm: {result.algorithm or 'n/a'}")
        print(f"issued_at: {result.issued_at or 'n/a'}")
        print(f"workspace_id: {claims.get('workspace_id', 'n/a')}")
        print(f"provider: {claims.get('upstream_provider', 'n/a')}")
        print(f"decision: {claims.get('decision', claims.get('gateway_decision', 'n/a'))}")
        print(f"forwarded: {claims.get('forwarded', 'n/a')}")
        print(f"policy_id: {claims.get('policy_id', 'n/a')}")
        print(f"policy_version: {claims.get('policy_version', 'n/a')}")
        print(f"policy_digest: {claims.get('policy_digest', 'n/a')}")
        if result.errors:
            print("errors:")
            for err in result.errors:
                print(f"  - {err}")
        if result.warnings:
            print("warnings:")
            for warn in result.warnings:
                print(f"  - {warn}")
    else:
        output = {
            "status": "VALID" if result.fully_valid else "INVALID",
            "signature_valid": result.signature_valid,
            "receipt_digest_valid": result.receipt_digest_valid,
            "chain_link_valid": result.chain_link_valid,
            "signer_key_id": result.signer_key_id,
            "algorithm": result.algorithm,
            "issued_at": result.issued_at,
            "claims": claims,
            "errors": result.errors,
            "warnings": result.warnings,
            "fully_valid": result.fully_valid,
        }
        print(json.dumps(output, indent=2))

    # Exit code
    if result.errors and any(
        "CBOR decode failed" in e or "not a COSE_Sign1" in e.lower()
        for e in result.errors
    ):
        return 2

    return 0 if result.fully_valid else 1


if __name__ == "__main__":
    sys.exit(main())
