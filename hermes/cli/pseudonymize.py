"""hermes/cli/pseudonymize.py — Insurance broker pseudonymization CLI

Usage:
  hermes-relay pseudonymize \\
    --input  clients.csv \\
    --output coded_clients.csv \\
    --linkage linkage.enc \\
    --receipt receipt.json \\
    [--target "ChatGPT"]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hermes.agent import run_pseudonymization_scan
from hermes.ingest.healthsherpa import HealthSherpaIngester
from hermes.pseudonymizer import Pseudonymizer


def cmd_pseudonymize(args: argparse.Namespace) -> None:
    try:
        ingester = HealthSherpaIngester(args.input)
        df = ingester.load()
        ingester.validate(df)
        phi_columns = ingester.identify_phi_columns(df)
        result = run_pseudonymization_scan(
            df=df,
            phi_columns=phi_columns,
            downstream_target=args.target,
        )

        output_path = Path(args.output)
        if output_path.exists():
            raise FileExistsError(output_path)
        result.coded_df.to_csv(output_path, index=False)

        p = Pseudonymizer(phi_columns)
        p.export_linkage_table(result.linkage_table, args.linkage)

        receipt_path = Path(args.receipt)
        if receipt_path.exists():
            raise FileExistsError(receipt_path)
        receipt_path.write_text(
            json.dumps(result.receipt.__dict__, default=str, indent=2),
            encoding="utf-8",
        )

        print("[Hermes] Pseudonymization complete.")
        print(f"Transaction ID : {result.transaction_id}")
        print(f"Rows processed : {len(df)}")
        print(f'PHI columns    : {", ".join(phi_columns) or "(none detected)"}')
        print(f"Coded CSV      : {args.output}")
        print(f"Linkage table  : {args.linkage}  (AES-256-GCM encrypted)")
        print(f"Receipt        : {args.receipt}")
        print(f"Zero-egress confirmed: {result.receipt.zero_pii_egress_confirmed}")
    except Exception as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
