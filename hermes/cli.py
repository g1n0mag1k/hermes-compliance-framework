"""
hermes/cli.py — Hermes Relay command-line interface.

Commands:
    hermes-relay serve           Start the FastAPI server
    hermes-relay install-service Write and enable systemd user service
    hermes-relay status          Show service status
    hermes-relay version         Show version
    hermes-relay keystore-init   Create the persistent gateway signing keystore
    hermes-relay keystore-public-key
                                 Print the gateway signing public key (PEM)
    hermes-relay export-receipts Export a workspace's gateway receipts as .cose files
"""
import argparse
import multiprocessing
import os
import subprocess
import sys
import textwrap
from pathlib import Path


VERSION = "1.0.0"

SYSTEMD_SERVICE = textwrap.dedent("""\
    [Unit]
    Description=Hermes Relay — PHI Detection & Compliance Evidence
    After=network.target

    [Service]
    Type=simple
    ExecStart=hermes-relay serve --both
    Restart=on-failure
    RestartSec=5
    Environment=HERMES_ENV=production

    [Install]
    WantedBy=default.target
""")


def _run_server(application, host, port):
    import uvicorn

    uvicorn.run(application, host=host, port=port, reload=False)


def cmd_serve(args):
    """Start the Hermes Relay API, gateway, or both services."""
    host = os.environ.get("HERMES_HOST", "127.0.0.1")
    hermes_port = int(os.environ.get("HERMES_PORT", "8787"))

    if args.gateway:
        print(f"Starting Hermes AI gateway on {host}:8788")
        _run_server("gateway.app:app", host, 8788)
        return

    if args.both:
        processes = [
            multiprocessing.Process(
                target=_run_server,
                args=("hermes.api:app", host, hermes_port),
            ),
            multiprocessing.Process(
                target=_run_server,
                args=("gateway.app:app", host, 8788),
            ),
        ]
        print(f"Starting Hermes Relay on {host}:{hermes_port}")
        print(f"Starting Hermes AI gateway on {host}:8788")
        for process in processes:
            process.start()

        try:
            for process in processes:
                process.join()
        except KeyboardInterrupt:
            print("Stopping Hermes Relay and AI gateway...")
            for process in processes:
                if process.is_alive():
                    process.terminate()
            for process in processes:
                process.join()
        return

    print(f"Starting Hermes Relay on {host}:{hermes_port}")
    _run_server("hermes.api:app", host, hermes_port)


def cmd_install_service(args):
    """Write and enable the systemd user service unit."""
    service_dir = os.path.expanduser("~/.config/systemd/user")
    service_path = os.path.join(service_dir, "hermes-relay.service")

    os.makedirs(service_dir, exist_ok=True)

    with open(service_path, "w") as f:
        f.write(SYSTEMD_SERVICE)

    print(f"Service unit written to {service_path}")

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            check=True
        )
        subprocess.run(
            ["systemctl", "--user", "enable", "hermes-relay"],
            check=True
        )
        subprocess.run(
            ["systemctl", "--user", "start", "hermes-relay"],
            check=True
        )
        print("Hermes Relay service enabled and started.")
        print("Run 'hermes-relay status' to confirm.")
    except subprocess.CalledProcessError as e:
        print(f"systemctl error: {e}")
        print("Service file written. Enable manually with:")
        print("  systemctl --user daemon-reload")
        print("  systemctl --user enable hermes-relay")
        print("  systemctl --user start hermes-relay")
        sys.exit(1)
    except FileNotFoundError:
        print("systemd not found on this system.")
        print(f"Service file written to {service_path}")
        print("Enable manually when running on a systemd Linux host.")


def cmd_status(args):
    """Show Hermes Relay service status."""
    try:
        subprocess.run(
            ["systemctl", "--user", "status", "hermes-relay"],
            check=False
        )
    except FileNotFoundError:
        print("systemd not available on this system.")


def cmd_version(args):
    """Show Hermes Relay version."""
    print(f"Hermes Relay v{VERSION}")
    print("hermesrelay.dev | Sui-Generis LLC")


def _keystore_env() -> tuple[Path, bytes]:
    path = os.environ.get("HERMES_GATEWAY_KEYSTORE_PATH")
    passphrase = os.environ.get("HERMES_GATEWAY_KEYSTORE_PASSPHRASE")
    if not path or not passphrase:
        print(
            "Error: HERMES_GATEWAY_KEYSTORE_PATH and "
            "HERMES_GATEWAY_KEYSTORE_PASSPHRASE must both be set.",
            file=sys.stderr,
        )
        sys.exit(2)
    return Path(path), passphrase.encode("utf-8")


def _open_gateway_signer():
    from hermes.receipts.v2.key_store import KeyStore

    path, passphrase = _keystore_env()
    try:
        return KeyStore.open(path, passphrase).load_signer()
    except FileNotFoundError:
        print(
            f"Error: Keystore not found at {path}. Run 'hermes-relay keystore-init' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_keystore_init(args):
    """Create the encrypted gateway signing keystore. Never overwrites."""
    from hermes.receipts.v2.key_store import KeyStore

    path, passphrase = _keystore_env()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        store = KeyStore.create(path, passphrase)
    except FileExistsError:
        print(
            f"Error: Keystore already exists at {path}; refusing to overwrite. "
            "Replacing it would make every existing receipt unverifiable "
            "with the new public key.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Created gateway keystore: {path}")
    print(f"algorithm: {store.algorithm}")
    print(f"key_id: {store.key_id}")


def cmd_keystore_public_key(args):
    """Print the gateway signing public key PEM to stdout (key id to stderr)."""
    manifest = _open_gateway_signer().public_key_manifest()
    print(f"key_id: {manifest['key_id']}", file=sys.stderr)
    sys.stdout.write(manifest["public_key_pem"])


def cmd_export_receipts(args):
    """Write every gateway receipt of a workspace to OUT as ordered .cose files."""
    from gateway.evidence import list_gateway_receipts
    from hermes.workspaces import get_workspace

    workspace = get_workspace(args.workspace)
    if workspace is None:
        print(f"Error: Workspace {args.workspace!r} not found.", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    if any(out_dir.glob("*.cose")):
        print(
            f"Error: {out_dir} already contains .cose files; use an empty directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    manifest = _open_gateway_signer().public_key_manifest()
    (out_dir / "gateway-public.pem").write_text(manifest["public_key_pem"], encoding="ascii")

    receipts = list_gateway_receipts(workspace)
    for receipt in receipts:
        payload = receipt["payload"]
        name = (
            f"{receipt['gateway_sequence']:08d}-{payload.get('decision', 'UNKNOWN')}-"
            f"{receipt['receipt_digest'][:16]}.cose"
        )
        (out_dir / name).write_bytes(bytes.fromhex(receipt["cose_sign1_hex"]))
        print(
            f"{name} decision={payload.get('decision')} "
            f"forwarded={payload.get('forwarded')} "
            f"transaction_id={receipt['transaction_id']}"
        )
    print(f"Exported {len(receipts)} receipt(s) for workspace {workspace.workspace_id!r} to {out_dir}")
    print(f"Public key: {out_dir / 'gateway-public.pem'} (key_id {manifest['key_id']})")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hermes-relay",
        description="Hermes Relay — Local-first PHI detection and compliance evidence for MSPs",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start Hermes Relay services")
    serve_modes = serve_parser.add_mutually_exclusive_group()
    serve_modes.add_argument(
        "--gateway",
        action="store_true",
        help="Start the AI enforcement gateway on port 8788",
    )
    serve_modes.add_argument(
        "--both",
        action="store_true",
        help="Start the Hermes API and AI gateway together",
    )
    subparsers.add_parser("install-service", help="Install and enable systemd user service")
    subparsers.add_parser("status", help="Show service status")
    subparsers.add_parser("version", help="Show version")
    subparsers.add_parser(
        "keystore-init",
        help="Create the gateway signing keystore at HERMES_GATEWAY_KEYSTORE_PATH",
    )
    subparsers.add_parser(
        "keystore-public-key",
        help="Print the gateway signing public key (PEM) to stdout",
    )
    export_parser = subparsers.add_parser(
        "export-receipts",
        help="Export a workspace's gateway receipts as ordered .cose files",
    )
    export_parser.add_argument("--workspace", required=True, help="Workspace ID")
    export_parser.add_argument("--out", required=True, help="Empty output directory")

    args = parser.parse_args(argv)

    commands = {
        "serve": cmd_serve,
        "install-service": cmd_install_service,
        "status": cmd_status,
        "version": cmd_version,
        "keystore-init": cmd_keystore_init,
        "keystore-public-key": cmd_keystore_public_key,
        "export-receipts": cmd_export_receipts,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
