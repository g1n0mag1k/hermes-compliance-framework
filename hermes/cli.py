"""
hermes/cli.py — Hermes Relay command-line interface.

Commands:
    hermes-relay serve           Start the FastAPI server
    hermes-relay install-service Write and enable systemd user service
    hermes-relay status          Show service status
    hermes-relay version         Show version
"""
import argparse
import os
import subprocess
import sys
import textwrap


VERSION = "1.0.0"

SYSTEMD_SERVICE = textwrap.dedent("""\
    [Unit]
    Description=Hermes Relay — PHI Detection & Compliance Evidence
    After=network.target

    [Service]
    Type=simple
    ExecStart=hermes-relay serve
    Restart=on-failure
    RestartSec=5
    Environment=HERMES_ENV=production

    [Install]
    WantedBy=default.target
""")


def cmd_serve(args):
    """Start the Hermes Relay FastAPI server."""
    import uvicorn
    host = os.environ.get("HERMES_HOST", "127.0.0.1")
    port = int(os.environ.get("HERMES_PORT", "8787"))
    print(f"Starting Hermes Relay on {host}:{port}")
    uvicorn.run("hermes.api:app", host=host, port=port, reload=False)


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


def main():
    parser = argparse.ArgumentParser(
        prog="hermes-relay",
        description="Hermes Relay — Local-first PHI detection and compliance evidence for MSPs",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("serve", help="Start the Hermes Relay API server")
    subparsers.add_parser("install-service", help="Install and enable systemd user service")
    subparsers.add_parser("status", help="Show service status")
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    commands = {
        "serve": cmd_serve,
        "install-service": cmd_install_service,
        "status": cmd_status,
        "version": cmd_version,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
