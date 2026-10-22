"""
Zero-egress regression test for /v1/scrub endpoint.
Proves no external TCP connections are made during scrubbing.
"""
import socket

from fastapi.testclient import TestClient


def test_scrub_makes_zero_external_network_calls(tmp_path, monkeypatch):
    """
    Regression: /v1/scrub must make zero external network connections
    even when all optional integrations are configured.

    Patches socket.socket to intercept any real TCP connection attempt
    and fail the test immediately if one is made.
    """
    from hermes.api import app

    monkeypatch.setenv("HERMES_DB_PATH", str(tmp_path / "chain.db"))
    monkeypatch.setenv("HERMES_DATA_DIR", str(tmp_path / "workspaces"))
    monkeypatch.setenv("HERMES_API_KEY", "test-egress-key")
    monkeypatch.setenv("HERMES_ENV", "development")
    # Set all optional integration URLs to confirm they are NOT called
    monkeypatch.setenv("HERMES_WEBHOOK_URL", "https://should-not-be-called.example.com")
    monkeypatch.setenv("HERMES_DRATA_CCT_URL", "https://should-not-be-called.example.com")
    monkeypatch.setenv("HERMES_VANTA_CLIENT_ID", "fake-client-id")
    monkeypatch.setenv("HERMES_VANTA_CLIENT_SECRET", "fake-secret")
    monkeypatch.setenv("HERMES_VANTA_RESOURCE_ID", "fake-resource-id")

    connection_attempts = []

    def intercept_connect(self, address):
        connection_attempts.append(address)
        raise OSError(f"ZERO-EGRESS TEST: blocked outbound connection to {address}")

    monkeypatch.setattr(socket.socket, "connect", intercept_connect)

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/v1/scrub",
        headers={"X-API-Key": "test-egress-key"},
        json={"text": "Patient SSN 123-45-6789 DOB 01/01/1980"},
    )

    assert len(connection_attempts) == 0, (
        f"ZERO-EGRESS VIOLATION: /v1/scrub attempted {len(connection_attempts)} "
        f"external network connection(s): {connection_attempts}"
    )
    assert response.status_code in (200, 201, 422), (
        f"Unexpected status: {response.status_code}"
    )
