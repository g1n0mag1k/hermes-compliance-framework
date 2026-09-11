"""
tests/test_proxy.py — Proxy attestation integration test
Verifies that relay() scrubs PHI, issues a complete attestation receipt,
and never forwards raw sensitive values upstream.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from hermes.proxy import ProxyRelay
from hermes.attestation import ATTESTATION_CHAIN


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        self.server.captured_body = self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"id":"fake","choices":[]}')

    def log_message(self, *args):
        pass


@pytest.fixture()
def fake_upstream():
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    server.captured_body = b""
    thread = threading.Thread(target=server.handle_request)
    thread.daemon = True
    thread.start()
    host, port = server.server_address
    yield server, f"http://{host}:{port}"
    server.server_close()


def test_proxy_scrubs_ssn_from_payload(fake_upstream):
    server, base_url = fake_upstream
    relay = ProxyRelay(timeout=5.0)

    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Patient SSN is 123-45-6789 and name is Jane Smith."}
        ]
    }).encode()

    response, transaction_id, flags_triggered = relay.relay(
        target=base_url,
        method="POST",
        path="/v1/chat/completions",
        headers={"content-type": "application/json"},
        body=payload,
    )

    upstream_body = server.captured_body.decode()

    assert "123-45-6789" not in upstream_body, "Raw SSN leaked to upstream"
    assert "[REDACTED_SSN]" in upstream_body, "SSN redaction placeholder missing"
    assert any("SSN" in k or "ssn" in k.lower() for k in flags_triggered), \
        f"SSN flag not in flags_triggered: {flags_triggered}"


def test_proxy_issues_attestation_receipt(fake_upstream):
    server, base_url = fake_upstream
    relay = ProxyRelay(timeout=5.0)

    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Call me at 555-867-5309, my SSN is 987-65-4321."}
        ]
    }).encode()

    chain_length_before = len(ATTESTATION_CHAIN._chain)

    relay.relay(
        target=base_url,
        method="POST",
        path="/v1/chat/completions",
        headers={"content-type": "application/json"},
        body=payload,
    )

    chain_length_after = len(ATTESTATION_CHAIN._chain)

    assert chain_length_after == chain_length_before + 1, \
        "No attestation receipt was issued by the proxy"

    receipt = ATTESTATION_CHAIN._chain[-1]

    assert receipt.count_detected, "count_detected is empty on receipt"
    assert receipt.count_redacted is not None, "count_redacted missing from receipt"

    total_triggered = sum(receipt.count_detected.values())
    total_redacted = sum(receipt.count_redacted.values())
    assert total_triggered == total_redacted, \
        f"Detection/redaction parity failed: triggered={total_triggered} redacted={total_redacted}"


def test_proxy_clean_payload_issues_receipt(fake_upstream):
    server, base_url = fake_upstream
    relay = ProxyRelay(timeout=5.0)

    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "What is the weather today?"}]
    }).encode()

    chain_length_before = len(ATTESTATION_CHAIN._chain)

    relay.relay(
        target=base_url,
        method="POST",
        path="/v1/chat/completions",
        headers={"content-type": "application/json"},
        body=payload,
    )

    assert len(ATTESTATION_CHAIN._chain) == chain_length_before + 1, \
        "No receipt issued for clean payload"
