"""
Mock Azure-OpenAI-compatible upstream for the Docker end-to-end test.

Records every request it receives so the test can prove what the gateway did
(and did not) forward. GET /__requests returns the recorded list as JSON.
Uses only the standard library.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RECORDED: list[dict] = []

RESPONSE = {
    "id": "chatcmpl-mock-0001",
    "object": "chat.completion",
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "Regular exercise improves cardiovascular health."},
            "finish_reason": "stop",
        }
    ],
}


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, body: object) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/__requests":
            self._send_json(200, RECORDED)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        RECORDED.append(
            {
                "method": "POST",
                "path": self.path,
                "body": body,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        )
        self._send_json(200, RESPONSE)

    def log_message(self, fmt: str, *args: object) -> None:
        print("mock-provider:", fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
