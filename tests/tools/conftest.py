"""Shared fixtures for tool tests: a local-lab engagement and a loopback server."""

import http.server
import json
import threading
from pathlib import Path

import pytest
import yaml

_PROGRAM = {
    "schema_version": 1,
    "program": {"name": "local-lab", "platform": "local-lab", "source": "manual"},
    "authorization": {"confirmed": False},
    "scope": {"in_scope": {"cidrs": ["127.0.0.0/8"]}},
    "testing_rules": {"max_requests_per_second": 2},
    "reporting": {"duplicate_policy": "first-reporter"},
}


@pytest.fixture
def lab_engagement(tmp_path: Path) -> Path:
    engagement = tmp_path / "local-lab"
    engagement.mkdir()
    (engagement / "program.yaml").write_text(yaml.safe_dump(_PROGRAM, sort_keys=False))
    (engagement / "scope.yaml").write_text(
        yaml.safe_dump({"schema_version": 1, **_PROGRAM["scope"]}, sort_keys=False)
    )
    (engagement / "authorization.json").write_text(
        json.dumps(
            {
                "confirmed": True,
                "confirmation_timestamp": "2000-01-01T00:00:00Z",
                "confirmed_by": "lab-operator",
            }
        )
    )
    return engagement


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"lab-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
