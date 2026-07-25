"""Shared fixtures for tool tests: a local-lab engagement and a loopback server."""

import http.server
import json
import ssl
import subprocess
import threading
from pathlib import Path

import pytest
import yaml

from hackbot.tools.actions import openssl_path

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

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        body = b"post-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("X-Lab", "head-ok")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET,HEAD,OPTIONS,POST")
        self.end_headers()

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


@pytest.fixture
def tls_server(tmp_path):
    openssl = openssl_path()
    if openssl is None:
        pytest.skip("openssl not installed")
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
