"""Shared fixtures for OpenSystem tests.

All target tests run against a REAL local HTTP server (stdlib http.server)
over genuine network I/O — there is no mock target anywhere.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opensystem.attack.planner import default_planner
from opensystem.core.engine import AdversarialEngine
from opensystem.knowledge.store import KnowledgeStore
from opensystem.policy.models import Policy
from opensystem.target.http_site import HttpSiteTarget


class VulnerableHandler(BaseHTTPRequestHandler):
    """A deliberately vulnerable app for authorized local testing."""

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence request logging
        pass

    def _send(self, status, body: bytes, content_type="text/html; charset=utf-8",
              extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.21.5")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, b"<html><head><title>VulnShop</title></head>"
                           b"<body>Welcome</body></html>")
        elif path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n")
        elif path == "/.env":
            self._send(200, b"APP_SECRET=supersecret\nDB_PASSWORD=hunter2\n")
        elif path == "/static/":
            self._send(200, b"<html><title>Index of /static/</title>"
                           b"<a href=\"x.txt\">x.txt</a></html>")
        elif path == "/admin":
            self._send(200, b"<html><body><h1>Admin Dashboard</h1></body></html>")
        elif path == "/login":
            self._send(302, b"", extra_headers={
                "Location": "https://opensystem-redirect-probe.example/",
                "Set-Cookie": "session=abc123; Path=/",
            })
        elif path == "/api/data":
            self._send(200, b'{"data":"ok"}',
                       content_type="application/json",
                       extra_headers={
                           "Access-Control-Allow-Origin": "https://opensystem-probe.example",
                       })
        elif path == "/clean":
            self._send(200, b"<html><body>clean</body></html>",
                       extra_headers={
                           "Content-Security-Policy": "default-src 'self'",
                           "X-Content-Type-Options": "nosniff",
                           "X-Frame-Options": "DENY",
                           "Referrer-Policy": "no-referrer",
                           "Strict-Transport-Security": "max-age=31536000",
                       })
        elif path.startswith("/opensystem-"):
            self._send(404, b"<pre>PHP Fatal error:  Uncaught Exception: boom\n"
                            b"Stack trace:\n  at php#0</pre>")
        else:
            self._send(404, b"<html><body>Not found</body></html>")

    def do_OPTIONS(self):
        self._send(200, b"", extra_headers={"Allow": "GET, POST, PUT, TRACE"})

    def do_TRACE(self):
        self._send(200, self.rfile.read(int(self.headers.get("Content-Length", 0))))

    def do_POST(self):
        if self.path.split("?", 1)[0] == "/login":
            self._send(302, b"", extra_headers={
                "Location": "https://opensystem-redirect-probe.example/",
            })
        else:
            self._send(200, b"ok")


@pytest.fixture(scope="module")
def vuln_server():
    """A real, locally-bound HTTP server exposing known weaknesses."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture()
def http_target(vuln_server) -> HttpSiteTarget:
    return HttpSiteTarget(url=vuln_server, environment="test",
                          authorized_scope=f"{vuln_server}/*")


@pytest.fixture()
def store(tmp_path):
    """A fresh in-temp-dir knowledge store for each test."""
    s = KnowledgeStore(str(tmp_path / "test.db"))
    yield s
    s.close()


@pytest.fixture()
def policy(http_target) -> Policy:
    target_model = http_target.discover()
    return Policy(
        target_name=target_model.adapter,
        environment=target_model.environment,
        scope=target_model.scope,
        max_rounds=20,
        max_experiments=100,
    )


@pytest.fixture()
def engine(store, http_target, policy) -> AdversarialEngine:
    return AdversarialEngine(store=store, policy=policy,
                             planner=default_planner(store))
