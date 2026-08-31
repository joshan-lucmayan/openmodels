"""End-to-end tests for the real HTTP target adapter.

These tests spin up a REAL HTTP server on 127.0.0.1 (stdlib http.server) and
exercise the adapter over genuine network I/O — there is no mock adapter, no
mocked HTTP layer. Each assertion reflects actual bytes received on the wire.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opensystem.attack.planner import default_planner
from opensystem.core.engine import AdversarialEngine
from opensystem.models import (
    Hypothesis,
    HypothesisStatus,
    Target,
    TestOutcome,
    TestSpec,
)
from opensystem.target.http_site import HttpSiteTarget
from opensystem.target.interface import (
    Capability,
    adapter_capability,
    adapter_supports,
)


class _VulnerableHandler(BaseHTTPRequestHandler):
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
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n")
        elif path == "/.env":
            self._send(200, b"APP_SECRET=supersecret\nDB_PASSWORD=hunter2\n")
        elif path == "/static/":
            self._send(200, b"<html><title>Index of /static/</title>"
                           b"<a href=\"x.txt\">x.txt</a></html>")
        elif path == "/admin":
            self._send(200, b"<html><body><h1>Admin Dashboard</h1>"
                           b"<p>Manage users here</p></body></html>")
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
                           "Access-Control-Allow-Credentials": "true",
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
        # echo is handled below for verification

    def do_POST(self):
        if self.path.split("?", 1)[0] == "/login":
            self._send(302, b"", extra_headers={
                "Location": "https://opensystem-redirect-probe.example/",
            })
        else:
            self._send(200, b"ok")


@pytest.fixture(scope="module")
def vuln_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture()
def http_target(vuln_server):
    return HttpSiteTarget(url=vuln_server, environment="test",
                          authorized_scope=f"{vuln_server}/*")


def test_adapter_declares_test_planning_capability(http_target):
    assert adapter_supports(http_target, Capability.TEST_PLANNING)
    assert adapter_capability(
        http_target, Capability.TEST_PLANNING, "plan_test"
    ) is not None


def test_discover_is_real(http_target):
    target_model = http_target.discover()
    assert target_model.kind == "web"
    assert target_model.adapter == "http"
    assert target_model.rules["base_url"] == http_target.base_url
    assert target_model.scope == f"{http_target.base_url}/*"
    assert target_model.interfaces  # root path discovered over the wire


def test_target_id_includes_port(http_target, vuln_server):
    port = vuln_server.rsplit(":", 1)[1]
    assert http_target.discover().id.endswith(f":{port}")


def test_evolve_from_blocked_never_leaks_mock_strategies(http_target, store):
    """Only http-* strategies are evolved for HTTP targets."""
    engine = AdversarialEngine(store)
    target_model = http_target.discover()

    blocked = Hypothesis(
        target_id=target_model.id,
        statement="can http-dir-listing be demonstrated as a weakness?",
        status=HypothesisStatus.REJECTED,
        origin="strategy:http-dir-listing",
    )
    store.save_hypothesis(blocked)

    next_hyp = engine._evolve_from_blocked(blocked, target_model)
    assert next_hyp is not None
    # The successor must be another http-* strategy.
    assert next_hyp.origin.startswith("strategy:http-")


def test_security_headers_missing_is_success(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-security-headers", "path": "/",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "Content-Security-Policy" in result.detail["missing"]
    # HSTS is only required on https targets; this is plaintext http.
    assert "Strict-Transport-Security" not in result.detail["missing"]


def test_security_headers_present_is_failure(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-security-headers", "path": "/clean",
    }))
    assert result.outcome == TestOutcome.FAILURE
    assert result.detail["missing"] == []


def test_server_disclosure(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-server-disclosure", "path": "/",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "nginx/1.21.5" in result.observed_result


def test_dir_listing(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-dir-listing",
        "dirs": ["/static/", "/assets/"],
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "/static/" in result.detail["exposed_dirs"]


def test_sensitive_paths(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-sensitive-paths",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "/.git/HEAD" in result.detail["exposed_paths"]
    assert "/.env" in result.detail["exposed_paths"]


def test_http_methods(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-methods", "path": "/",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "PUT" in result.detail["methods"]
    assert "TRACE" in result.detail["methods"]


def test_cors_reflection(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-cors", "path": "/api/data",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert result.detail["reflected_origin"] == "https://opensystem-probe.example"


def test_cookie_flags(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-cookie-flags", "path": "/login",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert any("session" in c and "HttpOnly" in c for c in result.detail["insecure_cookies"])


def test_open_redirect(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-open-redirect",
        "paths": ["/login"],
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "opensystem-redirect-probe.example" in result.detail["hits"][0]


def test_admin_exposure(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-admin-exposure",
        "paths": ["/admin"],
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "/admin" in result.detail["reachable"]


def test_error_disclosure(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-error-disclosure",
    }))
    assert result.outcome == TestOutcome.SUCCESS
    assert "PHP Fatal error" in result.detail["markers"]


def test_tls_plaintext_http(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-tls",
    }))
    # The local test target is plaintext HTTP → transport weakness.
    assert result.outcome == TestOutcome.SUCCESS


def test_unknown_test_is_error(http_target):
    result = http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-nope",
    }))
    assert result.outcome == TestOutcome.ERROR


def test_collect_evidence(http_target):
    http_target.execute_test(TestSpec(name="t", parameters={
        "weakness": "http-security-headers", "path": "/",
    }))
    evidence = http_target.collect_evidence()
    assert evidence
    assert evidence[0].data["status"] == 200
    assert evidence[0].data["body_bytes"] > 0


def test_plan_test_produces_adapter_specific_spec(http_target):
    h = Hypothesis(
        target_id="t",
        statement="can http-open-redirect be demonstrated?",
        status=HypothesisStatus.PROPOSED,
        origin="strategy:http-open-redirect",
    )
    spec = http_target.plan_test(h, Target(name="x"))
    assert spec.parameters == {"weakness": "http-open-redirect"}


def test_planner_generates_http_hypotheses_for_http_target(http_target, store):
    planner = default_planner(store)
    target_model = http_target.discover()
    hypotheses = planner.generate_hypotheses(target_model, http_target.observe())
    origins = {h.origin for h in hypotheses}
    assert "strategy:http-security-headers" in origins
    assert "strategy:http-open-redirect" in origins
    # Only http-* strategies apply to an HTTP target.
    assert all(o.startswith("strategy:http-") for o in origins)


def test_full_research_loop_finds_real_vulnerabilities(http_target, store):
    engine = AdversarialEngine(store)
    report = engine.research(http_target, rounds=8)

    assert report.experiments_run > 0
    assert report.findings_created > 0

    findings = store.list_findings(report.target_id)
    components = {f.affected_component for f in findings}
    assert "http-sensitive-paths" in components
    assert "http-security-headers" in components
    assert "http-open-redirect" in components
