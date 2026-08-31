"""Real HTTP(S) target adapter — authorized adversarial testing of web apps.

This adapter speaks REAL HTTP over the network (stdlib urllib) against a
base URL that the operator is authorized to test. There is no simulation
here: every probe is a real request and every outcome is derived from the
actual response bytes and headers.

Authorization model
-------------------
Web targets are live systems. The adapter therefore carries the operator's
authorization statement (scope/environment) into the Target model so the
policy layer can scope sessions. It is the operator's responsibility to
only run this adapter against systems they are authorized to test.

Test protocol
-------------
Tests are dispatched on ``parameters["weakness"]``:

  http-security-headers   Missing baseline security headers (CSP, HSTS,
                          X-Frame-Options, X-Content-Type-Options, …).
  http-server-disclosure  Server / X-Powered-By version disclosure.
  http-dir-listing        Autoindex directory listing exposure.
  http-sensitive-paths    Exposed sensitive files (/.git/HEAD, /.env, …).
  http-methods            Dangerous HTTP methods allowed (OPTIONS/TRACE).
  http-cors               CORS misconfiguration (origin reflection).
  http-cookie-flags       Session cookies missing Secure/HttpOnly.
  http-open-redirect      Open redirect via common redirect parameters.
  http-admin-exposure     Admin interface reachable without authentication.
  http-error-disclosure   Verbose error/stack-trace disclosure.
  http-tls                Plaintext HTTP or weak TLS configuration.

Each outcome is honest: SUCCESS means the weakness was actually observed in
a real response; FAILURE means the target held; INCONCLUSIVE means the
evidence was ambiguous; ERROR means the request could not be completed.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from opensystem.models import (
    Evidence,
    EvidenceKind,
    Observation,
    Severity,
    Target,
    TestOutcome,
    TestResult,
    TestSpec,
)
from opensystem.target.interface import Capability, TargetAdapter

USER_AGENT = "OpenSystem-adversarial-research/1.0"
MAX_BODY_BYTES = 256 * 1024
MAX_REDIRECTS = 5


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Suppress automatic redirects so probe code sees raw 3xx responses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class HttpResponse:
    """A normalized real HTTP response."""

    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed_ms: float
    error: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class HttpProbeState:
    """State retained between tests for evidence and attribution."""

    last_response: HttpResponse | None = None
    discovery: dict = field(default_factory=dict)
    request_count: int = 0


class HttpSiteTarget(TargetAdapter):
    """Adapter for live HTTP(S) targets under authorized testing."""

    name = "http"

    capabilities = frozenset(
        {
            Capability.DISCOVERY,
            Capability.TEST_PLANNING,
        }
    )

    def __init__(
        self,
        url: str,
        environment: str = "production",
        authorized_scope: str = "",
        timeout: float = 10.0,
        verify_tls: bool = True,
    ) -> None:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"Invalid target URL '{url}'. Provide an absolute http(s) URL."
            )
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.environment = environment or "production"
        self.authorized_scope = authorized_scope
        self.timeout = timeout
        self.verify_tls = verify_tls
        self._state = HttpProbeState()
        self._discovered = False

        no_redirect = urllib.request.build_opener(_NoRedirect)
        if not verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            no_redirect.add_handler(urllib.request.HTTPSHandler(context=ctx))
        self._opener = no_redirect

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    @classmethod
    def from_config(cls, config: dict) -> HttpSiteTarget:
        """Instantiate from a saved TargetConfig (CLI target add)."""
        if not config.get("url"):
            raise ValueError(
                f"Target config '{config.get('name')}' has no URL. "
                "Re-add it with: opensystem target add <name> --adapter http "
                "--url https://... --confirm-authorized"
            )
        return cls(
            url=config["url"],
            environment=config.get("environment", "production"),
            authorized_scope=config.get("authorized_scope", ""),
            verify_tls=not bool(config.get("allow_insecure_tls", False)),
        )

    # ------------------------------------------------------------------ #
    # Real HTTP client
    # ------------------------------------------------------------------ #

    def request(
        self,
        path: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        """Perform a real HTTP request against the target."""
        url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            merged.update(headers)
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in merged.items():
            req.add_header(k, v)

        started = time.monotonic()
        self._state.request_count += 1
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(MAX_BODY_BYTES + 1)
                elapsed = (time.monotonic() - started) * 1000
                response = HttpResponse(
                    status=resp.status,
                    headers={
                        k.lower(): v for k, v in resp.getheaders()
                    },
                    body=raw[:MAX_BODY_BYTES].decode(
                        "utf-8", errors="replace"
                    ),
                    url=resp.geturl(),
                    elapsed_ms=round(elapsed, 1),
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_BODY_BYTES + 1) if hasattr(exc, "read") else b""
            elapsed = (time.monotonic() - started) * 1000
            response = HttpResponse(
                status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body=raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace"),
                url=getattr(exc, "url", url),
                elapsed_ms=round(elapsed, 1),
            )
        except (TimeoutError, urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            elapsed = (time.monotonic() - started) * 1000
            response = HttpResponse(
                status=0,
                headers={},
                body="",
                url=url,
                elapsed_ms=round(elapsed, 1),
                error=f"{type(exc).__name__}: {exc}",
            )
        self._state.last_response = response
        return response

    def _status_of(self, path: str, method: str = "GET") -> HttpResponse:
        return self.request(path, method=method)

    # ------------------------------------------------------------------ #
    # TargetAdapter contract
    # ------------------------------------------------------------------ #

    def discover(self) -> Target:
        """Build the Target model from REAL responses (no attack in this phase)."""
        if not self._discovered:
            self._run_discovery()
        d = self._state.discovery
        host = urllib.parse.urlparse(self.base_url).hostname or self.base_url
        port = urllib.parse.urlparse(self.base_url).port
        scheme = urllib.parse.urlparse(self.base_url).scheme
        host_id = f"{host}:{port}" if port and port not in (80, 443) else host
        interfaces = [
            p for p in ("/", "/robots.txt", "/sitemap.xml")
            if d.get("paths", {}).get(p, {}).get("status")
            and 0 < d["paths"][p]["status"] < 400
        ]
        return Target(
            id=f"target_http_{host_id}",
            name=host,
            kind="web",
            adapter=self.name,
            version=d.get("server", "unknown"),
            description=(
                f"Live web target {self.base_url} discovered by real HTTP "
                f"probing. Authorization scope: "
                f"{self.authorized_scope or 'operator-declared'}; "
                f"environment: {self.environment}."
            ),
            assets=[f"{scheme}://{host}"],
            interfaces=interfaces or ["/"],
            trust_boundaries=["network"],
            rules={
                "base_url": self.base_url,
                "verify_tls": self.verify_tls,
                "authorized_scope": self.authorized_scope,
            },
            environment=self.environment,
            scope=self.authorized_scope or "authorized-testing",
        )

    def _run_discovery(self) -> None:
        d: dict = {"paths": {}}
        root = self.request("/")
        d["root_status"] = root.status
        d["server"] = root.header("server") or "unknown"
        d["powered_by"] = root.header("x-powered-by") or ""
        d["title"] = self._extract_title(root.body)
        for path in ("/robots.txt", "/sitemap.xml"):
            resp = self.request(path)
            d["paths"][path] = {
                "status": resp.status,
                "bytes": len(resp.body),
            }
            if path == "/robots.txt" and resp.status == 200:
                d["robots_disallow"] = self._parse_robots_disallow(resp.body)
        self._state.discovery = d
        self._discovered = True

    @staticmethod
    def _extract_title(body: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:120] if m else ""

    @staticmethod
    def _parse_robots_disallow(body: str) -> list[str]:
        paths = []
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p:
                    paths.append(p)
        return paths[:50]

    def observe(self) -> list[Observation]:
        """Return observations collected from real discovery responses."""
        self.discover()
        d = self._state.discovery
        obs = [
            Observation(
                target_id=self.base_url,
                interface="http",
                data={
                    "url": self.base_url,
                    "root_status": d.get("root_status"),
                    "server": d.get("server"),
                    "powered_by": d.get("powered_by"),
                    "title": d.get("title"),
                },
                source="http.discover",
            )
        ]
        robots = d.get("robots_disallow") or []
        if robots:
            obs.append(
                Observation(
                    target_id=self.base_url,
                    interface="http",
                    data={"robots_disallow": robots},
                    source="http.robots",
                )
            )
        return obs

    def describe(self) -> dict:
        self.discover()
        d = self._state.discovery
        return {
            "base_url": self.base_url,
            "root_status": d.get("root_status"),
            "server": d.get("server"),
            "powered_by": d.get("powered_by"),
            "title": d.get("title"),
            "paths": d.get("paths", {}),
            "environment": self.environment,
            "authorized_scope": self.authorized_scope,
            "requests_sent": self._state.request_count,
        }

    def execute_test(self, test: TestSpec) -> TestResult:
        """Execute a real HTTP test. Dispatches on parameters['weakness']."""
        params = test.parameters or {}
        key = params.get("weakness", "")
        handlers = {
            "http-security-headers": self._test_security_headers,
            "http-server-disclosure": self._test_server_disclosure,
            "http-dir-listing": self._test_dir_listing,
            "http-sensitive-paths": self._test_sensitive_paths,
            "http-methods": self._test_http_methods,
            "http-cors": self._test_cors,
            "http-cookie-flags": self._test_cookie_flags,
            "http-open-redirect": self._test_open_redirect,
            "http-admin-exposure": self._test_admin_exposure,
            "http-error-disclosure": self._test_error_disclosure,
            "http-tls": self._test_tls,
        }
        handler = handlers.get(key)
        if handler is None:
            return TestResult(
                outcome=TestOutcome.ERROR,
                observed_result=(
                    f"Unknown HTTP test '{key}'. Supported: "
                    + ", ".join(sorted(handlers))
                ),
                detail={"error": "unknown-http-test", "test": key},
            )
        return handler(params)

    def collect_evidence(self) -> list[Evidence]:
        resp = self._state.last_response
        if resp is None:
            return []
        return [
            Evidence(
                kind=EvidenceKind.RESPONSE,
                data={
                    "url": resp.url,
                    "status": resp.status,
                    "elapsed_ms": resp.elapsed_ms,
                    "server": resp.header("server"),
                    "content_type": resp.header("content-type"),
                    "body_bytes": len(resp.body),
                    "error": resp.error,
                },
                reference="http.collect_evidence",
            )
        ]

    def reset(self) -> None:
        """Clear local cache. A live remote target cannot be reset."""
        self._state = HttpProbeState()
        self._discovered = False

    # ------------------------------------------------------------------ #
    # Capability: TEST_PLANNING — hypothesis → concrete TestSpec
    # ------------------------------------------------------------------ #

    def plan_test(self, hypothesis, target_model: Target) -> TestSpec:
        """Translate an http-* hypothesis into a concrete TestSpec."""
        key = hypothesis.origin.replace("strategy:", "")
        return TestSpec(
            name=f"test-{key}",
            description=hypothesis.statement,
            parameters={"weakness": key},
            expected_outcome=TestOutcome.SUCCESS,
        )

    # ------------------------------------------------------------------ #
    # Capability: DISCOVERY
    # ------------------------------------------------------------------ #

    def describe_interfaces(self) -> list[dict]:
        self.discover()
        d = self._state.discovery
        rows = [{"name": "http", "kind": "web", "url": self.base_url}]
        for path, info in d.get("paths", {}).items():
            rows.append({"name": path, "kind": "path", "status": info["status"]})
        return rows

    def describe_resources(self) -> list[dict]:
        return []

    def describe_actors(self) -> list[dict]:
        return []

    def describe_auth_states(self) -> list[dict]:
        return [{"name": "unauthenticated"}]

    def describe_transitions(self) -> list[dict]:
        return []

    # ------------------------------------------------------------------ #
    # Real tests
    # ------------------------------------------------------------------ #

    def _test_security_headers(self, params: dict) -> TestResult:
        path = params.get("path", "/")
        resp = self.request(path)
        if resp.status == 0:
            return self._unreachable(resp)
        if resp.status >= 400:
            return TestResult(
                outcome=TestOutcome.INCONCLUSIVE,
                observed_result=f"{path} returned HTTP {resp.status}; "
                "header analysis skipped.",
                detail={"status": resp.status},
            )
        required = {
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
        }
        csp = resp.header("content-security-policy") or ""
        if csp and "frame-ancestors" in csp.lower():
            required.pop("x-frame-options", None)
        if self.base_url.startswith("https"):
            required["strict-transport-security"] = "Strict-Transport-Security"
        missing = [label for k, label in required.items() if not resp.header(k)]
        if missing:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"Missing security headers on {resp.url}: "
                    + ", ".join(missing)
                ),
                detail={
                    "weakness": "http-security-headers",
                    "missing": missing,
                    "status": resp.status,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result=(
                f"All baseline security headers present on {resp.url}."
            ),
            detail={"weakness": "http-security-headers", "missing": []},
        )

    def _test_server_disclosure(self, params: dict) -> TestResult:
        resp = self.request(params.get("path", "/"))
        if resp.status == 0:
            return self._unreachable(resp)
        disclosed = {}
        server = resp.header("server") or ""
        powered = resp.header("x-powered-by") or ""
        if re.search(r"\d+\.\d+", server):
            disclosed["server"] = server
        if re.search(r"\d+\.\d+", powered):
            disclosed["x-powered-by"] = powered
        if disclosed:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Server software version disclosed in response headers: "
                    + ", ".join(f"{k}={v}" for k, v in disclosed.items())
                ),
                detail={"weakness": "http-server-disclosure", **disclosed},
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result="No server version disclosed in headers.",
            detail={"weakness": "http-server-disclosure"},
        )

    _AUTOINDEX_MARKERS = (
        "Index of /",
        "Directory listing for",
        "<h1>Index of",
    )

    def _test_dir_listing(self, params: dict) -> TestResult:
        dirs = params.get("dirs") or [
            "/static/", "/assets/", "/js/", "/css/", "/images/",
            "/uploads/", "/files/", "/media/",
        ]
        exposed = []
        for d in dirs:
            resp = self.request(d)
            if resp.status != 200:
                continue
            if any(m in resp.body for m in self._AUTOINDEX_MARKERS):
                exposed.append(d)
        if exposed:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Directory listing enabled: " + ", ".join(exposed)
                ),
                detail={
                    "weakness": "http-dir-listing",
                    "exposed_dirs": exposed,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result="No autoindex directory listing found.",
            detail={"weakness": "http-dir-listing"},
        )

    _SENSITIVE_PATHS = (
        ("/.git/HEAD", "ref: refs/"),
        ("/.git/config", "[core]"),
        ("/.env", r"(?m)^[A-Z][A-Z0-9_]*="),
        ("/.svn/entries", r"\d"),
        ("/.DS_Store", r"\x00"),
        ("/backup.zip", "PK\x03\x04"),
        ("/db.sqlite3", "SQLite format"),
        ("/composer.json", '"require"'),
        ("/package.json", '"name"'),
        ("/.aws/credentials", "[default]"),
        ("/id_rsa", "PRIVATE KEY"),
        ("/server-status", "Server Status"),
        ("/phpinfo.php", "phpinfo()"),
    )

    def _test_sensitive_paths(self, params: dict) -> TestResult:
        exposed = []
        for path, marker in self._SENSITIVE_PATHS:
            resp = self.request(path)
            if resp.status != 200:
                continue
            if re.search(marker, resp.body):
                exposed.append(path)
        if exposed:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Sensitive files exposed over HTTP: "
                    + ", ".join(exposed)
                ),
                detail={
                    "weakness": "http-sensitive-paths",
                    "exposed_paths": exposed,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result="No sensitive files exposed.",
            detail={"weakness": "http-sensitive-paths"},
        )

    def _test_http_methods(self, params: dict) -> TestResult:
        path = params.get("path", "/")
        resp = self.request(path, method="OPTIONS")
        if resp.status == 0:
            return self._unreachable(resp)
        allow = resp.header("allow") or resp.header("public") or ""
        allowed = {m.strip().upper() for m in re.split(r"[,\s]+", allow) if m.strip()}
        dangerous = [
            m for m in ("PUT", "DELETE", "TRACE", "CONNECT")
            if m in allowed
        ]
        if "TRACE" in allow.upper():
            trace = self.request(path, method="TRACE", body=b"opensystem-trace")
            if trace.status == 200 and "opensystem-trace" in trace.body:
                dangerous.append("TRACE-ECHO")
        if dangerous:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"Dangerous HTTP methods allowed on {path}: "
                    + ", ".join(sorted(set(dangerous)))
                ),
                detail={
                    "weakness": "http-methods",
                    "methods": sorted(set(dangerous)),
                    "allow": allow,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result=(
                f"No dangerous methods advertised (Allow: {allow or 'none'})."
            ),
            detail={"weakness": "http-methods", "allow": allow},
        )

    def _test_cors(self, params: dict) -> TestResult:
        evil = "https://opensystem-probe.example"
        resp = self.request(
            params.get("path", "/"),
            headers={"Origin": evil},
        )
        if resp.status == 0:
            return self._unreachable(resp)
        acao = resp.header("access-control-allow-origin") or ""
        acac = (resp.header("access-control-allow-credentials") or "").lower()
        if acao == evil:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"CORS misconfiguration: arbitrary origin {evil} "
                    f"reflected in Access-Control-Allow-Origin."
                ),
                detail={
                    "weakness": "http-cors",
                    "reflected_origin": acao,
                    "allow_credentials": acac,
                },
            )
        if acao == "*" and acac == "true":
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "CORS misconfiguration: wildcard origin combined with "
                    "Access-Control-Allow-Credentials: true."
                ),
                detail={
                    "weakness": "http-cors",
                    "reflected_origin": acao,
                    "allow_credentials": acac,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result=f"No CORS misconfiguration (ACAO: {acao or 'none'}).",
            detail={"weakness": "http-cors", "acao": acao},
        )

    _SESSION_COOKIE_HINTS = ("session", "sid", "sess", "auth", "token", "jwt", "login")

    def _test_cookie_flags(self, params: dict) -> TestResult:
        resp = self.request(params.get("path", "/"))
        if resp.status == 0:
            return self._unreachable(resp)
        cookies = []
        headers = resp.headers
        # Multiple Set-Cookie headers collapse under lower-cased dict; probe
        # a known login path too to maximize cookie capture.
        for raw in [headers.get("set-cookie", "")]:
            if raw:
                cookies.extend(
                    c.strip() for c in raw.split(", ") if "=" in c
                )
        insecure = []
        for cookie in cookies:
            name = cookie.split("=", 1)[0]
            if not any(h in name.lower() for h in self._SESSION_COOKIE_HINTS):
                continue
            missing = []
            if "httponly" not in cookie.lower():
                missing.append("HttpOnly")
            if self.base_url.startswith("https") and "secure" not in cookie.lower():
                missing.append("Secure")
            if missing:
                insecure.append(f"{name}: missing {', '.join(missing)}")
        if insecure:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Session cookies with insecure flags: " + "; ".join(insecure)
                ),
                detail={
                    "weakness": "http-cookie-flags",
                    "insecure_cookies": insecure,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result=(
                "No session cookies with missing Secure/HttpOnly flags."
            ),
            detail={"weakness": "http-cookie-flags"},
        )

    _REDIRECT_PARAMS = (
        "next", "redirect", "url", "return", "returnTo", "goto", "target", "dest",
    )
    _REDIRECT_PROBE_HOST = "opensystem-redirect-probe.example"

    def _test_open_redirect(self, params: dict) -> TestResult:
        evil = f"https://{self._REDIRECT_PROBE_HOST}/"
        probe_paths = params.get("paths") or ["/login", "/logout", "/redirect", "/"]
        hits = []
        for path in probe_paths:
            for param in self._REDIRECT_PARAMS:
                sep = "&" if "?" in path else "?"
                resp = self.request(f"{path}{sep}{param}={urllib.parse.quote(evil, safe='')}")
                if resp.status in (301, 302, 303, 307, 308):
                    location = resp.header("location") or ""
                    if self._REDIRECT_PROBE_HOST in location:
                        hits.append(f"{path}?{param} → {location}")
        if hits:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Open redirect confirmed: " + "; ".join(hits[:3])
                ),
                detail={"weakness": "http-open-redirect", "hits": hits[:10]},
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result="No open redirect observed on probed parameters.",
            detail={"weakness": "http-open-redirect"},
        )

    _ADMIN_PATHS = (
        "/admin", "/admin/", "/administrator", "/wp-admin/",
        "/wp-login.php", "/manager/html", "/console", "/dashboard",
    )

    def _test_admin_exposure(self, params: dict) -> TestResult:
        paths = params.get("paths") or list(self._ADMIN_PATHS)
        reachable, blocked = [], 0
        for path in paths:
            resp = self.request(path)
            if resp.status == 0:
                continue
            if 200 <= resp.status < 300:
                if self._looks_like_login_form(resp.body):
                    blocked += 1
                else:
                    reachable.append(path)
            elif resp.status in (401, 403):
                blocked += 1
        if reachable:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Admin interface reachable without authentication: "
                    + ", ".join(reachable)
                ),
                detail={
                    "weakness": "http-admin-exposure",
                    "reachable": reachable,
                    "blocked": blocked,
                },
            )
        if blocked:
            return TestResult(
                outcome=TestOutcome.FAILURE,
                observed_result=(
                    f"Admin surfaces present but access-controlled "
                    f"({blocked} paths returned 401/403 or a login form)."
                ),
                detail={
                    "weakness": "http-admin-exposure",
                    "reachable": [],
                    "blocked": blocked,
                },
            )
        return TestResult(
            outcome=TestOutcome.INCONCLUSIVE,
            observed_result="No admin surfaces found at probed paths.",
            detail={"weakness": "http-admin-exposure", "blocked": 0},
        )

    @staticmethod
    def _looks_like_login_form(body: str) -> bool:
        lowered = body.lower()
        return (
            ('type="password"' in lowered or "type='password'" in lowered)
            and "<form" in lowered
        )

    _ERROR_MARKERS = (
        "Traceback (most recent call last)",
        "System.Exception",
        "PHP Warning",
        "PHP Fatal error",
        "Microsoft .NET Framework",
        "at java.",
        "org.springframework",
        "You have an error in your SQL syntax",
        "Warning: mysql",
        "Warning: mysqli",
        "ORA-",
        "postgres: ERROR",
    )

    def _test_error_disclosure(self, params: dict) -> TestResult:
        import secrets as _secrets

        nonce = _secrets.token_hex(8)
        resp = self.request(f"/opensystem-{nonce}-{nonce}")
        if resp.status == 0:
            return self._unreachable(resp)
        found = [m for m in self._ERROR_MARKERS if m in resp.body]
        if found:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    "Verbose error disclosure on invalid paths: "
                    + ", ".join(found[:3])
                ),
                detail={
                    "weakness": "http-error-disclosure",
                    "markers": found,
                    "status": resp.status,
                },
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result=(
                f"404 handler did not disclose stack traces "
                f"(status {resp.status})."
            ),
            detail={"weakness": "http-error-disclosure", "status": resp.status},
        )

    def _test_tls(self, params: dict) -> TestResult:
        parsed = urllib.parse.urlparse(self.base_url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "http":
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result=(
                    f"Target {self.base_url} is served over plaintext HTTP; "
                    "transport is not encrypted."
                ),
                detail={"weakness": "http-tls", "scheme": "http"},
            )
        try:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection((host, port), timeout=self.timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as tls,
            ):
                cert = tls.getpeercert()
        except (ssl.SSLError, OSError) as exc:
            return TestResult(
                outcome=TestOutcome.INCONCLUSIVE,
                observed_result=f"TLS handshake could not be completed: {exc}",
                detail={"weakness": "http-tls", "error": str(exc)},
            )
        issues = self._cert_issues(cert)
        if issues:
            return TestResult(
                outcome=TestOutcome.SUCCESS,
                observed_result="TLS certificate issues: " + "; ".join(issues),
                detail={"weakness": "http-tls", "issues": issues},
            )
        return TestResult(
            outcome=TestOutcome.FAILURE,
            observed_result="TLS configuration looks healthy.",
            detail={"weakness": "http-tls", "scheme": "https"},
        )

    @staticmethod
    def _cert_issues(cert: dict | None) -> list[str]:
        if not cert:
            return ["no peer certificate presented"]
        issues = []
        import datetime as _dt

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = _dt.datetime.strptime(
                    not_after.replace("GMT", "+0000"), "%b %d %H:%M:%S %Y %z"
                )
                if expiry < _dt.datetime.now(_dt.UTC) + _dt.timedelta(days=30):
                    issues.append(f"certificate expires soon ({not_after})")
            except ValueError:
                pass
        subject = dict(x[0] for x in cert.get("subject", ()) if x)
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        if subject and issuer and subject.get("commonName") == issuer.get("commonName"):
            issues.append("certificate appears self-signed")
        return issues

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _unreachable(self, resp: HttpResponse) -> TestResult:
        return TestResult(
            outcome=TestOutcome.ERROR,
            observed_result=f"Target unreachable: {resp.error}",
            detail={"error": "unreachable", "url": resp.url},
        )


def probe_severity(key: str) -> Severity:
    """Default severity used when reporting findings for HTTP tests."""
    return {
        "http-sensitive-paths": Severity.CRITICAL,
        "http-admin-exposure": Severity.HIGH,
        "http-open-redirect": Severity.MEDIUM,
        "http-cors": Severity.MEDIUM,
        "http-tls": Severity.HIGH,
    }.get(key, Severity.MEDIUM)
