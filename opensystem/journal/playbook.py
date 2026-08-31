"""Attack playbook — documented methodology for every OpenSystem attack.

This is the canonical, human-readable account of how each attack type is
performed. The journal combines these entries with the runtime specifics of
each actual experiment so every recorded attack explains *how it was done* in
detail.
"""

from __future__ import annotations

PLAYBOOK: dict[str, dict] = {
    "http-security-headers": {
        "name": "Missing Security Headers",
        "family": "http-headers",
        "severity": "MEDIUM",
        "summary": "Detects web pages served without baseline security headers.",
        "how_it_was_done": (
            "A GET request is sent to the target path (default \"/\"). The "
            "response headers are inspected for Content-Security-Policy, "
            "X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. "
            "If the target is served over HTTPS, Strict-Transport-Security is "
            "also required. If Content-Security-Policy is present and includes "
            "a frame-ancestors directive, X-Frame-Options is not required. Any "
            "missing header is reported as a weakness; the response status and "
            "the list of missing headers are recorded."
        ),
        "why_it_matters": (
            "Missing security headers increase exposure to clickjacking, "
            "MIME-sniffing attacks, and cross-site scripting. HSTS forces "
            "browsers to use HTTPS and prevents protocol-downgrade attacks."
        ),
    },
    "http-server-disclosure": {
        "name": "Server Software Disclosure",
        "family": "information-disclosure",
        "severity": "LOW",
        "summary": "Detects server software versions disclosed in HTTP headers.",
        "how_it_was_done": (
            "A GET request is sent to the target path (default \"/\"). The "
            "response is inspected for the Server and X-Powered-By headers. If "
            "either header contains a version number (e.g. nginx/1.21.5), the "
            "software and version are recorded as disclosed."
        ),
        "why_it_matters": (
            "Disclosed versions let an attacker identify known CVEs for the "
            "exact server software in use, reducing the effort needed to find "
            "an exploit."
        ),
    },
    "http-dir-listing": {
        "name": "Directory Listing / Autoindex",
        "family": "information-disclosure",
        "severity": "MEDIUM",
        "summary": "Detects web servers exposing directory listings.",
        "how_it_was_done": (
            "GET requests are sent to common directory paths (e.g. /static/, "
            "/assets/, /js/, /css/, /images/, /uploads/, /files/, /media/). "
            "Any 200 response whose body contains an autoindex marker such as "
            "\"Index of /\", \"Directory listing for\", or \"<h1>Index of\" is "
            "flagged as directory listing exposure."
        ),
        "why_it_matters": (
            "Directory listings reveal the full contents of a directory, "
            "including backups, source files, and configuration that should "
            "never be publicly accessible."
        ),
    },
    "http-sensitive-paths": {
        "name": "Exposed Sensitive Files",
        "family": "information-disclosure",
        "severity": "CRITICAL",
        "summary": "Detects sensitive files exposed over HTTP.",
        "how_it_was_done": (
            "GET requests are sent to a curated set of sensitive paths: "
            "/.git/HEAD, /.git/config, /.env, /.svn/entries, /.DS_Store, "
            "/backup.zip, /db.sqlite3, /composer.json, /package.json, "
            "/.aws/credentials, /id_rsa, /server-status, /phpinfo.php. A path "
            "is confirmed exposed when it returns HTTP 200 AND its body "
            "matches a content signature (e.g. /.git/HEAD containing "
            "\"ref: refs/\", /.env containing KEY=VALUE lines, .zip containing "
            "the PK\\x03\\x04 magic bytes)."
        ),
        "why_it_matters": (
            "Exposed sensitive files can leak credentials, private keys, "
            "source code, and database contents — frequently leading directly "
            "to full compromise."
        ),
    },
    "http-methods": {
        "name": "Dangerous HTTP Methods",
        "family": "http-configuration",
        "severity": "MEDIUM",
        "summary": "Detects dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT).",
        "how_it_was_done": (
            "An OPTIONS request is sent to the target path (default \"/\"). The "
            "Allow/Public header is parsed into a method set. If PUT, DELETE, "
            "TRACE, or CONNECT is advertised, an additional TRACE request is "
            "sent with a body containing a marker string; if the server echoes "
            "the marker back, TRACE-ECHO is recorded, confirming the method "
            "actually executes."
        ),
        "why_it_matters": (
            "Dangerous methods let attackers modify or delete resources (PUT/"
            "DELETE), or perform cross-site tracing / reflect requests (TRACE), "
            "which can bypass defenses and expose session data."
        ),
    },
    "http-cors": {
        "name": "CORS Misconfiguration",
        "family": "http-configuration",
        "severity": "MEDIUM",
        "summary": "Detects CORS configurations that allow arbitrary origins.",
        "how_it_was_done": (
            "A GET request is sent to the target path (default \"/\") with the "
            "header \"Origin: https://opensystem-probe.example\". The response "
            "is checked for Access-Control-Allow-Origin. If the header exactly "
            "echoes the attacker-controlled origin, or if a wildcard \"*\" is "
            "combined with Access-Control-Allow-Credentials: true, the "
            "misconfiguration is confirmed."
        ),
        "why_it_matters": (
            "A reflected or wildcard CORS origin lets a malicious site make "
            "authenticated cross-origin requests that read the victim's data "
            "from the target."
        ),
    },
    "http-cookie-flags": {
        "name": "Insecure Session Cookie Flags",
        "family": "session-management",
        "severity": "MEDIUM",
        "summary": "Detects session cookies missing Secure/HttpOnly flags.",
        "how_it_was_done": (
            "A GET request is sent to the target path (default \"/\"). Set-Cookie "
            "headers are examined. Cookies whose name matches a session hint "
            "(session, sid, sess, auth, token, jwt, login) are checked: a "
            "missing HttpOnly flag or (on HTTPS targets) a missing Secure flag "
            "is reported."
        ),
        "why_it_matters": (
            "Cookies without HttpOnly can be read by JavaScript (enabling "
            "session theft via XSS). Cookies without Secure are transmitted "
            "over plaintext HTTP and can be captured on the wire."
        ),
    },
    "http-open-redirect": {
        "name": "Open Redirect",
        "family": "input-validation",
        "severity": "MEDIUM",
        "summary": "Detects redirect parameters that forward to external hosts.",
        "how_it_was_done": (
            "GET requests are sent to common endpoints (/login, /logout, "
            "/redirect, /) with each of several redirect parameters (next, "
            "redirect, url, return, returnTo, goto, target, dest) set to an "
            "attacker-controlled host (https://opensystem-redirect-probe.example). "
            "A 3xx response whose Location header contains the probe host "
            "confirms an open redirect."
        ),
        "why_it_matters": (
            "Open redirects are used for phishing and to launder malicious "
            "URLs through a trusted domain, undermining user trust and "
            "defeating URL-based allowlists."
        ),
    },
    "http-admin-exposure": {
        "name": "Exposed Administrative Interface",
        "family": "authorization",
        "severity": "HIGH",
        "summary": "Detects admin surfaces reachable without authentication.",
        "how_it_was_done": (
            "GET requests are sent to common administrative paths (/admin, "
            "/administrator, /wp-admin/, /wp-login.php, /manager/html, "
            "/console, /dashboard). A 200 response that does NOT contain a "
            "login form (password field + <form>) is reported as an admin "
            "interface reachable without authentication. Paths returning 401/"
            "403 or a login form are counted as access-controlled."
        ),
        "why_it_matters": (
            "An administrative interface reachable without authentication "
            "hands over the most privileged functionality of the application "
            "to anyone on the network."
        ),
    },
    "http-error-disclosure": {
        "name": "Verbose Error Disclosure",
        "family": "information-disclosure",
        "severity": "LOW",
        "summary": "Detects error pages that leak stack traces or SQL errors.",
        "how_it_was_done": (
            "A GET request is sent to a random, non-existent path "
            "(/opensystem-<nonce>-<nonce>). The response body is scanned for "
            "framework/stack-trace markers: \"Traceback (most recent call last)\", "
            "\"System.Exception\", \"PHP Warning\", \"PHP Fatal error\", "
            "\"Microsoft .NET Framework\", \"at java.\", \"org.springframework\", "
            "SQL syntax errors, and ORA-/postgres error prefixes. Any marker "
            "confirms verbose error disclosure."
        ),
        "why_it_matters": (
            "Verbose errors reveal the application stack, framework versions, "
            "file paths, and SQL details — the exact information an attacker "
            "needs to craft targeted exploits."
        ),
    },
    "http-tls": {
        "name": "Weak Transport Security",
        "family": "transport-security",
        "severity": "HIGH",
        "summary": "Detects plaintext HTTP and weak TLS configurations.",
        "how_it_was_done": (
            "The target's scheme is checked. If it is plaintext http://, a "
            "weakness is confirmed immediately. For https://, a TLS handshake "
            "is performed and the peer certificate is inspected: an expiry "
            "within 30 days or a self-signed certificate (subject common name "
            "equal to issuer) is reported."
        ),
        "why_it_matters": (
            "Plaintext HTTP allows interception and modification of all "
            "traffic. Expired or self-signed certificates break trust and "
            "expose users to man-in-the-middle attacks."
        ),
    },
}

# Ordered list of attack keys, matching the planner's HTTP_STRATEGIES order.
ATTACK_KEYS = [
    "http-security-headers",
    "http-server-disclosure",
    "http-dir-listing",
    "http-sensitive-paths",
    "http-methods",
    "http-cors",
    "http-cookie-flags",
    "http-open-redirect",
    "http-admin-exposure",
    "http-error-disclosure",
    "http-tls",
]


def playbook_for(attack_key: str) -> dict | None:
    """Return the documented methodology for an attack key."""
    return PLAYBOOK.get(attack_key)
