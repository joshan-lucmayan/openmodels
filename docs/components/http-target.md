# HTTP(S) Target Adapter

**Module**: `opensystem/target/http_site.py`

## Responsibility

A live-network `TargetAdapter` for web applications the operator is
authorized to test. It performs real HTTP(S) requests (stdlib `urllib`) and
derives every test outcome from the actual response — there is no simulation.

## Authorization

- Instantiation requires an absolute `url` (`http://` or `https://`).
- `environment`, `authorized_scope`, and `verify_tls` are carried into the
  `Target` model, where the policy layer scopes sessions.
- The CLI (`target add --adapter http`) requires `--url` and
  `--confirm-authorized` before a live target can be registered.
- The operator is responsible for only testing systems they are authorized to
  test.

## Capabilities

Declared capabilities:

- `DISCOVERY` — `describe_interfaces()` from real path probing.
- `TEST_PLANNING` — `plan_test()` translates a `Hypothesis` (origin
  `strategy:http-*`) into a concrete `TestSpec` with
  `parameters={"weakness": key}`.

## Test Protocol

`execute_test()` dispatches on `parameters["weakness"]`:

| Test | Weakness confirmed when |
| --- | --- |
| `http-security-headers` | baseline security headers missing (CSP, X-Frame-Options, X-Content-Type-Options, HSTS on https, Referrer-Policy) |
| `http-server-disclosure` | `Server`/`X-Powered-By` disclose a version |
| `http-dir-listing` | a directory returns an autoindex listing |
| `http-sensitive-paths` | sensitive files exposed (`.git/HEAD`, `.env`, backups, …) |
| `http-methods` | dangerous methods advertised/echoed (PUT, DELETE, TRACE, CONNECT) |
| `http-cors` | arbitrary origin reflected in `Access-Control-Allow-Origin`, or `*` with credentials |
| `http-cookie-flags` | session cookies missing `Secure`/`HttpOnly` |
| `http-open-redirect` | a common redirect parameter forwards to an external host |
| `http-admin-exposure` | an admin surface is reachable without authentication |
| `http-error-disclosure` | 4xx pages disclose stack traces / SQL errors |
| `http-tls` | plaintext HTTP, weak/expiring/self-signed TLS |

Outcomes are honest: `SUCCESS` (weakness observed), `FAILURE` (target held),
`INCONCLUSIVE` (ambiguous evidence), `ERROR` (request could not be completed).

## Key Design Decisions

- Real requests only; no mocked HTTP layer. Tests run against genuinely live
  servers (the test suite spins up a real local server over 127.0.0.1).
- `plan_test()` uses the hypothesis origin so the core engine needs no
  knowledge of the HTTP protocol.
- Discovery is lightweight (root, robots.txt, sitemap) and never attacks.
- Target ID is derived from scheme+host+port, so distinct servers never
  collide and sessions resume across processes via `Target.rules`.
