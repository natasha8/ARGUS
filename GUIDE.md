# Argus guide

Argus is a scanner for REST APIs **you control** or that you have written permission to test. You must confirm the scope before every scan. The target host must be in the allowlist (`ALLOWED_TARGET_HOSTS`). Cloud metadata hosts, such as `169.254.169.254`, are rejected anyway.

An empty result does not mean the API is secure. Argus looks only for the classes described below, with deliberately limited probes.

## How to use it

1. Start Argus, the lab, and the callback (see the README).
2. Open the dashboard at http://localhost:3000 or use the CLI.
3. Provide the target base URL and the OpenAPI specification (a URL, or a JSON or YAML file), or enter endpoints by hand: method, path, parameters, tags, and JSON body fields.
4. Provide profiles for authorization tests. Each one is Bearer (a token, or a username and password with a login path), an API key, or Basic. Add or remove profiles in the dashboard; the CLI reads the same fields from a JSON file. In the lab: `alice` / `alice123`, `bob` / `bob123`, `admin` / `admin123`. Login is `POST /api/login`. Use at least two profiles for BOLA.
5. Confirm authorization and start.
6. Read the findings. **Confirmed** means a second step distinguished the vulnerable behavior from a normal response. **Potential** means there is a signal, but not the counter-check.

You can download the report as Markdown or JSON from the scan page, or with `GET /scans/{id}/report?format=markdown`.

### Allowlist

Default value: `localhost`, `127.0.0.1`, `vulnerable-api`, `host.docker.internal`.

- On your machine the lab is `http://127.0.0.1:8001`.
- Inside Docker the lab is `http://vulnerable-api:8000` and the callback is `http://collaborator:8090`.

The callback must be reachable both from Argus and from the API under test. Argus does not send metadata URLs: the only address used for SSRF is the callback you configure.

### Scanner safety limits

- Maximum concurrency 20, maximum rate 50 requests per second. The dashboard asks for both (defaults: 4 concurrent requests, 8 per second). The CLI flags are `--concurrency` and `--rate-limit`.
- Authorization checks use `GET` only.
- The page-size probe never asks for more than 40 rows. There is no request flood.
- Inventory requests only the previous version number found in the specification. It does not guess hidden paths.
- Injection probes do not use stacked queries, do not read files, and do not chain commands. On `POST` they run only if the path contains words such as `search`, `find`, `query`, `login`, or `items`.
- The business-flow check is off unless you select it. It sends two identical `POST` requests and nothing else.
- `PUT`, `PATCH`, and `DELETE` are not modified, except the opt-in mass-assignment check.

## How to read a finding

Each card shows severity, status, OWASP category, endpoint, description, remediation, and request excerpts. `Authorization` headers are not stored in the evidence. If a JWT secret is guessed, it is not written in the report: only the fact that it belonged to a short list of obvious values.

## Checks

### BOLA, API1:2023

An authenticated user must not read another user's object just because they know its ID.

With two profiles, Argus reads the collection when it exists (for example `GET /api/orders`) and tries the configured IDs (`101`, `102`, `1`, `2`). It marks the finding confirmed only if the anonymous request is `401` or `403` and the body read by one user has an owner that matches the other profile. If the owner field is missing, the finding stays potential.

In the lab, `GET /api/orders/{order_id}` is vulnerable. `GET /api/orders/{order_id}/secure` checks the owner and must not appear.

### JWT, API2:2023

Three checks, only on `GET` endpoints that require authentication and where anonymous requests receive `401` or `403`:

- the HMAC signature matches a trivial secret (`secret`, `password`, `changeme`, and a few others);
- a token with `alg: none` and an empty signature is accepted;
- after the secret is recognized, a token with `exp` in the past is still accepted.

`GET /api/secure/me` in the lab verifies algorithm, signature, and expiry, and must not appear in the list of endpoints that accept `alg: none`.

Once the secret is recovered, Argus also re-signs a non-admin token with `role: admin` and sends it to admin-looking `GET` endpoints. It is confirmed where the real token gets 401 or 403 and the forged one succeeds. In the lab, `GET /api/admin/audit` checks the role, but trusts the role inside a forgeable token.

### Excessive data exposure, API3:2023

For every `GET`, Argus reads the response as an authenticated profile and looks for property names that should never reach a client, such as `password_hash`, `secret`, `private_key`, or `reset_token`. These are confirmed. Weaker names such as `token` or `api_key` are only potential, because they are sometimes legitimate. The report lists field names only; values are redacted.

`GET /api/profile` in the lab exposes a password hash and a reset token. `GET /api/secure/profile` returns only public fields and must not appear.

Mass assignment, the write side of API3, is an **opt-in** check (`mass_assignment`), off by default because it sends a state-changing request. When enabled, it only flips a privileged property it can already read back on a `PATCH`/`PUT` endpoint with a matching `GET`, then restores the original value. In the lab, `PATCH /api/profile` lets a normal user set `role: admin`; the probe confirms it and restores `role: user`.

### Resource consumption, API4:2023

Two signals, both read-only. Page size: on a query parameter named `limit`, `page_size`, or `per_page`, Argus asks for 40 rows and confirms the finding only when the list is that long. It never asks for more. Missing rate-limit headers (`X-RateLimit-*` or `Retry-After`) are a single potential finding, because a missing header is not proof that requests are unlimited.

In the lab, `GET /api/feed` returns the requested 40 rows (the lab itself stops at 100 so it cannot be used to exhaust memory). `GET /api/feed/safe` stops at 10 and must not appear.

### BFLA, API5:2023

Argus treats paths or tags containing `admin`, `manage`, `internal`, `staff`, or `audit` as administrative. It compares anonymous, a non-admin role, and the admin role when present. It is confirmed if the low role receives success and anonymous does not. `GET /api/admin/users` in the lab does not check the role. `GET /api/admin/audit` does, and must not produce a finding.

### Sensitive business flows, API6:2023

This check is **opt-in** (`business_flow`), off by default, because it sends two `POST` requests. It only considers paths or tags containing `checkout`, `purchase`, `transfer`, `payment`, `redeem`, or `invite`. Both requests carry the same `Idempotency-Key`. It is confirmed when both succeed and a `count` field, or a list, grows by one on the second call. If both succeed but nothing countable comes back, the finding stays potential.

In the lab, `POST /api/checkout` creates a purchase every time, on a list that is separate from the BOLA orders. `POST /api/checkout/secure` returns the first result when the key is repeated and must not appear.

### SSRF, API7:2023

Only query parameters whose name is explicitly a URL (`url`, `uri`, `webhook`, `callback`, and a few synonyms). The value is the callback URL. The finding is confirmed if the response contains the marker `ARGUS-CALLBACK-...` or the callback counted the request. Arbitrary internal addresses are not probed.

`GET /api/preview` in the lab really performs the HTTP request, but it rejects metadata hosts and does not follow redirects.

### Security misconfiguration, API8:2023

Three non-destructive signals, all read-only. CORS: Argus sends an `Origin` header and confirms a finding when the server reflects that origin (or returns `*`) together with `Access-Control-Allow-Credentials: true`; a reflection without credentials is only potential. Missing security headers: it lists absent hardening headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, and HSTS on HTTPS) as a potential. Verbose errors: a request to a random path that returns a stack trace or debug page is a confirmed disclosure.

In the lab, `GET /api/widget/config` reflects the origin with credentials and is confirmed; `GET /api/widget/config-safe` uses a fixed trusted origin and must not appear.

### Inventory, API9:2023

Argus does not guess hidden paths. If the specification contains `/api/v2/...`, it requests `/api/v1/...` and nothing further. The finding is confirmed when that previous version is absent from the specification and still returns success. A 404 is ignored.

In the lab, `GET /api/v2/status` is documented. `GET /api/v1/status` is omitted from the OpenAPI document and still responds. A missing `v0` path is not reported.

### Unsafe consumption of APIs, API10:2023

Only a query parameter named `provider`. The value is the collaborator URL `/trust/{token}`, which returns a marker `ARGUS-TRUST-...` and a price. The finding is confirmed when the API under test copies that marker into its own response. Opening the connection is not enough: that is the SSRF check.

`GET /api/quotes` in the lab copies the upstream body. `GET /api/quotes/safe` performs the request and returns only `{"ok": true}`, so it must not appear.

### Injection, A03:2021

Three subtypes, distinguished by `evidence.subtype`:

- **sql**: a quote that produces a SQL error and, as confirmation, two boolean conditions that change the number of results. The probe does not use `UNION` or write commands. If the error indicates MySQL, a single `SLEEP(1)` can confirm the delay. On the SQLite lab, the boolean comparison is enough. `GET /api/products/search-safe` is parameterized and must not appear.
- **nosql**: a JSON string field is replaced with `{"$gt": ""}`. It is confirmed if the result list grows, or if a `401` becomes success. In the lab, `POST /api/items/find` applies the operator with a small local interpreter: that is the behavior to recognize, not a MongoDB server.
- **command**: only parameters named `host`, `hostname`, `ip`, `domain`, `cmd`, or `command`. It compares `127.0.0.1` with a quote. In the lab, `GET /api/diag/ping` **does not start a shell**: it returns a shell-style error when it sees a metacharacter, so the check can be demonstrated without running commands.

## The lab

`targets/vulnerable-api` is a training target. It intentionally contains the flaws above, plus the correct variants the tests use to measure false positives. Lab passwords are fake and public in the code.

`targets/collaborator` remembers in memory which tokens it has seen. `/marker/{token}` confirms SSRF. `/trust/{token}` returns a JSON body for the unsafe-consumption check. Both clear on restart.

## Reports

The JSON report has `summary.by_severity`, `summary.confirmed`, and the finding list with evidence. The Markdown report is the same content, readable. Status `potential` should be treated as a clue, not as a demonstrated vulnerability.

## Variables

| Variable | Role |
| --- | --- |
| `DATABASE_URL` | SQLite locally, PostgreSQL in Docker |
| `ALLOWED_TARGET_HOSTS` | Hosts Argus may contact |
| `COLLABORATOR_BASE_URL` | Default callback |
| `NEXT_PUBLIC_API_URL` | API URL seen by the browser |

The schema is created on startup. Alembic, in `backend/alembic`, is for evolving an empty database with `alembic upgrade head` run from the `backend` directory.
