# Step 15 — Security misconfiguration (API8)

## Goal

Add OWASP API8:2023 coverage with non-destructive, header-based checks.

Code: `backend/app/engine/checks/misconfig.py`. Id: `misconfig`. It is part of the default set.

## Three signals

### CORS origin reflection

Argus sends an `Origin: https://argus-probe.example` header on each `GET` and reads the response:

- **Confirmed (high)** if `Access-Control-Allow-Origin` echoes the probe origin (or is `*`) **and** `Access-Control-Allow-Credentials: true`. Any website could then read authenticated responses on behalf of a logged-in user.
- **Potential (medium)** if the origin is reflected or wildcarded without credentials. Lower impact, but it still relaxes the same-origin policy.

Affected endpoints are grouped into a single finding.

### Missing security headers

On a representative response, Argus lists the common hardening headers that are absent: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, and `Strict-Transport-Security` on HTTPS targets. This is a **potential**, low-severity finding, because the right policy depends on the API.

### Verbose errors

Argus requests a random, non-existent path. If the response body contains a stack-trace or debug signature (for example `Traceback (most recent call last)`, `Werkzeug`, `sqlalchemy`, `java.lang.`), it is a **confirmed** disclosure. If the path returns a 5xx without a known signature, it is a **potential** finding.

Everything here is read-only; no state is changed.

## In the lab

| Route | Expected |
| --- | --- |
| `GET /api/widget/config` | reflects the Origin with credentials: CORS confirmed |
| `GET /api/widget/config-safe` | fixed trusted origin: no finding |
| any response | the plain lab sets no hardening headers: missing-headers potential |

The lab does not run in debug mode, so the verbose-error signal stays quiet unless you introduce a crashing route.

## How to verify it

```bash
cd backend
python -m pytest -q
```

`test_lab_scan.py` asserts the confirmed CORS finding on `/api/widget/config`, its absence on `/api/widget/config-safe`, and the presence of the missing-headers signal.

## Remediation

Allowlist exact CORS origins and never pair a reflected or wildcard origin with credentials. Set the standard security headers in middleware. Return generic errors to clients and disable debug mode in production.
