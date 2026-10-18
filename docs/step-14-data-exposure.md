# Step 14 — API3 (data exposure + mass assignment) and JWT claim tampering

## Goal

Extend OWASP coverage with API3:2023 on both sides (read and write), and complete the JWT check with the claim tampering the plan described for Step 7.

## Excessive data exposure, API3:2023

Code: `backend/app/engine/checks/data_exposure.py`.

API3 (Broken Object Property Level Authorization) has two sides. The **read** side is excessive data exposure: the API returns properties the client should not see. The **write** side is mass assignment: the client sets properties it should not control.

Argus automates only the read side, because it is read-only. For every `GET`, it reads the response as an authenticated profile and looks for property names that should never reach a client:

- **Confirmed** (strong names): `password`, `password_hash`, `secret`, `private_key`, `ssn`, `credit_card`, `cvv`, `reset_token`, `salt`, `mfa_secret`, and similar.
- **Potential** (weak names): `token`, `api_key`, `access_key`, `refresh_token`. These are sometimes legitimate, so they need a manual review.

A field only counts if it has a non-empty value. The evidence lists the field **names**; the values are replaced with `[redacted]` before the excerpt is stored, so the report never contains the hash or token.

By default, mass assignment (the write side) is not probed. There is an **opt-in** check for it, described below.

### Mass assignment (opt-in), API3:2023

Code: `backend/app/engine/checks/mass_assignment.py`. Id: `mass_assignment`. It is **off by default** and not part of the standard set, because it sends a state-changing request.

When enabled, it is deliberately conservative:

- it only targets `PATCH` or `PUT` endpoints that have a matching `GET` on the same path, so it can read the object before and after;
- it only flips a privileged property that is already present in the `GET` response: a role-like string (set to `admin`) or a boolean flag (set to `true`). It never invents a field;
- it restores the original value immediately after the probe and records in the evidence whether the restore succeeded.

It is confirmed only if a re-read shows the property actually changed to the injected value. In the lab, `PATCH /api/profile` writes every property, so alice can set `role: admin`; the probe confirms it and then restores `role: user`. `PATCH /api/secure/profile` accepts only `display_name`, so it produces no finding.

Enable it from the dashboard checkbox **Mass assignment (opt-in)**, or with the CLI `--checks` list, for example `--checks mass_assignment`.

### In the lab

| Route | Expected |
| --- | --- |
| `GET /api/profile` | returns `password_hash` and `reset_token`: confirmed |
| `GET /api/secure/profile` | returns only `username`, `display_name`, `role`: no finding |
| `PATCH /api/profile` | mass assignment confirmed (opt-in), then restored |
| `PATCH /api/secure/profile` | accepts only `display_name`: no finding |

## JWT claim tampering, API2:2023

Code: `_claim_tampering` in `backend/app/engine/checks/auth_jwt.py`.

It runs only after the weak HMAC secret has been recovered. Argus takes the token of a profile whose `role` claim is not `admin`, re-signs it with `role: admin`, and sends it to admin-looking `GET` endpoints. The finding is confirmed only where the real low-privilege token gets 401 or 403 and the forged token gets 2xx.

In the lab, alice's real token gets 403 on `GET /api/admin/audit`. The re-signed token with `role: admin` gets 200, so the finding is confirmed. That route still produces **no BFLA finding**, because the server does check the role; the problem is that the role comes from a token anyone can forge once the secret is known.

## How to verify it

```bash
cd backend
python -m pytest -q
```

`test_lab_scan.py` asserts the confirmed exposure on `/api/profile`, its absence on `/api/secure/profile`, that the reset token value is not in the evidence, and that the forged role claim is detected.

## Remediation

Serialize responses through an explicit allowlist of fields. For tokens, use a long random secret and do not trust authorization claims beyond what the server can verify.
