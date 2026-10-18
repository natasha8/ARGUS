# 03 — Implementation

Read the files in this order. Each one is short enough to follow with the test beside it.

1. `backend/app/engine/safeguards.py` — what is rejected before any request.
2. `backend/app/engine/discovery/openapi.py` — from a specification to a list of `EndpointSpec`, including the security scheme objects, not only a yes/no flag.
3. `backend/app/engine/http.py` — auth headers, rate limit, excerpts for evidence.
4. `backend/app/engine/checks/bola.py` — the clearest check: two users, one ID, one owner field.
5. `backend/app/engine/checks/auth_jwt.py` — token proofs, grouped so they do not flood the dashboard.
6. `backend/app/engine/runner.py` — order: discovery, login, checks, dedup, save.
7. `targets/vulnerable-api/lab_app.py` — the same path, seen from the target. The `secure`, `search-safe`, and `audit` routes are the negative controls.

## One request, in detail

For order 101 the BOLA check does roughly this:

- `GET /api/orders` as alice → `[{id:101, owner:alice}]`
- `GET /api/orders/101` without a token → 403
- `GET /api/orders/101` as bob → 200 and `owner: alice`

Alice is a known profile, bob is not the owner of that object, and anonymous was rejected. The finding is confirmed. The `/secure` route stops at bob's 403 and produces nothing.

## Where severity is decided

In the check, not in the report. The report counts. The dashboard colors. If you want to change a severity, change it in the check module and update the test if the assertion looks at the title or the status, not the color.

## Tests as the specification

`backend/tests/test_lab_scan.py` is the executable description of the behavior. If a check starts flagging `search-safe` or `/api/secure/me`, the test fails. That is how the project keeps false positives low while the code changes.
