# Step 17 — API4, API6, API9, and API10

## Goal

Automate the four OWASP API Security Top 10 2023 items that were only named before, with the same confirmed/potential rule and a safe route that must stay quiet.

## Resource consumption, API4:2023

Code: `backend/app/engine/checks/resource_limits.py`. Id: `resource_limits`. It is part of the default set and it is read-only.

- **Confirmed** when a query parameter named `limit`, `page_size`, or `per_page` returns exactly 40 items. The probe never asks for more than 40.
- **Potential**, once per scan, when a successful response has neither `Retry-After` nor an `X-RateLimit-*` header. A missing header is not proof that the server has no limit.

In the lab, `GET /api/feed` honors 40 and stops internally at 100 so the process cannot be used to exhaust memory. `GET /api/feed/safe` stops at 10 and must not be confirmed.

## Sensitive business flows, API6:2023

Code: `backend/app/engine/checks/business_flow.py`. Id: `business_flow`. **Off by default**, like mass assignment, because it sends two `POST` requests.

It only looks at paths or tags containing `checkout`, `purchase`, `transfer`, `payment`, `redeem`, or `invite`. Both requests use the same `Idempotency-Key`. It is confirmed when both succeed and a `count`, or a list, is one larger on the second response. Success without a counter stays potential.

`POST /api/checkout` appends to a purchase list that is not the BOLA order list. `POST /api/checkout/secure` stores the first result for that key and returns it again.

## Inventory, API9:2023

Code: `backend/app/engine/checks/inventory.py`. Id: `inventory`. Default set. No wordlist.

If a discovered `GET` path contains `/v2/` (or a higher integer), Argus requests the same path with the version decreased by one. It is confirmed when that path is not in the specification and the response is 2xx. Anything else, including 404, is ignored. Versions below 1 are not requested.

`GET /api/v2/status` is in the lab specification. `GET /api/v1/status` is implemented with `include_in_schema=False` and still returns 200.

## Unsafe consumption, API10:2023

Code: `backend/app/engine/checks/unsafe_consumption.py`. Id: `unsafe_consumption`. Default set.

The only parameter name is `provider`. The value is `{collaborator}/trust/{token}`. The collaborator answers with `ARGUS-TRUST-...` and a price. The finding is confirmed only when that marker appears in the target's own body.

`GET /api/quotes` copies the upstream JSON. `GET /api/quotes/safe` calls the collaborator and returns `{"ok": true}`.

## How to verify it

```bash
cd backend
python -m pytest tests/test_lab_scan.py -q
```

The default lab scan must confirm `/api/feed`, `/api/v1/status`, and `/api/quotes`, and must not confirm the safe twins or `/api/v0/status`. A separate test enables only `business_flow` and expects `POST /api/checkout` confirmed, with `POST /api/checkout/secure` absent.

## Concepts

These four items are easy to turn into a noisy or destructive scanner. The limits are the coverage: one modest page size, one previous version, one upstream marker, and an opt-in replay of a single business call. A clean result still does not mean the API is safe against every variant of these classes.
