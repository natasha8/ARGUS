# Step 13 — Lab, tests, and guide

## Goal

Demonstrate true positives and block false positives with a local target and repeatable tests.

## Lab

`targets/vulnerable-api/lab_app.py` is marked as a training target. Do not publish it.

It intentionally contains the flaws described in steps 6–10 and the correct counterparts:

| Route | Expected |
| --- | --- |
| `GET /api/orders/{order_id}` | BOLA confirmed |
| `GET /api/orders/{order_id}/secure` | no BOLA |
| `GET /api/account` | JWT `alg: none` and expiry |
| `GET /api/secure/me` | strict JWT, excluded from the `alg: none` finding |
| `GET /api/profile` | excessive data exposure confirmed |
| `GET /api/secure/profile` | no data exposure |
| `GET /api/admin/users` | BFLA confirmed |
| `GET /api/admin/audit` | no BFLA |
| `GET /api/preview` | SSRF confirmed toward the callback |
| `GET /api/products/search` | SQL injection confirmed |
| `GET /api/products/search-safe` | no injection |
| `POST /api/items/find` | JSON operator confirmed |
| `GET /api/diag/ping` | metacharacters, without starting a shell |
| `GET /api/widget/config` | CORS reflects origin with credentials: confirmed |
| `GET /api/widget/config-safe` | fixed trusted origin: no finding |

The callback is `targets/collaborator`. It counts visits in memory.

## Tests

```bash
cd backend
python -m pytest -q
```

`test_lab_scan.py` starts the lab and the callback on free ports, runs the engine, and asserts both the expected findings and the absences. The other tests cover discovery, scope, JWT shape, and the HTTP API.

## Guide and path

- [GUIDE.md](../GUIDE.md) explains usage, limits, and how to read reports.
- [learn/](../learn/00-OVERVIEW.md) walks through concepts, architecture, implementation, and exercises.

## Concept

A check is credible if it stays quiet on the correct routes of the same lab. That is why every planted flaw has a variant that must remain silent.
