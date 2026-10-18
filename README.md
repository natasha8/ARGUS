# Argus

Security scanner for REST APIs you are authorized to test. It compares responses across users, checks JWTs, administrative functions, URL parameters, and queries, then separates **confirmed** results from **potential** ones.

This version covers:

| Check | API Security 2023 | Top 10:2025 |
| --- | --- | --- |
| BOLA / IDOR | API1 | A01 Broken Access Control |
| Weak JWT, `alg: none`, ignored expiry, forged role claim | API2 | A07 Authentication Failures |
| Excessive data exposure, including a fast password hash | API3 | A04 Cryptographic Failures |
| Uncapped page size, missing rate-limit headers | API4 | A10 Mishandling of Exceptional Conditions |
| BFLA | API5 | A01 Broken Access Control |
| Sensitive business flow, opt-in | API6 | A06 Insecure Design |
| SSRF to a lab callback | API7 | A01 Broken Access Control |
| Security misconfiguration (CORS, headers) | API8 | A02 Security Misconfiguration |
| Verbose errors | API8 | A10 Mishandling of Exceptional Conditions |
| Previous API version still reachable | API9 | A02 Security Misconfiguration |
| Upstream response copied into the result | API10 | A08 Software or Data Integrity Failures |
| Mass assignment, opt-in | API3 | A08 Software or Data Integrity Failures |
| SQL, NoSQL operators, command metacharacters | — | A05 Injection |
| Required query parameter ignored | — | A10 Mishandling of Exceptional Conditions |

A03:2025 Software Supply Chain Failures and A09:2025 Security Logging and Alerting Failures are not probed. Supply-chain compromises and server logs are not visible on the API, and Argus does not guess dependency files or try component exploits.

API6 and mass assignment stay off unless you select them, because those probes change server state. The [guide](GUIDE.md) explains what each check confirms.

## Start with Docker

Requires Docker Desktop.

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000
- Argus API: http://localhost:8000
- Lab API: http://localhost:8001
- Callback: http://localhost:8090

In the dashboard, use **Fill Docker lab**, confirm authorization, and start. From inside the container the target is `http://vulnerable-api:8000`.

Ports are published only on `127.0.0.1`.

## Local start, without Docker

```bash
python -m pip install -r backend/requirements.txt
python -m uvicorn collaborator_app:app --app-dir targets/collaborator --port 8090
python -m uvicorn lab_app:app --app-dir targets/vulnerable-api --port 8001
python -m uvicorn app.main:app --app-dir backend --port 8000
cd frontend && npm install && npm run dev
```

In the dashboard, use **Fill local lab**. The target is `http://127.0.0.1:8001`. The form also accepts Bearer, API key, and Basic profiles, a JSON or YAML specification, several manual endpoints, and the concurrency and rate limits.

## CLI

From the `backend` directory, with the lab already listening:

```bash
python -m app.cli scan --target http://127.0.0.1:8001 --openapi-url http://127.0.0.1:8001/openapi.json --profiles ../examples/profiles.lab.json --collaborator http://127.0.0.1:8090 --confirm-scope
python -m app.cli list
python -m app.cli report SCAN_ID --format markdown
```

## Tests

```bash
cd backend
python -m pytest -q
```

## Documentation

- [Usage and checks](GUIDE.md)
- [Step index](docs/README.md)
- [Learning path](learn/00-OVERVIEW.md)

The lab in `targets/` is intentionally vulnerable. Do not expose it beyond localhost.
