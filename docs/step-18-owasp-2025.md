# Step 18 — OWASP Top 10:2025

## Goal

Label every Argus finding with the [OWASP Top 10:2025](https://owasp.org/Top10/2025/) category that matches the probe, without replacing the API Security Top 10 2023 checks and without adding exploit-style probes.

The 2025 document is the web application list. Two categories are new: software supply chain failures, and mishandling of exceptional conditions. Server-side request forgery moved into broken access control. Injection moved from A03:2021 to A05:2025.

Each finding keeps `owasp_id` (the API id, or `A05:2025` / `A10:2025` when there is no API id) and gains `owasp_web`. The column is added by Alembic revision `003_finding_owasp_web`. Startup also adds it to an existing local database.

## Mapping

| Check | `owasp_id` | `owasp_web` |
| --- | --- | --- |
| `bola`, `bfla`, `ssrf` | API1, API5, API7 | A01:2025 Broken Access Control |
| `misconfig` CORS and headers, `inventory` | API8, API9 | A02:2025 Security Misconfiguration |
| `data_exposure` | API3 | A04:2025 Cryptographic Failures |
| `injection` | A05:2025 | A05:2025 Injection |
| `business_flow` | API6 | A06:2025 Insecure Design |
| `auth_jwt` | API2 | A07:2025 Authentication Failures |
| `mass_assignment`, `unsafe_consumption` | API3, API10 | A08:2025 Software or Data Integrity Failures |
| `resource_limits`, verbose errors in `misconfig`, `fail_open` | API4, API8, A10 | A10:2025 Mishandling of Exceptional Conditions |

The SSRF probe is unchanged. Only its web label moved, because the 2025 introduction folds SSRF into A01.

## Fast password hashes

`data_exposure` still confirms sensitive field names and redacts values. When a confirmed password-hash field is 32, 40, or 64 hexadecimal characters and the same object has no salt, `evidence.fast_hashes` records the field and `md5`, `sha1`, or `sha256`. The digest is not stored and is not cracked.

In the lab, `GET /api/profile` returns an unsalted SHA-256 `password_hash`.

## Fail-open

Code: `backend/app/engine/checks/fail_open.py`. Id: `fail_open`. Default set. GET only.

For a query parameter the specification marks required, Argus sends one placeholder value, then omits that parameter. It is confirmed when both responses are 2xx and the body matches. A changed body stays potential. 4xx is ignored.

`GET /api/reports/export` is documented with `format` required and still returns the report. `GET /api/reports/export/safe` rejects a missing `format` and must not be reported.

## Not probed

- **A03:2025 Software Supply Chain Failures.** The 2025 text notes that this category is hard to test from the outside. Argus does not guess dependency manifests, query CVE feeds, or send component-exploit probes.
- **A09:2025 Security Logging and Alerting Failures.** Logs and alerts are not visible on the API. Argus does not spray logins and does not diff an audit endpoint.

A completed scan with no findings still does not mean those two categories are fine.

## How to verify it

```bash
cd backend
python -m pytest tests/test_lab_scan.py -q
```

The default lab scan confirms `GET /api/reports/export` and does not confirm `GET /api/reports/export/safe`. The profile exposure carries `A04:2025` and `fast_hashes` with `sha256`. Injection findings use `A05:2025`.
