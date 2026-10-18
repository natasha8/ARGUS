# Step 11 — Reports, API, and CLI

## Goal

Start a scan and read the result without opening the database.

## API

| Method | Path | Role |
| --- | --- | --- |
| `GET` | `/health` | Process status |
| `GET` | `/meta` | Disclaimer, checks, allowed hosts |
| `POST` | `/scans` | Creates the scan and starts it in the background. Responds immediately with status `pending` |
| `GET` | `/scans` | List, with finding counts |
| `GET` | `/scans/{id}` | Detail, endpoints, warnings, findings |
| `GET` | `/scans/{id}/report?format=json` | JSON report |
| `GET` | `/scans/{id}/report?format=markdown` | Markdown report |

The `POST /scans` body is the `ScanCreate` schema: name, URL, `scope_confirmed`, `discovery_mode`, a specification object or `spec_text` (JSON or YAML), manual endpoints, profiles, checks, concurrency, rate limit, callback, and `id_probes`. `spec_text` is parsed and stored as the document, so the engine does not download the URL as well.

## Reports

`json_report.py` summarizes severity and how many findings are confirmed. `markdown_report.py` renders the same content in a readable form, with the disclaimer at the top. Evidence includes the HTTP status and a body excerpt, not authorization headers.

## CLI

```bash
cd backend
python -m app.cli scan --target http://127.0.0.1:8001 --openapi-url http://127.0.0.1:8001/openapi.json --profiles ../examples/profiles.lab.json --collaborator http://127.0.0.1:8090 --confirm-scope
python -m app.cli list
python -m app.cli report SCAN_ID --format markdown
```

`--confirm-scope` is required in the sense that, without that flag, the command exits with a scope error. You can pass `--spec file.json` instead of the URL, or `--manual file.json`.

## How to verify it

`backend/tests/test_api.py` checks `/health`, `/meta`, and the rejection of an unauthorized scan. The lab test checks that the Markdown report contains the expected findings.

## Concepts

The scanner API and the API under test are two different things. The first listens on port 8000. The second, in the lab, listens on 8001.
