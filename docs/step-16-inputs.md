# Step 16 — Dashboard inputs and security schemes

## Goal

Make the dashboard send the same scan inputs the API and CLI already accepted, and keep the security schemes discovery reads.

## What changed

### Profiles

`/scans/new` edits every profile field the engine uses:

- **Bearer / JWT**: a token, or a username, password, and login path when the token is empty
- **API key**: the key and the header name (default `X-API-Key`)
- **Basic**: username and password
- **None**: a named profile with no credentials

**Add profile** and **Remove** change the list. BOLA still needs two authenticated profiles. **Fill local lab** and **Fill Docker lab** still create alice, bob, and admin.

### Manual endpoints

Manual mode accepts more than one endpoint. Each row has method, path, tags, JSON body field names, an authentication flag, an optional scheme (Bearer, API key, or Basic), and parameters (`path`, `query`, or `header`). The payload matches `examples/manual-endpoints.json` plus `security`.

### Specification upload

The file input accepts JSON and YAML. The browser sends the file text as `spec_text`. `load_spec_text` in `backend/app/engine/discovery/openapi.py` parses it and the scan stores the object. When a file is set, the OpenAPI URL is not fetched.

### Speed

The form asks for concurrency (1–20, default 4) and requests per second (0.2–50, default 8). Those are the same bounds as `validate_scan_options`.

### Security schemes

Discovery no longer keeps only `auth_required`. Each endpoint stores:

- `requirements`: the OpenAPI alternatives (a list of groups of scheme names and scopes)
- `schemes`: the resolved objects (`type`, `scheme`, `location`, `param_name`)

OpenAPI 3 uses `components.securitySchemes`. Swagger 2 uses `securityDefinitions`. The scan detail page shows the scheme names next to `auth` or `public`.

The column is `endpoints.security`. New databases get it from the model. Databases created earlier gain it on startup through `ensure_schema`. Alembic revision `002_endpoint_security` adds the same column when the database is managed with Alembic.

## Confirmation stays inside each check

The original plan sketched a separate `validate()` after `run()`. The confirming request (the second user, the boolean SQL pair, the callback poll) is part of the same probe, and the status is chosen there. A later `validate()` would either repeat the traffic or only rename a status that is already known. Checks still return `confirmed` or `potential` drafts, and the runner keeps the stronger one when titles collide.

## How to verify it

```bash
cd backend
python -m pytest tests/test_discovery_and_scope.py -q
```

That covers Bearer and API-key scheme parsing, YAML and JSON text, a manual security object, and adding the `security` column to an older table.

With the dashboard running, open http://localhost:3000/scans/new:

1. **Fill local lab** sets three Bearer profiles and confirms the scope.
2. Change one profile to API key and the key plus header fields appear. Basic shows username and password.
3. Switch discovery to **Manual endpoints**, add a second row, and set its method.
4. Change concurrency or the rate outside 1–20 or 0.2–50 and the form refuses to submit.

## Concepts

A specification's `security` list says which scheme the author declared, not that the server enforces it. Argus keeps both facts: the boolean the checks already use, and the scheme objects so a reader can see whether the operation was documented as Bearer, an API key, or something else.
