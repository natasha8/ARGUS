# Step 4 — Engine and safeguards

## Goal

Run the checks asynchronously, with a speed cap, and reject targets that are out of scope.

## Flow

`execute_scan` in `backend/app/engine/runner.py`:

1. Moves the scan to `running`.
2. Checks the allowlist again.
3. Loads the specification or the manual endpoints and stores them, including security schemes.
4. Logs in the profiles.
5. Runs the selected checks. An error in one check does not cancel the others.
6. Deduplicates findings, keeps the stronger status (`confirmed` beats `potential`), and saves.
7. Closes with `completed` or `failed`.

`ProbeClient` limits concurrency (1–20) and requests per second (0.2–50). It does not follow redirects. The User-Agent is `Argus-API-Scanner/1.0 (authorized-testing)`.

## Safeguards

`backend/app/engine/safeguards.py` requires `scope_confirmed`. It accepts only `http` and `https`. The host must be in `ALLOWED_TARGET_HOSTS`. `169.254.169.254`, `169.254.*` hosts, and Google metadata names are always blocked.

Checks that change state do not run on `PUT`, `PATCH`, and `DELETE`. Active `POST` probes are limited to search or login paths.

## How to verify it

```bash
cd backend
python -m pytest tests/test_discovery_and_scope.py tests/test_api.py -q
```

`POST /scans` without confirmation returns 400. A target of `example.com` or a metadata IP is rejected before a connection is opened.

## Concepts

The scanner is itself a powerful client. The scope limit lives in the program, not only in the README text: if the host is not allowed, the scan does not start.
