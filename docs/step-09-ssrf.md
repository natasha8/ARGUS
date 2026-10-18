# Step 9 — SSRF

## Goal

See whether the API, starting from a parameter, makes an HTTP request to an address chosen by the caller.

Reference: OWASP API7:2023. Code: `backend/app/engine/checks/ssrf.py` and `targets/collaborator`.

## How it is tested

Argus considers only query parameters with an explicit name: `url`, `uri`, `link`, `webhook`, `callback`, `dest`, `redirect`, `website`, `fetch_url`, `endpoint_url`, `target_url`.

The value is `{COLLABORATOR_BASE_URL}/marker/{token}`. The collaborator responds with `ARGUS-CALLBACK-{token}` and increments a counter. The finding is confirmed if that marker comes back in the API body or if `GET /hits/{token}` has a count greater than zero.

Metadata IPs, arbitrary internal networks, and URLs from a cloud-infrastructure list are not probed. The only address is the callback you configured.

The check is limited to `GET`, so it does not create webhooks or records on the API while observing it.

## In the lab

`GET /api/preview?url=` really fetches the URL with an HTTP client, without following redirects, and rejects metadata hosts. In Docker the callback is `http://collaborator:8090`. Locally it is `http://127.0.0.1:8090`. It must be reachable from the lab process, not only from the browser.

## False positives avoided

A connection error is not an SSRF. Without a marker and without a hit on the callback, Argus records nothing.

## Remediation

Do not let the API fetch a free-form URL. If a fetch is required, allow only expected hosts and block link-local, metadata, and open redirects.
