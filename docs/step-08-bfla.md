# Step 8 — BFLA

## Goal

See whether an administrative function accepts a role it should not.

Reference: OWASP API5:2023. Code: `backend/app/engine/checks/bfla.py`.

## How it is tested

An endpoint is a candidate if the path or a tag contains `admin`, `manage`, `internal`, `staff`, or `audit`. Argus issues three `GET` requests:

- without credentials;
- with a profile whose role is not `admin`;
- with the admin profile, if you provided one.

It is confirmed when the low role receives a success response and anonymous receives 401 or 403. If admin also fails, the endpoint is skipped: it is not a function that is actually available. If anonymous also succeeds, the finding says the function is open, and it is marked critical.

## In the lab

`GET /api/admin/users` requires a JWT but not a role: alice can read it. `GET /api/admin/audit` uses `require_admin` and returns 403 to alice. The second must not produce a finding.

## False positives avoided

The path name alone is not enough. The difference between roles is required. A 404 or a 403 for everyone does not become a finding.

## Remediation

Every privileged operation checks the role on the server, after authentication. Hiding the URL is not a control.
