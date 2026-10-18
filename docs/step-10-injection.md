# Step 10 — Injection

## Goal

Recognize input that changes a query or is treated as a command, without destructive probes.

Reference: OWASP Top 10 A05:2025 (this was A03:2021). The API Security Top 10 2023 does not have a separate item named "injection"; the issue is still real in APIs that concatenate SQL or pass input to a shell. Code: `backend/app/engine/checks/injection.py`. Findings use `owasp_id` and `owasp_web` `A05:2025`.

## Where probes run

Only `GET` and `HEAD`, plus `POST` whose path contains `search`, `find`, `query`, `filter`, `login`, or `items`. Never `PUT`, `PATCH`, or `DELETE`. Parameters already used for SSRF or the command check are not reused as SQL.

## SQL

For a string parameter Argus sends:

- the value `notebook`, as a baseline;
- a quote, to look for a database error;
- `x' OR '1'='1' --` and `x' OR '1'='2' --`, to see whether the number of results changes.

It is confirmed if the true condition returns more rows than the false condition and, in addition, either there is a SQL error or the true condition also beats the baseline. There are no `UNION` queries, no writes, and no file reads.

If the error is clearly MySQL, a single `SLEEP(1)` probe can confirm a delay of at least 700 ms above the baseline. SQLite, used by the lab, does not need this step: the boolean comparison is enough.

`GET /api/products/search` concatenates `q` into a `SELECT`. `GET /api/products/search-safe` uses a bound parameter and must not produce a finding.

## JSON operators

On a body with properties, Argus replaces a string with `{"$gt": ""}`. It is confirmed if the list grows, or if a 401/403 becomes success. In the lab, `POST /api/items/find` applies `$gt` with a minimal interpreter written in Python: it demonstrates the operator being passed through, and it does not talk to MongoDB.

## Commands

Only the parameters `host`, `hostname`, `ip`, `domain`, `cmd`, and `command`. It compares `127.0.0.1` with a single quote and a double quote. If the baseline is clean and both quotes produce a shell-style error, the finding is confirmed.

`GET /api/diag/ping` does not start `sh` or `cmd`. It returns an error message when it sees a metacharacter. That exists so detection can be exercised without running commands.

## False positives avoided

Two different strings that do not change a list are not enough. A generic error without a SQL signature and without a result difference is not enough. An endpoint that already mentions "syntax error" in the baseline is skipped by the command check, because the signal is not distinguishable.

## Remediation

Parameterized queries, expected types instead of free JSON objects, and arguments passed as a list to a process rather than interpolated into a shell.
