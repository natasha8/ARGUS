# 00 — Overview

Argus is a learning and portfolio project: a scanner for authorized REST APIs, with a dashboard, a CLI, and a vulnerable lab used only locally.

Before reading the code, start the lab as in the [README](../README.md) and run a scan. Then come back here.

## What you need

- Python 3.12
- Node.js 20, if you want the dashboard
- Docker, if you want the full stack
- The idea of an HTTP request, status codes, the `Authorization` header, and JSON

## What it is not

It is not permission to scan other people's APIs. The allowlist and the scope confirmation are part of the program. It automates the OWASP API Security Top 10 2023 (API1 through API10) and labels each finding with the matching OWASP Top 10:2025 category. Injection is A05:2025. A required query parameter that can be omitted is A10:2025. A03:2025 (software supply chain) and A09:2025 (logging and alerting) are not probed. API6 and the write side of API3 stay off unless you select them, because those probes change state.

## Reading order

1. [Concepts](01-CONCEPTS.md)
2. [Architecture](02-ARCHITECTURE.md)
3. [Implementation](03-IMPLEMENTATION.md)
4. [Exercises](04-CHALLENGES.md)

The more operational step documentation is in [docs](../docs/README.md).
