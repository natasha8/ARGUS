# Step 1 — Setup

## Goal

Have a project that starts locally and with Docker: Argus API, dashboard, PostgreSQL, lab API, and callback.

## What it contains

- `docker-compose.yml` publishes every port only on `127.0.0.1`.
- `backend/` is FastAPI. The image uses Python 3.12.
- `frontend/` is Next.js. The browser calls `http://localhost:8000`.
- `targets/vulnerable-api` and `targets/collaborator` are separate services.
- `.env.example` lists `DATABASE_URL`, `ALLOWED_TARGET_HOSTS`, and `COLLABORATOR_BASE_URL`.

In Docker the database is PostgreSQL. Outside Docker the default is SQLite (`sqlite:///./argus.db`), so you can try the tool without containers.

## How to verify it

```bash
docker compose up --build
```

Then `GET http://localhost:8000/health` must respond `{"status":"ok","service":"argus"}`.

Without Docker, from the project root:

```bash
python -m uvicorn app.main:app --app-dir backend --port 8000
```

## Concepts

Keeping the scanner, the target, and the callback in different processes avoids confusing "Argus called the API" with "the API called the callback". That difference is what makes an SSRF demonstrable.
