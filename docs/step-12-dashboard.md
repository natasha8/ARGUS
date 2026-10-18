# Step 12 — Dashboard

## Goal

Configure a scan and read the findings without using the CLI.

Code: `frontend/`. Next.js 15, TypeScript, no component library: styles are in `app/globals.css`.

## Pages

- `/` lists scans and refreshes every 3 seconds. It shows status, target, and how many findings are confirmed.
- `/scans/new` asks for the name, URL, OpenAPI discovery (URL or a JSON/YAML file) or several manual endpoints, profiles, checks, callback, concurrency, rate limit, and the authorization confirmation. The **Fill local lab** and **Fill Docker lab** buttons fill in the correct URLs for the two ways of running. Profile types, manual parameters, and the speed limits are described in [step 16](step-16-inputs.md).
- `/scans/[id]` polls the scan until it is `completed` or `failed`. It filters by severity, status, and category. It opens the evidence and can request the Markdown or JSON report. Discovered endpoints show `auth` or `public`, plus the security scheme names when the specification declared them.

The browser talks to `NEXT_PUBLIC_API_URL`, default `http://localhost:8000`. In Docker that value is fixed at build time, because from the browser `localhost` is your machine, not the backend container.

## How to verify it

With the backend, lab, and callback running:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000, use **Fill local lab**, start, and wait for the findings. A confirmed finding on `GET /api/orders/{order_id}` means the path is complete. `search-safe` and `/api/admin/audit` must not appear.

## Concepts

The dashboard does not add scanning capability. It makes the difference between confirmed and potential visible, which is the point of the project: fewer alarms to discard by hand.
