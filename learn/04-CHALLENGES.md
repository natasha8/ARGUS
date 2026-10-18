# 04 — Exercises

Do them on the local lab. Do not point Argus at hosts that are not in the allowlist.

1. Run a lab scan and write, for one confirmed finding and one that is missing, why the second is absent. Use `/api/admin/audit` or `search-safe`.
2. In `lab_app.py`, make `GET /api/orders/{order_id}` return 403 when `order["owner"]` is not `user["sub"]`. Re-run the tests and see which assertion now fails. Then put the flaw back: the lab must stay vulnerable for the others.
3. Add a new, informational-only check that flags a JSON response containing the key `password`. It must be `potential` or `info`, it must not send payloads, and it must have a test that fails if it flags an endpoint that does not return that key.
4. Explain, without implementing it, how you would recognize API3 (mass assignment) on a `PATCH /api/profile` that accepts a `role` field. Which comparison between two requests would make the finding confirmed instead of potential?
5. Read `safeguards.py` and add a test for a `file://` URL and for the host `metadata.google.internal`. Both must raise `ScopeError`.

When you change a check, update the matching page in `docs/` and the paragraph in `GUIDE.md`. The documentation is part of the project, not an attachment.
