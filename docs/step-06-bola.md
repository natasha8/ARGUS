# Step 6 — BOLA / IDOR

## Goal

See whether an authenticated user reads another user's object.

Reference: OWASP API1:2023. Code: `backend/app/engine/checks/bola.py`.

## How it is tested

The check looks only at `GET` requests with a path parameter and `auth_required`. For each endpoint:

1. If the collection exists (from `/api/orders/{order_id}` it derives `/api/orders`), it reads it with the first profile and collects `id` fields.
2. It adds probe IDs, in the lab `101`, `102`, `1`, `2`.
3. For each ID it requests the resource anonymously and with each profile.

It is **confirmed** only if anonymous receives 401 or 403 and the owner in the JSON matches another authenticated profile, not the caller. The fields it looks for are `owner`, `owner_id`, `user`, `user_id`, `username`, `sub`, `account`.

It is **potential** if two users receive the same body, anonymous is rejected, but there is no owner field. A shared object with owner `system` is not promoted to confirmed, because that value is not another profile's identity.

## In the lab

`GET /api/orders/{order_id}` does not check the owner: bob reads alice's order 101. `GET /api/orders/{order_id}/secure` returns 403 to anyone who is not the owner and must not produce a finding.

## False positives avoided

A public resource responds 200 even without a token: it is skipped. A missing resource responds 404 to everyone: it is skipped. Without two profiles the check produces nothing, instead of guessing.

## Remediation

On the server, after authenticating the caller, compare the object's owner with the token identity. The ID in the path is not an authorization.
