# Step 7 — JWT authentication

## Goal

See whether the API trusts a token it should reject.

Reference: OWASP API2:2023. Code: `backend/app/engine/checks/auth_jwt.py` and `jwtutil.py`.

## Three proofs

They run only on authenticated `GET` endpoints, and only if the real token succeeds while anonymous receives 401 or 403.

1. **Weak secret.** The token's HMAC signature is compared locally with a short list: `secret`, `password`, `changeme`, `jwt-secret`, `supersecret`, `secret123`. If it matches, the finding is confirmed. The value does not enter the report.
2. **`alg: none`.** Argus resends the same payload with algorithm `none` and an empty signature. If the endpoint responds with success, the signature is not verified. Affected endpoints are grouped into one finding.
3. **Expiry.** Only if the secret was recognized, Argus re-signs the payload with `exp` in the past. If the API accepts it, expiry is not checked.
4. **Claim tampering.** Only if the secret was recognized, Argus re-signs a non-admin token with `role: admin` and sends it to admin-looking endpoints. It is confirmed where the real token gets 401 or 403 and the forged one succeeds. See [step 14](step-14-data-exposure.md).

## In the lab

The "loose" decoder accepts `alg: none` and ignores `exp`. It is used by `/api/account`, orders, and `/api/admin/users`. `GET /api/secure/me` accepts only HS256, verifies the signature, and rejects expired tokens: it must not appear among the `alg: none` endpoints.

The lab secret is `secret`, on purpose.

## False positives avoided

A public endpoint would respond 200 to both the real token and a forged one. Without the anonymous comparison, that would look like a bypass. Argus does not flag it.

## Remediation

Accept only the algorithms you chose, verify the signature with a long random secret, and reject tokens with `exp` in the past.
