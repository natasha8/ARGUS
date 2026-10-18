# Step 5 — Target authentication

## Goal

Talk to the API the way different users would, without hardcoding a single header.

## Profiles

A profile has a `type`:

- `bearer`: `Authorization: Bearer ...` header. If the token is missing and `login_path` is set, Argus `POST`s `username` and `password` and reads `access_token` (or `token`), `sub`, and `role`.
- `api_key`: configurable header, default `X-API-Key`.
- `basic`: Basic header computed from username and password.
- `none`: no credentials.

The implementation is in `backend/app/engine/auth/profiles.py` and `auth_headers` in `http.py`. Lab profiles are in `examples/profiles.lab.json`.

The dashboard edits the same fields: type, role, token, login path, API key header, and Basic username and password. **Add profile** and **Remove** change how many identities the scan compares. **Fill local lab** still creates alice, bob, and admin as Bearer profiles that log in at `/api/login`.

## Why more than one user is needed

BOLA compares two identities. BFLA compares a low role, an admin, and anonymous. A single token is not enough to say whether access control exists.

## JWT is read, not judged yet

`jwtutil.py` can decode the payload without trusting the signature, only to read `sub` and to build the proofs for the next step. The judgment lives in the `auth_jwt` check, not in login.

## How to verify it

The lab also exposes `GET /api/keys/ping` (key `lab-key`) and `GET /api/basic/ping` (`carol` / `carol123`). The `test_auth_headers` test checks the header shape. The lab scan verifies the real login of alice, bob, and admin: if login failed, BOLA findings could not be confirmed.

## Concepts

Target credentials are sensitive. Argus uses them for requests and does not copy them into evidence excerpts. Do not put them in a public repository.
