# 01 — Concepts

## Authorization and authentication

Authentication answers "who are you". Authorization answers "what may you do". A valid JWT proves the first. It does not prove the second: the API still has to check the object and the function.

BOLA is a failure of the first check after login: the user is authentic, but reads someone else's order. BFLA is a failure of the function check: the user is authentic, but opens an admin area.

## Why tokens break

A JWT is three base64 pieces: header, payload, signature. The signature only means something if the server recomputes it with a secret the client does not choose. If the server accepts `alg: none`, the client decides the payload. If the secret is the word `secret`, anyone can re-sign. If `exp` is not read, a stolen token does not expire.

Argus does not print the secret in the report. It only tells you that it was in a list of obvious values.

## SSRF

The API becomes an HTTP client. The caller chooses the URL and observes the result, or observes a side effect (the callback that saw the request). The risk is reaching services that are not exposed from your PC, but are exposed from the server. That is why the lab still blocks metadata hosts, and why Argus, on the scanner side, sends only the configured callback.

## Injection

Concatenating a string into SQL mixes data with the command. A quote closes the string earlier than expected; a `'1'='1` condition can make a `WHERE` true. The parameterized version sends the value outside the SQL sentence, so the quote stays a character to search for, not syntax.

The same boundary shift happens if a metacharacter ends up in a shell. The Argus lab simulates that boundary without starting a shell: the goal is to recognize the signal, not to obtain a command.

## Confirm, do not only flag

A 500 error can be any bug. Argus marks SQL injection as confirmed only if a true condition and a false condition change the results, or if a MySQL delay is measurable. In the same way, two users who see the same public object are not a BOLA: anonymous must be rejected and the owner must be the other user.

## The rest of the API Top 10 2023

**API3** Broken Object Property Level Authorization is covered on both sides. The read side (excessive data exposure, such as a password hash in a response) runs by default. The write side, mass assignment (for example `role` accepted in a profile update), is an opt-in check that changes server state and then restores it, so it is off unless you ask for it.

**API4** Unrestricted Resource Consumption asks a list for 40 rows and confirms the finding only when it receives 40. It does not flood the server. Missing rate-limit headers stay potential.

**API6** Unrestricted Access to Sensitive Business Flows is opt-in. Two identical checkout-like requests with the same idempotency key are confirmed only when a counter shows the second one also created something.

**API8** Security Misconfiguration is automated through CORS origin reflection, missing security headers, and verbose error disclosure (step 15).

**API9** Improper Inventory Management requests only the previous version number present in the specification. A path that answers 404 is ignored.

**API10** Unsafe Consumption of APIs is confirmed when the target copies a collaborator marker from an upstream JSON body into its own response. The SSRF check only proves that a request was made.

The lab keeps a safe twin for each of these, and the scan test fails if that twin is reported.
