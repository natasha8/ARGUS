# Step 3 — Discovery

## Goal

Obtain the list of operations to test, from a specification or from a list written by hand.

## OpenAPI and Swagger

`backend/app/engine/discovery/openapi.py` reads `paths`. For each HTTP method it extracts:

- path and query parameters, resolving local `$ref`s;
- the type, including the Swagger 2 style where `type` sits on the parameter and not inside `schema`;
- JSON body properties;
- `auth_required`, true when the operation or the document declares `security`;
- the security schemes themselves: name, type (`http`, `apiKey`, and the others), HTTP scheme (`bearer`, `basic`), and for an API key the header or query name. OpenAPI 3 reads `components.securitySchemes`. Swagger 2 reads `securityDefinitions`. An empty `security` list means the operation is public even if the document has a default.

The `servers` URL in the specification is ignored. The base URL you provided is the one that counts, so in Docker you can point at `vulnerable-api` even if the spec says `localhost`.

## Manual entry

`manual.py` accepts objects with `method`, `path` (must start with `/`), `parameters`, `request_body`, `tags`, `auth_required`, and an optional `security` object in the same shape the parser stores (`requirements` and `schemes`). An example is `examples/manual-endpoints.json`.

A specification pasted or uploaded as text is parsed by `load_spec_text`. JSON and YAML both work. The dashboard sends that text as `spec_text`; the CLI still reads the file itself.

## How to verify it

```bash
cd backend
python -m pytest tests/test_discovery_and_scope.py -q
```

The test covers an OpenAPI 3 document with `$ref` and a Bearer scheme, a Swagger 2 document with an API key, YAML and JSON text, a manual security object, and a manual path without a leading slash, which must be rejected.

## Concepts

Discovery does not decide whether an endpoint is vulnerable. It only says what exists and whether the specification considers it protected. Later checks use `auth_required` so a public page is not treated as an authentication bypass.
