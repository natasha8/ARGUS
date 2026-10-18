"""In-memory callback used to confirm SSRF inside the lab."""

from fastapi import FastAPI

app = FastAPI(title="Argus Collaborator", version="1.0.0")
HITS: dict[str, int] = {}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "argus-collaborator"}


@app.get("/marker/{token}")
def marker(token: str) -> dict:
    HITS[token] = HITS.get(token, 0) + 1
    return {"marker": f"ARGUS-CALLBACK-{token}"}


@app.get("/hits/{token}")
def hits(token: str) -> dict:
    return {"count": HITS.get(token, 0)}


@app.get("/trust/{token}")
def trust(token: str) -> dict:
    HITS[token] = HITS.get(token, 0) + 1
    return {"marker": f"ARGUS-TRUST-{token}", "price": 0}
