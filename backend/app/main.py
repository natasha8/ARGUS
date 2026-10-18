"""Argus application entrypoint."""

from fastapi import FastAPI

app = FastAPI(title="Argus API Security Scanner", version="1.0.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "argus"}
