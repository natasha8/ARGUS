"""Argus application entrypoint."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scans import router as scans_router
from app.config import settings
from app.db.session import ensure_schema
from app.disclaimer import CHECK_CATALOG, DISCLAIMER
from app.engine.safeguards import allowed_hosts

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_schema()
    yield


app = FastAPI(title="Argus API Security Scanner", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(scans_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "argus"}


@app.get("/meta")
def meta() -> dict:
    return {
        "service": "argus",
        "disclaimer": DISCLAIMER,
        "checks": CHECK_CATALOG,
        "allowed_target_hosts": sorted(allowed_hosts()),
        "collaborator_base_url": settings.collaborator_base_url,
    }
