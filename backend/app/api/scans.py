"""HTTP API for Argus."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.db.session import get_db
from app.engine.report import build_json_report, render_markdown
from app.engine.runner import execute_scan
from app.engine.safeguards import ScopeError
from app.models import Scan
from app.schemas.scan import ScanCreate, ScanDetail, ScanSummary
from app.services.scans import create_scan, to_detail, to_summary

router = APIRouter()
_TASKS: set[asyncio.Task] = set()


def _load(db: Session, scan_id: str) -> Scan:
    scan = db.scalar(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.findings), selectinload(Scan.endpoints))
    )
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.post("/scans", response_model=ScanSummary, status_code=201)
async def start_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanSummary:
    try:
        scan = create_scan(db, payload)
    except (ScopeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    task = asyncio.create_task(_run(scan.id))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return to_summary(scan)


async def _run(scan_id: str) -> None:
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        await execute_scan(db, scan_id)
    finally:
        db.close()


@router.get("/scans", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db)) -> list[ScanSummary]:
    scans = db.scalars(
        select(Scan).options(selectinload(Scan.findings)).order_by(Scan.created_at.desc())
    ).all()
    return [to_summary(scan) for scan in scans]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanDetail:
    return to_detail(_load(db, scan_id))


@router.get("/scans/{scan_id}/report")
def get_report(scan_id: str, format: str = "json", db: Session = Depends(get_db)):
    scan = _load(db, scan_id)
    findings = list(scan.findings)
    if format == "markdown":
        body = render_markdown(scan, findings)
        return Response(content=body, media_type="text/markdown; charset=utf-8")
    if format != "json":
        raise HTTPException(status_code=400, detail="Supported formats: json or markdown.")
    return build_json_report(scan, findings)
