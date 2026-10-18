"""Create scans and map them to API schemas."""

from sqlalchemy.orm import Session

from app.config import settings
from app.engine.discovery import load_spec_text
from app.engine.safeguards import validate_scan_options
from app.models import Finding, Scan
from app.schemas.scan import EndpointRead, FindingRead, ScanCreate, ScanDetail, ScanSummary


def create_scan(db: Session, payload: ScanCreate) -> Scan:
    validate_scan_options(
        target_base_url=payload.target_base_url,
        scope_confirmed=payload.scope_confirmed,
        checks=payload.checks,
        concurrency=payload.concurrency,
        rate_limit_rps=payload.rate_limit_rps,
        openapi_url=payload.openapi_url,
    )
    spec_document = load_spec_text(payload.spec_text) if payload.spec_text else payload.spec_document
    if payload.discovery_mode == "openapi" and not spec_document and not payload.openapi_url:
        raise ValueError("OpenAPI discovery needs a document or a URL.")
    if payload.discovery_mode == "manual" and not payload.manual_endpoints:
        raise ValueError("Manual discovery needs at least one endpoint.")
    scan = Scan(
        name=payload.name.strip(),
        target_base_url=payload.target_base_url.rstrip("/"),
        discovery_mode=payload.discovery_mode,
        spec_document=spec_document,
        manual_endpoints=[item.model_dump() for item in payload.manual_endpoints],
        auth_profiles=[item.to_storage() for item in payload.profiles],
        scope_confirmed=payload.scope_confirmed,
        status="pending",
        config={
            "checks": payload.checks,
            "concurrency": payload.concurrency,
            "rate_limit_rps": payload.rate_limit_rps,
            "collaborator_base_url": payload.collaborator_base_url or settings.collaborator_base_url,
            "openapi_url": None if spec_document else payload.openapi_url,
            "id_probes": payload.id_probes,
            "warnings": [],
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _counts(findings: list[Finding]) -> tuple[int, int]:
    return len(findings), sum(1 for finding in findings if finding.status == "confirmed")


def to_summary(scan: Scan) -> ScanSummary:
    total, confirmed = _counts(list(scan.findings))
    return ScanSummary(
        id=scan.id,
        name=scan.name,
        target_base_url=scan.target_base_url,
        discovery_mode=scan.discovery_mode,
        status=scan.status,
        error_message=scan.error_message,
        scope_confirmed=scan.scope_confirmed,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        findings_count=total,
        confirmed_count=confirmed,
    )


def to_detail(scan: Scan) -> ScanDetail:
    summary = to_summary(scan)
    warnings = list((scan.config or {}).get("warnings") or [])
    findings = sorted(scan.findings, key=lambda item: item.created_at)
    return ScanDetail(
        **summary.model_dump(),
        findings=[FindingRead.model_validate(item) for item in findings],
        endpoints=[EndpointRead.model_validate(item) for item in scan.endpoints],
        warnings=warnings,
    )
