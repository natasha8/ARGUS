"""Load endpoints, run checks, persist findings."""

import logging
from datetime import datetime, timezone

import httpx
import yaml
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.config import settings
from app.engine.auth.profiles import resolve_profiles
from app.engine.checks import build_checks
from app.engine.discovery import parse_manual, parse_spec
from app.engine.http import ProbeClient
from app.engine.safeguards import assert_url_allowed
from app.engine.types import EndpointSpec, FindingDraft, Profile, ScanContext
from app.models import Endpoint, Finding, Scan

logger = logging.getLogger("argus.engine")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_RANK = {"confirmed": 2, "potential": 1}


def dedup(findings: list[FindingDraft]) -> list[FindingDraft]:
    best: dict[tuple, FindingDraft] = {}
    for finding in findings:
        key = (finding.category, finding.title, finding.endpoint_key)
        previous = best.get(key)
        if previous is None or STATUS_RANK.get(finding.status, 0) > STATUS_RANK.get(previous.status, 0):
            best[key] = finding
    return sorted(best.values(), key=lambda item: SEVERITY_ORDER.get(item.severity, 9))


async def _load_spec(scan: Scan) -> dict:
    if isinstance(scan.spec_document, dict) and scan.spec_document.get("paths"):
        return scan.spec_document
    url = (scan.config or {}).get("openapi_url")
    if not url:
        raise RuntimeError("Missing OpenAPI document or specification URL.")
    assert_url_allowed(url)
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        response = await client.get(url)
    if response.status_code >= 400:
        raise RuntimeError(f"Could not download the specification (HTTP {response.status_code}).")
    if "yaml" in response.headers.get("content-type", "") or url.endswith((".yaml", ".yml")):
        document = yaml.safe_load(response.text)
    else:
        document = response.json()
    if not isinstance(document, dict):
        raise RuntimeError("The specification is not a JSON or YAML object.")
    scan.spec_document = document
    flag_modified(scan, "spec_document")
    return document


def _endpoints_for(scan: Scan, document: dict | None) -> list[EndpointSpec]:
    if scan.discovery_mode == "manual":
        return parse_manual(scan.manual_endpoints or [])
    if document is None:
        raise RuntimeError("Specification is missing.")
    return parse_spec(document)


async def execute_scan(db: Session, scan_id: str) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.error_message = None
    db.commit()
    client: ProbeClient | None = None
    try:
        assert_url_allowed(scan.target_base_url)
        document = None
        if scan.discovery_mode == "openapi":
            document = await _load_spec(scan)
            db.commit()
        endpoints = _endpoints_for(scan, document)
        if not endpoints:
            raise RuntimeError("No endpoints to scan.")
        db.query(Finding).filter(Finding.scan_id == scan.id).delete(synchronize_session=False)
        db.query(Endpoint).filter(Endpoint.scan_id == scan.id).delete(synchronize_session=False)
        for spec in endpoints:
            db.add(
                Endpoint(
                    scan_id=scan.id,
                    method=spec.method,
                    path=spec.path,
                    parameters=spec.parameters,
                    request_body=spec.request_body,
                    tags=spec.tags,
                    auth_required=spec.auth_required,
                    security=spec.security,
                )
            )
        db.commit()
        config = dict(scan.config or {})
        client = ProbeClient(
            scan.target_base_url,
            rate_limit_rps=float(config.get("rate_limit_rps") or 5),
            concurrency=int(config.get("concurrency") or 4),
        )
        resolved, warnings = await resolve_profiles(
            client, [Profile.from_dict(item) for item in (scan.auth_profiles or [])]
        )
        config["warnings"] = warnings
        scan.config = config
        flag_modified(scan, "config")
        db.commit()
        ctx = ScanContext(
            scan_id=scan.id,
            base_url=scan.target_base_url,
            endpoints=endpoints,
            profiles=resolved,
            client=client,
            collaborator_base_url=str(config.get("collaborator_base_url") or settings.collaborator_base_url),
            id_probes=[int(item) for item in (config.get("id_probes") or [1, 2])],
        )
        drafts: list[FindingDraft] = []
        for check in build_checks(list(config.get("checks") or [])):
            try:
                drafts.extend(await check.run(ctx))
            except Exception:
                logger.exception("Check %s failed", check.name)
                warnings.append(f"Check {check.name} hit an internal error.")
        drafts = dedup(drafts)
        stored_endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan.id).all()
        labels = {f"{item.method} {item.path}": item.id for item in stored_endpoints}
        for draft in drafts:
            db.add(
                Finding(
                    scan_id=scan.id,
                    endpoint_id=labels.get(draft.endpoint_key or ""),
                    endpoint_label=draft.endpoint_key,
                    category=draft.category,
                    severity=draft.severity,
                    status=draft.status,
                    title=draft.title,
                    description=draft.description,
                    owasp_id=draft.owasp_id,
                    remediation=draft.remediation,
                    evidence=draft.evidence,
                )
            )
        config["warnings"] = warnings
        scan.config = config
        flag_modified(scan, "config")
        scan.status = "completed"
    except Exception as exc:
        logger.exception("Scan failed")
        scan.status = "failed"
        scan.error_message = str(exc)
    finally:
        if client is not None:
            await client.aclose()
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
