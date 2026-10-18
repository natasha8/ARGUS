"""Argus command line."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
import yaml

from app.db.session import SessionLocal, ensure_schema
from app.disclaimer import DISCLAIMER
from app.engine.report import render_markdown
from app.engine.runner import execute_scan
from app.engine.safeguards import ScopeError
from app.models import Scan
from app.schemas.scan import AuthProfileIn, ManualEndpointIn, ScanCreate
from app.services.scans import create_scan

cli = typer.Typer(help="Argus, a security scanner for authorized REST APIs.")


def _init_db() -> None:
    ensure_schema()


def _load_structured(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


@cli.command("scan")
def scan_command(
    target: str = typer.Option(..., help="Base URL of the authorized API."),
    name: str = typer.Option("cli-scan", help="Scan name."),
    spec: Optional[Path] = typer.Option(None, help="OpenAPI/Swagger JSON or YAML file."),
    openapi_url: Optional[str] = typer.Option(None, help="Specification URL, if you do not pass a file."),
    manual: Optional[Path] = typer.Option(None, help="JSON file with manual endpoints."),
    profiles: Optional[Path] = typer.Option(None, help="JSON file with authentication profiles."),
    checks: str = typer.Option(
        "bola,auth_jwt,data_exposure,resource_limits,bfla,ssrf,misconfig,inventory,unsafe_consumption,injection"
    ),
    collaborator: Optional[str] = typer.Option(None, help="Base URL of the lab callback."),
    rate_limit: float = typer.Option(5),
    concurrency: int = typer.Option(4),
    confirm_scope: bool = typer.Option(False, "--confirm-scope", help="Confirm you are authorized to test the target."),
    output: Optional[Path] = typer.Option(None, help="Write the Markdown report to a file."),
) -> None:
    """Run a scan and print the Markdown report."""
    typer.echo(DISCLAIMER)
    _init_db()
    profile_models = []
    if profiles:
        profile_models = [AuthProfileIn(**item) for item in _load_structured(profiles)]
    manual_models = []
    spec_document = None
    mode = "openapi"
    if manual:
        mode = "manual"
        manual_models = [ManualEndpointIn(**item) for item in _load_structured(manual)]
    elif spec:
        spec_document = _load_structured(spec)
    payload = ScanCreate(
        name=name,
        target_base_url=target,
        scope_confirmed=confirm_scope,
        discovery_mode=mode,
        spec_document=spec_document,
        openapi_url=openapi_url,
        manual_endpoints=manual_models,
        profiles=profile_models,
        checks=[item.strip() for item in checks.split(",") if item.strip()],
        concurrency=concurrency,
        rate_limit_rps=rate_limit,
        collaborator_base_url=collaborator,
    )
    db = SessionLocal()
    try:
        try:
            created = create_scan(db, payload)
        except (ScopeError, ValueError) as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc
        scan_id = created.id
    finally:
        db.close()
    asyncio.run(_execute(scan_id))
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise typer.Exit(code=1)
        text = render_markdown(scan, list(scan.findings))
        status = scan.status
    finally:
        db.close()
    if output:
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Report written to {output}")
    typer.echo(text)
    if status == "failed":
        raise typer.Exit(code=1)


async def _execute(scan_id: str) -> None:
    db = SessionLocal()
    try:
        await execute_scan(db, scan_id)
    finally:
        db.close()


@cli.command("list")
def list_command() -> None:
    """List saved scans."""
    _init_db()
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
        if not scans:
            typer.echo("No scans.")
            return
        for scan in scans:
            typer.echo(f"{scan.id}  {scan.status:<10}  {scan.target_base_url}  {scan.name}")
    finally:
        db.close()


@cli.command("report")
def report_command(
    scan_id: str = typer.Argument(...),
    format: str = typer.Option("markdown"),
    output: Optional[Path] = typer.Option(None),
) -> None:
    """Print the report for an existing scan."""
    _init_db()
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            typer.secho("Scan not found.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if format == "json":
            from app.engine.report import build_json_report

            text = json.dumps(build_json_report(scan, list(scan.findings)), indent=2, ensure_ascii=False)
        elif format == "markdown":
            text = render_markdown(scan, list(scan.findings))
        else:
            typer.secho("Supported formats: json or markdown.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
    finally:
        db.close()
    if output:
        output.write_text(text, encoding="utf-8")
    typer.echo(text)


if __name__ == "__main__":
    cli()
