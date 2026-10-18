"""Markdown report."""

from app.engine.report.json_report import build_json_report
from app.models import Finding, Scan


def render_markdown(scan: Scan, findings: list[Finding]) -> str:
    report = build_json_report(scan, findings)
    summary = report["summary"]
    lines = [
        f"# Argus report — {report['scan']['name']}",
        "",
        report["disclaimer"],
        "",
        f"- Target: `{report['scan']['target']}`",
        f"- Status: {report['scan']['status']}",
        f"- Endpoints: {summary['endpoints']}",
        f"- Findings: {summary['findings']} ({summary['confirmed']} confirmed, {summary['potential']} potential)",
        "",
        "## Severity summary",
        "",
    ]
    for name, count in summary["by_severity"].items():
        lines.append(f"- {name}: {count}")
    lines.append("")
    lines.append("## Finding")
    lines.append("")
    if not report["findings"]:
        lines.append("No findings. An empty result does not prove the API is secure.")
        lines.append("")
    for finding in report["findings"]:
        lines.append(f"### [{finding['severity'].upper()}] [{finding['status']}] {finding['title']}")
        lines.append("")
        lines.append(f"- Category: `{finding['category']}` · {finding['owasp_id']}")
        if finding["endpoint"]:
            lines.append(f"- Endpoint: `{finding['endpoint']}`")
        lines.append("")
        lines.append(finding["description"])
        lines.append("")
        lines.append(f"Remediation: {finding['remediation']}")
        lines.append("")
        notes = (finding.get("evidence") or {}).get("notes")
        if notes:
            lines.append(f"Note: {notes}")
            lines.append("")
        for request in (finding.get("evidence") or {}).get("requests") or []:
            lines.append(
                f"- {request.get('label')}: {request.get('method')} {request.get('url')} → {request.get('status')}"
            )
        affected = (finding.get("evidence") or {}).get("affected_endpoints") or []
        if affected:
            lines.append("")
            lines.append("Affected endpoints:")
            for item in affected:
                lines.append(f"- `{item}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
