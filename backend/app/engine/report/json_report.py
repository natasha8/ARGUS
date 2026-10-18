"""JSON report."""

from app.disclaimer import DISCLAIMER
from app.models import Finding, Scan

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build_json_report(scan: Scan, findings: list[Finding]) -> dict:
    counts = {name: 0 for name in SEVERITY_ORDER}
    confirmed = 0
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        if finding.status == "confirmed":
            confirmed += 1
    return {
        "scanner": "argus",
        "disclaimer": DISCLAIMER,
        "scan": {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target_base_url,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "error_message": scan.error_message,
        },
        "summary": {
            "endpoints": len(scan.endpoints),
            "findings": len(findings),
            "confirmed": confirmed,
            "potential": len(findings) - confirmed,
            "by_severity": counts,
        },
        "findings": [
            {
                "id": finding.id,
                "category": finding.category,
                "severity": finding.severity,
                "status": finding.status,
                "title": finding.title,
                "description": finding.description,
                "owasp_id": finding.owasp_id,
                "endpoint": finding.endpoint_label,
                "remediation": finding.remediation,
                "evidence": finding.evidence,
            }
            for finding in findings
        ],
    }
