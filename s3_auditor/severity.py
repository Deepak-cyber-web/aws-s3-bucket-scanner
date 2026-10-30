from __future__ import annotations

from typing import Dict

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_to_score(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)


def calculate_security_score(findings: list[Dict]) -> int:
    deductions = {
        "CRITICAL": 30,
        "HIGH": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 1,
    }
    total = 100
    for finding in findings:
        if finding.get("status") != "FAIL":
            continue
        total -= deductions.get(finding.get("severity", "INFO").upper(), 0)
    return max(0, total)
