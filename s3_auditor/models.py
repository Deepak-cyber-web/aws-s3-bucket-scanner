from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class BucketInfo:
    name: str
    creation_date: Optional[datetime] = None
    region: str = "unknown"


@dataclass
class Finding:
    finding_id: str
    bucket: str
    check_name: str
    status: str
    severity: str
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    remediation_available: bool = False
    remediation_action: str = ""
    aws_api: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds") + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "bucket": self.bucket,
            "check_name": self.check_name,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "remediation_available": self.remediation_available,
            "remediation_action": self.remediation_action,
            "aws_api": self.aws_api,
            "timestamp": self.timestamp,
        }
