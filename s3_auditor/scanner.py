from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

from .aws_session import get_aws_session, safe_get_bucket_region
from .logger import configure_logger
from .models import BucketInfo, Finding

logger = configure_logger()


def list_buckets(session=None) -> List[BucketInfo]:
    aws_session = session or get_aws_session()
    s3_client = aws_session.client("s3")
    buckets: List[BucketInfo] = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            region = safe_get_bucket_region(s3_client, bucket_name)
            buckets.append(
                BucketInfo(
                    name=bucket_name,
                    creation_date=bucket.get("CreationDate"),
                    region=region,
                )
            )
    except (ClientError, EndpointConnectionError) as exc:
        logger.error("list_buckets failed: %s", exc)
    return buckets


def _finding_from_result(bucket: str, check_name: str, result: Dict[str, Any]) -> Finding:
    return Finding(
        finding_id=result["finding_id"],
        bucket=bucket,
        check_name=check_name,
        status=result["status"],
        severity=result["severity"],
        title=result["title"],
        description=result["description"],
        evidence=result.get("evidence", {}),
        recommendation=result.get("recommendation", ""),
        remediation_available=result.get("remediation_available", False),
        remediation_action=result.get("remediation_action", ""),
        aws_api=result.get("aws_api", ""),
    )


def scan_bucket(bucket_name: str, region_name: str | None = None) -> List[Finding]:
    session = get_aws_session(region_name=region_name)
    s3_client = session.client("s3", region_name=region_name)
    findings: List[Finding] = []
    for check_name in [
        "public_access",
        "bucket_policy",
        "acl",
        "encryption",
        "versioning",
        "logging",
        "ownership",
        "secure_transport",
    ]:
        try:
            module = __import__(f"s3_auditor.checks.{check_name}", fromlist=["check_bucket"])
            result = module.check_bucket(s3_client, bucket_name)
            findings.append(_finding_from_result(bucket_name, check_name, result))
        except Exception as exc:  # pragma: no cover - fallback guard
            logger.error("Check %s failed for %s: %s", check_name, bucket_name, exc)
            findings.append(
                Finding(
                    finding_id="GEN-ERROR",
                    bucket=bucket_name,
                    check_name=check_name,
                    status="ERROR",
                    severity="MEDIUM",
                    title="Check execution failure",
                    description="The security check raised an unexpected runtime error.",
                    evidence={"error": str(exc)},
                    recommendation="Investigate runtime issues in the scanner or AWS API responses.",
                    remediation_available=False,
                    remediation_action="",
                    aws_api="N/A",
                )
            )
    return findings


def build_scan_summary(findings: List[Finding]) -> Dict[str, Any]:
    summary = {
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for finding in findings:
        status = finding.status.upper()
        severity = finding.severity.upper()
        if status == "PASS":
            summary["passed"] += 1
        elif status == "FAIL":
            summary["failed"] += 1
        elif status == "ERROR":
            summary["errors"] += 1
        if severity.lower() in {"critical", "high", "medium", "low", "info"}:
            summary[severity.lower()] += 1
    return summary


def json_output(account_id: str, identity: str, buckets: List[BucketInfo], findings: List[Finding], scan_time: str | None = None) -> Dict[str, Any]:
    serialized_buckets = []
    for bucket in buckets:
        bucket_payload = {
            "name": bucket.name,
            "creation_date": bucket.creation_date.isoformat() if isinstance(bucket.creation_date, datetime) else bucket.creation_date,
            "region": bucket.region,
        }
        serialized_buckets.append(bucket_payload)

    return {
        "metadata": {
            "tool": "S3 Security Auditor",
            "version": "0.1.0",
            "scan_time": scan_time or datetime.utcnow().isoformat(timespec="seconds") + "Z",
        },
        "account": account_id,
        "identity": identity,
        "buckets": serialized_buckets,
        "findings": [finding.to_dict() for finding in findings],
        "summary": build_scan_summary(findings),
    }


def write_json_report(path: str, data: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
