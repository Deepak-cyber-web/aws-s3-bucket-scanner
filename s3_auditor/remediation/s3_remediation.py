from __future__ import annotations

from typing import Any, Dict


REMEDIATION_BY_FINDING = {
    "S3-001": {
        "title": "Enable Block Public Access",
        "api": "s3.put_public_access_block()",
        "description": "Set all Block Public Access settings to true.",
    },
    "S3-004": {
        "title": "Enable default encryption",
        "api": "s3.put_bucket_encryption()",
        "description": "Add a default encryption configuration such as AES256 or SSE-KMS.",
    },
    "S3-005": {
        "title": "Enable versioning",
        "api": "s3.put_bucket_versioning()",
        "description": "Turn on bucket versioning to preserve previous object versions.",
    },
    "S3-006": {
        "title": "Enable server access logging",
        "api": "s3.put_bucket_logging()",
        "description": "Configure server access logging to a dedicated logging bucket.",
    },
    "S3-007": {
        "title": "Set BucketOwnerEnforced ownership controls",
        "api": "s3.put_bucket_ownership_controls()",
        "description": "Use BucketOwnerEnforced to remove reliance on ACL-based public access.",
    },
    "S3-008": {
        "title": "Add secure transport policy condition",
        "api": "s3.put_bucket_policy()",
        "description": "Add a Deny statement for aws:SecureTransport == false.",
    },
}


def plan_remediation(finding_id: str, bucket_name: str, current_state: Any, dry_run: bool = False) -> Dict[str, Any]:
    config = REMEDIATION_BY_FINDING.get(finding_id, {})
    return {
        "finding_id": finding_id,
        "bucket": bucket_name,
        "current_state": current_state,
        "proposed_change": config.get("description", "No action defined"),
        "api": config.get("api", "N/A"),
        "dry_run": dry_run,
    }
