from __future__ import annotations

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Check whether modern object ownership controls are being used to disable ACLs."""
    try:
        response = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
        rules = response.get("OwnershipControls", {}).get("Rules", [])
        for rule in rules:
            if rule.get("ObjectOwnership") == "BucketOwnerEnforced":
                return {
                    "finding_id": "S3-007",
                    "status": "PASS",
                    "severity": "MEDIUM",
                    "title": "BucketOwnerEnforced is active",
                    "description": "Object Ownership is set to BucketOwnerEnforced, which reduces ACL reliance and simplifies authorization.",
                    "evidence": {"rules": rules},
                    "recommendation": "Keep BucketOwnerEnforced to eliminate public ACLs and reduce misconfiguration risk.",
                    "remediation_available": True,
                    "remediation_action": "Set BucketOwnerEnforced ownership controls",
                    "aws_api": "s3.get_bucket_ownership_controls()",
                }
        return {
            "finding_id": "S3-007",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Bucket ownership controls are not enforced",
            "description": "The bucket does not explicitly enforce BucketOwnerEnforced ownership controls.",
            "evidence": {"rules": rules},
            "recommendation": "Configure Object Ownership to BucketOwnerEnforced to remove ACL-based public access risk.",
            "remediation_available": True,
            "remediation_action": "Set BucketOwnerEnforced ownership controls",
            "aws_api": "s3.put_bucket_ownership_controls()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code in {"OwnershipControlsNotFoundError", "NoSuchBucketOwnershipControls"}:
            return {
                "finding_id": "S3-007",
                "status": "FAIL",
                "severity": "MEDIUM",
                "title": "Ownership controls are not defined",
                "description": "No ownership controls are currently configured for the bucket.",
                "evidence": {"error_code": code},
                "recommendation": "Configure taking Object Ownership control to BucketOwnerEnforced for modern S3 access patterns.",
                "remediation_available": True,
                "remediation_action": "Set BucketOwnerEnforced ownership controls",
                "aws_api": "s3.get_bucket_ownership_controls()",
            }
        return {
            "finding_id": "S3-007",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to verify ownership controls",
            "description": "The scanner encountered a client-side or AWS-side issue while retrieving ownership controls.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Verify bucket region, permissions, and AWS API availability before relying on the result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_ownership_controls()",
        }
