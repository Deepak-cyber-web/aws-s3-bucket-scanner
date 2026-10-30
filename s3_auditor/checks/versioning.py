from __future__ import annotations

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Check whether versioning is enabled for the bucket so recoverability improves."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status")
        if status == "Enabled":
            return {
                "finding_id": "S3-005",
                "status": "PASS",
                "severity": "MEDIUM",
                "title": "Versioning is enabled",
                "description": "Bucket versioning is enabled and helps protect against accidental overwrite or deletion.",
                "evidence": {"status": status},
                "recommendation": "Keep versioning enabled and consider MFA Delete when required for critical data sets.",
                "remediation_available": True,
                "remediation_action": "Keep versioning enabled",
                "aws_api": "s3.get_bucket_versioning()",
            }
        return {
            "finding_id": "S3-005",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Versioning is disabled",
            "description": "The bucket does not currently have versioning enabled.",
            "evidence": {"status": status},
            "recommendation": "Enable versioning to preserve previous object versions and improve recovery options.",
            "remediation_available": True,
            "remediation_action": "Enable versioning",
            "aws_api": "s3.put_bucket_versioning()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return {
            "finding_id": "S3-005",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to verify versioning status",
            "description": "The scanner could not check bucket versioning due to an AWS error.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Verify IAM permissions and bucket configuration before interpreting the versioning result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_versioning()",
        }
