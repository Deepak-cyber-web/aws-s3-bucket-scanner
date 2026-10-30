from __future__ import annotations

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Check whether S3 server access logging is configured for the bucket."""
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        target = response.get("LoggingEnabled")
        if target:
            return {
                "finding_id": "S3-006",
                "status": "PASS",
                "severity": "LOW",
                "title": "Server access logging is enabled",
                "description": "The bucket has server access logging configured.",
                "evidence": {"logging_enabled": target},
                "recommendation": "Keep server access logging enabled and review logs for suspicious access patterns.",
                "remediation_available": False,
                "remediation_action": "",
                "aws_api": "s3.get_bucket_logging()",
            }
        return {
            "finding_id": "S3-006",
            "status": "FAIL",
            "severity": "LOW",
            "title": "Server access logging is not enabled",
            "description": "The bucket does not have S3 server access logging configured.",
            "evidence": {"logging_enabled": False},
            "recommendation": "Configure server access logging to a dedicated logging bucket to record access events.",
            "remediation_available": True,
            "remediation_action": "Enable server access logging",
            "aws_api": "s3.put_bucket_logging()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return {
            "finding_id": "S3-006",
            "status": "ERROR",
            "severity": "LOW",
            "title": "Unable to review access logging configuration",
            "description": "The scanner encountered an AWS error while checking server access logging.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Verify IAM permissions and the bucket's logging configuration before relying on this result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_logging()",
        }
