from __future__ import annotations

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Verify that default server-side encryption is enabled for the bucket."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            return {
                "finding_id": "S3-004",
                "status": "PASS",
                "severity": "MEDIUM",
                "title": "Default encryption is enabled",
                "description": "The bucket has a default encryption rule configured.",
                "evidence": {"rules": rules},
                "recommendation": "Continue to review whether SSE-S3 or SSE-KMS fits the security requirement.",
                "remediation_available": True,
                "remediation_action": "Keep or adjust default encryption",
                "aws_api": "s3.get_bucket_encryption()",
            }
        return {
            "finding_id": "S3-004",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Default encryption is missing",
            "description": "No default encryption rule exists for the bucket.",
            "evidence": {"rules": []},
            "recommendation": "Configure default encryption with SSE-S3 or SSE-KMS to protect data at rest.",
            "remediation_available": True,
            "remediation_action": "Enable default encryption",
            "aws_api": "s3.get_bucket_encryption()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucketEncryption"}:
            return {
                "finding_id": "S3-004",
                "status": "FAIL",
                "severity": "MEDIUM",
                "title": "Default encryption is missing",
                "description": "The bucket does not currently have a default encryption configuration.",
                "evidence": {"error_code": code},
                "recommendation": "Add bucket default encryption using SSE-S3 or a KMS key to encrypt objects.",
                "remediation_available": True,
                "remediation_action": "Enable default encryption",
                "aws_api": "s3.get_bucket_encryption()",
            }
        return {
            "finding_id": "S3-004",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to review encryption settings",
            "description": "The scanner encountered an AWS error while checking encryption.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Check the bucket, region, and IAM permissions before relying on this result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_encryption()",
        }
    except Exception as exc:
        return {
            "finding_id": "S3-004",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Default encryption is missing",
            "description": "The bucket does not currently have a default encryption configuration.",
            "evidence": {"error_message": str(exc)},
            "recommendation": "Add bucket default encryption using SSE-S3 or a KMS key to encrypt objects.",
            "remediation_available": True,
            "remediation_action": "Enable default encryption",
            "aws_api": "s3.get_bucket_encryption()",
        }
