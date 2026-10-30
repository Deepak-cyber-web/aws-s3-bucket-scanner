from __future__ import annotations

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Verify whether S3 Block Public Access is configured to block public access."""
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
        disabled = [
            name for name, enabled in config.items() if enabled is False
        ]
        if disabled:
            return {
                "finding_id": "S3-001",
                "status": "FAIL",
                "severity": "HIGH",
                "title": "Block Public Access is not fully enforced",
                "description": "One or more Block Public Access protections are disabled for the bucket.",
                "evidence": {"disabled_settings": disabled, "config": config},
                "recommendation": "Enable all Block Public Access settings for the bucket.",
                "remediation_available": True,
                "remediation_action": "Enable Block Public Access",
                "aws_api": "s3.get_public_access_block() / s3.put_public_access_block()",
            }
        return {
            "finding_id": "S3-001",
            "status": "PASS",
            "severity": "HIGH",
            "title": "Block Public Access is enabled",
            "description": "All block public access settings are enabled.",
            "evidence": {"config": config},
            "recommendation": "Continue to review bucket policies and ACLs periodically.",
            "remediation_available": True,
            "remediation_action": "Keep Block Public Access enabled",
            "aws_api": "s3.get_public_access_block()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return {
            "finding_id": "S3-001",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to verify public access configuration",
            "description": f"AWS returned an error while retrieving public access block settings: {code}.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Check IAM permissions and bucket availability before relying on this result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_public_access_block()",
        }
