from __future__ import annotations

import json

from botocore.exceptions import ClientError


def check_bucket(s3_client, bucket_name: str):
    """Ensure the bucket policy enforces HTTPS for secure transport."""
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = response.get("Policy")
        if not policy_document:
            return {
                "finding_id": "S3-008",
                "status": "FAIL",
                "severity": "MEDIUM",
                "title": "Bucket policy does not enforce HTTPS",
                "description": "There is no bucket policy that denies or restricts insecure HTTP transport.",
                "evidence": {"policy_present": False},
                "recommendation": "Add a Deny statement with aws:SecureTransport == false to enforce HTTPS only.",
                "remediation_available": True,
                "remediation_action": "Add secure transport policy condition",
                "aws_api": "s3.get_bucket_policy()",
            }

        policy = json.loads(policy_document)
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue
            condition = statement.get("Condition", {})
            if statement.get("Effect") == "Deny":
                if condition.get("Bool", {}).get("aws:SecureTransport") is False:
                    return {
                        "finding_id": "S3-008",
                        "status": "PASS",
                        "severity": "MEDIUM",
                        "title": "Secure transport is enforced",
                        "description": "The bucket policy explicitly denies non-HTTPS requests using aws:SecureTransport.",
                        "evidence": {"statement": statement},
                        "recommendation": "Keep the secure transport restriction in place and review policy changes periodically.",
                        "remediation_available": False,
                        "remediation_action": "",
                        "aws_api": "s3.get_bucket_policy()",
                    }
        return {
            "finding_id": "S3-008",
            "status": "FAIL",
            "severity": "MEDIUM",
            "title": "Bucket policy does not enforce HTTPS",
            "description": "The bucket policy lacks a Deny statement to require aws:SecureTransport=true or false for HTTP.",
            "evidence": {"statement_count": len(statements)},
            "recommendation": "Add a Deny policy for aws:SecureTransport == false to enforce HTTPS.",
            "remediation_available": True,
            "remediation_action": "Add secure transport policy condition",
            "aws_api": "s3.get_bucket_policy()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "NoSuchBucketPolicy")
        if code == "NoSuchBucketPolicy":
            return {
                "finding_id": "S3-008",
                "status": "FAIL",
                "severity": "MEDIUM",
                "title": "Bucket policy does not enforce HTTPS",
                "description": "No bucket policy exists, so there is no HTTPS enforcement.",
                "evidence": {"error_code": code},
                "recommendation": "Add a bucket policy with a Deny statement for aws:SecureTransport == false.",
                "remediation_available": True,
                "remediation_action": "Add secure transport policy condition",
                "aws_api": "s3.get_bucket_policy()",
            }
        return {
            "finding_id": "S3-008",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to review secure transport policy",
            "description": "The scanner could not inspect the bucket policy for secure transport rules.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Check IAM permissions and policy validity before relying on the secure transport result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_policy()",
        }
