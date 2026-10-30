from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError


def _principal_is_public(principal: Any) -> bool:
    if principal is None:
        return False
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, list):
        return any(_principal_is_public(item) for item in principal)
    if isinstance(principal, dict):
        for key, value in principal.items():
            if key == "AWS" and value == "*":
                return True
            if isinstance(value, list) and any(item == "*" for item in value):
                return True
            if isinstance(value, str) and value.strip() == "*":
                return True
        return False
    return False


def check_bucket(s3_client, bucket_name: str):
    """Evaluate bucket policy statements for public access or insecure transport."""
    try:
        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = policy_response.get("Policy")
        if not policy_document:
            return {
                "finding_id": "S3-002",
                "status": "PASS",
                "severity": "HIGH",
                "title": "No bucket policy is attached",
                "description": "The bucket does not have a bucket policy.",
                "evidence": {"policy_present": False},
                "recommendation": "Maintain default least-privilege access and review any future bucket policy statements.",
                "remediation_available": False,
                "remediation_action": "",
                "aws_api": "s3.get_bucket_policy()",
            }
        try:
            policy = json.loads(policy_document)
        except json.JSONDecodeError as exc:
            return {
                "finding_id": "S3-002",
                "status": "ERROR",
                "severity": "MEDIUM",
                "title": "Bucket policy is not valid JSON",
                "description": "The bucket policy could not be parsed as valid JSON.",
                "evidence": {"parse_error": str(exc), "policy_preview": policy_document[:200]},
                "recommendation": "Correct the bucket policy before relying on the result.",
                "remediation_available": False,
                "remediation_action": "",
                "aws_api": "s3.get_bucket_policy()",
            }

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        public_statements = []
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            principal = statement.get("Principal")
            effect = statement.get("Effect")
            action = statement.get("Action")
            if effect == "Allow" and _principal_is_public(principal):
                public_statements.append({
                    "Action": action,
                    "Principal": principal,
                    "Resource": statement.get("Resource"),
                    "Condition": statement.get("Condition"),
                })

        if public_statements:
            return {
                "finding_id": "S3-002",
                "status": "FAIL",
                "severity": "CRITICAL",
                "title": "Bucket policy grants public access",
                "description": "At least one bucket policy statement allows public access to the bucket or objects.",
                "evidence": {"public_statements": public_statements},
                "recommendation": "Restrict the principal to trusted AWS principals and avoid wildcard public access.",
                "remediation_available": True,
                "remediation_action": "Remove public bucket policy statements",
                "aws_api": "s3.get_bucket_policy()",
            }

        return {
            "finding_id": "S3-002",
            "status": "PASS",
            "severity": "HIGH",
            "title": "Bucket policy does not grant public access",
            "description": "No policy statement grants broad public access to the bucket.",
            "evidence": {"statement_count": len(statements)},
            "recommendation": "Keep bucket policy statements scoped to trusted principals and least privilege.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_policy()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "NoSuchBucketPolicy")
        if code == "NoSuchBucketPolicy":
            return {
                "finding_id": "S3-002",
                "status": "PASS",
                "severity": "HIGH",
                "title": "No bucket policy is attached",
                "description": "The bucket does not currently have a bucket policy.",
                "evidence": {"error_code": code},
                "recommendation": "Continue to audit future bucket policy changes.",
                "remediation_available": False,
                "remediation_action": "",
                "aws_api": "s3.get_bucket_policy()",
            }
        return {
            "finding_id": "S3-002",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to review bucket policy",
            "description": "The scanner could not retrieve the bucket policy.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Check IAM permissions and bucket access before interpreting the bucket policy result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_policy()",
        }
