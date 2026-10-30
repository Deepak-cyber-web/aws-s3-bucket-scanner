from __future__ import annotations

from botocore.exceptions import ClientError

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def check_bucket(s3_client, bucket_name: str):
    """Check ACL grants to public groups, including AllUsers and AuthenticatedUsers."""
    try:
        response = s3_client.get_bucket_acl(Bucket=bucket_name)
        grants = response.get("Grants", [])
        public_grants = []
        for grant in grants:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")
            if uri in PUBLIC_GROUP_URIS:
                public_grants.append({
                    "URI": uri,
                    "Permission": grant.get("Permission"),
                    "DisplayName": grantee.get("DisplayName"),
                })
        if public_grants:
            return {
                "finding_id": "S3-003",
                "status": "FAIL",
                "severity": "HIGH",
                "title": "Bucket ACL grants public access",
                "description": "The bucket ACL is granting access to public groups.",
                "evidence": {"public_grants": public_grants},
                "recommendation": "Remove public ACL grants and prefer bucket policies or object ownership controls instead.",
                "remediation_available": True,
                "remediation_action": "Remove public ACL grants",
                "aws_api": "s3.get_bucket_acl()",
            }
        return {
            "finding_id": "S3-003",
            "status": "PASS",
            "severity": "HIGH",
            "title": "Bucket ACL is not public",
            "description": "No public ACL grants were identified.",
            "evidence": {"grants_count": len(grants)},
            "recommendation": "Continue to monitor ACL changes and prefer Object Ownership enforcement.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_acl()",
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        return {
            "finding_id": "S3-003",
            "status": "ERROR",
            "severity": "MEDIUM",
            "title": "Unable to review bucket ACL",
            "description": "The scanner could not retrieve the bucket ACL from AWS.",
            "evidence": {"error_code": code, "error_message": str(exc)},
            "recommendation": "Verify IAM access and bucket existence before interpreting the ACL result.",
            "remediation_available": False,
            "remediation_action": "",
            "aws_api": "s3.get_bucket_acl()",
        }
