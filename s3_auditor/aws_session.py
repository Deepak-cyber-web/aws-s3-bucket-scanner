from __future__ import annotations

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError


def get_aws_session(region_name: str | None = None):
    """Create a boto3 session using the AWS CLI credential chain."""
    return boto3.Session(region_name=region_name)


def get_caller_identity(session=None):
    """Return the caller identity from STS and avoid exposing secret credentials."""
    aws_session = session or get_aws_session()
    sts_client = aws_session.client("sts", region_name=aws_session.region_name)
    response = sts_client.get_caller_identity()
    return response


def get_default_region(session=None):
    aws_session = session or get_aws_session()
    return aws_session.region_name or "us-east-1"


def safe_get_bucket_region(s3_client, bucket_name: str) -> str:
    """Return the region of a bucket when available, falling back to the client region."""
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = response.get("LocationConstraint")
        return "us-east-1" if loc in (None, "EU") else loc
    except (ClientError, EndpointConnectionError):
        return "unknown"
