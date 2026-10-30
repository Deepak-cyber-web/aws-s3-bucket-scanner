# AWS CLI Guide

This guide connects the AWS CLI, AWS API, boto3 functions, and Python scanner logic.

## Relationship overview

AWS CLI
  ↓
AWS API
  ↓
boto3
  ↓
Python function
  ↓
Finding

## Command: `aws sts get-caller-identity`

What it does:

Shows the active IAM identity, AWS account, and ARN.

AWS service:

- AWS Security Token Service (STS)

IAM permission:

- `sts:GetCallerIdentity`

boto3 equivalent:

```python
session.client("sts").get_caller_identity()
```

Scanner use:

The scanner verifies the caller before scanning buckets.

## Command: `aws s3api list-buckets`

What it does:

Lists all buckets in the account.

AWS service:

- Amazon S3

IAM permission:

- `s3:ListAllMyBuckets`

boto3 equivalent:

```python
session.client("s3").list_buckets()
```

## Command: `aws s3api get-bucket-location --bucket <bucket>`

What it does:

Returns the bucket's location/region.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketLocation`

boto3 equivalent:

```python
session.client("s3").get_bucket_location(Bucket=bucket)
```

## Command: `aws s3api get-public-access-block --bucket <bucket>`

What it does:

Shows the Block Public Access configuration.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetPublicAccessBlock`

boto3 equivalent:

```python
session.client("s3").get_public_access_block(Bucket=bucket)
```

## Command: `aws s3api get-bucket-policy --bucket <bucket>`

What it does:

Shows the JSON bucket policy assigned to the bucket.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketPolicy`

boto3 equivalent:

```python
session.client("s3").get_bucket_policy(Bucket=bucket)
```

## Command: `aws s3api get-bucket-acl --bucket <bucket>`

What it does:

Shows bucket ACL grants, including public groups.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketAcl`

boto3 equivalent:

```python
session.client("s3").get_bucket_acl(Bucket=bucket)
```

## Command: `aws s3api get-bucket-encryption --bucket <bucket>`

What it does:

Shows the default encryption rules for the bucket.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketEncryption`

boto3 equivalent:

```python
session.client("s3").get_bucket_encryption(Bucket=bucket)
```

## Command: `aws s3api get-bucket-versioning --bucket <bucket>`

What it does:

Shows whether versioning is enabled.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketVersioning`

boto3 equivalent:

```python
session.client("s3").get_bucket_versioning(Bucket=bucket)
```

## Command: `aws s3api get-bucket-logging --bucket <bucket>`

What it does:

Shows whether server access logging is configured.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketLogging`

boto3 equivalent:

```python
session.client("s3").get_bucket_logging(Bucket=bucket)
```

## Command: `aws s3api get-bucket-ownership-controls --bucket <bucket>`

What it does:

Shows bucket ownership controls.

AWS service:

- Amazon S3

IAM permission:

- `s3:GetBucketOwnershipControls`

boto3 equivalent:

```python
session.client("s3").get_bucket_ownership_controls(Bucket=bucket)
```

## Manual learning workflow

A student should practice the sequence:

1. Configure AWS CLI
2. Run `aws sts get-caller-identity`
3. Run `aws s3api list-buckets`
4. Pick a bucket and inspect it with the API calls above
5. Translate each CLI command into the matching boto3 method
6. Map the response fields to finding logic
7. Validate the result with the Python scanner

This is the learning model used in this project.
