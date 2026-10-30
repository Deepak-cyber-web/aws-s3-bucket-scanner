# Walkthrough

This document describes the internal flow of the S3 Security Auditor from AWS configuration to a usable security finding.

## Flow overview

CLI
  ↓
main.py
  ↓
cli.py
  ↓
AWS Session
  ↓
STS GetCallerIdentity
  ↓
S3 Discovery
  ↓
Scanner
  ↓
Individual Checks
  ↓
Finding Model
  ↓
Severity Engine
  ↓
Remediation
  ↓
Verification
  ↓
Report Generator

## AWS configuration and boto3 credential chain

The auditor intentionally uses the standard AWS SDK credential chain instead of reading static environment variables from source code.

This means boto3 uses the configuration discovered by the AWS CLI and associated credentials providers.

The relevant Python function is:

- `get_aws_session()` in `s3_auditor/aws_session.py`

### Example

```python
session = boto3.Session(region_name=region)
```

### AWS CLI equivalent

```bash
aws sts get-caller-identity
```

### Why this matters

This lets the student learn the normal AWS flow:

AWS CLI configuration
  ↓
AWS credentials provider chain
  ↓
boto3.Session()
  ↓
AWS STS / AWS S3 API calls

## STS identity verification

The scanner calls `sts.get_caller_identity()` to confirm the active AWS identity before scanning bucket settings.

Relevant function:

- `get_caller_identity()` in `s3_auditor/aws_session.py`

Example:

```python
sts_client = session.client("sts")
response = sts_client.get_caller_identity()
```

This is the AWS API call:

- `GetCallerIdentity`

IAM permission:

- `sts:GetCallerIdentity`

Return value example:

```json
{
  "UserId": "AIDAXXXXX",
  "Account": "123456789012",
  "Arn": "arn:aws:iam::123456789012:user/s3-auditor"
}
```

This becomes the identity shown in the CLI and report.

## Bucket discovery

The scanner enumerates buckets with `s3.list_buckets()`.

Relevant function:

- `list_buckets()` in `s3_auditor/scanner.py`

Example:

```python
s3_client = session.client("s3")
response = s3_client.list_buckets()
```

AWS API:

- `ListBuckets`

IAM permission:

- `s3:ListAllMyBuckets`

The function collects:

- bucket name
- creation date
- bucket region when available

## Check: S3-001 Block Public Access

Function:

- `s3_auditor/checks/public_access.py::check_bucket`

AWS API:

- `GetPublicAccessBlock`

boto3 method:

```python
s3_client.get_public_access_block(Bucket=bucket_name)
```

IAM permission:

- `s3:GetPublicAccessBlock`

Purpose:

The API returns the bucket's current `PublicAccessBlockConfiguration` with the following fields:

- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

If any are false, the scanner records a `FAIL` result for `S3-001`.

The logic is simple and intentionally educational:

```python
if any(setting is False for setting in config.values()):
    status = "FAIL"
```

## Check: S3-002 Bucket Policy Public Access

Function:

- `s3_auditor/checks/bucket_policy.py::check_bucket`

AWS API:

- `GetBucketPolicy`

boto3 method:

```python
s3_client.get_bucket_policy(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketPolicy`

Purpose:

The function retrieves the policy document, parses JSON, and checks whether a statement grants public access via wildcards or public principals.

It does not blindly search for `*`; instead it parses the policy into statements and inspects the relevant fields.

## Check: S3-003 Bucket ACL

Function:

- `s3_auditor/checks/acl.py::check_bucket`

AWS API:

- `GetBucketAcl`

boto3 method:

```python
s3_client.get_bucket_acl(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketAcl`

Purpose:

The script reviews the `Grants` list and flags public ACL groups such as:

- `AllUsers`
- `AuthenticatedUsers`

## Check: S3-004 Default Encryption

Function:

- `s3_auditor/checks/encryption.py::check_bucket`

AWS API:

- `GetBucketEncryption`

boto3 method:

```python
s3_client.get_bucket_encryption(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketEncryption`

Purpose:

This checks whether a default encryption rule exists. If no rule is configured, the scanner marks the bucket as `FAIL`.

The scanner explains that default encryption may be:

- SSE-S3
- SSE-KMS

## Check: S3-005 Versioning

Function:

- `s3_auditor/checks/versioning.py::check_bucket`

AWS API:

- `GetBucketVersioning`

boto3 method:

```python
s3_client.get_bucket_versioning(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketVersioning`

Purpose:

The scanner checks the `Status` field. If it is not `Enabled`, it raises a `FAIL` condition.

Versioning helps recover from inadvertent deletes or overwrites but does not guarantee complete protection from all attacks.

## Check: S3-006 Server Access Logging

Function:

- `s3_auditor/checks/logging.py::check_bucket`

AWS API:

- `GetBucketLogging`

boto3 method:

```python
s3_client.get_bucket_logging(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketLogging`

Purpose:

The bucket is evaluated for `LoggingEnabled`. If not present, the scanner marks it as `FAIL`.

It is important to distinguish this from CloudTrail data events or CloudWatch logging.

## Check: S3-007 Object Ownership

Function:

- `s3_auditor/checks/ownership.py::check_bucket`

AWS API:

- `GetBucketOwnershipControls`

boto3 method:

```python
s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketOwnershipControls`

Purpose:

The scanner looks for `BucketOwnerEnforced` and prefers that configuration because it reduces ACL-based public access risk.

## Check: S3-008 Secure Transport

Function:

- `s3_auditor/checks/secure_transport.py::check_bucket`

AWS API:

- `GetBucketPolicy`

boto3 method:

```python
s3_client.get_bucket_policy(Bucket=bucket_name)
```

IAM permission:

- `s3:GetBucketPolicy`

Purpose:

The scanner examines the policy for a `Deny` block requiring `aws:SecureTransport` to be false or equivalent. If the policy lacks this, the bucket receives a `FAIL` result for secure transport.

## Finding model

The core object is the `Finding` dataclass in `s3_auditor/models.py`.

It includes fields such as:

- `finding_id`
- `bucket`
- `check_name`
- `status`
- `severity`
- `title`
- `description`
- `evidence`
- `recommendation`
- `aws_api`

## Severity engine

The scanner uses a centralized severity mapping in `s3_auditor/severity.py`.

The score is a heuristic for learning rather than an official AWS compliance metric.

## Reporting and output

The scanner writes JSON output using the `json_output()` helper and can produce a text summary via the CLI.

The HTML report is rendered with Jinja2 and includes:

- account and identity metadata
- scan time and tool version
- executive summary
- severity summary
- per-bucket results
- per-finding details

This is important because real security reviews need evidence and a readable summary, not just raw API payloads.

## Lab validation workflow

A strong student workflow for the AWS lab is:

1. Configure AWS CLI credentials with a dedicated auditing identity.
2. Run `aws sts get-caller-identity` to verify the correct account.
3. Run `python main.py verify` to confirm the scanner sees the same identity.
4. Run `python main.py scan --bucket <lab-bucket>` to inspect one bucket.
5. Observe the findings and their evidence.
6. Compare the result to the AWS CLI output for the same bucket.
7. Use dry-run remediation to inspect the proposed change without editing AWS resources.
8. Re-run the scan to confirm the result after any explicit remediation.

This creates a repeatable learning loop:

AWS configuration
  ↓
AWS CLI
  ↓
AWS API
  ↓
boto3 call
  ↓
Python function
  ↓
Finding
  ↓
Evidence and recommendation

## Integration tests and lab notes

The project keeps unit tests separate from lab tests.

Unit tests validate the logic of a check in isolation, using mocked or synthetic objects. They must not require AWS credentials.

Integration tests validate the real environment. They are expected to:

- check that the AWS credentials are present
- verify `sts:GetCallerIdentity`
- list buckets through the AWS API
- inspect a known lab bucket

These tests should be run only with a dedicated auditor identity and a clearly labeled lab bucket.

If the auditor identity lacks permissions, the tests should fail gracefully with a clear explanation, not a crash. This is an important learning concept because `AccessDenied` is a valid security and permission state.

## Function-to-AWS-API mapping

| Python function | boto3 method | AWS API | IAM permission | Purpose |
| --- | --- | --- | --- | --- |
| `get_caller_identity()` | `sts_client.get_caller_identity()` | `GetCallerIdentity` | `sts:GetCallerIdentity` | Identify the active AWS identity |
| `list_buckets()` | `s3_client.list_buckets()` | `ListBuckets` | `s3:ListAllMyBuckets` | Discover buckets |
| `check_bucket()` | `s3_client.get_public_access_block()` | `GetPublicAccessBlock` | `s3:GetPublicAccessBlock` | Review public access protections |
| `check_bucket()` | `s3_client.get_bucket_policy()` | `GetBucketPolicy` | `s3:GetBucketPolicy` | Review policy public access |
| `check_bucket()` | `s3_client.get_bucket_acl()` | `GetBucketAcl` | `s3:GetBucketAcl` | Review ACL-based access |
| `check_bucket()` | `s3_client.get_bucket_encryption()` | `GetBucketEncryption` | `s3:GetBucketEncryption` | Review default encryption |
| `check_bucket()` | `s3_client.get_bucket_versioning()` | `GetBucketVersioning` | `s3:GetBucketVersioning` | Review versioning state |
| `check_bucket()` | `s3_client.get_bucket_logging()` | `GetBucketLogging` | `s3:GetBucketLogging` | Review access logging |
| `check_bucket()` | `s3_client.get_bucket_ownership_controls()` | `GetBucketOwnershipControls` | `s3:GetBucketOwnershipControls` | Review ownership controls |
| `check_bucket()` | `s3_client.get_bucket_policy()` | `GetBucketPolicy` | `s3:GetBucketPolicy` | Review secure transport policy |

## Important learning note

This project is designed to show the full chain from AWS config to scanning logic. The code is intentionally readable so a student can inspect the path from the API call to the final finding.
