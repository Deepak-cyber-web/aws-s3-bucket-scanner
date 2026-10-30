# S3 Security Auditor

S3 Security Auditor is a Python-based, defensive AWS S3 security scanner built for a lab environment. It authenticates with the normal AWS CLI credential chain, verifies the caller identity, enumerates S3 buckets, inspects bucket security settings, and produces both human-readable and machine-readable output.

## Project overview

This project is designed to help students learn how AWS security controls map to boto3 API operations, IAM permissions, security findings, and remediation workflows.

The scanner is read-only by default and only performs modifications when remediation is explicitly requested.

## Architecture

The project is intentionally simple and educational:

- `main.py` starts the CLI.
- `s3_auditor/aws_session.py` handles AWS session creation and STS verification.
- `s3_auditor/scanner.py` discovers buckets and runs security checks.
- `s3_auditor/checks/` contains the individual S3 checks.
- `s3_auditor/models.py` defines the internal finding and bucket models.
- `s3_auditor/reporting/` contains JSON and HTML report generation.
- `s3_auditor/remediation/` will manage explicit remediation flows.

## Features

- AWS CLI credential chain support via boto3
- STS caller verification
- S3 bucket discovery
- Checks for public access, policies, ACLs, encryption, versioning, logging, ownership, and HTTPS transport
- Severity evaluation and security score
- JSON and HTML report generation
- Dry-run remediation support
- Test suite for unit and integration scenarios

## Requirements

- Python 3.10+
- AWS CLI configured with a valid identity
- boto3 and related dependencies

## Installation

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Then install dependencies:

```bash
pip install -r requirements.txt
```

## AWS CLI configuration

Configure AWS CLI separately before using the auditor:

```bash
aws configure
```

You can verify the active identity with:

```bash
aws sts get-caller-identity
```

This auditor uses the same AWS credential chain that boto3 uses. No secrets should be stored in source files.

## IAM permissions

Minimum read-only permissions for the scanner include:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyS3Audit",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketOwnershipControls",
        "s3:GetPublicAccessBlock",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Remediation permissions should be granted separately and only when explicitly needed.

## Usage

### Verify identity

```bash
python main.py verify
```

### Scan all buckets

```bash
python main.py scan
```

### Scan a single bucket

```bash
python main.py scan --bucket my-bucket
```

### Scan a region

```bash
python main.py scan --region ap-south-1
```

### Output JSON report

```bash
python main.py scan --format json --output output/report.json
```

### Dry-run remediation

```bash
python main.py remediate --finding S3-001 --dry-run
```

## Example output

```text
============================================================
             AWS S3 SECURITY AUDITOR
============================================================

Account : 123456789012
Identity: arn:aws:iam::123456789012:user/s3-auditor
Buckets discovered: 3

[private-bucket]
  S3-001 PASS Block Public Access
  S3-002 PASS Bucket Policy
  S3-003 PASS ACL
  S3-004 PASS Encryption
  S3-005 PASS Versioning
  S3-006 FAIL Logging
  S3-007 PASS Object Ownership
  S3-008 PASS Secure Transport

Scan Summary
Critical : 0
High     : 0
Medium   : 1
Low      : 0
Passed   : 7
Security Score: 90/100
```

## Testing

Run the unit test suite:

```bash
pytest -v
```

Run the integration tests only in the AWS lab environment:

```bash
pytest tests/integration -v
```

The integration tests are designed to validate:

- AWS identity verification
- bucket discovery
- API read access
- expected findings for a known lab bucket

These tests are skipped automatically when AWS credentials are not configured.

## AWS lab validation workflow

Use a dedicated lab bucket only. Never test these settings against a production environment.

### 1. Confirm AWS CLI identity

```bash
aws sts get-caller-identity
```

### 2. List buckets

```bash
aws s3api list-buckets
```

### 3. Run the auditor

```bash
python main.py verify
python main.py scan --bucket <lab-bucket-name>
```

### 4. Review the findings

The tool reports findings such as:

- Block Public Access failure
- missing versioning
- missing logging
- missing secure transport policy
- AccessDenied for checks the auditor is not allowed to perform

### 5. Check the generated report

```bash
python main.py scan --bucket <lab-bucket-name> --output output/report.html
```

Open the generated HTML file to review the results and evidence.

## Integration test notes

The project includes a separate integration test suite in `tests/integration/`.

These tests are intentionally different from unit tests:

- they use real boto3 calls
- they require AWS credentials
- they validate real lab behavior
- they must be run in a controlled, test-only S3 environment

Integration tests do not create or delete production resources automatically. They only verify the configured lab identity and read bucket metadata.

## Security considerations

- The scanner is intentionally read-only during normal scanning.
- Remediation requires explicit confirmation unless `--yes` is supplied.
- Credentials are never written to source code or logs.
- Sensitive object contents are never reported.
- All lab testing should be isolated to the designated AWS auditor user and test bucket.

## Limitations

- This is a learning-focused tool and not an official AWS compliance analyzer.
- S3 bucket policies can be complex; policy analysis is intentionally conservative.
- Some bucket-level settings depend on region or account context.
- Read-only scanning may produce `ERROR` results if the audit identity lacks the required IAM action.

## Future improvements

- Lifecycle rules
- MFA delete
- Replication checks
- Object lock detection
- CloudTrail data event validation
- Additional reporting and remediation flows

## Learning objectives

This project teaches:

- AWS CLI and boto3 credential discovery
- boto3 S3 API usage
- IAM least-privilege design
- security misconfiguration detection
- evidence-based findings and remediation
- Python CLI design and testing
- how to reason from AWS API output to a security finding
