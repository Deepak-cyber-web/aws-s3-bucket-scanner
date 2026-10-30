# Security assumptions and limitations

This project is designed for a defensive AWS lab environment.

## Safety model

- The default scan mode is read-only.
- The tool does not modify AWS resources during a standard scan.
- Remediation is opt-in and requires explicit confirmation.
- A `--dry-run` mode should be used before applying changes.

## Important limitations

- This is not an official AWS compliance engine.
- The security score is a heuristic for educational use.
- Some findings depend on bucket configuration and account-specific access.
- IAM permissions and bucket policies vary by region and account.

## Credentials and secrets

- The tool uses the default boto3 credential chain.
- No credentials are stored in code.
- Secrets are never printed to logs or reports.
