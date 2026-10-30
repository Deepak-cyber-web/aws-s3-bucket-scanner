from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .aws_session import get_aws_session, get_caller_identity
from .logger import configure_logger
from .remediation.s3_remediation import plan_remediation
from .reporting.html_report import write_html_report
from .reporting.json_report import write_json_report
from .scanner import list_buckets, scan_bucket, json_output
from .severity import calculate_security_score

logger = configure_logger()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="S3 Security Auditor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--region", help="AWS region to prefer for the scan")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan S3 buckets for common misconfigurations")
    scan_parser.add_argument("--bucket", help="A single bucket to scan")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--output", help="Write the final JSON report to this file")

    remediate_parser = subparsers.add_parser("remediate", help="Remediate an S3 finding")
    remediate_parser.add_argument("--finding", help="Specific finding ID to remediate")
    remediate_parser.add_argument("--dry-run", action="store_true", help="Show action without changing AWS resources")
    remediate_parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts")

    subparsers.add_parser("verify", help="Verify AWS identity and list discovered buckets")
    return parser


def _print_scan_results(account_id: str, identity: str, bucket_list, findings):
    print("=" * 60)
    print("AWS S3 SECURITY AUDITOR")
    print("=" * 60)
    print(f"Account : {account_id}")
    print(f"Identity: {identity}")
    print(f"Buckets discovered: {len(bucket_list)}")
    print()

    for bucket in bucket_list:
        bucket_findings = [f for f in findings if f.bucket == bucket.name]
        print(f"[{bucket.name}]")
        for finding in bucket_findings:
            print(f"  {finding.finding_id:>7} {finding.status:<4} {finding.title}")
        print()

    summary = {}
    for word in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        summary[word] = sum(1 for f in findings if f.severity.upper() == word and f.status == "FAIL")
    passed = sum(1 for f in findings if f.status == "PASS")
    score = calculate_security_score([f.to_dict() for f in findings])
    print("Scan Summary")
    print(f"Critical : {summary['CRITICAL']}")
    print(f"High     : {summary['HIGH']}")
    print(f"Medium   : {summary['MEDIUM']}")
    print(f"Low      : {summary['LOW']}")
    print(f"Passed   : {passed}")
    print(f"Security Score: {score}/100")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "verify":
        session = get_aws_session(args.region)
        identity = get_caller_identity(session)
        account_id = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")
        print(f"AWS Account: {account_id}")
        print(f"ARN: {arn}")
        buckets = list_buckets(session)
        print(f"Buckets discovered: {len(buckets)}")
        for bucket in buckets:
            print(f"- {bucket.name} ({bucket.region})")
        return 0

    if args.command == "scan":
        session = get_aws_session(args.region)
        identity = get_caller_identity(session)
        account_id = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")
        discovered_buckets = list_buckets(session)

        if args.bucket:
            bucket_list = [bucket for bucket in discovered_buckets if bucket.name == args.bucket]
        else:
            bucket_list = discovered_buckets

        findings = []
        for bucket in bucket_list:
            findings.extend(scan_bucket(bucket.name, region_name=args.region))

        payload = json_output(account_id, arn, bucket_list, findings)
        payload["region"] = args.region or session.region_name or "unknown"
        payload["security_score"] = calculate_security_score([finding.to_dict() for finding in findings])

        if args.output:
            output_file = Path(args.output)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            if output_file.suffix.lower() == ".html":
                write_html_report(str(output_file), payload)
            else:
                write_json_report(str(output_file), payload)
            print(f"Report written to {output_file}")

        if args.format == "json":
            print(json.dumps(payload, indent=2))
            return 0

        _print_scan_results(account_id, arn, bucket_list, findings)
        return 0 if not any(f.status == "FAIL" for f in findings) else 1

    if args.command == "remediate":
        session = get_aws_session(args.region)
        identity = get_caller_identity(session)
        account_id = identity.get("Account", "unknown")
        arn = identity.get("Arn", "unknown")

        if not args.finding:
            print("A finding ID is required for remediation, for example: --finding S3-001")
            return 2

        candidate_buckets = list_buckets(session)
        bucket_name = candidate_buckets[0].name if candidate_buckets else "unknown-bucket"
        current_state = {"account": account_id, "identity": arn, "bucket": bucket_name}
        plan = plan_remediation(args.finding, bucket_name, current_state, dry_run=args.dry_run)

        print("Finding:", plan["finding_id"])
        print("Bucket:", plan["bucket"])
        print("Current state:", json.dumps(plan["current_state"], indent=2))
        print("Proposed change:", plan["proposed_change"])
        print("AWS API:", plan["api"])
        print("Dry run:", plan["dry_run"])

        if args.dry_run:
            print("Dry-run mode: no AWS write actions were performed.")
            return 0

        if not args.yes:
            confirmation = input("Apply this remediation? [y/N]: ")
            if confirmation.lower() not in {"y", "yes"}:
                print("Remediation cancelled.")
                return 0

        print("Remediation requested and would require write access to the target bucket.")
        print("This example is intentionally opt-in and does not perform a live AWS modification in this scaffolded phase.")
        return 0

    parser.print_help()
    return 2
