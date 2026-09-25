"""
CLI entry point: discovers the AWS asset inventory, runs rule checks
against it, prints a summary, and persists everything to PostgreSQL + a
JSON snapshot.

Usage:
    python main.py
    python main.py --profile my-aws-profile --region us-west-2
    python main.py --endpoint-url https://aws.example.internal  # Custom AWS-compatible endpoint
"""

import argparse
import json
import os
import sys

from botocore.exceptions import (
    ClientError,
    InvalidRegionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from src import db
from src.aws_client import get_account_id, get_session
from src.inventory.aws_inventory import discover_assets
from src.scanner import run_scan
from src.scoring import calculate_score, score_grade

_CREDENTIALS_HINT = (
    "  Configure credentials using:\n"
    "      aws configure\n"
    "  or run with a named profile:\n"
    "      python main.py --profile your-profile"
)


def main():
    parser = argparse.ArgumentParser(description="Run a CSPM scan against an AWS account.")
    parser.add_argument("--profile", default=None, help="Named AWS CLI profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region for regional API calls")
    parser.add_argument("--endpoint-url", default=None, help="Custom AWS-compatible endpoint URL")
    args = parser.parse_args()

    # CLI flag takes precedence over AWS_ENDPOINT_URL environment variable.
    endpoint_url = args.endpoint_url or os.environ.get("AWS_ENDPOINT_URL") or None

    print("Connecting to AWS...")
    try:
        session = get_session(profile=args.profile, region=args.region, endpoint_url=endpoint_url)
        account_id = get_account_id(session)
    except ProfileNotFound as e:
        print(f"\nERROR: AWS profile '{args.profile}' does not exist.", file=sys.stderr)
        print("  Check your configured profiles with:\n      aws configure list-profiles",
              file=sys.stderr)
        sys.exit(1)
    except NoCredentialsError:
        print("\nERROR: AWS credentials were not found.", file=sys.stderr)
        print(_CREDENTIALS_HINT, file=sys.stderr)
        sys.exit(1)
    except PartialCredentialsError:
        print("\nERROR: AWS credentials are incomplete.", file=sys.stderr)
        print(_CREDENTIALS_HINT, file=sys.stderr)
        sys.exit(1)
    except InvalidRegionError:
        print(f"\nERROR: Invalid AWS region '{args.region}'.", file=sys.stderr)
        print("  Use a valid region such as us-east-1, us-west-2, or eu-west-1.",
              file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("AccessDenied", "AccessDeniedException"):
            print("\nERROR: Access denied when connecting to AWS.", file=sys.stderr)
            print("  The IAM identity used must have read-only permissions "
                  "(e.g. the SecurityAudit managed policy).", file=sys.stderr)
        elif error_code in ("InvalidClientTokenId", "InvalidAccessKeyId"):
            print("\nERROR: AWS credentials were rejected (invalid access key).",
                  file=sys.stderr)
            print(_CREDENTIALS_HINT, file=sys.stderr)
        else:
            print(f"\nERROR: AWS API error ({error_code}).", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error while connecting to AWS: {type(e).__name__}: {e}",
              file=sys.stderr)
        raise

    print(f"Scanning account: {account_id}\n")

    db.init_db()

    print("Discovering assets...")
    assets = discover_assets(session, account_id)
    print(f"Discovered {len(assets)} assets\n")

    asset_id_map = db.save_assets(assets, account_id)

    print("Running rule checks against inventory...")
    findings = run_scan(assets)

    # Link each finding back to the asset row it was evaluated against.
    # Account-level findings (e.g. CloudTrail) have no single matching
    # asset and are left with asset_id = None.
    for f in findings:
        f["asset_id"] = asset_id_map.get((f.get("service"), f.get("resource")))

    score_result = calculate_score(findings)
    grade = score_grade(score_result["score"])

    print("\n" + "=" * 50)
    print(f"  Assets discovered: {len(assets)}")
    print(f"  Posture Score: {score_result['score']}/100  (Grade {grade})")
    print(f"  Checks: {score_result['passed_checks']} passed, "
          f"{score_result['failed_checks']} failed "
          f"({score_result['total_checks']} total)")
    print("=" * 50)

    for severity, counts in score_result["by_severity"].items():
        if counts["fail"] > 0:
            print(f"  {severity}: {counts['fail']} failing")

    scan_id = db.save_scan(account_id, findings, score_result, total_assets=len(assets))
    print(f"\nSaved scan #{scan_id} to PostgreSQL")

    with open("latest_findings.json", "w") as f:
        json.dump({
            "account_id": account_id,
            "asset_count": len(assets),
            "score": score_result,
            "findings": findings,
        }, f, indent=2)
    print("Wrote latest_findings.json")
    print("\nRun 'uvicorn api.main:app --reload' and 'npm run dev' in frontend/ to view the dashboard.")


if __name__ == "__main__":
    main()
