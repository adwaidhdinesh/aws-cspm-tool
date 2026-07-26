"""
CLI entry point: runs a full CSPM scan against the current AWS credentials,
prints a summary, and persists results to SQLite + a JSON snapshot.

Usage:
    python main.py
    python main.py --profile my-aws-profile --region us-west-2
"""

import argparse
import json

from src import db
from src.aws_client import get_account_id, get_session
from src.scanner import run_scan
from src.scoring import calculate_score, score_grade


def main():
    parser = argparse.ArgumentParser(description="Run a CSPM scan against an AWS account.")
    parser.add_argument("--profile", default=None, help="Named AWS CLI profile to use")
    parser.add_argument("--region", default="us-east-1", help="AWS region for regional API calls")
    args = parser.parse_args()

    print("Connecting to AWS...")
    session = get_session(profile=args.profile, region=args.region)
    account_id = get_account_id(session)
    print(f"Scanning account: {account_id}\n")

    findings = run_scan(session)
    score_result = calculate_score(findings)
    grade = score_grade(score_result["score"])

    print("\n" + "=" * 50)
    print(f"  Posture Score: {score_result['score']}/100  (Grade {grade})")
    print(f"  Checks: {score_result['passed_checks']} passed, "
          f"{score_result['failed_checks']} failed "
          f"({score_result['total_checks']} total)")
    print("=" * 50)

    for severity, counts in score_result["by_severity"].items():
        if counts["fail"] > 0:
            print(f"  {severity}: {counts['fail']} failing")

    db.init_db()
    scan_id = db.save_scan(account_id, findings, score_result)
    print(f"\nSaved scan #{scan_id} to cspm.db")

    with open("latest_findings.json", "w") as f:
        json.dump({
            "account_id": account_id,
            "score": score_result,
            "findings": findings,
        }, f, indent=2)
    print("Wrote latest_findings.json")
    print("\nRun 'streamlit run dashboard.py' to view results in the dashboard.")


if __name__ == "__main__":
    main()
