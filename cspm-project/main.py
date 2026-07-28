"""
CLI entry point: discovers the AWS asset inventory, runs rule checks
against it, prints a summary, and persists everything to SQLite + a
JSON snapshot.

Usage:
    python main.py
    python main.py --profile my-aws-profile --region us-west-2
"""

import argparse
import json

from src import db
from src.aws_client import get_account_id, get_session
from src.inventory.aws_inventory import discover_assets
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
    print(f"\nSaved scan #{scan_id} to cspm.db")

    with open("latest_findings.json", "w") as f:
        json.dump({
            "account_id": account_id,
            "asset_count": len(assets),
            "score": score_result,
            "findings": findings,
        }, f, indent=2)
    print("Wrote latest_findings.json")
    print("\nRun 'streamlit run dashboard.py' to view results in the dashboard.")


if __name__ == "__main__":
    main()
