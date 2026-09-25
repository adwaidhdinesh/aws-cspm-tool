"""Contract tests for real AWS (Tier 3).

These tests run against actual AWS and require explicit opt-in.
They validate critical discovery behavior against real AWS.

Usage:
    pytest -m aws

Requires:
    - AWS credentials configured (aws configure)
    - Explicit permission to run (e.g., CSPM_RUN_AWS_TESTS=1)
"""

import os

import pytest

# Require explicit opt-in for real AWS tests
aws_opt_in = os.environ.get("CSPM_RUN_AWS_TESTS") == "1"


@pytest.mark.aws
@pytest.mark.skipif(
    not aws_opt_in,
    reason="Real AWS tests require CSPM_RUN_AWS_TESTS=1 environment variable"
)
class TestRealAWSContracts:
    """Contract tests against real AWS."""

    def test_aws_connection(self):
        """Verify AWS credentials work."""
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        assert "Account" in identity

    def test_s3_list_buckets(self):
        """Verify S3 list_buckets works."""
        import boto3
        s3 = boto3.client("s3")
        resp = s3.list_buckets()
        assert "Buckets" in resp

    def test_iam_list_users(self):
        """Verify IAM list_users works."""
        import boto3
        iam = boto3.client("iam")
        resp = iam.list_users()
        assert "Users" in resp
