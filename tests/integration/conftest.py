"""Shared fixtures for Floci integration tests.

These tests require Floci to be running at http://localhost:4566.
Skip tests gracefully when Floci is unavailable rather than failing.
"""

import subprocess
import time

import boto3
import pytest
from botocore.exceptions import ClientError

FLOCI_ENDPOINT = "http://localhost:4566"
AWS_REGION = "us-east-1"
DUMMY_ACCESS_KEY = "test"
DUMMY_SECRET_KEY = "test"


def floci_available() -> bool:
    """Check if Floci is reachable and healthy."""
    try:
        import requests
        resp = requests.get(f"{FLOCI_ENDPOINT}/_localstack/health", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def floci_session() -> boto3.Session:
    """Create a boto3 session pointing at Floci with dummy credentials."""
    return boto3.Session(
        aws_access_key_id=DUMMY_ACCESS_KEY,
        aws_secret_access_key=DUMMY_SECRET_KEY,
        region_name=AWS_REGION,
    )


def floci_client(service: str):
    """Create a boto3 client for a service pointed at Floci."""
    return floci_session().client(
        service, endpoint_url=FLOCI_ENDPOINT
    )


@pytest.fixture(scope="session", autouse=True)
def floci_check():
    """Skip all tests in this module if Floci is not running."""
    if not floci_available():
        pytest.skip("Floci is not running at %s — start it with: "
                    "docker compose -f docker-compose.floci.yml up -d" % FLOCI_ENDPOINT)
    yield


@pytest.fixture(scope="session")
def session():
    """A shared boto3 session pointing at Floci."""
    sess = floci_session()
    sess._endpoint_url = FLOCI_ENDPOINT  # Set so get_client() uses it
    return sess


@pytest.fixture(scope="session")
def account_id(session) -> str:
    """The account ID Floci reports for the test session."""
    sts = session.client("sts", endpoint_url=FLOCI_ENDPOINT)
    return sts.get_caller_identity()["Account"]