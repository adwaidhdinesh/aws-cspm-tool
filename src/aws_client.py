"""
Helpers for creating a boto3 session used by every rule module.

Centralizing this makes it trivial to later add support for:
- Assuming a cross-account role
- Using a named profile
- Restricting to a specific region
- Overriding the endpoint URL (for Floci/local testing)
"""

from typing import Optional

import boto3
from botocore.config import Config

_GLOBAL_ENDPOINT_URL: Optional[str] = None


def get_session(
    profile: Optional[str] = None,
    region: str = "us-east-1",
    endpoint_url: Optional[str] = None
) -> boto3.Session:
    """Create a boto3 session.

    Args:
        profile: Optional named AWS CLI profile to use.
        region: Default region for regional API calls (IAM/S3 are global).
        endpoint_url: Optional custom endpoint URL (e.g., for Floci/local testing).

    Returns:
        A configured boto3.Session.
    """
    global _GLOBAL_ENDPOINT_URL
    _GLOBAL_ENDPOINT_URL = endpoint_url
    
    return boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)


def get_client(session: boto3.Session, service: str):
    """Create a boto3 client for the given service, respecting endpoint overrides."""
    # Add robust exponential backoff retries to all API calls
    config = Config(retries={'max_attempts': 5, 'mode': 'standard'})
    
    if _GLOBAL_ENDPOINT_URL:
        return session.client(service, endpoint_url=_GLOBAL_ENDPOINT_URL, config=config)
    return session.client(service, config=config)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID the session is authenticated against."""
    sts = get_client(session, "sts")
    return sts.get_caller_identity()["Account"]
