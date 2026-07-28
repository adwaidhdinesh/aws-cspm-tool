"""
Helpers for creating a boto3 session used by every rule module.

Centralizing this makes it trivial to later add support for:
- Assuming a cross-account role
- Using a named profile
- Restricting to a specific region
"""

from typing import Optional

import boto3


def get_session(profile: Optional[str] = None, region: str = "us-east-1") -> boto3.Session:
    """Create a boto3 session.

    Args:
        profile: Optional named AWS CLI profile to use.
        region: Default region for regional API calls (IAM/S3 are global).

    Returns:
        A configured boto3.Session.
    """
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Return the AWS account ID the session is authenticated against."""
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]
