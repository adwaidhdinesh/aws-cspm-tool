#!/usr/bin/env python3
"""
Floci seed environment script for CSPM integration testing.

Creates deterministic AWS resources in Floci for testing the CSPM scanner.
Resources are created via standard boto3 API calls to ensure the same API
surface is tested as with real AWS.

Usage:
    python scripts/seed_floci.py --profile insecure
    python scripts/seed_floci.py --profile secure
    python scripts/seed_floci.py --profile mixed

Requirements:
    - Floci running at http://localhost:4566
    - boto3 installed
"""

import argparse
import json
import sys
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError

FLOCI_ENDPOINT = "http://localhost:4566"
AWS_ACCOUNT_ID = "123456789012"  # Floci default account ID


def get_session(endpoint_url: Optional[str] = None) -> boto3.Session:
    """Create a boto3 session for Floci."""
    return boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )


def get_client(service: str, endpoint_url: Optional[str] = None):
    """Get a boto3 client for a service, optionally pointing to Floci."""
    session = get_session()
    kwargs = {"region_name": "us-east-1"}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return session.client(service, **kwargs)


def idempotent_create(func, *args, **kwargs):
    """Call a creation function idempotently - skip if resource exists."""
    try:
        return func(*args, **kwargs)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        # Various "already exists" codes across services (S3, IAM,
        # EC2 security groups, Lambda, etc.)
        duplicate_codes = {
            "AlreadyExists",
            "EntityAlreadyExists",
            "InvalidGroup.Duplicate",
            "ResourceConflictException",
            "TrailAlreadyExistsException",
            "BucketAlreadyOwnedByYou",
        }
        if error_code in duplicate_codes:
            print(f"    Already exists, skipping...")
            return None
        raise


def ensure_bucket(name: str) -> bool:
    """Create an S3 bucket if it doesn't already exist.

    Returns True if the bucket already existed, False if it was created.
    Floci's create_bucket silently succeeds on an existing bucket (no error
    like real AWS), so we check list_buckets first to keep seeding idempotent
    and the logs honest.
    """
    s3 = get_client("s3", FLOCI_ENDPOINT)
    existing = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    if name in existing:
        return True
    s3.create_bucket(Bucket=name)
    return False


def ensure_security_group(group_name: str, description: str):
    """Create an EC2 security group if one with the given name doesn't exist.

    Floci permits duplicate security-group names within a VPC (real AWS
    rejects them), so we check describe_security_groups first. Returns the
    existing/created GroupId.
    """
    ec2 = get_client("ec2", FLOCI_ENDPOINT)
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        if sg["GroupName"] == group_name:
            return sg["GroupId"], True  # already existed
    vpcs = ec2.describe_vpcs()["Vpcs"]
    vpc_id = vpcs[0]["VpcId"] if vpcs else None
    kwargs = {"GroupName": group_name, "Description": description}
    if vpc_id:
        kwargs["VpcId"] = vpc_id
    response = ec2.create_security_group(**kwargs)
    return response["GroupId"], False


def cleanup_resources():
    """Remove all seeded resources (idempotent)."""
    print("Cleaning up seeded resources...")
    
    # S3
    try:
        s3 = get_client("s3", FLOCI_ENDPOINT)
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            if name.startswith("cspm-test-"):
                try:
                    # Empty bucket first
                    objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
                    for obj in objs:
                        s3.delete_object(Bucket=name, Key=obj["Key"])
                    s3.delete_bucket(Bucket=name)
                    print(f"  Deleted S3 bucket: {name}")
                except ClientError:
                    pass
    except ClientError as e:
        print(f"  Warning: S3 cleanup failed: {e}")
    
    # IAM Users
    try:
        iam = get_client("iam", FLOCI_ENDPOINT)
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                if user["UserName"].startswith("cspm-test-"):
                    # Remove user policies
                    policies = iam.list_user_policies(UserName=user["UserName"]).get("PolicyNames", [])
                    for policy_name in policies:
                        iam.delete_user_policy(UserName=user["UserName"], PolicyName=policy_name)
                    # Delete user
                    iam.delete_user(UserName=user["UserName"])
                    print(f"  Deleted IAM user: {user['UserName']}")
    except ClientError as e:
        print(f"  Warning: IAM user cleanup failed: {e}")
    
    # IAM Policies
    try:
        iam = get_client("iam", FLOCI_ENDPOINT)
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                if policy["PolicyName"].startswith("cspm-test-"):
                    iam.delete_policy(PolicyArn=policy["Arn"])
                    print(f"  Deleted IAM policy: {policy['PolicyName']}")
    except ClientError as e:
        print(f"  Warning: IAM policy cleanup failed: {e}")
    
    # EC2 Security Groups (non-default)
    try:
        ec2 = get_client("ec2", FLOCI_ENDPOINT)
        response = ec2.describe_security_groups()
        for sg in response["SecurityGroups"]:
            if sg["GroupName"].startswith("cspm-test-"):
                try:
                    ec2.delete_security_group(GroupId=sg["GroupId"])
                    print(f"  Deleted Security Group: {sg['GroupId']}")
                except ClientError:
                    pass
    except ClientError as e:
        print(f"  Warning: EC2 cleanup failed: {e}")
    
    # Lambda functions
    try:
        lam = get_client("lambda", FLOCI_ENDPOINT)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                if fn["FunctionName"].startswith("cspm-test-"):
                    lam.delete_function(FunctionName=fn["FunctionName"])
                    print(f"  Deleted Lambda function: {fn['FunctionName']}")
    except ClientError as e:
        print(f"  Warning: Lambda cleanup failed: {e}")
    
    print("Cleanup complete.")


def seed_s3_insecure():
    """Create S3 buckets with security issues (idempotent)."""
    print("\n=== Seeding S3 (insecure) ===")
    s3 = get_client("s3", FLOCI_ENDPOINT)
    
    # 1. Public bucket with ACL grant
    bucket_name = "cspm-test-public-bucket"
    existed = ensure_bucket(bucket_name)
    idempotent_create(
        s3.put_bucket_acl,
        Bucket=bucket_name,
        ACL="public-read"
    )
    print(f"  {'Found existing' if existed else 'Created'} public bucket: {bucket_name}")
    
    # 2. Bucket without encryption
    bucket_name = "cspm-test-unencrypted-bucket"
    existed = ensure_bucket(bucket_name)
    # Explicitly remove encryption
    try:
        s3.delete_bucket_encryption(Bucket=bucket_name)
    except ClientError:
        pass  # Already no encryption
    print(f"  {'Found existing' if existed else 'Created'} unencrypted bucket: {bucket_name}")
    
    # 3. Bucket without versioning
    bucket_name = "cspm-test-no-versioning-bucket"
    existed = ensure_bucket(bucket_name)
    print(f"  {'Found existing' if existed else 'Created'} bucket without versioning: {bucket_name}")
    
    # 4. Bucket with public policy
    bucket_name = "cspm-test-public-policy-bucket"
    existed = ensure_bucket(bucket_name)
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*"
        }]
    }
    idempotent_create(
        s3.put_bucket_policy,
        Bucket=bucket_name,
        Policy=json.dumps(public_policy)
    )
    print(f"  {'Found existing' if existed else 'Created'} bucket with public policy: {bucket_name}")


def seed_s3_secure():
    """Create S3 buckets with security best practices."""
    print("\n=== Seeding S3 (secure) ===")
    s3 = get_client("s3", FLOCI_ENDPOINT)
    
    # 1. Private bucket with encryption
    bucket_name = "cspm-test-secure-bucket"
    existed = ensure_bucket(bucket_name)
    idempotent_create(s3.put_bucket_encryption, 
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }
    )
    idempotent_create(s3.put_bucket_versioning,
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"}
    )
    idempotent_create(s3.put_public_access_block,
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )
    print(f"  {'Found existing' if existed else 'Created'} secure bucket: {bucket_name}")


def seed_iam_insecure():
    """Create IAM resources with security issues."""
    print("\n=== Seeding IAM (insecure) ===")
    iam = get_client("iam", FLOCI_ENDPOINT)
    
    # 1. User without MFA
    username = "cspm-test-user-no-mfa"
    user_resp = idempotent_create(iam.create_user, UserName=username)
    try:
        idempotent_create(
            iam.create_login_profile,
            UserName=username,
            Password="TempPassword123!",
            PasswordResetRequired=False
        )
    except ClientError as e:
        if "UnsupportedOperation" in str(e):
            print("    Note: Floci does not support create_login_profile - skipping")
        else:
            raise
    status = "Found existing" if user_resp is None else "Created"
    print(f"  {status} user without MFA: {username}")
    
    # 2. Wildcard admin policy
    policy_name = "cspm-test-wildcard-admin"
    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    policy_resp = idempotent_create(
        iam.create_policy,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(wildcard_policy)
    )
    # Attach to user
    try:
        iam.attach_user_policy(
            UserName=username,
            PolicyArn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:policy/{policy_name}"
        )
    except ClientError:
        pass
    status = "Found existing" if policy_resp is None else "Created"
    print(f"  {status} wildcard admin policy: {policy_name}")


def seed_iam_secure():
    """Create IAM resources with security best practices."""
    print("\n=== Seeding IAM (secure) ===")
    iam = get_client("iam", FLOCI_ENDPOINT)
    
    # 1. User with MFA
    username = "cspm-test-user-with-mfa"
    idempotent_create(iam.create_user, UserName=username)
    try:
        idempotent_create(
            iam.create_login_profile,
            UserName=username,
            Password="TempPassword123!",
            PasswordResetRequired=True
        )
    except ClientError as e:
        if "UnsupportedOperation" in str(e):
            print("    Note: Floci does not support create_login_profile - skipping")
        else:
            raise
    try:
        idempotent_create(iam.create_virtual_mfa_device, UserName=username)
    except ClientError as e:
        if "UnsupportedOperation" in str(e):
            print("    Note: Floci does not support create_virtual_mfa_device - skipping")
        else:
            raise
    print(f"  Created user with MFA: {username}")


def seed_ec2_insecure():
    """Create EC2 resources with security issues (idempotent)."""
    print("\n=== Seeding EC2 (insecure) ===")
    ec2 = get_client("ec2", FLOCI_ENDPOINT)

    # 1. Security group with open SSH
    sg_name = "cspm-test-open-ssh"
    try:
        sg_id, existed = ensure_security_group(sg_name, "Test SG with open SSH")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
        print(f"  {'Found existing' if existed else 'Created'} open SSH security group: {sg_id}")
    except ClientError as e:
        print(f"  Warning: Could not create security group: {e}")

    # 2. Security group with open RDP
    sg_name = "cspm-test-open-rdp"
    try:
        sg_id, existed = ensure_security_group(sg_name, "Test SG with open RDP")
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
        print(f"  {'Found existing' if existed else 'Created'} open RDP security group: {sg_id}")
    except ClientError as e:
        print(f"  Warning: Could not create security group: {e}")


def seed_ec2_secure():
    """Create EC2 resources with security best practices (idempotent)."""
    print("\n=== Seeding EC2 (secure) ===")
    ec2 = get_client("ec2", FLOCI_ENDPOINT)
    
    # Security group with restricted access
    sg_name = "cspm-test-restricted"
    try:
        sg_id, existed = ensure_security_group(sg_name, "Test SG with restricted access")
        # Only allow SSH from specific CIDR
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
            }]
        )
        print(f"  {'Found existing' if existed else 'Created'} restricted security group: {sg_id}")
    except ClientError as e:
        print(f"  Warning: Could not create security group: {e}")


def _make_lambda_zip() -> bytes:
    """Create a minimal valid Lambda deployment package in memory."""
    import io
    import zipfile

    code = (
        "def lambda_handler(event, context):\n"
        "    return {'statusCode': 200, 'body': 'Hello from CSPM test'}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def seed_lambda_insecure():
    """Create Lambda functions with security issues."""
    print("\n=== Seeding Lambda (insecure) ===")
    lam = get_client("lambda", FLOCI_ENDPOINT)
    
    # 1. Lambda with public resource policy
    function_name = "cspm-test-public-function"
    try:
        response = idempotent_create(
            lam.create_function,
            FunctionName=function_name,
            Runtime="python3.9",
            Role=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/lambda-role",
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": _make_lambda_zip()},
            Timeout=30,
            MemorySize=128
        )

        # Add public resource policy (idempotent - the ResourceConflictException
        # on a repeated StatementId is treated as already-present).
        idempotent_create(
            lam.add_permission,
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal="*"
        )
        status = "Found existing" if response is None else "Created"
        print(f"  {status} public Lambda function: {function_name}")
    except ClientError as e:
        print(f"  Warning: Could not create Lambda: {e}")


def seed_lambda_secure():
    """Create Lambda functions with security best practices."""
    print("\n=== Seeding Lambda (secure) ===")
    lam = get_client("lambda", FLOCI_ENDPOINT)
    
    # Lambda without public access
    function_name = "cspm-test-private-function"
    try:
        response = idempotent_create(
            lam.create_function,
            FunctionName=function_name,
            Runtime="python3.9",
            Role=f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/lambda-role",
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": _make_lambda_zip()},
            Timeout=30,
            MemorySize=128
        )
        status = "Found existing" if response is None else "Created"
        print(f"  {status} private Lambda function: {function_name}")
    except ClientError as e:
        print(f"  Warning: Could not create Lambda: {e}")


def _find_kms_key_by_description(description: str):
    """Return the key id of an existing KMS key with the given description,
    or None if it doesn't exist. This keeps KMS seeding idempotent since
    create_key always returns a brand-new key (no natural 'already exists').
    """
    kms = get_client("kms", FLOCI_ENDPOINT)
    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for entry in page["Keys"]:
            try:
                meta = kms.describe_key(KeyId=entry["KeyId"])["KeyMetadata"]
                if meta.get("Description") == description:
                    return entry["KeyId"]
            except ClientError:
                continue
    return None


def seed_kms():
    """Seed KMS keys idempotently. Reuse existing keys by description
    instead of creating duplicates on repeated runs."""
    print("\n=== Seeding KMS ===")
    kms = get_client("kms", FLOCI_ENDPOINT)

    # 1. Key with rotation enabled
    description = "CSPM test key with rotation"
    existing = _find_kms_key_by_description(description)
    if existing:
        print(f"  KMS key with rotation already exists: {existing}")
    else:
        try:
            response = idempotent_create(
                kms.create_key,
                Description=description,
                KeyUsage="ENCRYPT_DECRYPT",
                KeySpec="SYMMETRIC_DEFAULT"
            )
            if response:
                key_id = response["KeyMetadata"]["KeyId"]
                kms.enable_key_rotation(KeyId=key_id)
                print(f"  Created KMS key with rotation: {key_id}")
        except ClientError as e:
            print(f"  Warning: Could not create KMS key: {e}")

    # 2. Key without rotation
    description = "CSPM test key without rotation"
    existing = _find_kms_key_by_description(description)
    if existing:
        print(f"  KMS key without rotation already exists: {existing}")
    else:
        try:
            response = idempotent_create(
                kms.create_key,
                Description=description,
                KeyUsage="ENCRYPT_DECRYPT",
                KeySpec="SYMMETRIC_DEFAULT"
            )
            if response:
                key_id = response["KeyMetadata"]["KeyId"]
                print(f"  Created KMS key without rotation: {key_id}")
        except ClientError as e:
            print(f"  Warning: Could not create KMS key: {e}")


def seed_cloudtrail():
    """Create CloudTrail for testing."""
    print("\n=== Seeding CloudTrail ===")
    ct = get_client("cloudtrail", FLOCI_ENDPOINT)
    
    trail_name = "cspm-test-trail"
    s3_bucket = "cspm-test-cloudtrail-logs"
    
    # Create S3 bucket for trail logs
    s3 = get_client("s3", FLOCI_ENDPOINT)
    ensure_bucket(s3_bucket)
    
    # Create trail (idempotent)
    try:
        trail_resp = idempotent_create(
            ct.create_trail,
            Name=trail_name,
            S3BucketName=s3_bucket,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True
        )
        ct.start_logging(Name=trail_name)
        status = "Found existing" if trail_resp is None else "Created"
        print(f"  {status} CloudTrail: {trail_name}")
    except ClientError as e:
        print(f"  Warning: Could not create CloudTrail: {e}")


def seed_vpc():
    """Create VPC resources idempotently. Reuses an existing 'cspm-test-vpc'
    instead of creating a duplicate on repeated runs."""
    print("\n=== Seeding VPC ===")
    ec2 = get_client("ec2", FLOCI_ENDPOINT)

    # Look for an existing tagged VPC first (create_vpc has no natural
    # "already exists" error, so tags are the idempotency key).
    filters = [{"Name": "tag:Name", "Values": ["cspm-test-vpc"]}]
    existing = ec2.describe_vpcs(Filters=filters)["Vpcs"]
    if existing:
        print(f"  VPC already exists: {existing[0]['VpcId']}")
        return

    try:
        response = ec2.create_vpc(
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[{
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": "cspm-test-vpc"}]
            }]
        )
        if response:
            vpc_id = response["Vpc"]["VpcId"]
            print(f"  Created VPC: {vpc_id}")
    except ClientError as e:
        print(f"  Warning: Could not create VPC: {e}")


def seed_profile(profile_name: str):
    """Seed resources based on the specified profile."""
    print(f"\n{'='*60}")
    print(f"Seeding Floci with profile: {profile_name}")
    print(f"Endpoint: {FLOCI_ENDPOINT}")
    print(f"{'='*60}")
    
    if profile_name == "insecure":
        seed_s3_insecure()
        seed_iam_insecure()
        seed_ec2_insecure()
        seed_lambda_insecure()
        seed_kms()
        seed_cloudtrail()
        seed_vpc()
    elif profile_name == "secure":
        seed_s3_secure()
        seed_iam_secure()
        seed_ec2_secure()
        seed_lambda_secure()
        seed_kms()
        seed_vpc()
    elif profile_name == "mixed":
        seed_s3_insecure()
        seed_s3_secure()
        seed_iam_insecure()
        seed_iam_secure()
        seed_ec2_insecure()
        seed_ec2_secure()
        seed_lambda_insecure()
        seed_lambda_secure()
        seed_kms()
        seed_cloudtrail()
        seed_vpc()
    else:
        print(f"Error: Unknown profile '{profile_name}'")
        print("Available profiles: insecure, secure, mixed")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print("Seeding complete!")
    print(f"{'='*60}")


def main():
    global FLOCI_ENDPOINT
    parser = argparse.ArgumentParser(
        description="Seed Floci with test resources for CSPM integration testing"
    )
    parser.add_argument(
        "--profile",
        choices=["insecure", "secure", "mixed"],
        required=True,
        help="Resource profile to seed"
    )
    parser.add_argument(
        "--endpoint-url",
        default=FLOCI_ENDPOINT,
        help=f"Floci endpoint URL (default: {FLOCI_ENDPOINT})"
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove all seeded resources before seeding"
    )
    
    args = parser.parse_args()
    
    FLOCI_ENDPOINT = args.endpoint_url
    
    if args.cleanup:
        cleanup_resources()
    
    seed_profile(args.profile)


if __name__ == "__main__":
    main()