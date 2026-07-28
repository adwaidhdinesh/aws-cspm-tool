"""
Discovers AWS resources and normalizes them into Asset objects.

This is the ONLY place in the codebase that calls boto3. Every rule in
src/rules/ receives a list of already-discovered Asset objects and reads
whatever it needs from asset.metadata — it never touches AWS directly.

Each discover_<service>_assets(session) function returns a list[Asset].
discover_assets(session) runs all of them and returns the combined list,
skipping any service that raises (e.g. missing permission) with a warning,
the same way the old per-rule scanning used to.
"""

import json

from botocore.exceptions import ClientError

from src.inventory.inventory import Asset

# Ports considered sensitive if open to 0.0.0.0/0 or ::/0 — used by both
# discovery (to precompute) and the EC2 rule that reads this metadata.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
}


def discover_iam_assets(session, account_id: str) -> list:
    iam = session.client("iam")
    assets = []

    # Root account is modeled as a single pseudo-asset so root MFA fits
    # the same Asset -> rule -> finding pipeline as everything else.
    summary = iam.get_account_summary()["SummaryMap"]
    assets.append(Asset(
        account_id=account_id,
        service="IAM",
        resource_id=account_id,
        resource_type="IAM::RootAccount",
        name="root",
        metadata={"mfa_enabled": summary.get("AccountMFAEnabled", 0) == 1},
    ))

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            has_console_access = True
            try:
                iam.get_login_profile(UserName=username)
            except iam.exceptions.NoSuchEntityException:
                has_console_access = False

            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

            assets.append(Asset(
                account_id=account_id,
                service="IAM",
                resource_id=username,
                resource_type="IAM::User",
                arn=user.get("Arn", ""),
                name=username,
                metadata={
                    "has_console_access": has_console_access,
                    "mfa_enabled": len(mfa_devices) > 0,
                },
            ))

    policy_paginator = iam.get_paginator("list_policies")
    for page in policy_paginator.paginate(Scope="Local"):  # customer-managed only
        for policy in page["Policies"]:
            policy_doc = iam.get_policy_version(
                PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"]

            assets.append(Asset(
                account_id=account_id,
                service="IAM",
                resource_id=policy["PolicyName"],
                resource_type="IAM::Policy",
                arn=policy["Arn"],
                name=policy["PolicyName"],
                metadata={"is_wildcard_admin": _has_full_wildcard(policy_doc)},
            ))

    return assets


def discover_s3_assets(session, account_id: str) -> list:
    s3 = session.client("s3")
    assets = []

    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        is_public = False
        is_encrypted = True
        versioning_enabled = False
        region = ""

        try:
            loc = s3.get_bucket_location(Bucket=name)["LocationConstraint"]
            region = loc or "us-east-1"
        except ClientError:
            pass

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = grant.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public = True
        except ClientError:
            pass

        try:
            if s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]:
                is_public = True
        except ClientError:
            pass

        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            is_encrypted = False

        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            versioning_enabled = versioning.get("Status") == "Enabled"
        except ClientError:
            pass

        assets.append(Asset(
            account_id=account_id,
            service="S3",
            resource_id=name,
            resource_type="S3::Bucket",
            region=region,
            arn=f"arn:aws:s3:::{name}",
            name=name,
            metadata={
                "public": is_public,
                "encrypted": is_encrypted,
                "versioning_enabled": versioning_enabled,
            },
        ))

    return assets


def discover_ec2_assets(session, account_id: str) -> list:
    ec2 = session.client("ec2")
    assets = []

    # Security groups
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            open_ports = _find_open_sensitive_ports(sg.get("IpPermissions", []))

            assets.append(Asset(
                account_id=account_id,
                service="EC2",
                resource_id=sg_id,
                resource_type="EC2::SecurityGroup",
                region=session.region_name,
                name=sg_name,
                metadata={
                    "is_default": sg_name == "default",
                    "has_inbound_rules": len(sg.get("IpPermissions", [])) > 0,
                    "open_sensitive_ports": open_ports,
                },
            ))

    # Instances
    inst_paginator = ec2.get_paginator("describe_instances")
    for page in inst_paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)

                assets.append(Asset(
                    account_id=account_id,
                    service="EC2",
                    resource_id=instance_id,
                    resource_type="EC2::Instance",
                    region=session.region_name,
                    name=name,
                    tags=tags,
                    metadata={
                        "state": instance.get("State", {}).get("Name"),
                        "instance_type": instance.get("InstanceType"),
                        "public_ip": instance.get("PublicIpAddress"),
                        "private_ip": instance.get("PrivateIpAddress"),
                    },
                ))

    return assets


def discover_cloudtrail_assets(session, account_id: str) -> list:
    ct = session.client("cloudtrail")
    assets = []

    for trail in ct.describe_trails()["trailList"]:
        name = trail["Name"]
        status = ct.get_trail_status(Name=trail["TrailARN"])

        assets.append(Asset(
            account_id=account_id,
            service="CloudTrail",
            resource_id=name,
            resource_type="CloudTrail::Trail",
            region=trail.get("HomeRegion", ""),
            arn=trail.get("TrailARN", ""),
            name=name,
            metadata={
                "is_multiregion": trail.get("IsMultiRegionTrail", False),
                "is_logging": status.get("IsLogging", False),
                "log_validation_enabled": trail.get("LogFileValidationEnabled", False),
            },
        ))

    return assets


def discover_rds_assets(session, account_id: str) -> list:
    rds = session.client("rds")
    assets = []

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for instance in page["DBInstances"]:
            identifier = instance["DBInstanceIdentifier"]

            assets.append(Asset(
                account_id=account_id,
                service="RDS",
                resource_id=identifier,
                resource_type="RDS::Instance",
                region=session.region_name,
                arn=instance.get("DBInstanceArn", ""),
                name=identifier,
                metadata={
                    "engine": instance.get("Engine"),
                    "status": instance.get("DBInstanceStatus"),
                    "publicly_accessible": instance.get("PubliclyAccessible", False),
                    "storage_encrypted": instance.get("StorageEncrypted", False),
                },
            ))

    return assets


def discover_kms_assets(session, account_id: str) -> list:
    kms = session.client("kms")
    assets = []

    paginator = kms.get_paginator("list_keys")
    for page in paginator.paginate():
        for key in page["Keys"]:
            key_id = key["KeyId"]

            try:
                metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError:
                continue

            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            if metadata.get("KeyState") != "Enabled":
                continue

            rotation_enabled = False
            if metadata.get("KeySpec") == "SYMMETRIC_DEFAULT":
                try:
                    rotation_enabled = kms.get_key_rotation_status(
                        KeyId=key_id
                    )["KeyRotationEnabled"]
                except ClientError:
                    pass

            assets.append(Asset(
                account_id=account_id,
                service="KMS",
                resource_id=key_id,
                resource_type="KMS::Key",
                region=session.region_name,
                arn=metadata.get("Arn", ""),
                name=metadata.get("Description") or key_id,
                metadata={
                    "key_spec": metadata.get("KeySpec"),
                    "rotation_enabled": rotation_enabled,
                },
            ))

    return assets


def discover_vpc_assets(session, account_id: str) -> list:
    ec2 = session.client("ec2")
    assets = []

    vpcs = ec2.describe_vpcs()["Vpcs"]
    flow_logs = ec2.describe_flow_logs()["FlowLogs"]
    vpcs_with_logs = {
        fl["ResourceId"] for fl in flow_logs if fl.get("ResourceType") == "VPC"
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}

        assets.append(Asset(
            account_id=account_id,
            service="VPC",
            resource_id=vpc_id,
            resource_type="VPC::Vpc",
            region=session.region_name,
            name=tags.get("Name", vpc_id),
            tags=tags,
            metadata={
                "is_default": vpc.get("IsDefault", False),
                "has_flow_logs": vpc_id in vpcs_with_logs,
            },
        ))

    return assets


def discover_lambda_assets(session, account_id: str) -> list:
    lam = session.client("lambda")
    assets = []

    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        for fn in page["Functions"]:
            name = fn["FunctionName"]
            is_public = False

            try:
                policy_doc = json.loads(lam.get_policy(FunctionName=name)["Policy"])
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal")
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        is_public = True
            except ClientError:
                pass

            assets.append(Asset(
                account_id=account_id,
                service="Lambda",
                resource_id=name,
                resource_type="Lambda::Function",
                region=session.region_name,
                arn=fn.get("FunctionArn", ""),
                name=name,
                metadata={
                    "runtime": fn.get("Runtime"),
                    "public": is_public,
                },
            ))

    return assets


# Every discovery function to run, in order. Add new services here.
ALL_DISCOVERERS = [
    discover_iam_assets,
    discover_s3_assets,
    discover_ec2_assets,
    discover_cloudtrail_assets,
    discover_rds_assets,
    discover_kms_assets,
    discover_vpc_assets,
    discover_lambda_assets,
]


def discover_assets(session, account_id: str, verbose: bool = True) -> list:
    """Run every registered discoverer and return the combined asset list.

    A discoverer that raises (e.g. missing IAM permission for that service)
    is skipped with a warning rather than failing the whole scan.
    """
    all_assets = []

    for discoverer in ALL_DISCOVERERS:
        name = discoverer.__name__
        try:
            if verbose:
                print(f"  Discovering via {name}...")
            assets = discoverer(session, account_id)
            all_assets.extend(assets)
        except Exception as e:
            if verbose:
                print(f"  ⚠️  Skipped {name} due to error: {e}")

    return all_assets


def _find_open_sensitive_ports(ip_permissions):
    open_ports = []
    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        is_world_open = any(
            r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])
        ) or any(
            r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])
        )

        if not is_world_open or from_port is None or to_port is None:
            continue

        for port, name in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                open_ports.append(f"{name} ({port})")

    return open_ports


def _has_full_wildcard(policy_doc: dict) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources

        if "*" in actions and "*" in resources:
            return True

    return False
