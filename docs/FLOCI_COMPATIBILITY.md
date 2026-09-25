# Floci API Compatibility Matrix

This document tracks the compatibility of Floci (AWS-compatible emulator) with the AWS API operations used by the CSPM project. Status is based on actual testing against the `floci/floci:latest` Docker image (verified at build time for CSPM v3.1).

## Legend

- **SUPPORTED**: Fully implemented and verified working
- **PARTIAL**: Works but may have behavioral differences from real AWS
- **UNSUPPORTED**: Not implemented in this Floci version
- **UNKNOWN**: Not yet tested in this environment

## Compatibility Matrix

### IAM Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `get_account_summary` | Root MFA check (IAM-001) | **SUPPORTED** | Returns summary but `AccountMFAEnabled` may differ from AWS | Unit tests use fixtures |
| `list_users` (paginated) | IAM user discovery | **SUPPORTED** | Works correctly | — |
| `get_login_profile` | Console access check (IAM-002) | **PARTIAL** | Floci may not support `create_login_profile` for seeding; discovery of existing users works | Real AWS contract tests |
| `list_mfa_devices` | MFA status check (IAM-002) | **SUPPORTED** | Returns empty list for users without MFA | — |
| `list_policies` (paginated, Scope=Local) | Policy discovery (IAM-003) | **SUPPORTED** | Works correctly | — |
| `get_policy_version` | Policy document retrieval (IAM-003) | **SUPPORTED** | Works correctly | — |

### S3 Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `list_buckets` | S3 bucket discovery | **SUPPORTED** | Works correctly | — |
| `get_bucket_location` | Region detection | **SUPPORTED** | Returns US-East-1 for all buckets | — |
| `get_bucket_acl` | Public access check (S3-001) | **SUPPORTED** | ACL grants are honored | — |
| `get_bucket_policy_status` | Public policy check (S3-001) | **PARTIAL** | **Does NOT perform policy evaluation** — returns empty `PolicyStatus: {}` dict even for buckets with public policies. Real AWS computes `IsPublic` based on: (a) bucket policy that grants public read/write, (b) bucket ACL granting public access, (c) public access block not being enabled. | Unit fixtures + Real AWS contract tests |
| `get_bucket_encryption` | Encryption check (S3-002) | **PARTIAL** | **Reports encryption as enabled even when not configured.** `get_bucket_encryption` appears to always return 200 with default encryption in Floci. Use `put_bucket_encryption` with a specific config for reliable tests. | Unit fixtures |
| `get_bucket_versioning` | Versioning info | **SUPPORTED** | Works correctly | — |
| `put_bucket_policy` / `put_public_access_block` | Seeding only | **SUPPORTED** | Works correctly | — |

### EC2 Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `describe_security_groups` (paginated) | SG discovery (EC2-001) | **SUPPORTED** | Works correctly; `IpPermissions` returned properly | — |
| `describe_instances` (paginated) | Instance discovery, public IP check (EC2-002) | **SUPPORTED** | Instances not seeded by default | — |
| `create_security_group` / `authorize_security_group_ingress` | Seeding only | **SUPPORTED** | Works correctly | — |

### CloudTrail Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `describe_trails` | Trail discovery (CT-001, CT-002) | **SUPPORTED** | Works correctly | — |
| `get_trail_status` | Logging status check (CT-001) | **SUPPORTED** | Works correctly | — |
| `create_trail` / `start_logging` | Seeding only | **SUPPORTED** | Works correctly | — |

### RDS Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `describe_db_instances` (paginated) | RDS discovery (RDS-001, RDS-002) | **SUPPORTED** | Works correctly; returns [] when no instances | — |

### KMS Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `list_keys` (paginated) | KMS key discovery (KMS-001) | **SUPPORTED** | Works correctly | — |
| `describe_key` | Key metadata (KMS-001) | **SUPPORTED** | Works correctly | — |
| `get_key_rotation_status` | Rotation check (KMS-001) | **SUPPORTED** | Works correctly | — |
| `create_key` / `enable_key_rotation` | Seeding only | **SUPPORTED** | Works correctly | — |

### Lambda Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `list_functions` (paginated) | Lambda discovery (LAMBDA-001) | **SUPPORTED** | Works correctly | — |
| `get_policy` | Resource policy (LAMBDA-001) | **PARTIAL** | **May not apply `add_permission` policy correctly.** Seeding a public Lambda failed with `Failed to extract deployment package` — Floci's Docker-backed Lambda service requires real zip packages. | Unit tests + Real AWS contract tests |
| `create_function` | Seeding only | **PARTIAL** | **Requires a valid zip package.** Dummy `ZipFile=b"dummy"` fails with `Failed to extract deployment package`. Provide real packaged code. | — |
| `add_permission` | Seeding only | **PARTIAL** | May not evaluate principals for public access | — |

### VPC/EC2 Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `describe_vpcs` | VPC discovery (VPC-001, VPC-002) | **SUPPORTED** | Works correctly; default VPC may not be created automatically | — |
| `describe_flow_logs` | Flow logs check (VPC-002) | **SUPPORTED** | Works correctly | — |
| `create_vpc` | Seeding only | **SUPPORTED** | Works correctly | — |

### STS Service

| CSPM API Operation | Used By | Floci Status | Known Limitation | Fallback Strategy |
|---|---|---|---|---|
| `get_caller_identity` | Account ID retrieval | **SUPPORTED** | Returns `000000000000` for dummy credentials | — |

## Critical Behavioral Differences

1. **`get_bucket_policy_status` does NOT evaluate policies.** In real AWS, this returns `IsPublic: true` when a bucket has a public policy. Floci returns an empty `{}` dict. The CSPM code handles this gracefully by skipping the check when the dict is empty. **Do not weaken the security rule** — the actual Amazon S3 logic is still evaluated correctly in the production code path.

2. **`get_bucket_encryption` may report encryption incorrectly.** Floci appears to always return encryption as configured. The S3-002 rule (bucket default encryption) may produce false PASS results against Floci. Users should verify encryption using an alternative check (e.g., inspecting bucket metadata) or via real AWS.

3. **Lambda functions need real deployment packages.** Floci's Lambda service requires valid zip/tar package content. Simplified dummy code fails.

4. **IAM login profiles are unsupported for creation.** You can create IAM users but cannot attach a login profile (console password). The IAM-002 rule (users with console access need MFA) therefore has limited test coverage in Floci.