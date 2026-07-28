"""
The Asset model — a normalized representation of any AWS resource,
independent of which service it came from.

This is the boundary between "what exists" (discovery) and "what's wrong"
(rule checks). Discovery functions in aws_inventory.py build Asset objects
by calling AWS APIs; rule functions then only ever look at Asset objects,
never boto3 directly. That means rules can be unit-tested with plain
Python objects and don't need AWS credentials to run.
"""

from dataclasses import dataclass, field


@dataclass
class Asset:
    account_id: str
    service: str            # e.g. "IAM", "S3", "EC2", "RDS"
    resource_id: str        # stable identifier, e.g. bucket name, instance id
    resource_type: str      # e.g. "S3::Bucket", "EC2::Instance"
    region: str = ""
    arn: str = ""
    name: str = ""
    tags: dict = field(default_factory=dict)

    # Normalized, service-specific config captured at discovery time
    # (e.g. {"encrypted": False, "public": True} for an S3 bucket).
    # Rules read from here instead of calling AWS again — this is what
    # actually lets discovery and rule-checking be separate steps.
    metadata: dict = field(default_factory=dict)

    def key(self):
        """Identity used to match this asset across scans: same service +
        resource_id = same real-world resource, even if metadata changed."""
        return (self.service, self.resource_id)
