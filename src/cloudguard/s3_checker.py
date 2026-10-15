
"""Offline S3 security configuration checker.

Analyzes simulated S3 configuration data only.
Does not connect to AWS or make API calls.
"""

from typing import Any

Finding = dict[str, str]


def _finding(
    check: str,
    severity: str,
    message: str,
    remediation: str,
) -> Finding:
    """Build a consistently structured security finding."""
    return {
        "check": check,
        "severity": severity,
        "message": message,
        "remediation": remediation,
    }


def _has_https_deny_policy(
    bucket_policy: Any,
    bucket_name: Any,
) -> bool:
    """Check for an HTTPS-deny policy covering the target bucket.

    This is a focused policy-pattern check, not a complete IAM
    policy evaluator.
    """
    if not isinstance(bucket_name, str) or not bucket_name.strip():
        return False

    if not isinstance(bucket_policy, dict):
        return False

    statements = bucket_policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return False

    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    required_resources = {bucket_arn, f"{bucket_arn}/*"}

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Deny":
            continue

        action = statement.get("Action")
        if isinstance(action, str):
            actions = [action]
        elif isinstance(action, list):
            actions = action
        else:
            continue

        covers_s3 = any(
            isinstance(item, str)
            and item.lower() in {"s3:*", "*"}
            for item in actions
        )
        if not covers_s3:
            continue

        resource = statement.get("Resource")
        if isinstance(resource, str):
            resources = [resource]
        elif isinstance(resource, list):
            resources = resource
        else:
            continue

        valid_resources = {
            item for item in resources if isinstance(item, str)
        }

        covers_resources = (
            "*" in valid_resources
            or required_resources.issubset(valid_resources)
        )
        if not covers_resources:
            continue

        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            continue

        bool_condition = condition.get("Bool")
        if not isinstance(bool_condition, dict):
            continue

        secure_transport = bool_condition.get("aws:SecureTransport")

        denies_http = (
            secure_transport is False
            or (
                isinstance(secure_transport, str)
                and secure_transport.lower() == "false"
            )
        )

        if denies_http:
            return True

    return False


def check_s3_bucket(config: Any) -> list[Finding]:
    """Return security findings for a simulated S3 configuration.

    Invalid or missing configuration data is treated as unverified
    and reported as a security finding rather than trusted as secure.
    """
    if not isinstance(config, dict):
        config = {}

    findings: list[Finding] = []

    # Check all four S3 Block Public Access settings.
    public_access = config.get("public_access_block")
    if not isinstance(public_access, dict):
        public_access = {}

    public_checks = {
        "block_public_acls": "Block public ACLs",
        "ignore_public_acls": "Ignore public ACLs",
        "block_public_policy": "Block public bucket policies",
        "restrict_public_buckets": "Restrict public buckets",
    }

    for setting, description in public_checks.items():
        if public_access.get(setting) is not True:
            findings.append(
                _finding(
                    check=setting,
                    severity="HIGH",
                    message=f"Missing protection: {description}.",
                    remediation=f"Set {setting} to true.",
                )
            )

    # Check default server-side encryption.
    encryption = config.get("encryption")
    if not isinstance(encryption, dict):
        encryption = {}

    if encryption.get("enabled") is not True:
        findings.append(
            _finding(
                check="encryption",
                severity="HIGH",
                message="Default server-side encryption is not enabled.",
                remediation=(
                    "Enable default server-side encryption for the bucket "
                    "and verify the configured encryption requirements."
                ),
            )
        )

    # Check bucket versioning.
    versioning = config.get("versioning")
    if not isinstance(versioning, dict):
        versioning = {}

    if versioning.get("enabled") is not True:
        findings.append(
            _finding(
                check="versioning",
                severity="MEDIUM",
                message="Bucket versioning is not enabled.",
                remediation=(
                    "Enable bucket versioning to help recover previous "
                    "object versions."
                ),
            )
        )

    # Check HTTPS enforcement using the simulated bucket policy.
    if not _has_https_deny_policy(
        config.get("bucket_policy"),
        config.get("bucket_name"),
    ):
        findings.append(
            _finding(
                check="https_only",
                severity="HIGH",
                message=(
                    "An explicit policy denying insecure transport "
                    "for the target bucket could not be verified."
                ),
                remediation=(
                    "Add a bucket policy with Effect Deny, an applicable "
                    "S3 action, the correct bucket and object resources, "
                    "and a Bool condition setting "
                    "aws:SecureTransport to false."
                ),
            )
        )

    return findings
