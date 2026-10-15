
"""Offline S3 security configuration checker.

This module checks simulated JSON data only.
It does not connect to AWS or make API calls.
"""

from typing import Any


def check_s3_bucket(config: dict[str, Any]) -> list[dict[str, str]]:
    """Return security findings for a simulated S3 bucket configuration."""
    findings: list[dict[str, str]] = []

    public_access = config.get("public_access_block", {})
    public_checks = {
        "block_public_acls": "Block public ACLs",
        "ignore_public_acls": "Ignore public ACLs",
        "block_public_policy": "Block public bucket policies",
        "restrict_public_buckets": "Restrict public buckets",
    }

    for setting, description in public_checks.items():
        if public_access.get(setting) is not True:
            findings.append({
                "check": setting,
                "severity": "HIGH",
                "message": f"Missing protection: {description}.",
                "remediation": f"Set {setting} to true.",
            })

    if config.get("encryption", {}).get("enabled") is not True:
        findings.append({
            "check": "encryption",
            "severity": "HIGH",
            "message": "Default server-side encryption is not enabled.",
            "remediation": "Enable default server-side encryption for the bucket.",
        })

    if config.get("versioning", {}).get("enabled") is not True:
        findings.append({
            "check": "versioning",
            "severity": "MEDIUM",
            "message": "Bucket versioning is not enabled.",
            "remediation": "Enable bucket versioning to help recover previous object versions.",
        })

    if config.get("https_only") is not True:
        findings.append({
            "check": "https_only",
            "severity": "HIGH",
            "message": "Explicit HTTPS-only enforcement is missing.",
            "remediation": (
                "Add a bucket policy that denies requests when "
                "aws:SecureTransport is false."
            ),
        })

    return findings
