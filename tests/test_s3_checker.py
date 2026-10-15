
import json
import unittest
from pathlib import Path

from src.cloudguard.s3_checker import check_s3_bucket

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = PROJECT_ROOT / "fixtures"


def load_fixture(filename: str) -> dict:
    """Load a local JSON test fixture."""
    with (FIXTURES_DIR / filename).open(encoding="utf-8") as file:
        return json.load(file)


class TestS3Checker(unittest.TestCase):

    def test_secure_bucket_has_no_findings(self):
        config = load_fixture("secure_bucket.json")

        findings = check_s3_bucket(config)

        self.assertEqual(findings, [])

    def test_empty_config_reports_all_seven_findings(self):
        findings = check_s3_bucket({})

        self.assertEqual(len(findings), 7)
        self.assertTrue(
            all(finding["severity"] for finding in findings)
        )
        self.assertTrue(
            all(finding["remediation"] for finding in findings)
        )

    def test_insecure_bucket_has_seven_findings(self):
        config = load_fixture("insecure_bucket.json")

        findings = check_s3_bucket(config)

        self.assertEqual(len(findings), 7)

    def test_findings_include_severity_and_remediation(self):
        config = load_fixture("insecure_bucket.json")

        findings = check_s3_bucket(config)

        for finding in findings:
            self.assertIn("severity", finding)
            self.assertIn("remediation", finding)
            self.assertIn("message", finding)
            self.assertTrue(finding["remediation"])

    def test_all_required_security_checks_are_present(self):
        config = load_fixture("insecure_bucket.json")

        findings = check_s3_bucket(config)
        checks = {finding["check"] for finding in findings}

        expected_checks = {
            "block_public_acls",
            "ignore_public_acls",
            "block_public_policy",
            "restrict_public_buckets",
            "encryption",
            "versioning",
            "https_only",
        }

        self.assertEqual(checks, expected_checks)


    def test_null_sections_do_not_crash(self):
        config = {
            "public_access_block": None,
            "encryption": None,
            "versioning": None,
        }

        findings = check_s3_bucket(config)

        self.assertEqual(len(findings), 7)

    def test_invalid_top_level_inputs_do_not_crash(self):
        invalid_inputs = [
            None,
            "not-a-config",
            [],
            123,
        ]

        for config in invalid_inputs:
            with self.subTest(config=config):
                findings = check_s3_bucket(config)
                self.assertEqual(len(findings), 7)

    def test_string_true_is_not_accepted_as_boolean_true(self):
        config = {
            "public_access_block": {
                "block_public_acls": "true",
                "ignore_public_acls": "true",
                "block_public_policy": "true",
                "restrict_public_buckets": "true",
            },
            "encryption": {"enabled": "true"},
            "versioning": {"enabled": "true"},
            "https_only": "true",
        }

        findings = check_s3_bucket(config)

        self.assertEqual(len(findings), 7)

    
    def test_https_policy_with_wrong_action_is_rejected(self):
        bucket_name = "demo-secure-bucket"
        bucket_arn = f"arn:aws:s3:::{bucket_name}"

        config = {
            "bucket_name": bucket_name,
            "bucket_policy": {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": [
                            bucket_arn,
                            f"{bucket_arn}/*",
                        ],
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false"
                            }
                        },
                    }
                ]
            },
        }

        findings = check_s3_bucket(config)
        checks = {finding["check"] for finding in findings}

        self.assertIn("https_only", checks)


    def test_https_policy_with_wrong_resource_is_rejected(self):
        config = {
            "bucket_name": "demo-secure-bucket",
            "bucket_policy": {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::different-bucket/*",
                        "Condition": {
                            "Bool": {
                                "aws:SecureTransport": "false"
                            }
                        },
                    }
                ]
            }
        }

        findings = check_s3_bucket(config)
        checks = {finding["check"] for finding in findings}

        self.assertIn("https_only", checks)


if __name__ == "__main__":
    unittest.main()
