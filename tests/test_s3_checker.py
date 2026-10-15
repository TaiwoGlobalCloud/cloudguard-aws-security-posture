
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


if __name__ == "__main__":
    unittest.main()
