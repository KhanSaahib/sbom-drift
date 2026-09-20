import unittest
from pathlib import Path

from sbom_drift.cyclonedx import load
from sbom_drift.lint import lint

FIXTURES = Path(__file__).parent / "fixtures"


class LintTests(unittest.TestCase):
    def test_clean_sbom_has_no_findings(self):
        doc = load(FIXTURES / "baseline.json")
        self.assertEqual(lint(doc), [])

    def test_bad_hygiene_sbom_flags_all_checks(self):
        doc = load(FIXTURES / "bad_hygiene.json")
        checks = {f.check for f in lint(doc)}
        self.assertIn("missing-hash", checks)
        self.assertIn("missing-license", checks)
        self.assertIn("unknown-version", checks)
        self.assertIn("duplicate-component-conflicting-version", checks)

    def test_missing_hash_flags_only_the_component_without_a_hash(self):
        doc = load(FIXTURES / "bad_hygiene.json")
        missing_hash = [f for f in lint(doc) if f.check == "missing-hash"]
        self.assertEqual(len(missing_hash), 1)
        self.assertEqual(missing_hash[0].component, "no-hash-pkg@1.0.0")

    def test_duplicate_component_reports_both_versions(self):
        doc = load(FIXTURES / "bad_hygiene.json")
        dup = [f for f in lint(doc) if f.check == "duplicate-component-conflicting-version"]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0].details["versions"], ["1.0.0", "1.1.0"])
        self.assertEqual(dup[0].severity, "high")

    def test_findings_sorted_with_highest_severity_first(self):
        doc = load(FIXTURES / "bad_hygiene.json")
        ranks = {"high": 3, "medium": 2, "low": 1, "info": 0}
        severities = [ranks[f.severity] for f in lint(doc)]
        self.assertEqual(severities, sorted(severities, reverse=True))


if __name__ == "__main__":
    unittest.main()
