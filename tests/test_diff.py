import unittest
from pathlib import Path

from sbom_drift.cyclonedx import Component, SBOMDocument, load
from sbom_drift.diff import diff

FIXTURES = Path(__file__).parent / "fixtures"


class DiffTests(unittest.TestCase):
    def test_identical_sboms_produce_no_findings(self):
        baseline = load(FIXTURES / "baseline.json")
        current = load(FIXTURES / "current_clean.json")
        self.assertEqual(diff(baseline, current), [])

    def test_drifted_sbom_flags_added_version_and_hash_changes(self):
        baseline = load(FIXTURES / "baseline.json")
        current = load(FIXTURES / "current_drift.json")
        checks = {f.check: f for f in diff(baseline, current)}

        self.assertIn("hash-changed-same-version", checks)
        self.assertEqual(checks["hash-changed-same-version"].component, "left-pad@1.3.0")
        self.assertEqual(checks["hash-changed-same-version"].severity, "high")

        self.assertIn("version-changed", checks)
        self.assertEqual(
            checks["version-changed"].details, {"before": "2.31.0", "after": "2.32.0"}
        )

        self.assertIn("component-added", checks)
        self.assertEqual(checks["component-added"].component, "mystery-pkg@0.0.1")

        self.assertIn("component-removed", checks)
        self.assertEqual(checks["component-removed"].component, "internal-utils@0.4.1")

    def test_version_change_does_not_also_report_hash_changed(self):
        baseline = load(FIXTURES / "baseline.json")
        current = load(FIXTURES / "current_drift.json")
        requests_findings = [f for f in diff(baseline, current) if "requests" in f.component]
        self.assertEqual({f.check for f in requests_findings}, {"version-changed"})

    def test_license_change_detected_for_same_version(self):
        before = SBOMDocument(
            format="CycloneDX",
            spec_version="1.5",
            serial_number=None,
            components=(
                Component(
                    name="pkg", version="1.0.0", purl="pkg:npm/pkg@1.0.0", licenses=("MIT",)
                ),
            ),
            source_path="before.json",
        )
        after = SBOMDocument(
            format="CycloneDX",
            spec_version="1.5",
            serial_number=None,
            components=(
                Component(
                    name="pkg",
                    version="1.0.0",
                    purl="pkg:npm/pkg@1.0.0",
                    licenses=("GPL-3.0",),
                ),
            ),
            source_path="after.json",
        )
        findings = diff(before, after)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check, "license-changed")


if __name__ == "__main__":
    unittest.main()
