import contextlib
import io
import json
import unittest
from pathlib import Path

from sbom_drift.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)

    def test_lint_clean_sbom_exits_zero(self):
        code, out, _ = run_cli(["lint", str(FIXTURES / "baseline.json")])
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_lint_bad_hygiene_exits_nonzero_on_high_severity(self):
        code, _, _ = run_cli(["lint", str(FIXTURES / "bad_hygiene.json")])
        self.assertEqual(code, 1)

    def test_diff_drift_json_output_is_parseable(self):
        code, out, _ = run_cli(
            [
                "--format",
                "json",
                "diff",
                str(FIXTURES / "baseline.json"),
                str(FIXTURES / "current_drift.json"),
            ]
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["mode"], "diff")
        self.assertEqual(payload["finding_count"], len(payload["findings"]))
        self.assertTrue(any(f["check"] == "hash-changed-same-version" for f in payload["findings"]))

    def test_fail_on_never_always_exits_zero(self):
        code, _, _ = run_cli(
            [
                "--fail-on",
                "never",
                "diff",
                str(FIXTURES / "baseline.json"),
                str(FIXTURES / "current_drift.json"),
            ]
        )
        self.assertEqual(code, 0)

    def test_unrecognized_file_errors_cleanly(self):
        code, _, err = run_cli(["lint", str(FIXTURES / "not_a_real_file.json")])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_non_cyclonedx_json_errors_cleanly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps({"foo": "bar"}))
            code, _, err = run_cli(["lint", str(bad)])
        self.assertEqual(code, 2)
        self.assertIn("CycloneDX", err)


if __name__ == "__main__":
    unittest.main()
