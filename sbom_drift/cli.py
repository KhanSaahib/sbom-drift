from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .cyclonedx import SBOMFormatError, load
from .diff import diff as diff_sboms
from .findings import Finding
from .lint import lint as lint_sbom
from .report import render

MIN_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _max_severity_rank(findings: list[Finding]) -> int:
    if not findings:
        return -1
    return max(MIN_SEVERITY_RANK.get(f.severity, 0) for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-drift",
        description="Offline CycloneDX SBOM linter and drift detector.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "info", "never"),
        default="high",
        help="exit non-zero if a finding at or above this severity exists (default: high)",
    )
    parser.add_argument("-o", "--output", type=Path, help="write report to this path instead of stdout")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    lint_p = sub.add_parser("lint", help="check a single SBOM for hygiene issues")
    lint_p.add_argument("sbom", type=Path, help="path to a CycloneDX JSON SBOM")

    diff_p = sub.add_parser("diff", help="compare two SBOM snapshots for drift")
    diff_p.add_argument("baseline", type=Path, help="path to the baseline CycloneDX JSON SBOM")
    diff_p.add_argument("current", type=Path, help="path to the current CycloneDX JSON SBOM")

    return parser


def _emit(report_text: str, output: Path | None) -> None:
    if output:
        output.write_text(
            report_text if report_text.endswith("\n") else report_text + "\n",
            encoding="utf-8",
        )
    else:
        print(report_text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "lint":
            doc = load(args.sbom)
            findings = lint_sbom(doc)
            sources = {"sbom": doc.source_path}
            mode = "lint"
        else:
            baseline = load(args.baseline)
            current = load(args.current)
            findings = diff_sboms(baseline, current)
            sources = {"baseline": baseline.source_path, "current": current.source_path}
            mode = "diff"
    except SBOMFormatError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report_text = render(findings, mode=mode, sources=sources, fmt=args.format)
    try:
        _emit(report_text, args.output)
    except OSError as exc:
        print(f"error: could not write report: {exc}", file=sys.stderr)
        return 2

    if args.fail_on == "never":
        return 0
    threshold = MIN_SEVERITY_RANK[args.fail_on]
    return 1 if _max_severity_rank(findings) >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
