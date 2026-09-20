"""Single-SBOM hygiene checks.

These catch the SBOM-quality gaps that quietly defeat the purpose of
publishing an SBOM at all: components nobody can verify (no hash), whose
license terms are unknown, or whose identity is ambiguous (two entries for
the same purl claiming different versions).
"""
from __future__ import annotations

from collections import defaultdict

from .cyclonedx import Component, SBOMDocument
from .findings import Finding, sort_findings

UNKNOWN_VERSION_MARKERS = {"", "latest", "unknown", "0.0.0", "unspecified"}


def check_missing_hash(components: tuple[Component, ...]) -> list[Finding]:
    findings = []
    for c in components:
        if not c.hashes:
            findings.append(
                Finding(
                    check="missing-hash",
                    severity="medium",
                    component=c.coordinate,
                    message=(
                        "component has no integrity hash recorded; a rebuild "
                        "or registry compromise swapping its contents would "
                        "be undetectable"
                    ),
                )
            )
    return findings


def check_missing_license(components: tuple[Component, ...]) -> list[Finding]:
    findings = []
    for c in components:
        if not c.licenses:
            findings.append(
                Finding(
                    check="missing-license",
                    severity="low",
                    component=c.coordinate,
                    message="component declares no license information",
                )
            )
    return findings


def check_unknown_version(components: tuple[Component, ...]) -> list[Finding]:
    findings = []
    for c in components:
        if c.version.strip().lower() in UNKNOWN_VERSION_MARKERS:
            findings.append(
                Finding(
                    check="unknown-version",
                    severity="medium",
                    component=c.name or "(unnamed component)",
                    message=(
                        f"version is missing or a floating marker "
                        f"({c.version!r}); drift between builds cannot be "
                        "tracked for this component"
                    ),
                )
            )
    return findings


def check_duplicate_components(components: tuple[Component, ...]) -> list[Finding]:
    """Flag the same package identity appearing with conflicting versions.

    This is the SBOM-level equivalent of a dependency-confusion smell: two
    entries claiming to be the same package but disagreeing on version
    usually means the SBOM was assembled from inconsistent sources.
    """
    by_key: dict[str, set[str]] = defaultdict(set)
    for c in components:
        by_key[c.key].add(c.version)

    findings = []
    for key, versions in by_key.items():
        if len(versions) > 1:
            findings.append(
                Finding(
                    check="duplicate-component-conflicting-version",
                    severity="high",
                    component=key,
                    message=(
                        "same component identity appears multiple times with "
                        f"conflicting versions: {sorted(versions)}"
                    ),
                    details={"versions": sorted(versions)},
                )
            )
    return findings


CHECKS = (
    check_missing_hash,
    check_missing_license,
    check_unknown_version,
    check_duplicate_components,
)


def lint(doc: SBOMDocument) -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(doc.components))
    return sort_findings(findings)
