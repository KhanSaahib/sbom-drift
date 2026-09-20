"""Drift detection between two SBOM snapshots of the same build/artifact.

The interesting signal for supply-chain tampering is rarely "a dependency
changed" (that's normal) -- it's a component whose *name and version* stayed
identical but whose *hash* changed, or a new component silently entering the
tree between two SBOM snapshots that should otherwise be similar (e.g. two
runs of the same CI pipeline, or a nightly rebuild).
"""
from __future__ import annotations

from .cyclonedx import Component, SBOMDocument
from .findings import Finding, sort_findings


def _hash_changed(before: Component, after: Component) -> bool:
    common_algs = set(before.hashes) & set(after.hashes)
    if not common_algs:
        return False
    return any(before.hashes[alg] != after.hashes[alg] for alg in common_algs)


def diff(baseline: SBOMDocument, current: SBOMDocument) -> list[Finding]:
    findings: list[Finding] = []

    before_by_key = baseline.component_by_key()
    after_by_key = current.component_by_key()

    added_keys = set(after_by_key) - set(before_by_key)
    removed_keys = set(before_by_key) - set(after_by_key)
    common_keys = set(before_by_key) & set(after_by_key)

    for key in sorted(added_keys):
        c = after_by_key[key]
        findings.append(
            Finding(
                check="component-added",
                severity="medium",
                component=c.coordinate,
                message="new component present in current SBOM but absent from baseline",
            )
        )

    for key in sorted(removed_keys):
        c = before_by_key[key]
        findings.append(
            Finding(
                check="component-removed",
                severity="info",
                component=c.coordinate,
                message="component present in baseline is no longer in current SBOM",
            )
        )

    for key in sorted(common_keys):
        before = before_by_key[key]
        after = after_by_key[key]

        if before.version != after.version:
            findings.append(
                Finding(
                    check="version-changed",
                    severity="info",
                    component=before.name or key,
                    message=f"version changed: {before.version!r} -> {after.version!r}",
                    details={"before": before.version, "after": after.version},
                )
            )
            # A version bump naturally changes hashes; don't also flag it
            # as a same-version hash mismatch below.
            continue

        if _hash_changed(before, after):
            findings.append(
                Finding(
                    check="hash-changed-same-version",
                    severity="high",
                    component=before.coordinate,
                    message=(
                        "component contents changed while name and version "
                        "stayed identical -- possible tampering, a mutable "
                        "tag, or a non-reproducible build"
                    ),
                    details={"before_hashes": before.hashes, "after_hashes": after.hashes},
                )
            )
        elif before.hashes and not after.hashes:
            findings.append(
                Finding(
                    check="hash-removed-same-version",
                    severity="medium",
                    component=before.coordinate,
                    message="integrity hashes disappeared while name and version stayed identical",
                    details={"before_hashes": before.hashes, "after_hashes": after.hashes},
                )
            )

        before_licenses = set(before.licenses)
        after_licenses = set(after.licenses)
        if before_licenses != after_licenses:
            findings.append(
                Finding(
                    check="license-changed",
                    severity="low",
                    component=before.coordinate,
                    message=(
                        f"declared license changed: {sorted(before_licenses)} -> "
                        f"{sorted(after_licenses)}"
                    ),
                    details={
                        "before": sorted(before_licenses),
                        "after": sorted(after_licenses),
                    },
                )
            )

    return sort_findings(findings)
