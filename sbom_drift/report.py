"""Render findings as text, markdown, or JSON."""
from __future__ import annotations

import json

from .findings import Finding

SEVERITY_LABEL = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def to_json(findings: list[Finding], *, mode: str, sources: dict[str, str]) -> str:
    payload = {
        "mode": mode,
        "sources": sources,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def to_text(findings: list[Finding], *, mode: str, sources: dict[str, str]) -> str:
    lines = [f"sbom-drift {mode} report"]
    for label, path in sources.items():
        lines.append(f"  {label}: {path}")
    if not findings:
        lines.append("\nNo findings.")
        return "\n".join(lines)

    lines.append(f"\n{len(findings)} finding(s):\n")
    for f in findings:
        lines.append(f"[{SEVERITY_LABEL.get(f.severity, f.severity.upper())}] {f.check} - {f.component}")
        lines.append(f"    {f.message}")
    return "\n".join(lines)


def to_markdown(findings: list[Finding], *, mode: str, sources: dict[str, str]) -> str:
    lines = [f"# sbom-drift {mode} report", ""]
    for label, path in sources.items():
        lines.append(f"- **{label}**: `{path}`")
    lines.append("")
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("| Severity | Check | Component | Message |")
    lines.append("|---|---|---|---|")
    for f in findings:
        message = f.message.replace("|", "\\|")
        lines.append(
            f"| {SEVERITY_LABEL.get(f.severity, f.severity)} | {f.check} | "
            f"`{f.component}` | {message} |"
        )
    return "\n".join(lines)


RENDERERS = {"text": to_text, "markdown": to_markdown, "json": to_json}


def render(findings: list[Finding], *, mode: str, sources: dict[str, str], fmt: str) -> str:
    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:
        raise ValueError(f"unknown format: {fmt!r}") from exc
    return renderer(findings, mode=mode, sources=sources)
