"""Minimal reader for CycloneDX JSON SBOM documents.

Only the public CycloneDX 1.4/1.5 JSON field layout is consulted (see
NOTICE.md). Unknown/extra fields are ignored rather than rejected, since
SBOM producers vary in how much optional detail they emit.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SBOMFormatError(ValueError):
    """Raised when a file is not a recognizable CycloneDX SBOM."""


_PURL_VERSION_RE = re.compile(r"@[^?#]+")


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    type: str = "library"
    purl: str | None = None
    bom_ref: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    licenses: tuple[str, ...] = ()
    supplier: str | None = None

    @property
    def key(self) -> str:
        """Identity used to match the "same" component across two SBOMs.

        A purl embeds its version (`pkg:npm/left-pad@1.3.0`), so matching on
        the raw purl would treat a version bump as a remove+add instead of a
        version change. The version segment is stripped so the same package
        at two different versions still resolves to one identity; falls
        back to name alone for components with no purl at all.
        """
        if self.purl:
            return _PURL_VERSION_RE.sub("", self.purl, count=1)
        return self.name

    @property
    def coordinate(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass(frozen=True)
class SBOMDocument:
    format: str
    spec_version: str
    serial_number: str | None
    components: tuple[Component, ...]
    source_path: str

    def component_by_key(self) -> dict[str, Component]:
        by_key: dict[str, Component] = {}
        for c in self.components:
            # First occurrence wins; duplicate keys are surfaced separately
            # by the lint pass (see lint.duplicate_components).
            by_key.setdefault(c.key, c)
        return by_key


def _extract_licenses(raw_licenses: Any) -> tuple[str, ...]:
    if not raw_licenses:
        return ()
    names: list[str] = []
    for entry in raw_licenses:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            name = lic.get("id") or lic.get("name")
            if name:
                names.append(str(name))
        elif entry.get("expression"):
            names.append(str(entry["expression"]))
    return tuple(names)


def _extract_hashes(raw_hashes: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not raw_hashes:
        return out
    for entry in raw_hashes:
        if isinstance(entry, dict) and entry.get("alg") and entry.get("content"):
            out[str(entry["alg"])] = str(entry["content"])
    return out


def _parse_component(raw: dict[str, Any]) -> Component:
    return Component(
        name=str(raw.get("name", "")),
        version=str(raw.get("version", "")),
        type=str(raw.get("type", "library")),
        purl=raw.get("purl"),
        bom_ref=raw.get("bom-ref") or raw.get("bomRef"),
        hashes=_extract_hashes(raw.get("hashes")),
        licenses=_extract_licenses(raw.get("licenses")),
        supplier=(raw.get("supplier") or {}).get("name")
        if isinstance(raw.get("supplier"), dict)
        else None,
    )


def load(path: str | Path) -> SBOMDocument:
    """Load and validate a CycloneDX JSON SBOM from disk."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SBOMFormatError(f"{p}: not valid JSON ({exc})") from exc

    if not isinstance(raw, dict) or raw.get("bomFormat") != "CycloneDX":
        raise SBOMFormatError(
            f"{p}: missing or unrecognized 'bomFormat' — expected a CycloneDX "
            "SBOM (bomFormat: \"CycloneDX\")"
        )

    components_raw = raw.get("components") or []
    if not isinstance(components_raw, list):
        raise SBOMFormatError(f"{p}: 'components' must be a list")

    components = tuple(
        _parse_component(c) for c in components_raw if isinstance(c, dict)
    )

    return SBOMDocument(
        format=raw.get("bomFormat", ""),
        spec_version=str(raw.get("specVersion", "")),
        serial_number=raw.get("serialNumber"),
        components=components,
        source_path=str(p),
    )
