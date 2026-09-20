# Notice and attributions

`sbom-drift` is original code written for this repository. No third-party
source code was copied into this project. The items below are the external
references that informed its design; each is credited even though nothing
was reused verbatim.

## Data format

- **CycloneDX specification** — https://cyclonedx.org/ — Apache License 2.0.
  `sbom_drift/cyclonedx.py` reads the public CycloneDX JSON field layout
  (field names such as `bomFormat`, `components`, `purl`, `hashes`,
  `licenses`). Only the documented, public JSON field layout was consulted;
  no code from the CycloneDX tooling repositories was copied.

## Conceptual prior art (ideas only, no code reused)

- **Anchore Syft / Grype** — https://github.com/anchore/syft,
  https://github.com/anchore/grype — Apache License 2.0. Popular tools for
  generating and scanning SBOMs; informed the general shape of an SBOM CLI
  (subcommands, JSON output) but no code or config was copied.
- **CycloneDX CLI** — https://github.com/CycloneDX/cyclonedx-cli — Apache
  License 2.0. Its `diff` subcommand suggested the value of SBOM-to-SBOM
  drift comparison; `sbom-drift`'s diff engine is an independent
  implementation with its own scoring/classification logic.
- **OWASP Dependency-Track** — https://github.com/DependencyTrack/dependency-track
  — Apache License 2.0. General inspiration for treating SBOM hygiene
  (missing hashes/licenses) as a first-class finding category.

If you believe any part of this project reproduces licensed code beyond
what is credited here, please open an issue.
