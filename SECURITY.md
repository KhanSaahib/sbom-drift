# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| `0.1.x` | Supported |
| Earlier versions | Not supported |

Only the latest patch release on the current minor line receives security
fixes. The `main` branch may contain unreleased changes.

## Reporting a vulnerability

Use the repository's **Security** tab to submit a private vulnerability
report. If private reporting is unavailable, open a minimal issue requesting a
private contact channel and do not include exploit details.

Include the affected version, a minimal reproduction, observed impact, and any
suggested remediation or embargo needs. The maintainer will acknowledge reports
on a best-effort basis, validate the impact, and coordinate disclosure before
publishing details.

## Scope

`sbom-drift` analyzes evidence supplied by an SBOM producer. A clean report is
not proof of artifact integrity, and a hash change is a signal to investigate,
not proof of compromise. Review report paths and component metadata before
sharing them outside your organization.
