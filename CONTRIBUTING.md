# Contributing

Thanks for helping improve `sbom-drift`.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
For usage questions, read [SUPPORT.md](SUPPORT.md). Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

Keep the runtime dependency-free and offline. New lint or drift checks should
include clean and failing fixtures, define an actionable severity, and avoid
describing a signal as proof of compromise. Preserve unknown CycloneDX fields
so the reader remains forward-compatible.

## Pull requests

- Keep each pull request focused and explain the user-facing impact.
- Add clean and failing fixtures for new lint or drift behavior.
- Update the README and `[Unreleased]` changelog for user-visible changes.
- Run `python -m pytest -q` and `python -m build` before requesting review.
- Do not include private SBOMs, package inventories, or proprietary artifacts.

Maintainers may request changes when evidence is incomplete, behavior is not
deterministic, or a contribution expands the project's stated scope.
