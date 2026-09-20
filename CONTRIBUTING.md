# Contributing

Thanks for helping improve `sbom-drift`.

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
