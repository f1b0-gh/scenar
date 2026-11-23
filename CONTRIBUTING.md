# Contributing

Scenar builds reproducible synthetic security datasets. Keep changes focused on
authoring, generation, data fidelity, provenance, visibility and delivery. Detector
runtimes and model evaluation belong to consumers.

## Development environment

Use Python 3.12+ and uv from the repository root:

```sh
uv sync --locked
uv run --locked pytest -q
uv run --locked ruff check src tests tools
uv run --locked ruff format --check src tests tools
uv lock --check
uv run --locked scenar --help
```

The normal suite uses controlled backend processes and native fixtures. It does not
require a sibling checkout, running EvidenceForge, Docker or Nickel.
Optional tests skip unless their explicit prerequisite is provided.

Read [the Python guide](skills/python/SKILL.md) before implementation or review.
Use versioned Pydantic contracts and preserve strict acceptance flags, integer time
units, failed attempts, and public/private boundaries. Never change imported source
provenance to hide a modification.

## Optional checks

- With Nickel on PATH: `bash tests/run.sh` and the Nickel pytest tests.
- `SCENAR_PARITY_ARCHIVE`: a preserved investigation archive for replay parity.
- `SCENAR_C2_ARCHIVE`: the preserved 12-view C2 archive named in the
  [regression catalogue](packs/regressions.json).
- `SCENAR_ANNOTATED_ARCHIVE`: an annotated frozen replay for coverage integrity.

These archives are historical regression material and are not included in the
repository or distributions. Do not mistake a skipped check or reused capture for
a fresh native verification result.

[Native host smoke checks](docs/data-generation.md#fresh-native-host-smoke-checks)
use a compatible pinned backend and a separate trusted runner. They do not run
untrusted pull-request code. Core CI runs on hosted runners without secrets.

## Before a release

Follow [the release guide](docs/releasing.md). Verify the actual source and wheel
archives and run the installed wheel outside the checkout. Include the tests run,
any skipped integrations and unresolved limitations in the change description.

## Documentation

Keep the README and `docs/` limited to current interfaces, behavior and procedures.
Use the [documentation index](docs/README.md) as the entry point. Store work plans,
superseded versions, proposals and local execution notes in gitignored `.local/`.
Do not link published documentation to that private working directory. License
notices and provenance for shipped components remain part of the distribution.
