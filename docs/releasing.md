# Release procedure

Scenar builds reproducible synthetic security datasets.

The Python distribution includes authoring, dataset orchestration, telemetry
audits, visibility, provenance and disk/S3 delivery. The source archive also contains
tests, examples, the optional Nickel frontend and current documentation.
Scenar-owned code is licensed under [Apache 2.0](../LICENSE); component notices
remain attached to their code and data.

## Build and inspect

From the release checkout:

```sh
uv sync --locked
uv lock --check
uv run --locked pytest -q -ra
uv run --locked ruff check src tests tools
uv run --locked ruff format --check src tests tools
uv build
uv run --locked python tools/check_release.py dist/*.tar.gz dist/*.whl --require-license
```

The archive checker requires the console entry point, project description,
license, resource files and component notices. It rejects local work directories,
credentials, generated runs, caches, unsafe paths, links and common embedded
credential markers. `.local/` is ignored by Git and excluded from distributions.
The checker does not inspect Git history or perform a comprehensive secret scan.

Inspect the archive inventory and the Git content being released. Install the wheel
in a separate environment outside the checkout, then run `scenar --help` and a
`dataset prepare`/`dataset inspect` cycle. This checks installed resources without
source-tree imports masking packaging errors. Builds and core tests do not require
EvidenceForge, a Rust toolchain, a GPU or Docker.

## Verification scope

[Core CI](../.github/workflows/ci.yml) runs tests, lint, builds and archive validation
on hosted runners. It also exercises the installed wheel outside the source tree.
No package upload is automated.

Fresh generation requires a checkout matching the [backend pin](evidenceforge-sync.md)
and a provisioned host. The pin identifies a source snapshot, not a verified
pristine upstream revision. Record fresh-generation and live S3/RustFS results
separately from fixture tests and archive replay. Include exact versions, commands,
results and skipped checks in release evidence.

The [native host workflow](../.github/workflows/native-smoke.yml) is opt-in through
`SCENAR_NATIVE_SMOKE_ENABLED=true`. Its trusted runner, backend and store
requirements are documented in [host smoke checks](data-generation.md#fresh-native-host-smoke-checks).
