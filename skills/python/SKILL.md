---
name: python
description: Use when implementing or reviewing Scenar's Python CLI, Pydantic models, uv packaging, EvidenceForge adapters, or downstream dataset contracts.
---

# Python development for Scenar

Scenar is a Python application with typed boundaries and reproducible execution. Use the [documentation index](../../docs/README.md) for current interfaces. Keep work plans, superseded documentation and execution notes in gitignored `.local/`; published documentation describes implemented behavior.

## Package and execution

- Keep application code in `src/scenar/`; expose `scenar.cli:main` through `[project.scripts]`. Shell launchers only forward arguments. Nickel is an optional authoring frontend, not a core runtime requirement.
- Inspect `pyproject.toml` and `uv.lock` before changing dependencies. Use `uv add` for runtime dependencies and `uv add --dev` for development tools; review both files. Do not install into the system Python or edit generated lockfiles manually.
- Use Pydantic v2 and Python 3.12 or newer, as declared in `pyproject.toml`.
- Keep CLI parsing, filesystem/network I/O, and backend invocation separate from testable domain logic. Use explicit typed parameters and return values; validate external data once at its boundary.

## Pydantic contracts

- Use `BaseModel` for configuration, protocols, manifests, external records, and results. For Scenar-owned versioned contracts, use `ConfigDict(extra="forbid")`, explicit schema versions, and strict types where coercion changes meaning. Backend adapters declare their own policy for extra upstream fields.
- Require actual booleans for acceptance flags: neither `"false"` nor `0` is a valid substitute. A missing acceptance verdict is invalid, not success. Keep missing, unknown, false, and empty distinct.
- Validate through the real reader: strict JSON validation and strict Python-object validation differ for dates and similar values. For YAML, normalize allowed timestamp representations explicitly; reject naive or date-only timestamps where an instant is required. Preserve exact integer time units.
- Use Pydantic v2 validation, serialization, and schema APIs (`model_validate`, `model_validate_json`, `model_dump`, `model_dump_json`, `model_json_schema`). Never bypass validation with `model_construct` for external inputs.
- Use field constraints and model validators for finite values, time intervals, and cross-field invariants. Avoid `dict[str, Any]` as a substitute for a stable contract; retain it only for intentionally opaque backend payloads.

## EvidenceForge and evaluation boundaries

Keep EvidenceForge unchanged and separately pinned. Scenar-owned evaluation helpers live in Scenar; generator fixes belong upstream. Record source/configuration identity, not just the installed package version.

Qualification requires both backend acceptance and native audit success. Exit zero and a high score do not establish eligibility. Preserve the declared acceptance contract when changing orchestration.

Separate public observations from private authoring truth and broker replay state. Public exports use explicit allowlists. Validate hashes, cutoffs, and availability before evaluation; preserve rejected attempts and unknown outcomes.

## Downstream consumers

Supply generated telemetry through exported files and versioned data contracts. A downstream normalization pipeline parses these files and supplies normalized inputs to Detect. Scenar does not implement that pipeline. Detect owns ingestion of normalized inputs, inference, investigation, dossier construction and performance evaluation. Do not import or embed Detect runtime code to supply its inputs.

Keep public detector observations separate from restricted manifests, capture lineage, visibility receipts and grader truth. The trusted experiment controller retains provenance and chooses splits; do not copy private authoring metadata into public exports for convenience.

Native telemetry audits and host smoke tests refer to backend-emitted evidence. Normalization and detector runtime code are outside this repository's scope.

## Verification

From the repository root:

| Purpose | Command |
|---|---|
| Check dependency consistency | `uv lock --check` |
| Reproduce the environment | `uv sync --locked` |
| Exercise affected behavior | `uv run --locked pytest tests/<affected_test>.py -q` |
| Lint and formatting | `uv run --locked ruff check src tests tools` and `uv run --locked ruff format --check src tests tools` |
| CLI smoke check | `uv run --locked scenar --help` |

Test meaningful boundaries: serialized round trips, invalid acceptance flags, native-audit rejection, unknown schema versions and private-field leakage. Test an installed wheel outside the source tree. Run broader checks when the change warrants them; report skipped or unavailable checks explicitly. Do not bootstrap the application merely to validate a documentation edit.

For version-specific behavior, consult the installed dependencies and official references: [Pydantic strict validation](https://docs.pydantic.dev/latest/concepts/strict_mode/) and [uv locking](https://docs.astral.sh/uv/concepts/projects/sync/).
