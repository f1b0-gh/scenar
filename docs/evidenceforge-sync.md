# EvidenceForge setup and identity

Scenar uses an external EvidenceForge checkout. Set its location with
`SCENAR_EVIDENCEFORGE` or a command's `--backend` option. Scenar does not install or
patch the backend.

EvidenceForge validates scenarios, generates telemetry and produces backend quality
reports. Scenar invokes these stages through `uv run --locked --project CHECKOUT
eforge`, then checks the acceptance verdict and audits emitted records against the
dataset's declared effects. Scenar owns the dataset matrix, frozen inputs, retries,
visibility transformations, ground truth, lineage and storage. Both the generator's
acceptance and the native audit must pass for dataset qualification.

## Active pin

The same identity is retained in `toolchains/evidenceforge.json` for review and
`src/scenar/resources/evidenceforge.json` for installed commands:

- EvidenceForge package version: `2.1.2`.
- Generation behavior revision: `162`.
- Source and dependency-lock SHA-256 digests.
- `revision: null` and `upstream_verified: false`.

This is an inspected source snapshot, not a verified pristine upstream revision.
An arbitrary checkout with the same package version is not sufficient. The exact
digests in the pin are authoritative.

`inspect_backend` hashes `src/evidenceforge`, the command implementation,
`pyproject.toml` and `uv.lock`, excluding Python bytecode. Preparation freezes the
selected identity, and generation checks it. Prepare/validate/generate commands
enforce the packaged active pin; `--pin` selects an explicit alternative.

```sh
scenar backend inspect --backend /path/to/EvidenceForge
scenar backend check --backend /path/to/EvidenceForge --pin toolchains/evidenceforge.json
```

The backend needs its own locked environment and filesystem permissions. For a
prepared dataset, check readiness without generating telemetry:

```sh
scenar dataset preflight runs/dataset --backend /path/to/EvidenceForge
```

See [preflight and runtime measurements](data-generation.md#preflight-and-measured-runtime-history)
for the supported checks. Successful preflight establishes prerequisites, not
generation success.

## Compare backends

```sh
mkdir -p checks
scenar backend compare /path/to/candidate --backend /path/to/active
scenar backend compare /path/to/candidate --backend /path/to/active \
  --matrix-output checks/candidate-01
scenar backend schema --backend /path/to/candidate > checks/candidate-schema.json
```

The compatibility matrix runs two seeds each of `benign_only` and
`independent_shared_parent` on both backends. Its verdict covers complete
qualification of those cases. Schema differences and failed slots are retained;
the verdict does not establish compatibility for every recipe or platform.
The matrix output directory must be new.

When changing the active backend, review its source/configuration differences,
run the relevant generation and regression checks, and update the packaged and
reviewable pins together. Existing frozen runs require their recorded identities.
Changing the backend produces a new capture, not a replay. No automatic backend
synchronization or pin update runs in the background.

## Nickel contracts

`generated/ef_events.ncl` supplies the optional authoring contracts. Nickel checks
supported scalar/event shapes. Nullable unions, nested references and unsupported
schema forms use `Dyn`; backend validation remains authoritative. These contracts
are not a complete EvidenceForge validator.

To generate contracts from a selected checkout:

```sh
uv run --locked --project /path/to/EvidenceForge python \
  /path/to/scenar/tools/gen_ef_contracts.py > checks/ef_events.ncl
```

The generator records a canonical scenario-schema digest in its output. Review
contract changes and run `bash tests/run.sh` with Nickel installed before replacing
`generated/ef_events.ncl`.
