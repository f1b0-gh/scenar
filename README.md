# Scenar

Scenar builds reproducible synthetic security datasets

Author scenarios, generate telemetry with EvidenceForge, audit emitted evidence,
and publish verified datasets. Scenar keeps private ground truth separate from
public observations and records the configuration, seeds and source identities
needed to inspect or reproduce a run.

- **Controlled datasets:** reusable families, benign/malicious controls, routine
  activity, environment sizes and configurable telemetry visibility.
- **Auditable output:** native record checks, explicit unknowns, private truth,
  reproducible visibility receipts and dataset lineage.
- **Reliable runs:** frozen inputs, resumable execution, retained failures,
  preflight checks and measured runtime history.
- **Verified delivery:** checksummed disk/S3 bundles and explicit public exports.

## Relationship to EvidenceForge

[EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) is the external engine
that generates synthetic telemetry. Scenar invokes its `eforge` CLI in a separately
managed environment and records the exact backend identity used for each run.

| Component | Responsibility |
| --- | --- |
| EvidenceForge | Scenario validation, telemetry generation and backend quality reports |
| Scenar | Scenario authoring, dataset matrices, seeds, execution/resume, native evidence audits, ground truth, visibility, provenance and exports |

Dataset qualification requires both EvidenceForge's explicit acceptance verdict
and Scenar's audit of the emitted evidence. EvidenceForge is installed separately;
Scenar does not bundle or patch its generator. See
[backend setup](docs/evidenceforge-sync.md) for the required source pin and
[component provenance](ACKNOWLEDGEMENTS.md) for the retained helper-code notices.

The integration boundary is **Scenar → normalization pipeline → Detect**.
Scenar exports telemetry in its generated formats. Normalization and detector
runtime are outside this repository; neither is required to generate or export data.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). Nickel and Docker
are optional. From a source checkout:

```sh
uv sync --locked
uv run --locked scenar --help

# Prepare and inspect a small matrix without generating telemetry.
uv run --locked scenar dataset prepare examples/dataset-small.yaml --output runs/small
uv run --locked scenar dataset inspect runs/small

# Select a compatible EvidenceForge checkout, then check and run it.
export SCENAR_EVIDENCEFORGE=/path/to/EvidenceForge
uv run --locked scenar dataset preflight runs/small
uv run --locked scenar dataset run runs/small

# Export observations only, after checking the generated dataset.
uv run --locked scenar export-public runs/small --output exports/small
```

Generation requires the exact configured backend identity. The checked-in pin is
an inspected EvidenceForge snapshot, **not a verified pristine upstream release**;
an arbitrary checkout with the same version may differ. Read
[backend setup and synchronization](docs/evidenceforge-sync.md) before selecting it.

After stopping an interrupted run, reuse verified captures in a new run:

```sh
uv run --locked scenar dataset resume runs/small --output runs/retry
```

Output directories must be new. Failed or unqualified attempts remain inspectable;
only fully qualified datasets can advance the normal publication pointer.
The full bundle contains private truth: distribute only an explicit public export
to consumers that must not see labels or authoring state.

## Documentation

- [Dataset generation, visibility, resume, lineage and diagnostics](docs/data-generation.md)
- [ATT&CK mapping, ground truth and background activity](docs/attack-ground-truth.md)
- [Disk/S3 storage and local RustFS](docs/storage.md)
- [Consumer data contract](docs/consumer-contract.md)
- [Reference and compatibility commands](docs/reference-tools.md)
- [Contributing and verification](CONTRIBUTING.md)
- [Release procedure](docs/releasing.md)
- [Documentation index](docs/README.md)

## Attribution and scope

Scenar-owned code is licensed under the [Apache License 2.0](LICENSE).
Third-party components retain their own notices and terms.

See [acknowledgements and component provenance](ACKNOWLEDGEMENTS.md) for
EvidenceForge and MITRE ATT&CK attribution.

The project is experimental. Fresh generation requires a compatible backend and a
provisioned host. See the [release procedure](docs/releasing.md) for verification scope.
