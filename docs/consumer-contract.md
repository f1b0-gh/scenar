# Consumer data contract

Scenar exports generated telemetry for downstream normalization and analysis.
The integration boundary is **Scenar → normalization pipeline → Detect**.
Normalization, detector inference, investigation and dossier construction are
outside Scenar. This repository supplies no normalization pipeline or Detect
runtime and does not require either to generate or export datasets.

## Export observations

Verify a completed bundle and export its approved observations:

```sh
scenar verify runs/dataset
scenar export-public runs/dataset --output exports/normalization-input
```

The destination must be new. `export-public` verifies the source bundle and copies
only approved `public/` files, removing that prefix. Dataset exports are checked
against the capture inventory or reconstructed derived view before copying.

| Source workflow | Public export |
| --- | --- |
| `scenar dataset` | Windows Security/Sysmon XML and Zeek connection/DNS files, grouped by capture digest or derived-view ID |
| Investigation reference pack | Candidate feeds and public JSON views used by the [reference harness](reference-tools.md#reference-evaluation) |

These formats are distinct. Dataset exports retain source telemetry formats;
Scenar does not convert them to a Detect-specific schema. Generated formats outside
the export allowlist, including eCAR, stay in the restricted capture.

Derived views preserve source timestamps. Their visibility transformations and
availability assumptions are described in [dataset generation](data-generation.md#qualify-a-deliberately-degraded-public-view).
Missing records do not establish benign activity or the absence of an event.

## Restricted provenance and truth

The full bundle is for the trusted experiment controller and evaluator. It
contains material that must not be exposed as detector input:

| Artifact | Purpose |
| --- | --- |
| `manifest.json` | Versioned inventory with file paths, sizes, SHA-256 hashes and capture/view identity |
| Frozen scenarios, backend identity and source configuration | Reproduction and integrity checks |
| Private ground truth and audit reports | Scoped labels and evidence qualification |
| `reports/visibility/CASE.json` in derived mode | Source/output hashes, record inclusion decisions and modeled availability |
| `scenar dataset lineage RUN` output | Capture ancestry, family/environment identity and split validation |

`export-public` does not copy the full manifest, private truth, lineage or visibility
receipts. They can reveal scenario structure or omitted records. Restrict access
to the source bundle and store independently of the public export directory.

## Evaluation references

Scenar's coverage and intent-grading commands accept explicit consumer results
linked to source evidence. Their formats are documented in
[ground truth and coverage](attack-ground-truth.md#qualified-packs-replay-and-coverage).
Downstream normalization must retain the source references needed for that linkage;
a normalized record ID alone does not identify a Scenar native observation.

Qualification checks generation acceptance and emitted evidence, independently of
Detect's decisions. Public views and normalized derivatives of one capture share
that capture's ancestry; they are not independent evaluation samples. Use
[lineage and split validation](data-generation.md#inspect-lineage-and-validate-splits)
with the restricted metadata when organizing experiments.
