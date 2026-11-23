# Controlled synthetic datasets

Scenar prepares and generates a frozen matrix of synthetic workflows without
executing detector policies. It exports telemetry for downstream normalization
and keeps truth restricted to evaluation. See the [consumer contract](consumer-contract.md).
EvidenceForge is the separately pinned engine that produces the native records.

## Families and controls

| Family | Authored workflow and checked effects |
| --- | --- |
| `inventory_archive` | Remote session, process lineage, discovery, archive process and actual archive-file creation |
| `remote_access` | RDP session and linked execution on the destination host |
| `persistence` | Scheduled-task and service installation, actor/domain and session identity |
| `credential_access` | Process access to LSASS, requested access mask and exact source process |
| `c2` | Synthetic TLS contacts with periodic, burst, sparse or rotating-destination patterns and native Zeek connection evidence |

These are supported synthetic manifestations, not all ATT&CK techniques. Installing
a service/task does not prove its later execution. A process-access event does not
prove credentials were extracted. TLS contacts do not prove commands were received.
Persistent-connection and DNS-tunnel C2 are not claimed by these recipes.

Every family supports `normal`, `benign`, `malicious`, `mixed` and `ambiguous`.
`normal` contains scheduled routine activity and background only. Benign/malicious
controls keep neutral tools, commands and names while changing remote-session
source provenance. This is a controlled intervention, not a rule that a particular
source host proves compromise. `mixed` places both focal workflows in the same
environment. `ambiguous` preserves the benign authored Forge scenario with unknown
focal intent, explicitly retaining the limits of what observations can establish.

Routine cycles add sessions, administration, backups and unusual legitimate
diagnostics. Their explicit authored labels remain private. Unindexed baseline
records remain unknown; they are not automatically labeled benign. Changed
scenarios can change background bytes despite identical seeds.

## Environment and visibility choices

| Size | Hosts | Users |
| --- | ---: | ---: |
| `small` | 3 | 2 |
| `medium` | 10 | 8 |
| `large` | 30 | 28 |

All sizes include `DC-01`, `FILE-01`, `WS-01` and a network sensor. Hosts/users,
segments and references are generated together. Scenar does not prune arbitrary
user scenarios or silently lower workload to fit a timeout. The recipes retain
one hour of warm-up; duration, routine cycles, baseline intensity and stage timeout
are explicit. Source omissions such as the absence of a firewall remain backend
validation warnings, not an assertion that those sources were simulated.

Visibility settings compile into the backend's exact deployed source identities:

```yaml
visibility:
  - mode: complete
  - mode: lossy
    probability: 0.2
    hosts: [FILE-01]
  - mode: delayed
    delay_us: 60000000
    hosts: [FILE-01]
  - mode: missing_endpoint
    hosts: [FILE-01]
```

`complete` preserves the existing collection policy. Loss probability and batching
intervals are applied by Forge. Batching approximates delayed delivery; it is not
a guarantee of a fixed per-record delay or a reconstructed availability timestamp.
`missing_endpoint` disables both Windows Security and Sysmon on explicitly selected
hosts, retaining network collection. Alternatively select exact `source_instances`.
Unknown or conflicting selectors fail instead of silently changing another source.

## Prepare, inspect and generate

```sh
# Five slots, one family/size/seed. No backend generation during prepare.
uv run --locked scenar dataset prepare examples/dataset-small.yaml --output runs/dataset
uv run --locked scenar dataset inspect runs/dataset
uv run --locked scenar dataset run runs/dataset --backend /path/to/EvidenceForge

# Equivalent Nickel authoring:
uv run --locked scenar dataset prepare examples/dataset-small.ncl --output runs/from-nickel

uv run --locked scenar dataset schema spec
uv run --locked scenar dataset schema visibility
uv run --locked scenar dataset schema expectations
```

[dataset-matrix.yaml](../examples/dataset-matrix.yaml) expands to **480 slots**:
all families, intent variants, sizes, visibility modes and four C2 patterns. It is
an explicit coverage matrix, not a cheap smoke test. Preparing it does not run it.
Select a bounded matrix appropriate for available time before generation.

The same API is available in Python:

```python
from pathlib import Path
from scenar.datasets.matrix import DatasetSpec, prepare_dataset, run_dataset
from scenar.datasets.visibility import VisibilitySettings

spec = DatasetSpec(
    families=["remote_access", "persistence"],
    variants=["benign", "malicious", "mixed"],
    sizes=["small"],
    seeds=[9501],
    visibility=[VisibilitySettings()],
    stage_timeout_seconds=1800,
)
prepare_dataset(spec, Path("runs/native"))
report = run_dataset(Path("runs/native"), backend=Path("/path/to/EvidenceForge"))
```

Preparation freezes scenarios, expectation contracts, backend/catalogue identity,
seeds, configuration and Scenar sources. Source drift prevents execution or qualified
publication. Install the matching implementation to handle that frozen run, or
prepare a new run after an upgrade. Existing directories cannot be reused for retries.
Every planned case remains in the report, including failed generation and missing
native evidence. A malformed stage status does not discard later matrix slots.
`distinct_native_captures` counts unique native digests; distinct bytes alone do not
establish statistical independence. Many cases share recipes and environments.

## Native audits and delivery

Each expected effect is matched to actual Windows Security/Sysmon XML or Zeek
connection/DNS records with file hashes and native record locators. Process/file,
process-access and session relationships use native GUIDs/logon IDs. Authored
identity joins use the backend intent ledger, including reordered output. Beacon
checks anchor recurring ticks to the actual emitted start time. Missing, ambiguous,
unsupported and observed outcomes remain distinct.

The audit reconciles declared effects; it does not index every ambient or backend
occurrence. A passing command line or backend score cannot
substitute for the required file/network/session evidence. The audit includes no
detector accuracy or policy decision.

Qualified publication requires successful generation, explicit backend acceptance,
and a passing native audit for **every** planned case. Promotion recomputes the
audit and checks frozen input, seed, backend, private intent, annotation and public
telemetry consistency. With backend-applied visibility, cases missing required
evidence remain diagnostic. Derived views instead audit the base capture before
applying the declared degradation, as described below.

```sh
uv run --locked scenar publish runs/dataset ./datasets
uv run --locked scenar publish runs/dataset s3://scenar/datasets

# Includes incomplete/degraded cases; never advances the qualified latest pointer:
uv run --locked scenar publish runs/dataset ./datasets --diagnostic
uv run --locked scenar export-public runs/dataset --output exports/native
```

Native public exports allow only the supported Security/Sysmon XML and Zeek
connection/DNS files under opaque capture paths. Other generated formats such as
eCAR stay in the restricted capture and have no public export adapter.
The full dataset contains private authoring, labels and audits. Public export
validates the native file inventory even for diagnostic datasets; a checksummed
extra labels file is still rejected. See [storage](storage.md) for disk/S3 delivery.

## Verification limits

Recipe/schema and fixture checks do not establish fresh generation success.
Use the [host smoke check](#fresh-native-host-smoke-checks) to exercise the selected
backend, qualification and storage on a provisioned host. Qualification is bounded
by each family's declared effects and supported native formats.

## Resume without losing previous attempts

Stop the original runner before resuming. Resume creates a **new** run; it never
edits the source, overwrites a published identity, or deletes failed attempts:

```sh
uv run --locked scenar dataset resume runs/dataset --output runs/retry \
  --backend /path/to/EvidenceForge
```

The source's frozen inputs, backend identity and Scenar implementation must still
match. A completed, sealed generation is reused only after checksums, successful
stage verdicts, seed, timeout, scenario and private annotations are verified.
Native audits and public exports are recomputed. Failed or unsealed generation is
retried; successful generation with rejected native evidence is reused and remains
rejected if its audit still fails. This avoids regenerating data to fish for a
passing verdict. Change inputs by preparing a new dataset.

`private/history/previous/` retains the entire previous run, including failed or
interrupted attempts. This deliberately costs disk space and allows repeated
resumes to preserve ancestry. The new manifest records its parent's inventory
digest. Frozen runs made with older Scenar source require that matching version;
resume does not bypass source drift enforcement.

Run/resume report case progress on stderr and final JSON on stdout. The JSON
includes `reused`; `attempted` describes cases resolved in this run, including reuse.
Execution remains sequential.

## Qualify a deliberately degraded public view

`visibility_application: backend` is the default and preserves Forge's
collection behavior. Missing required native effects still fail that audit.
For controlled, auditable degradation of an otherwise qualified capture, opt in:

```yaml
families: [inventory_archive]
variants: [benign, malicious]
sizes: [small]
seeds: [9501]
visibility_application: derived
visibility:
  - mode: complete
  - mode: lossy
    probability: 0.2
    hosts: [FILE-01]
  - mode: missing_endpoint
    hosts: [FILE-01]
  - mode: delayed
    delay_us: 60000000
    hosts: [FILE-01]
# Optional; defaults to each generated scenario's collection-window end:
# visibility_cutoff: "2024-05-27T12:30:00Z"
```

Derived mode leaves collection overrides out of the generation treatment, requires
backend acceptance and the complete declared-effect native audit, then filters
supported Windows XML and Zeek connection/DNS records. It does not prove complete
coverage of ambient activity or change the underlying scenario's collection policy.
This is a Scenar transformation, separate from Forge's collection-loss simulation.

Loss uses a deterministic seed/file/record draw. Missing endpoints remove Windows
Security and Sysmon records on the selected hosts. Delay models availability using
source time plus the exact integer microsecond delay; connection summaries wait
for their recorded flow duration, and DNS responses wait for their recorded RTT.
Receipts preserve exact integer nanoseconds, including Windows 100-nanosecond ticks. Records unavailable at the cutoff are
withheld. Source timestamps are never rewritten. This availability model is an
explicit assumption, not a measured collector ingestion time. Unknown connection durations or DNS RTTs leave availability explicitly unknown;
those records are withheld and retained in private receipts. Unsupported timestamps
and malformed supported records fail closed.

The native capture stays private. `reports/visibility/CASE.json` records every
supported record's identity, source and availability times, inclusion or omission
reason, source hashes, output hashes and treatment. Receipts are restricted because
they describe omitted records. Public view paths use opaque receipt hashes.
Publication/export reconstruct the view and compare the receipt and public bytes.
Qualifying a derived view therefore does not relabel missing records as observed;
it establishes that the declared transformation of audited bytes was performed.
Views and regenerated look-alikes are not independent samples.

## Inspect lineage and validate splits

```sh
uv run --locked scenar dataset lineage runs/dataset > restricted-lineage.json
uv run --locked scenar dataset check-splits restricted-splits.json
```

Lineage verifies the bundle and frozen inputs, then derives capture hashes,
environment hashes excluding collection overrides, related variants, UTC calendar
days covered by the scenario, and parent inventory identity. This report includes
private family/variant metadata and must not accompany a public export.

Split assignments use this contract:

```json
{
  "schema": "scenar/dataset-splits/v1",
  "assignments": [
    {"run": "runs/development", "case_id": "case-...", "partition": "development", "exposed": true},
    {"run": "runs/holdout", "case_id": "case-...", "partition": "test", "exposed": false}
  ]
}
```

Supply every case of every referenced run exactly once, using actual IDs from
`dataset lineage`. Exposure must be explicitly declared; Scenar cannot establish
whether a person has already seen a capture. Exposed data cannot be a test holdout.
The conservative policy rejects shared capture, family, environment **or UTC day**
across development/test. It does not automatically split a matrix or infer
statistical independence. An unknown or ungenerated case is rejected.

## Preflight and measured runtime history

```sh
uv run --locked scenar dataset preflight runs/dataset \
  --backend /path/to/EvidenceForge --min-free-bytes 10737418240
uv run --locked scenar dataset timings runs/dataset/private/attempts/CASE \
  --history runs/dataset --history runs/previous-dataset
```

Preflight is read-only: selected backend pin, uv availability, the backend's
existing `.venv` interpreter/import, supported spool ancestry checks and writable
output/free space. It reports unknown checks explicitly and returns nonzero unless
all checks pass. It does not install the backend environment, alter permissions or
predict generation success. POSIX spool checks currently match behavior revision
162; other revisions/platforms need an adapter. Set `EFORGE_SPOOL_DIR` on the host
when appropriate, retaining all backend ownership requirements.

Each generation writes `reports/measurements.json`: measured stage duration/exit,
native file count and bytes, workload hash, and backend hash. Timing history verifies
bundles and recomputes measurements. Success ranges include only the same scenario
configuration (excluding seed) and backend source. Duplicate bundle identities are
counted once; failures/timeouts and incomparable samples are separate. `--history`
accepts raw generation directories or whole sealed datasets. The reference argument
is a raw generation directory, including a dataset's `private/attempts/CASE`.
No comparable history means no estimate. Host hardware/load are not normalized.

## Fresh native host smoke checks

```sh
uv run --locked scenar dataset smoke --output runs/native-smoke \
  --backend /path/to/EvidenceForge --stage-timeout-seconds 900 \
  --s3-store s3://scenar/native-smoke
```

This runs 16 small cases: all five families with benign/malicious controls plus
lossy, delayed and missing-endpoint inventory/archive views. It requires native
qualification of every case, then checks qualified disk publication/pull and, when
specified, a real S3-compatible roundtrip. Provision the S3 bucket first with
`scenar init-store`. A failed case or roundtrip returns nonzero; reports and partial
runs remain under the new output directory. Backend preflight runs before the matrix.
This is bounded coverage, not all sizes, seeds, C2 patterns or real-world realism.

The weekly/manual [host workflow](../.github/workflows/native-smoke.yml) requires a
trusted Linux self-hosted runner labelled `scenar-native`, Python 3.12+, uv, the
pinned Forge checkout with `uv sync --locked` already completed, and running RustFS.
Configure repository variables `SCENAR_EVIDENCEFORGE`, `SCENAR_SMOKE_S3` and
`RUSTFS_ENDPOINT`, plus secrets `RUSTFS_ACCESS_KEY` and `RUSTFS_SECRET_KEY`. Use a
store dedicated to this synthetic test data. The workflow runs no pull-request code,
serializes scheduled executions, and uploads only summary/preflight reports; full
bundles and truth remain in the restricted runner/store. Host provisioning and
enabling the workflow in a remote repository are separate from adding its file.
Set repository variable `SCENAR_NATIVE_SMOKE_ENABLED=true` after provisioning;
the job remains disabled until this explicit opt-in is configured.
