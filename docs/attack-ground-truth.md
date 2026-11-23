# ATT&CK scenarios, intent ground truth and normal background activity

Scenar validates scenario mappings against a pinned ATT&CK catalogue and keeps
**behavior, observed evidence and malicious intent separate**. It supports both
Nickel authoring and Python/YAML/JSON through the same Pydantic validation.

The installed Enterprise ATT&CK 20.1 projection contains 867 techniques (including
retired entries) and 15 tactics. It was derived from the retained Detect STIX
snapshot, SHA-256
`539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`.
Technique STIX IDs, modification times, object versions, parents, platforms,
tactics, retirement flags and markings are retained. The original source remains
unchanged. Attribution and the MITRE license are included in the package.

MITRE publishes the source datasets and versioned collections through its
[ATT&CK data tools](https://attack.mitre.org/resources/attack-data-and-tools/) and
[STIX collection index](https://github.com/mitre-attack/attack-stix-data/blob/master/index.json).
The projection covers scenario-level technique/tactic validation; it does not
convert ATT&CK prose or detection strategies into executable implementations.

## Configuration

A complete runnable example is [attack-mixed.yaml](../examples/attack-mixed.yaml).
Its envelope has this shape (the backend scenario is abbreviated here):

```yaml
schema: scenar/scenario/v1
attack:
  domain: enterprise-attack
  release: '20.1'
  mappings:
    - record_id: collection#0
      technique: T1560.001
      tactic: collection
      platforms: [Windows]
ground_truth:
  mode: intent-aware
  labels:
    collection#0:
      intent: malicious
      rationale: Author declares staging for theft in this synthetic experiment
    routine-archive#0:
      intent: benign
      rationale: Author declares an approved administrative archive
background:
  profile: office
  intensity: medium
  variation: medium
  suspicious_noise: low
evidenceforge:
  name: example
  # The complete environment, time window, events and outputs follow here.
```

`record_id` in authoring metadata means **step ID plus authored event index**.
When Forge renders or sorts events, Scenar joins labels through
`intent_reconciliation.intents[].intent_id`, rather than assuming that rendered
ordinals still match author order. A missing ledger permits ordinal fallback only
when the frozen source proves that the step has exactly one authored event;
ambiguous labeled cases fail closed. Omitted events do not inherit another
activity's label. Labels must reference known authored events; pack episode labels
must reference its frozen private membership contract.

`behavior-only` is the default and uses action/episode grading.
`intent-aware` enables independent maliciousness ground truth. Labels are
`malicious`, `benign`, or `unknown`; known labels require a rationale. The private
Scenar native-truth overlay exposes `is_malicious: true`, `false`, or `null`.
In behavior-only mode that field is null. The original Forge truth is retained
byte-for-byte: its storyline/red-herring classification does not decide intent.

Missing permission, a technique tag, a suspicious command and an investigator's
`escalate` decision never create a malicious label. Unlabeled events remain
unknown. Different members of one scenario may have opposite intent while using
the same technique. Missing native observations and failed captures remain
visible instead of becoming successful negatives.

### Nickel

[attack-noise.ncl](../examples/attack-noise.ncl) imports the existing branch-office
scenario and adds the same `attack`, `ground_truth` and `background` fields:

```nickel
base & {
  attack = { domain = "enterprise-attack", release = "20.1" },
  ground_truth = {
    mode = "intent-aware",
    labels = {
      "stage_archive#0" = {
        intent = "malicious",
        rationale = "Author declares staging for theft",
      },
    },
  },
  background = { profile = "office", intensity = "medium" },
}
```

The compiler carries procedure tactics, enabled-event offsets, session openers
and benign look-alike technique mappings as private metadata. Python validates
that metadata against the catalogue. The procedure technique remains meaningful
for benign activity. Select labels appropriate to the active branch; unknown
references are rejected rather than silently attached to another event.

## Normal background generation

Profiles are `quiet`, `office`, and `server`. They configure the unchanged
EvidenceForge baseline generator's routine user, web, DNS, time synchronization,
file-sharing, directory/authentication and persona traffic where the environment
supports them. Profile rates shift with `intensity`; explicit `traffic_rates`
overrides take precedence. Rate values are `low`/`medium`/`high`, a positive
integer up to 50,000, or an ordered two-integer range. The backend retains ownership
of each rate's units and rendered behavior.

Normal traffic runs alongside focal actions in the same generated time window.
`suspicious_noise` controls Forge's suspicious-but-benign ambient confounders.
The profile's intended benign status is private population metadata: it does not
license labeling every unindexed native record as benign. Unchanged capture
seeds/configuration provide reproducibility; backend revisions remain pinned.

```sh
uv run --locked scenar build examples/attack-mixed.yaml --output build/mixed
uv run --locked scenar build examples/attack-noise.ncl --output build/nickel
uv run --locked scenar generate examples/attack-mixed.yaml \
  --background office --intensity high --seed 42 --output runs/raw-mixed
uv run --locked scenar generate examples/attack-mixed.yaml \
  --background office --noise-only --seed 42 --output runs/raw-ambient
```

Noise-only generation validates the source first, then removes focal events,
red herrings, their technique mappings and their effective labels. It retains the
original source for provenance. Raw generation has no recipe-specific native audit
and remains **unqualified**; it cannot be promoted as qualified data.
Its checksummed bundle can be stored locally or on S3 (including RustFS) using
explicit diagnostic publication, which does not update the qualified `latest` pointer:

```sh
uv run --locked scenar publish runs/raw-ambient /path/to/store --diagnostic
uv run --locked scenar publish runs/raw-ambient s3://scenar/runs --diagnostic
```

These raw bundles support publication and retrieval; pack replay requires a
prepared pack protocol and its native audit contract.

The library exposes the same generation path:

```python
from pathlib import Path
from scenar.background import BackgroundActivity
from scenar.generation import generate_scenario

generate_scenario(
    Path("examples/attack-mixed.yaml"),
    Path("runs/ambient"),
    backend=Path("/path/to/EvidenceForge"),
    background=BackgroundActivity(profile="office", intensity="high"),
    noise_only=True,
    seed=42,
    stage_timeout_seconds=1800,
)
```

### Generation diagnostics and timeouts

`generate` runs backend validation, generation and `eforge eval --format json`.
Each stage uses `stage_timeout_seconds` (CLI `--stage-timeout-seconds`), default
300 seconds. A zero process exit is insufficient: quality must contain the
boolean `acceptance_passed: true`. Missing, malformed or rejected quality and
missing/malformed native truth fail the call. Successful raw generation still
requires a suitable native audit before qualified promotion.

After a successful build, ordinary stage/annotation failures retain an unqualified
manifest, partial backend output and logs, then propagate the error. These bundles
can be published with `--diagnostic`; success and failure both leave the qualified
latest pointer untouched. A forced kill of Scenar itself, storage failure or unsafe
artifact paths can prevent final sealing; such directories remain incomplete.

- `sources/generation.json`: effective seed and per-stage timeout. Seed precedence
  is explicit override, scenario `generation_seed`, then the pinned backend default
  42. The selected uint64 value is passed explicitly to the backend.
- `reports/workload.json`: configured system count, authored steps/events, declared
  time window/warm-up and baseline settings. It inventories configuration, not
  rendered volume or runtime; omitted fields still use backend defaults.
- `reports/generation.json`: versioned running/succeeded/failed status, current
  phase, completed stage timings/exits, nullable backend verdict and error.
- `reports/stages/`: stdout/stderr per stage, including the original quality report.
- `reports/qualification.json`: explicitly unqualified raw-capture status.

The authored event count is not a runtime estimate: baseline activity and warm-up
can dominate generation. Set caller/job deadlines to cover validation, generation,
quality evaluation and sealing. Increasing only the backend stage timeout leaves
an outer timeout unchanged. The 1800-second example is a configurable budget,
not a measured requirement. Use [preflight and measured runtime history](data-generation.md#preflight-and-measured-runtime-history)
to inspect prerequisites and comparable completed runs.

## Qualified packs, replay and coverage

```sh
uv run --locked scenar prepare investigation-episodes --family mixed \
  --ground-truth examples/intent-labels.json --background office --output runs/mixed
uv run --locked scenar run runs/mixed
uv run --locked scenar attack coverage runs/mixed --output reports/mixed

# Explicitly annotate historical bytes with the selected catalogue; no regeneration:
uv run --locked scenar replay archived-run --annotate-attack --output runs/annotated
```

`--ground-truth` accepts the same GroundTruth JSON contract on build, generate,
prepare and replay. For packs, `episodes` labels resolve through the private
membership contract; conflicting/unknown memberships stay unknown unless an
explicit per-action label adjudicates them. One file applies to the selected
cases, so prepare separately when families require different adjudications.
Replay preserves existing labels/catalogue unless explicitly overridden and
records any reannotation/readjudication. Background controls only affect new
captures; they never fabricate background traffic during replay.

Coverage produces `coverage.json` plus three separate Navigator layers:

- **Authored:** validated mappings in the frozen scenario.
- **Observed:** mappings reconciled to actual native records in qualified captures.
- **Detected:** explicit detector reports citing those qualified record IDs.

Observed evidence is recomputed from native records and authored lineage; a
rehash of a fabricated index cannot make nonexistent evidence count. Unsupported
native mappings remain authored-only. The current bounded investigator index
covers selected process births; it does not assert exhaustive coverage of every
ATT&CK behavior or every native record. In particular, session audit success does
not automatically create a per-technique occurrence mapping.

To supply detector reports, use `--detections detections.json` with this contract:

```json
{"schema_version":"scenar/attack-detections/v1","detector":"consumer/version-config",
 "detections":[{"case_id":"mixed-9501","technique":"T1083",
 "observation_id":"data/native-file#native-record-id"}]}
```

Per-case rows retain observed and detected record IDs, including which subset was
detected. These are consumer claims linked to verified evidence, not operational
certification. Navigator scores count the chosen coverage stage, not maliciousness.
Historical source mappings, retired entries and domain/version mismatches are
validated before generation. `allow_retired: true` is an explicit historical
opt-in and leaves warnings in the reports.

## Intent grading and privacy

`scenar grade-intent RUN predictions.json --output reports/intent.json` accepts a
mapping from capture IDs to `{"decisions":{"native-id":"malicious"}}`.
Decisions are `malicious`, `benign`, or `abstain`; reference policy escalations are
not accepted as intent predictions. Known labels with no prediction count as
unresolved, and predictions on unknown truth are counted separately. Failed or
unqualified captures remain identified as missing/diagnostic, never pooled as
accepted evaluation results.

Truth, profiles, catalogue selections and reports stay in restricted `private/`,
`sources/` or `reports/`. Only `export-public` feeds are intended for investigators.
A complete disk/S3 bundle remains restricted. Neither a directory name nor a
Navigator layer provides access control; do not give consumers the full store.

## Catalogue maintenance and schemas

```sh
scenar attack inspect
scenar attack show T1560.001
scenar attack list --tactic collection --platform Windows
scenar attack import mobile-attack.json --domain mobile-attack \
  --sha256 EXPECTED_SHA256 --output catalogues/mobile
scenar attack export --catalog catalogues/mobile --output mobile-original.stix.json
scenar attack schema scenario > scenario.schema.json
```

Import supports Enterprise, Mobile and ICS STIX catalogues and retains exact source
bytes. Pass `--catalog DIRECTORY` to select an imported pin. Runtime commands never
refresh from the network. Export of an imported catalogue returns original STIX;
export of the bundled catalogue returns its explicitly typed compact projection.
Enterprise's real retained dataset and Mobile/ICS contract fixtures are tested.
Catalogue support does not imply that Forge implements every technique/platform.

Scenar generates synthetic telemetry; it does not execute live adversary commands.
Generation requires a host that satisfies the pinned backend's prerequisites;
use [preflight](data-generation.md#preflight-and-measured-runtime-history) to check them.
