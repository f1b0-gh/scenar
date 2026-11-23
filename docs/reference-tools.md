# Reference tools and compatibility

Scenar includes scenario capture, investigation-pack evaluation and replay tools.
The main dataset workflow is documented in [dataset generation](data-generation.md).
These reference tools do not implement Detect's runtime.

## Build and capture a scenario

```sh
# YAML/JSON works without Nickel. build checks the envelope; validate uses Forge.
uv run --locked scenar build scenario.yaml --output build/authored
uv run --locked scenar validate scenario.yaml --output build/validated
uv run --locked scenar generate scenario.yaml --seed 9501 \
  --stage-timeout-seconds 1800 --output runs/raw
```

`generate` produces raw, unqualified captures. It runs backend validation,
generation and quality evaluation. Missing, malformed or rejected backend quality
fails the call. Configuration, stage logs and ordinary failures are retained in
checksummed diagnostic bundles. Successful generation alone does not establish
native qualification.

The default timeout is 300 seconds per backend stage. Set outer job deadlines to
cover every stage and artifact sealing. `reports/workload.json` inventories the
configured systems, events, time window and background settings; it does not
estimate runtime. See [generation diagnostics](attack-ground-truth.md#generation-diagnostics-and-timeouts).

## Investigation pack and replay

```sh
uv run --locked scenar prepare investigation-episodes --output runs/first
uv run --locked scenar run runs/first
uv run --locked scenar verify runs/first

# Regrade identical native bytes with the installed evaluator; no regeneration.
uv run --locked scenar replay runs/first --output runs/regraded
uv run --locked scenar export-public runs/regraded --output exports/investigator
```

Output directories must be new. `--family benign_only` on `prepare` selects two
captures. The full [pack](../packs/investigation-episodes/README.md) contains six
families, two seeds, three visibility contexts, four reference policies and four
budgets. `run` records validation, generation, backend quality, native qualification
and reference evaluation. A zero backend exit is insufficient: backend acceptance
and native audit must both pass. Partial execution returns nonzero and retains
failed attempts.

`qualify` and `evaluate --adapter reference` also regrade into a required new
`--output` directory. The reference evaluator is the only implemented adapter.

`replay` verifies the frozen protocol, scenarios, source archive and native bytes.
The new bundle records the installed evaluator's identity, original provenance,
unchanged captures and failed slots. It does not execute archived Python source.
Timings and result hashes can change; parity checks compare candidates, decisions,
memberships, traces and aggregate metric values.

## Reference evaluation

The investigation harness separates a public candidate feed from a trusted query
provider and private grader:

1. Verify the restricted bundle with `verify_bundle` and create a separate public
   directory with `export_public`. Expose only that directory to the investigator.
2. Candidate feeds contain observable commands at the protocol's UTC `as_of`,
   using opaque record IDs. They omit family names, episode memberships, authoring
   assumptions, private truth and late authorizations.
3. The trusted provider loads `broker/<capture-digest>/broker-snapshot-*.json.gz`.
   `evaluation.bench.Broker` applies query budgets and returns acquired evidence
   and receipts. The snapshot contains private provider records and visibility
   variants; it must stay outside the investigator process. The broker is a
   Python interface, not a network authentication service or OS sandbox.
4. Validate results with `evaluation.models.Result.model_validate_json`: candidate
   IDs, decisions, evidence references, groups and query traces. Shared account,
   host or parent process alone does not establish episode membership.
5. Grade committed results with `evaluation.bench.grade(result, oracle)` using the
   private oracle. Missing evidence stays unresolved; absence from a sampled index
   is not proof of absence from native records.

Metrics include action/episode recall, candidate misses, false escalations and
closures, unresolved cases, wrong merges, duplicate deliveries and query/byte cost.
Evaluation duration is measured separately. Capture digest, visibility view and
evaluator/configuration identity identify different aspects of the run; repeated
views and policies are not independent captures.

This protocol is specific to the reference harness. Dataset consumers use the
[file export contract](consumer-contract.md), without importing this evaluator.

## C2 structural query

```sh
scenar c2-query public-view.json.gz --start 2024-07-15T12:00:00Z
```

The query performs a full scan of a public JSON view for linked workflows. It does
not classify malicious intent or constitute a budget-matched investigator test.
See [query requirements and limits](../packs/c2-chain/README.md).

## Optional frontend and aliases

Nickel is optional. `lib/scenar.ncl` is the authoring entry point;
`lib/lookout-scenar.ncl` and `lookout-scenar` are compatibility aliases.
`EVIDENCEFORGE` and `LOOKOUT_BUCKET` are deprecated environment variables, with
lower precedence than `SCENAR_EVIDENCEFORGE` and `SCENAR_BUCKET`.
