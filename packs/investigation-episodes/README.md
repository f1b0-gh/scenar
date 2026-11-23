# Investigation episodes

The pack is implemented in `scenar.evaluation.pack`; its recipe and contracts are
installed under `scenar/resources/investigation-episodes`. Preparation freezes the
selected scenarios and backend before generation.

The full pack contains six families and two seeds, 9501 and 9502. Every capture
is evaluated with available/withheld/late authorization contexts, four reference
policies and budgets 0/4/16/64. The 576 comparison slots represent 12 attempted
native captures. Rejected captures remain in denominators and the attempt ledger.

Qualification reconciles RDP admission, session/process ancestry, commands,
archive-file effects and required records before policies run. An archive command
alone does not satisfy the file-evidence obligation. Episode membership and scoring
contracts are private; shared process ancestry alone does not merge episodes.

Use `scenar prepare investigation-episodes --output RUN`, then `scenar run RUN`.
Generation requires a compatible pinned backend and a host satisfying its
filesystem requirements. See [reference tools](../../docs/reference-tools.md#investigation-pack-and-replay).

For archive parity, set `SCENAR_PARITY_ARCHIVE` to the preserved cohort identified
in the [regression catalogue](../regressions.json), then run
`uv run --locked pytest tests/test_investigation_parity.py`. This cohort is exposed
regression material, not an independent holdout.
