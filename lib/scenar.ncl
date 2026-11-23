# Entry point. A scenario is written as
#
#   let sf = import "../../lib/scenar.ncl" in
#   sf.Scenario & { meta = ..., sessions = ..., steps = ..., evidenceforge = ... }
#
# and exported with
#
#   nickel export -f json main.ncl --field out.evidenceforge > scenario.json
#   nickel export -f json main.ncl --field out.graph > attack-graph.json
#   nickel export -f json main.ncl --field out.navigator > navigator-layer.json
#
# Because `Scenario` is a plain Nickel record, the outputs below are recomputed
# from whatever the scenario merges in, and any `| default` field (variables,
# assume) can be overridden from the command line.
let C = import "contracts.ncl" in
let compile = import "compile.ncl" in
{
  time = import "time.ncl",
  contracts = C,

  Scenario = {
    meta | C.Meta,
    variables | { _ : Dyn } | default = {},
    infrastructure | { _ : C.Infrastructure } | default = {},
    sessions | { _ : C.Session },
    steps | Array C.Step,
    red_herrings | Array C.RedHerring | default = [],
    # Assumed outcome per step id; drives `when` branches deterministically.
    assume | { _ : C.Outcome } | default = {},
    attack | C.AttackSettings | default = {},
    ground_truth | C.GroundTruth | default = {},
    # Empty means preserve the Forge baseline. Explicit profiles configure normal noise.
    background | C.BackgroundActivity | default = {},
    # Everything EvidenceForge needs besides the storyline: environment,
    # time_window, baseline_activity, output, ... (validated by `eforge validate`).
    evidenceforge
      | {
        version | String | default = "1.0",
        environment | { .. },
        time_window | { .. },
        baseline_activity | { .. },
        output | { .. },
        ..
      },

    # Where builds of this scenario are published in RustFS (S3 API).
    # Bucket and prefix can be overridden from the CLI or the environment
    # (SCENAR_BUCKET), see tools/rustfs.py.
    storage
      | {
        bucket | C.BucketName | default = "scenar",
        prefix | C.ObjectPrefix | default = "scenarios",
        # Upload generated logs too (not just the compiled scenario).
        include_logs | Bool | default = true,
        # Optional S3 object tags put on every uploaded object.
        tags | { _ : String } | default = {},
      }
      | default = {},

    # Compiled outputs.
    out =
      let m = meta in
      let ses = sessions in
      let st = steps in
      let rh = red_herrings in
      let asm = assume in
      let ef = evidenceforge in
      let sto = storage in
      let atk = attack in
      let gt = ground_truth in
      let bg = background in
      compile { meta = m, sessions = ses, steps = st, red_herrings = rh, assume = asm, evidenceforge = ef }
      & {
        scenar = { attack = atk, ground_truth = gt }
          & (if std.array.length (std.record.fields bg) > 0 then { background = bg } else {}),
        storage = {
          bucket = sto.bucket,
          include_logs = sto.include_logs,
          tags = sto.tags,
          # <prefix>/<scenario id>/<variant>/<build id>/...
          key_prefix = "%{sto.prefix}/%{m.id}",
        },
      },
  },
}
