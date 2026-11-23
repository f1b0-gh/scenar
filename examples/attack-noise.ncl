# Same shared configuration as YAML/JSON; Python validates the pinned catalogue.
let base = import "../scenarios/branch-office/main.ncl" in
base & {
  attack = { domain = "enterprise-attack", release = "20.1" },
  ground_truth = {
    mode = "intent-aware",
    labels = {
      "stage_archive#0" = {
        intent = "malicious",
        rationale = "Author declares staging for theft in this synthetic scenario",
      },
    },
  },
  background = {
    profile = "office",
    intensity = "medium",
    suspicious_noise = "low",
    traffic_rates = { user_activity = "high", web = [2, 5] },
  },
}
