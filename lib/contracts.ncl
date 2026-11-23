# Contracts (schemas) for the Scenar scenario graph layer.
#
# Session-bound steps use reusable procedures, explicit variables, declared
# attacker infrastructure, and a directed acyclic graph with conditions, mapped to
# MITRE ATT&CK and Atomic Red Team. Everything EvidenceForge-specific lives
# under the `evidenceforge` field and in generated/ef_events.ncl.
let T = import "time.ncl" in
let ef = import "../generated/ef_events.ncl" in
let Matches = fun re msg =>
  std.contract.from_validator (fun value =>
    if std.is_string value && std.string.is_match re value then 'Ok else 'Error { message = msg }
  )
in
{
  Seconds = T.Seconds,

  Id = Matches "^[a-zA-Z0-9_-]+$" "ids may only contain letters, digits, `-` and `_`",

  TechniqueId = Matches "^T[0-9]{4}(\\.[0-9]{3})?$" "ATT&CK technique ids look like T1046 or T1021.001",

  # Shared metadata is validated against the pinned catalogue by Python.
  AttackMapping = {
    record_id | String,
    technique | String,
    tactic | String | optional,
    platforms | Array String | default = [],
  },
  AttackSettings = {
    domain | String | default = "enterprise-attack",
    release | String | optional,
    allow_retired | Bool | default = false,
    mappings | Array { .. } | default = [],
  },
  IntentLabel = {
    intent | Matches "^(malicious|benign|unknown)$" "intent must be malicious, benign or unknown",
    rationale | String | optional,
  },
  GroundTruth = {
    mode | Matches "^(behavior-only|intent-aware)$" "unknown ground truth mode" | default = "behavior-only",
    labels | { _ : { .. } } | default = {},
    episodes | { _ : { .. } } | default = {},
  },
  BackgroundActivity = {
    profile | String | optional,
    intensity | String | optional,
    variation | String | optional,
    suspicious_noise | String | optional,
    traffic_rates | { .. } | optional,
  },

  Ipv4 = Matches "^([0-9]{1,3}\\.){3}[0-9]{1,3}$" "expected a dotted IPv4 address",

  # S3 bucket naming rules (also enforced by RustFS).
  BucketName =
    Matches
      "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
      "bucket names are 3-63 chars of lowercase letters, digits, `.` and `-`",

  ObjectPrefix =
    Matches
      "^[A-Za-z0-9!_.*'()-]+(/[A-Za-z0-9!_.*'()-]+)*$"
      "object prefixes are `/`-separated segments without leading/trailing `/`",

  Outcome = [| 'success, 'failure |],

  Technique = {
    id | TechniqueId,
    name | String,
    tactic | String | optional,
  },

  # Optional link to an Atomic Red Team test that implements the procedure on
  # a live range. `test` is the atomic's GUID or test number.
  AtomicRef = {
    technique | TechniqueId,
    test | String | optional,
  },

  # A reusable, parameterised technique implementation: what an attacker does,
  # expressed as the EvidenceForge events it leaves behind.
  Procedure = {
    name | String,
    technique | Technique,
    atomic | AtomicRef | optional,
    duration | Seconds | default = 0,
    event_spacing | { .. } | optional,
    events | Array ef.EventSpec,
  },

  InfraRole = [| 'scanner, 'c2, 'staging, 'exfil, 'phishing, 'redirector, 'other |],

  Infrastructure = {
    role | InfraRole,
    ip | Ipv4 | optional,
    domain | String | optional,
    port | std.number.Integer | optional,
    description | String | optional,
  },

  # Who the attacker is acting as, on which host, and how they got there.
  # `open` makes the compiler emit the session's logon evidence at its first step.
  Session = {
    actor | String,
    system | String,
    open | [| 'ssh, 'rdp, 'none |] | default = 'none,
    from | Ipv4 | optional,
    technique | String | optional,
    description | String | optional,
  },

  Condition = {
    step | Id,
    outcome | Outcome,
  },

  Step = {
    id | Id,
    session | String,
    procedure | Procedure,
    activity | String | optional,
    # Graph edges: this step starts once every listed step has finished.
    after | Array Id | default = [],
    # Earliest start, relative to time_window.start (seconds).
    at | Seconds | default = 0,
    delay | Seconds | default = 0,
    # Runtime condition: only runs if `step` had `outcome`.
    when | Condition | optional,
    # Outcome this run assumes for the step (overridable via `assume`).
    outcome | Outcome | default = 'success,
    notes | String | optional,
  },

  RedHerring = {
    id | Id,
    session | String,
    at | Seconds,
    explanation | String,
    procedure | Procedure,
    activity | String | optional,
  },

  Meta = {
    id | Id,
    name | String,
    description | String,
    version | String | default = "0.1.0",
    authors | Array String | default = [],
    threat_actor | String | optional,
    references | Array String | default = [],
  },
}
