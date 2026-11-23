# Compiles a Scenar scenario graph into:
#   - an EvidenceForge scenario (storyline + red_herrings with resolved times)
#   - a machine-readable attack graph (nodes/edges, ATT&CK-tagged)
#   - an ATT&CK Navigator layer of the techniques that actually play out
let T = import "time.ncl" in
let fail = std.fail_with in
let has = std.record.has_field in
let max = fun a b => if a > b then a else b in

let technique_label = fun t => "%{t.id} - %{t.name}" in

let session_open_event = fun s =>
  if s.open == 'ssh then
    [
      { type = "ssh_session", technique = if has "technique" s then s.technique else "T1021.004 - Remote Services: SSH" }
      & (if has "from" s then { source_ip = s.from } else {})
    ]
  else if s.open == 'rdp then
    [
      { type = "rdp_session", technique = if has "technique" s then s.technique else "T1021.001 - Remote Services: Remote Desktop Protocol" }
      & (if has "from" s then { source_ip = s.from } else {})
    ]
  else
    []
in

let tag_events = fun proc =>
  std.array.map
    (fun ev => if has "technique" ev then ev else ev & { technique = technique_label proc.technique })
    proc.events
in

fun s =>
  let env = s.evidenceforge.environment in
  let known_actors =
    (std.array.map (fun u => u.username) (if has "users" env then env.users else []))
    @ (if has "service_accounts" env then env.service_accounts else [])
    @ (std.array.map (fun u => u.username) (if has "stale_accounts" env then env.stale_accounts else []))
  in
  let known_systems = std.array.map (fun h => h.hostname) (if has "systems" env then env.systems else []) in

  let session_for = fun where name =>
    if has name s.sessions then
      let ses = s.sessions."%{name}" in
      if !(std.array.elem ses.actor known_actors) then
        fail "session `%{name}`: actor `%{ses.actor}` is not a user, service account or stale account in evidenceforge.environment"
      else if !(std.array.elem ses.system known_systems) then
        fail "session `%{name}`: system `%{ses.system}` is not a hostname in evidenceforge.environment.systems"
      else
        ses
    else
      fail "%{where}: unknown session `%{name}` (declared: %{std.string.join ", " (std.record.fields s.sessions)})"
  in

  let outcome_of = fun step =>
    if has step.id s.assume then s.assume."%{step.id}" else step.outcome
  in

  # Steps are folded in declaration order; every edge must point backwards,
  # which makes the graph acyclic by construction.
  let resolved =
    std.array.fold_left
      (fun acc step =>
        if has step.id acc.nodes then
          fail "step `%{step.id}` is declared twice"
        else
          let deps =
            std.array.map
              (fun d =>
                if has d acc.nodes then
                  acc.nodes."%{d}"
                else
                  fail "step `%{step.id}`: `after` references `%{d}`, which is not declared earlier (list steps in dependency order; this also rules out cycles)"
              )
              step.after
          in
          let cond_ok =
            if has "when" step then
              if has step.when.step acc.nodes then
                let c = acc.nodes."%{step.when.step}" in
                c.enabled && c.outcome == step.when.outcome
              else
                fail "step `%{step.id}`: `when` references `%{step.when.step}`, which is not declared earlier"
            else
              true
          in
          let is_enabled = cond_ok && std.array.all (fun d => d.enabled) deps in
          let t_start = (std.array.fold_left (fun m d => max m d.finish) step.at deps) + step.delay in
          let ses = session_for "step `%{step.id}`" step.session in
          let first_in_session = is_enabled && !(std.array.elem step.session acc.opened) in
          let node = {
            id = step.id,
            enabled = is_enabled,
            outcome = outcome_of step,
            start = t_start,
            finish = t_start + step.procedure.duration,
            session = step.session,
            technique = step.procedure.technique,
            event_offset = if first_in_session then std.array.length (session_open_event ses) else 0,
            opening_events = if first_in_session then session_open_event ses else [],
            after = step.after,
            when = if has "when" step then [step.when] else [],
          }
          in
          let entry =
            {
              id = step.id,
              time = T.offset t_start,
              actor = ses.actor,
              system = ses.system,
              activity = if has "activity" step then step.activity else step.procedure.name,
              events = (if first_in_session then session_open_event ses else []) @ tag_events step.procedure,
            }
            & (if has "event_spacing" step.procedure then { event_spacing = step.procedure.event_spacing } else {})
          in
          {
            nodes = acc.nodes & { "%{step.id}" = node },
            order = acc.order @ [step.id],
            opened = if first_in_session then acc.opened @ [step.session] else acc.opened,
            storyline = if is_enabled then acc.storyline @ [entry] else acc.storyline,
          }
      )
      { nodes = {}, order = [], opened = [], storyline = [] }
      s.steps
  in

  let compiled_red_herrings =
    std.array.map
      (fun rh =>
        let ses = session_for "red herring `%{rh.id}`" rh.session in
        {
          id = rh.id,
          time = T.offset rh.at,
          actor = ses.actor,
          system = ses.system,
          activity = if has "activity" rh then rh.activity else rh.procedure.name,
          explanation = rh.explanation,
          # Preserve historical Forge rendering; private procedure_metadata retains
          # ATT&CK mappings independently of the author's intent labels.
          events = rh.procedure.events,
        }
      )
      s.red_herrings
  in

  let played = std.array.filter (fun n => n.enabled) (std.array.map (fun id => resolved.nodes."%{id}") resolved.order) in

  let technique_index =
    std.array.fold_left
      (fun acc n =>
        let k = n.technique.id in
        if has k acc then
          std.record.update k (acc."%{k}" & { steps = acc."%{k}".steps @ [n.id] }) acc
        else
          acc & { "%{k}" = { technique = n.technique, steps = [n.id] } }
      )
      {}
      played
  in
  {
    procedure_metadata =
      (std.array.map
        (fun step => {
          id = step.id,
          enabled = resolved.nodes."%{step.id}".enabled,
          event_offset = resolved.nodes."%{step.id}".event_offset,
          opening_events = resolved.nodes."%{step.id}".opening_events,
          technique = step.procedure.technique,
          events = step.procedure.events,
        })
        s.steps)
      @ (std.array.map
        (fun rh => {
          id = rh.id,
          enabled = true,
          event_offset = 0,
          technique = rh.procedure.technique,
          events = rh.procedure.events,
        })
        s.red_herrings),
    evidenceforge =
      s.evidenceforge
      & {
        name = s.meta.id,
        description = s.meta.description,
        storyline = resolved.storyline,
        red_herrings = compiled_red_herrings,
      },

    graph = {
      scenario = s.meta,
      assumptions = s.assume,
      nodes =
        std.array.map
          (fun id =>
            let n = resolved.nodes."%{id}" in
            {
              id = n.id,
              technique = n.technique,
              session = n.session,
              actor = (session_for "step `%{n.id}`" n.session).actor,
              system = (session_for "step `%{n.id}`" n.session).system,
              start = T.offset n.start,
              finish = T.offset n.finish,
              assumed_outcome = n.outcome,
              plays_out = n.enabled,
            }
          )
          resolved.order,
      edges =
        std.array.flatten (
          std.array.map
            (fun id =>
              let n = resolved.nodes."%{id}" in
              (std.array.map (fun d => { from = d, to = id, kind = "after" }) n.after)
              @ (std.array.map (fun c => { from = c.step, to = id, kind = "when", outcome = c.outcome }) n.when)
            )
            resolved.order
        ),
    },

    navigator = {
      name = s.meta.name,
      description = "Techniques used in Scenar scenario `%{s.meta.id}`",
      domain = "enterprise-attack",
      versions = { layer = "4.5" },
      techniques =
        std.array.map
          (fun t =>
            {
              techniqueID = t.technique.id,
              score = std.array.length t.steps,
              comment = "steps: %{std.string.join ", " t.steps}",
            }
          )
          (std.record.values technique_index),
      gradient = { colors = ["#ffe766", "#ff6666"], minValue = 0, maxValue = 3 },
    },
  }
