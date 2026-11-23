#!/usr/bin/env bash
# Negative tests: each case patches the branch-office scenario and checks that
# Nickel rejects it with the expected message, before EvidenceForge runs.
set -u
cd "$(dirname "$0")/.."
pass=0; fail=0
check() { # name expected-substring nickel-file
  out=$(nickel export -f json "$3" --field out 2>&1)
  if [[ $? -ne 0 && "$out" == *"$2"* ]]; then echo "ok   $1"; pass=$((pass+1));
  else echo "FAIL $1"; echo "$out" | head -20; fail=$((fail+1)); fi
}
case_file() { # name base-merge-expression
  f="tests/.tmp_$1.ncl"
  printf 'let s = import "../scenarios/branch-office/main.ncl" in\n%s\n' "$2" > "$f"; echo "$f"
}

check unknown_event_type "unknown EvidenceForge event type \`proces\`" \
  "$(case_file unknown_event_type 's & { steps | force = std.array.map (fun st => if st.id == "net_config" then st & { procedure.events | force = [{ type = "proces", process_name = "x" }] } else st) s.steps }')"

check misspelled_event_field "command_lin" \
  "$(case_file misspelled_event_field 's & { steps | force = std.array.map (fun st => if st.id == "net_config" then st & { procedure.events | force = [{ type = "process", process_name = "/usr/sbin/ip", command_lin = "ip a" }] } else st) s.steps }')"

check bad_technique_id "ATT&CK technique ids look like" \
  "$(case_file bad_technique_id 's & { steps | force = std.array.map (fun st => if st.id == "recon" then st & { procedure.technique.id | force = "T1595.2" } else st) s.steps }')"

check forward_reference "not declared earlier" \
  "$(case_file forward_reference 's & { steps | force = std.array.map (fun st => if st.id == "foothold" then st & { after | force = ["c2_beacon"] } else st) s.steps }')"

check unknown_actor "is not a user, service account or stale account" \
  "$(case_file unknown_actor 's & { sessions.admin_workstation.actor | force = "nina.kapur" }')"

check unknown_session "unknown session \`web-shell\`" \
  "$(case_file unknown_session 's & { steps | force = std.array.map (fun st => if st.id == "net_config" then st & { session | force = "web-shell" } else st) s.steps }')"

check bad_bucket_name "bucket names are 3-63 chars" \
  "$(case_file bad_bucket_name 's & { storage.bucket | force = "Scenar_Invalid" }')"

rm -f tests/.tmp_*.ncl
echo "$pass passed, $fail failed"; [[ $fail -eq 0 ]]
