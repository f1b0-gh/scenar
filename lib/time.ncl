# Durations are plain integers of seconds inside Nickel, so the attack graph
# can do arithmetic on them. They are rendered back to EvidenceForge's
# duration strings ("+1h5m", "35m") only at export time.
let render = fun secs =>
  let s = std.number.truncate secs in
  let h = std.number.truncate (s / 3600) in
  let m = std.number.truncate ((s % 3600) / 60) in
  let r = s % 60 in
  let part = fun n unit => if n == 0 then "" else "%{std.to_string n}%{unit}" in
  if s == 0 then "0s" else "%{part h "h"}%{part m "m"}%{part r "s"}"
in
{
  sec = 1,
  min = 60,
  hour = 3600,
  day = 86400,

  # 3900 -> "1h5m"
  duration = render,
  # 3900 -> "+1h5m" (EvidenceForge relative offset from time_window.start)
  offset = fun secs => "+%{render secs}",

  Seconds = std.contract.from_predicate (fun v => std.is_number v && v >= 0 && std.number.is_integer v),
}
