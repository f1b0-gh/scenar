# Branch-office intrusion expressed as a Scenar scenario graph.
#
# With the default assumptions this compiles to the same storyline as
# EvidenceForge's branch-office-example. Flip one assumption and the graph
# takes a different branch:
#
#   nickel export -f yaml main.ncl --field out.evidenceforge -- "assume.harvest_creds='failure"
let sf = import "../../lib/scenar.ncl" in
let P = import "../../procedures/library.ncl" in
let T = sf.time in
let base = import "environment.yaml" in

sf.Scenario
& {
  meta = {
    id = "branch-office-graph",
    name = "Branch office: DMZ web compromise to C2",
    description = m%"
      Public web reconnaissance leads to a shell on the DMZ web server. The
      attacker harvests credentials from the web root; if that works they RDP
      to the file server as a domain admin, stage an archive and beacon out
      from the admin workstation. If it fails, they fall back to a password
      spray against the domain controller.
    "%,
    authors = ["scenar example"],
    references = ["https://github.com/Cisco-Talos/EvidenceForge/tree/main/scenarios/branch-office-example"],
  },

  # Explicit variables: change these, everything downstream follows.
  variables = {
    attacker_ip | default = "185.199.110.42",
    portal_public_ip | default = "45.83.220.5",
    portal_hostname | default = "portal.northstarclaims.net",
    web_server_ip | default = "10.44.30.10",
    compromised_admin | default = "nina.kapoor",
  },

  # Runtime conditions are resolved at authoring time (generation is
  # deterministic). Override from the CLI to explore the other branch.
  assume = { harvest_creds | default = 'success },

  infrastructure = {
    scanner = { role = 'scanner, ip = variables.attacker_ip, description = "VPS used for scanning and the web-server shell" },
    c2 = { role = 'c2, ip = "45.83.221.30", domain = "northlakeportal.com", port = 443 },
  },

  sessions = {
    external = { actor = "www-data", system = "WEB-BO-01", description = "Activity observed at the portal before any foothold" },
    web_shell = {
      actor = "www-data",
      system = "WEB-BO-01",
      open = 'ssh,
      from = infrastructure.scanner.ip,
      technique = "T1078.003 - Valid Accounts: Local Accounts",
    },
    fileserver_rdp = {
      actor = variables.compromised_admin,
      system = "FILE-BO-01",
      open = 'rdp,
      from = variables.web_server_ip,
    },
    admin_workstation = { actor = variables.compromised_admin, system = "WS-NKAPOOR-01" },
    dc_spray = { actor = "www-data", system = "DC-BO-01" },
    vpn_user = { actor = "victor.hale", system = "WS-VHALE-01" },
  },

  steps = [
    {
      id = "recon",
      session = "external",
      at = 55 * T.min,
      procedure =
        P.web_vuln_scan {
          source_ip = infrastructure.scanner.ip,
          dst_ip = variables.portal_public_ip,
          hostname = variables.portal_hostname,
        },
      activity = "External vulnerability scanner probes the public claims portal",
    },
    {
      id = "foothold",
      session = "web_shell",
      after = ["recon"],
      delay = 7 * T.min,
      procedure = P.linux_owner_discovery {},
      activity = "Attacker obtains a shell on the web server and checks process identity",
    },
    { id = "net_config", session = "web_shell", after = ["foothold"], delay = 5 * T.min, procedure = P.linux_network_config_discovery {} },
    { id = "net_conns", session = "web_shell", after = ["net_config"], delay = 30, procedure = P.linux_network_connections_discovery {} },
    {
      id = "internal_scan",
      session = "web_shell",
      after = ["net_conns"],
      delay = 30,
      procedure = P.internal_port_scan { source_ip = variables.web_server_ip, target_segment = "servers" },
    },
    {
      id = "harvest_creds",
      session = "web_shell",
      after = ["internal_scan"],
      delay = 3 * T.min,
      procedure = P.linux_credentials_in_files {},
      notes = "Runtime condition: did the web root contain reusable admin credentials?",
    },

    # Branch A: credentials found -> lateral movement with the admin account.
    {
      id = "lateral_rdp",
      session = "fileserver_rdp",
      after = ["harvest_creds"],
      when = { step = "harvest_creds", outcome = 'success },
      delay = 6 * T.min,
      procedure =
        P.enter_session {
          name = "RDP from the DMZ web server to the file server with harvested admin credentials",
          technique = { id = "T1021.001", name = "Remote Services: Remote Desktop Protocol", tactic = "lateral-movement" },
        },
    },
    { id = "share_discovery", session = "fileserver_rdp", after = ["lateral_rdp"], delay = 6 * T.min, procedure = P.windows_share_discovery { share = "\\\\FILE-BO-01\\Claims" } },
    {
      id = "stage_archive",
      session = "fileserver_rdp",
      after = ["share_discovery"],
      delay = 2 * T.min,
      procedure =
        P.archive_via_powershell {
          source = "\\\\FILE-BO-01\\Claims\\Q2",
          destination = "C:\\Windows\\Temp\\q2-rollup.zip",
        },
    },
    {
      id = "c2_beacon",
      session = "admin_workstation",
      after = ["stage_archive"],
      delay = 12 * T.min,
      procedure = P.https_beacon { c2 = infrastructure.c2 },
      activity = "Compromised admin workstation beacons through the explicit proxy to attacker infrastructure",
    },

    # Branch B: nothing useful in the web root -> noisy password spray.
    {
      id = "spray_dc",
      session = "dc_spray",
      after = ["harvest_creds"],
      when = { step = "harvest_creds", outcome = 'failure },
      delay = 10 * T.min,
      procedure =
        P.password_spray {
          source_ip = variables.web_server_ip,
          accounts = ["maya.patel", "owen.reed", "lena.morris", "nina.kapoor", "victor.hale"],
        },
    },
  ],

  red_herrings = [
    {
      id = "rh-vpn-typo",
      session = "vpn_user",
      at = 2 * T.hour + 20 * T.min,
      procedure = P.mistyped_vpn_password { source_ip = "198.51.100.77" },
      activity = "Branch manager mistypes a password during a VPN reconnect",
      explanation = "Benign user error that creates a small cluster of failed authentication evidence",
    },
  ],

  evidenceforge =
    base
    & {
      output = {
        logs = [
          { format = "windows" },
          { format = "zeek" },
          { format = "ecar" },
          { format = "syslog" },
          { format = "bash_history" },
          { format = "snort_alert" },
          { format = "cisco_asa" },
          { format = "web_access" },
          { format = "proxy_access" },
        ],
        destination = "out/branch-office",
        compression = false,
      },
    },
}
