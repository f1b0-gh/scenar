# Reusable procedures: one ATT&CK technique each, parameterised, expressed as
# the EvidenceForge events the technique leaves behind. Think of these as the
# synthetic-telemetry counterpart of an Atomic Red Team test: same technique
# id, but instead of commands to run on a range they describe the evidence.
#
# Each procedure is a function from a parameter record (with defaults) to a
# `Procedure` (see lib/contracts.ncl).
let T = import "../lib/time.ncl" in
{
  # --- Reconnaissance --------------------------------------------------------
  web_vuln_scan = fun p =>
    let p = { preset | default = "nikto", rate | default = 4.0, duration | default = 3 * T.min, port | default = 80 } & p in
    {
      name = "Vulnerability scan of a public web application",
      technique = { id = "T1595.002", name = "Active Scanning: Vulnerability Scanning", tactic = "reconnaissance" },
      duration = p.duration,
      events = [
        {
          type = "web_scan",
          source_ip = p.source_ip,
          dst_ip = p.dst_ip,
          dst_port = p.port,
          hostname = p.hostname,
          preset = p.preset,
          rate = p.rate,
          duration = T.duration p.duration,
        }
      ],
    },

  # --- Discovery -------------------------------------------------------------
  linux_owner_discovery = fun _p =>
    {
      name = "Check current user identity",
      technique = { id = "T1033", name = "System Owner/User Discovery", tactic = "discovery" },
      atomic = { technique = "T1033" },
      events = [{ type = "process", process_name = "/usr/bin/id", command_line = "id" }],
    },

  linux_network_config_discovery = fun _p =>
    {
      name = "Enumerate network interfaces",
      technique = { id = "T1016", name = "System Network Configuration Discovery", tactic = "discovery" },
      atomic = { technique = "T1016" },
      events = [{ type = "process", process_name = "/usr/sbin/ip", command_line = "ip addr" }],
    },

  linux_network_connections_discovery = fun _p =>
    {
      name = "Enumerate listening sockets and connections",
      technique = { id = "T1049", name = "System Network Connections Discovery", tactic = "discovery" },
      atomic = { technique = "T1049" },
      events = [{ type = "process", process_name = "/usr/sbin/ss", command_line = "ss -tulpn" }],
    },

  internal_port_scan = fun p =>
    let p = { target_count | default = 8, ports | default = [22, 80, 445, 3389], rate | default = 8.0 } & p in
    {
      name = "Low-volume internal port scan",
      technique = { id = "T1046", name = "Network Service Discovery", tactic = "discovery" },
      atomic = { technique = "T1046" },
      duration = 2 * T.min,
      events = [
        {
          type = "port_scan",
          source_ip = p.source_ip,
          target_segment = p.target_segment,
          target_count = p.target_count,
          ports = p.ports,
          scan_rate = p.rate,
        }
      ],
    },

  windows_share_discovery = fun p =>
    {
      name = "Recursively list a file share",
      technique = { id = "T1083", name = "File and Directory Discovery", tactic = "discovery" },
      atomic = { technique = "T1083" },
      events = [
        {
          type = "process",
          process_name = "C:\\Windows\\System32\\cmd.exe",
          command_line = "cmd.exe /c dir %{p.share} /s",
        }
      ],
    },

  # --- Credential access -----------------------------------------------------
  linux_credentials_in_files = fun p =>
    let p = { path | default = "/var/www" } & p in
    {
      name = "Search web root for stored credentials",
      technique = { id = "T1552.001", name = "Unsecured Credentials: Credentials In Files", tactic = "credential-access" },
      atomic = { technique = "T1552.001" },
      events = [
        {
          type = "process",
          process_name = "/usr/bin/grep",
          command_line = "grep -riE 'pass(word)?|pwd' %{p.path} --include=*.php --include=*.env",
        }
      ],
    },

  password_spray = fun p =>
    let p = { interval | default = 30, count | default = 20, logon_type | default = 3 } & p in
    {
      name = "Password spray against domain accounts",
      technique = { id = "T1110.003", name = "Brute Force: Password Spraying", tactic = "credential-access" },
      atomic = { technique = "T1110.003" },
      duration = p.interval * p.count,
      events = [
        {
          type = "credential_spray",
          source_ip = p.source_ip,
          pattern = "spray",
          target_accounts = p.accounts,
          interval = T.duration p.interval,
          count = p.count,
          logon_type = p.logon_type,
        }
      ],
    },

  # --- Lateral movement ------------------------------------------------------
  # Marker step for moving into a session. The logon evidence itself is
  # emitted by the session's `open` setting at its first step.
  enter_session = fun p =>
    {
      name = p.name,
      technique = p.technique,
      events = [],
    },

  # --- Collection ------------------------------------------------------------
  archive_via_powershell = fun p =>
    {
      name = "Stage collected files in a zip archive",
      technique = { id = "T1560.001", name = "Archive Collected Data: Archive via Utility", tactic = "collection" },
      atomic = { technique = "T1560.001" },
      events = [
        {
          type = "process",
          process_name = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line = "powershell.exe -NoProfile -Command Compress-Archive -Path %{p.source} -DestinationPath %{p.destination} -Force",
        }
      ],
    },

  # --- Command and control ---------------------------------------------------
  https_beacon = fun p =>
    let p = { interval | default = 5 * T.min, duration | default = 35 * T.min, port | default = 443 } & p in
    {
      name = "Periodic HTTPS beaconing to attacker infrastructure",
      technique = { id = "T1071.001", name = "Application Layer Protocol: Web Protocols", tactic = "command-and-control" },
      duration = p.duration,
      events = [
        {
          type = "beacon",
          dst_ip = p.c2.ip,
          dst_port = p.port,
          hostname = p.c2.domain,
          service = "ssl",
          interval = T.duration p.interval,
          duration = T.duration p.duration,
          action = "allow",
        }
      ],
    },

  # --- Benign look-alikes (red herrings) -------------------------------------
  mistyped_vpn_password = fun p =>
    {
      name = "User mistypes a password during VPN reconnect",
      technique = { id = "T1078", name = "Valid Accounts (benign look-alike)" },
      events = [{ type = "failed_logon", source_ip = p.source_ip, logon_type = 3 }],
    },
}
