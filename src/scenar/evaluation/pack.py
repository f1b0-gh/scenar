"""Prepare and freeze the bounded six-family experiment before inspecting outputs."""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .models import Approval, Contract

FAMILIES = (
    "benign_only",
    "unauthorized",
    "mixed",
    "independent_job_shells",
    "independent_shared_parent",
    "one_episode_two_hosts",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def make_case(base: dict[str, Any], family: str, template: dict[str, Any]) -> dict[str, Any]:
    scenario = copy.deepcopy(base)
    scenario.update(
        name="investigation-" + family.replace("_", "-"),
        description="Controlled inventory and archive workflows; commands rendered only.",
    )
    scenario["time_window"]["duration"] = "30m"
    scenario["storyline"] = []
    scenario["red_herrings"] = []
    scenario["output"]["destination"] = "generated/investigation-episodes"
    if family == "one_episode_two_hosts":
        target = next(
            s for s in scenario["environment"]["systems"] if s["hostname"] == "WS-LMORRIS-01"
        )
        if "rdp" not in target["services"]:
            target["services"].append("rdp")
    count = 1 if family in {"benign_only", "unauthorized"} else 2
    audits, approvals, members = [], [], []
    episodes: dict[str, str] = {}
    sessions: set[str] = set()
    parents: set[str] = set()
    for j in range(count):
        host = "WS-LMORRIS-01" if family == "one_episode_two_hosts" and j == 1 else "FILE-BO-01"
        fqdn = host + ".northstar-branch.local"
        actor = "NORTHSTAR-BRANCH\\nina.kapoor"
        shared = family == "independent_shared_parent"
        parent = "shell-0" if shared else f"shell-{j}"
        session = "session-" + host
        episode = "e0" if family == "one_episode_two_hosts" else f"e{j}"
        benign = family == "benign_only" or (family == "mixed" and j == 0)
        episodes[episode] = "benign" if benign else "actionable"
        resource = r"C:\BranchData\Shared" if shared else rf"C:\BranchData\Records{j}"
        destination = rf"C:\Windows\Temp\job-{j:02d}.zip"
        common = {"actor": "nina.kapoor", "system": host}
        if session not in sessions:
            scenario["storyline"].append(
                {
                    **common,
                    "id": session,
                    "time": "+5m",
                    "activity": "Remote administration session",
                    "events": [
                        {
                            "type": "rdp_session",
                            "source_ip": "10.44.10.24",
                            "technique": "T1021.001",
                        }
                    ],
                }
            )
            sessions.add(session)
        if parent not in parents:
            scenario["storyline"].append(
                {
                    **common,
                    "id": parent,
                    "time": "+6m",
                    "activity": "Persistent workflow shell",
                    "events": [
                        {
                            "type": "process",
                            "process_name": r"C:\Windows\System32\cmd.exe",
                            "command_line": "cmd.exe /k",
                            "process_ref": parent,
                        }
                    ],
                }
            )
            parents.add(parent)
            members.append(
                {"authored_record_id": parent + "#0", "episode_ids": [], "role": "context"}
            )
        discovery = f"cmd.exe /c dir {resource} /s"
        archive = (
            f"powershell.exe -NoProfile -Command Compress-Archive -Path {resource} "
            f"-DestinationPath {destination} -Force"
        )
        for label, time, image, command, technique in (
            ("discover", "+7m", r"C:\Windows\System32\cmd.exe", discovery, "T1083"),
            (
                "archive",
                "+9m",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                archive,
                "T1560.001",
            ),
        ):
            step = f"{label}-{j}"
            scenario["storyline"].append(
                {
                    **common,
                    "id": step,
                    "time": time,
                    "activity": "Inventory" if label == "discover" else "Archive staging",
                    "events": [
                        {
                            "type": "process",
                            "process_name": image,
                            "command_line": command,
                            "technique": technique,
                            "parent_ref": parent,
                        }
                    ],
                }
            )
            members.append(
                {"authored_record_id": step + "#0", "episode_ids": [episode], "role": "action"}
            )
        audit = {
            k: copy.deepcopy(template[k])
            for k in ("source_ip", "as_of", "max_source_time_skew_seconds")
        }
        audit.update(
            case_id=f"job-{j}",
            target_host=fqdn,
            actor=actor,
            archive_path=destination,
            required_commands=[discovery, archive],
            required_record_ids=[session + "#0", f"discover-{j}#0", f"archive-{j}#0"],
        )
        audits.append(audit)
        if benign or family == "unauthorized":
            approved_input = resource if benign else r"C:\BranchData\Records9"
            approval = Approval(
                id=f"CHG-{j}",
                revision=1,
                available_at="2024-05-26T09:00:00Z",
                valid_from="2024-05-27T12:00:00Z",
                valid_until="2024-05-27T12:15:00Z",
                account=actor,
                hosts=[fqdn],
                grants=[
                    {"action": "inventory", "input_path": approved_input},
                    {"action": "archive", "input_path": approved_input, "output_path": destination},
                ],
            )
            approvals.append(approval.model_dump(mode="json"))
    # Keep author order chronological even across hosts/jobs.
    scenario["storyline"].sort(key=lambda s: int(s["time"][1:-1]))
    private = Contract(episodes=episodes, members=members)
    return {
        "scenario_value": scenario,
        "audits": audits,
        "approvals": approvals,
        "private": private.model_dump(mode="json"),
    }
