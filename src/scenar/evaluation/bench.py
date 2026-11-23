"""Frozen transparent reference algorithms, not production Detect detection logic.

Every candidate comes from a native command, including unadjudicated background.
An escalation requests review; lack of authorization is not proof of an attack.
Only the grader consumes private episode membership.
"""

import json
import re
from itertools import combinations

from .models import Approval, Candidate, Oracle, Policy, Receipt, Record, Result, Snapshot

INVENTORY = re.compile(r"cmd\.exe /c dir (?P<input>[A-Z]:\\[^\s]+) /s", re.I)
ARCHIVE = re.compile(
    r"powershell\.exe -NoProfile -Command Compress-Archive -Path "
    r"(?P<input>[A-Z]:\\[^\s]+) -DestinationPath (?P<output>[A-Z]:\\[^\s]+) -Force",
    re.I,
)
PAGE_RECORDS = 32
PAGE_BYTES = 24576


def size(value: object) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def candidate(row: Record) -> Candidate | None:
    if row.source != "sysmon" or row.event_id != 1:
        return None
    command = row.data.get("CommandLine", "")
    for action, pattern in (("inventory", INVENTORY), ("archive", ARCHIVE)):
        match = pattern.fullmatch(command)
        if match:
            return Candidate(
                record=row,
                action=action,
                input_path=match["input"].casefold(),
                output_path=match.groupdict().get("output", "").casefold() or None,
            )
    return None


def candidates(snapshot: Snapshot) -> list[Candidate]:
    return sorted(
        [
            c
            for r in snapshot.records
            if snapshot.start <= r.time <= snapshot.as_of and (c := candidate(r)) is not None
        ],
        key=lambda c: (c.record.time, c.record.id),
    )


def candidate_feed(snapshot: Snapshot) -> dict:
    """Initial detector input: as-of candidates only; context stays behind Broker."""
    return {
        "format": "forge-investigation-candidates/1",
        "start": snapshot.start.isoformat(),
        "as_of": snapshot.as_of.isoformat(),
        "candidates": [c.model_dump(mode="json") for c in candidates(snapshot)],
    }


def same_lineage(left: Record, right: Record) -> bool:
    keys = ("ParentProcessGuid", "LogonId", "User")
    return left.host.casefold() == right.host.casefold() and all(
        left.data.get(k) and left.data.get(k).casefold() == right.data.get(k, "").casefold()
        for k in keys
    )


class Broker:
    """Bounded point queries; replies and incomplete pages are accounted explicitly."""

    def __init__(self, snapshot: Snapshot, budget: int):
        if type(budget) is not int or budget < 0:
            raise ValueError("Invalid budget")
        self.snapshot = snapshot
        self.budget = budget
        self.trace: list[Receipt] = []

    def query(self, c: Candidate, kind: str) -> tuple[list[Record | Approval], bool]:
        if len(self.trace) >= self.budget:
            return [], False
        rows: list[Record | Approval]
        if kind == "authorization":
            # Revision selection precedes scope filtering, including revoked/changed scopes.
            latest: dict[str, Approval] = {}
            for grant in self.snapshot.approvals:
                if grant.available_at <= self.snapshot.as_of and (
                    grant.id not in latest or grant.revision > latest[grant.id].revision
                ):
                    latest[grant.id] = grant
            rows = sorted(
                [
                    g
                    for g in latest.values()
                    if g.account.casefold() == c.record.data.get("User", "").casefold()
                    and c.record.host.casefold() in {h.casefold() for h in g.hosts}
                ],
                key=lambda g: (g.id, g.revision),
            )
        elif kind == "lineage":
            parent = c.record.data.get("ParentProcessGuid")
            sibling_guids = {
                r.data.get("ProcessGuid")
                for r in self.snapshot.records
                if r.source == "sysmon"
                and r.event_id == 1
                and r.time <= self.snapshot.as_of
                and same_lineage(c.record, r)
            } - {None, ""}
            rows = sorted(
                [
                    r
                    for r in self.snapshot.records
                    if r.time <= self.snapshot.as_of
                    and r.source == "sysmon"
                    and r.host.casefold() == c.record.host.casefold()
                    and (
                        (
                            r.event_id == 1
                            and (
                                same_lineage(c.record, r)
                                or (parent and r.data.get("ProcessGuid") == parent)
                            )
                        )
                        or (r.event_id == 11 and r.data.get("ProcessGuid") in sibling_guids)
                    )
                ],
                key=lambda r: (r.time, r.id),
            )
        else:
            raise ValueError("Unknown query")
        returned: list[Record | Approval] = []
        payload: list[dict] = []
        for row in rows:
            encoded = row.model_dump(mode="json")
            if len(returned) >= PAGE_RECORDS or size([*payload, encoded]) > PAGE_BYTES:
                break
            returned.append(row)
            payload.append(encoded)
        complete = len(returned) == len(rows)
        self.trace.append(
            Receipt(
                kind=kind,
                candidate=c.record.id,
                returned_ids=[
                    r.id if isinstance(r, Record) else f"approval:{r.id}:{r.revision}"
                    for r in returned
                ],
                response_bytes=size(payload),
                complete=complete,
            )
        )
        return returned, complete


def authorized(c: Candidate, rows: list[Record | Approval]) -> bool:
    return any(
        isinstance(g, Approval)
        and g.valid_from <= c.record.time < g.valid_until
        and any(
            s.action == c.action
            and s.input_path.casefold() == c.input_path
            and (s.output_path.casefold() if s.output_path else None) == c.output_path
            for s in g.grants
        )
        for g in rows
    )


def chain_edges(rows: list[Record | Approval]) -> set[tuple[str, str]]:
    records = [r for r in rows if isinstance(r, Record)]
    births = [r for r in records if r.event_id == 1]
    parsed = [c for r in births if (c := candidate(r)) is not None]
    edges: set[tuple[str, str]] = set()
    for d in parsed:
        if d.action != "inventory":
            continue
        for a in parsed:
            if a.action != "archive" or not same_lineage(d.record, a.record):
                continue
            parents = [
                p
                for p in births
                if p.data.get("ProcessGuid") == d.record.data.get("ParentProcessGuid")
                and p.host.casefold() == d.record.host.casefold()
                and p.data.get("User", "").casefold() == d.record.data.get("User", "").casefold()
                and p.time <= d.record.time
            ]
            files = [
                f
                for f in records
                if f.event_id == 11
                and f.host.casefold() == a.record.host.casefold()
                and f.data.get("ProcessGuid") == a.record.data.get("ProcessGuid")
                and f.data.get("TargetFilename", "").casefold() == a.output_path
                and a.record.time <= f.time
            ]
            if (
                len(parents) == 1
                and files
                and d.input_path == a.input_path
                and d.record.time < a.record.time
            ):
                edges.add((d.record.id, a.record.id))
    return edges


def investigate(snapshot: Snapshot, policy: Policy, budget: int) -> Result:
    if policy not in {"alert_only", "context", "unique_chain", "entity_fusion"}:
        raise ValueError("Unknown reference policy")
    broker = Broker(snapshot, budget)
    items = candidates(snapshot)
    decisions: dict[str, str] = {}
    edges: set[tuple[str, str]] = set()
    for c in items:
        key = c.record.id
        if policy == "alert_only":
            decisions[key] = "escalate"
            continue
        approvals, complete = broker.query(c, "authorization")
        if complete and authorized(c, approvals):
            decisions[key] = "clear"
            continue
        records, complete = broker.query(c, "lineage")
        supported = chain_edges(records) if complete else set()
        edges.update(supported)
        decisions[key] = "escalate" if any(key in pair for pair in supported) else "unresolved"
    groups = [[c.record.id] for c in items]
    merge: set[tuple[str, str]] = set()
    if policy == "unique_chain":
        active = {(a, b) for a, b in edges if decisions.get(a) == decisions.get(b) == "escalate"}
        for a, b in active:
            # Any ambiguous alternative, even a cleared one, prevents uniqueness claims.
            if sum(a == x for x, _ in edges) == sum(b == y for _, y in edges) == 1:
                merge.add((a, b))
    elif policy == "entity_fusion":
        for left, right in combinations(items, 2):
            a, b = left.record, right.record
            if (
                decisions[a.id] == decisions[b.id] == "escalate"
                and a.host.casefold() == b.host.casefold()
                and a.data.get("User")
                and a.data.get("User") == b.data.get("User")
            ):
                merge.add((a.id, b.id))
    for a, b in sorted(merge):
        ga, gb = next(g for g in groups if a in g), next(g for g in groups if b in g)
        if ga is not gb:
            ga.extend(gb)
            groups.remove(gb)
    return Result(
        policy=policy,
        budget=budget,
        candidates=[c.record.id for c in items],
        decisions=decisions,
        groups=sorted(sorted(g) for g in groups),
        trace=broker.trace,
        scanned_records=sum(r.time <= snapshot.as_of for r in snapshot.records),
        scanned_bytes=size(
            [r.model_dump(mode="json") for r in snapshot.records if r.time <= snapshot.as_of]
        ),
    )


def grade(result: Result, oracle: Oracle) -> dict[str, int]:
    # Known membership only; unrelated unlabeled activity is not adjudicated benign.
    known = {
        i: set(ids) if all(oracle.episodes[e] != "unknown" for e in ids) else set()
        for i, ids in oracle.actions.items()
    }
    actionable = {e for e, status in oracle.episodes.items() if status == "actionable"}
    actionable_actions = {i for i, episodes in oracle.actions.items() if set(episodes) & actionable}
    delivered = [g for g in result.groups if any(result.decisions[i] == "escalate" for i in g)]
    deliveries = {
        e: sum(any(e in oracle.actions.get(i, []) for i in g) for g in delivered)
        for e in actionable
    }
    false_pairs = unknown_pairs = 0
    for group in delivered:
        for a, b in combinations(group, 2):
            left, right = known.get(a, set()), known.get(b, set())
            if not left or not right:
                unknown_pairs += 1
            elif not left & right:
                false_pairs += 1
    return {
        "candidates": len(result.candidates),
        "unknown_candidates": sum(not known.get(i) for i in result.candidates),
        "cleared": sum(v == "clear" for v in result.decisions.values()),
        "unresolved": sum(v == "unresolved" for v in result.decisions.values()),
        "escalations": len(delivered),
        "false_escalations": sum(
            all(known.get(i) and all(oracle.episodes[e] == "benign" for e in known[i]) for i in g)
            for g in delivered
        ),
        "unknown_escalations": sum(any(not known.get(i) for i in g) for g in delivered),
        "actionable_episodes": len(actionable),
        "actionable_actions": len(actionable_actions),
        "escalated_actionable_actions": sum(
            result.decisions.get(i) == "escalate" for i in actionable_actions
        ),
        "missed_actionable_actions": sum(
            result.decisions.get(i) != "escalate" for i in actionable_actions
        ),
        "false_cleared_actions": sum(
            result.decisions.get(i) == "clear" for i in actionable_actions
        ),
        "recalled_episodes": sum(n > 0 for n in deliveries.values()),
        "missed_episodes": sum(n == 0 for n in deliveries.values()),
        "duplicate_escalations": sum(max(0, n - 1) for n in deliveries.values()),
        "false_fusion_pairs": false_pairs,
        "ungraded_fusion_pairs": unknown_pairs,
        "queries": result.queries,
        "response_bytes": sum(t.response_bytes for t in result.trace),
        "useful_evidence_read": len(
            {i for t in result.trace for i in t.returned_ids} & set(oracle.useful_evidence)
        ),
        "scanned_records": result.scanned_records,
        "scanned_bytes": result.scanned_bytes,
    }
