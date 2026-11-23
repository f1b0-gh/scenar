"""Evidence-gated review requests over public candidates and metered replies only.

A documented temporal scope conflict can request review; it does not prove an
attack. Permission alone never proves benign intent. This corpus has no independent
benign attestation, so these policies deliberately cannot return a benign clearance.
"""

from collections.abc import Callable
from typing import Literal

from . import bench
from .models import Approval, Candidate, Model, Receipt, Record, Result

Reply = list[Record | Approval]
Query = Callable[[Candidate, str], tuple[Reply, bool]]
ProofPolicy = Literal["proof_guard", "proof_adaptive"]


class Reason(Model):
    code: str
    evidence_ids: list[str]


class ProofRun(Model):
    result: Result
    reasons: dict[str, Reason]


def _approval_id(grant: Approval) -> str:
    return f"approval:{grant.id}:{grant.revision}"


def authorization(c: Candidate, rows: Reply, complete: bool) -> Reason:
    if not complete:
        return Reason(code="authorization_incomplete", evidence_ids=[])
    exact = [
        g
        for g in rows
        if isinstance(g, Approval)
        and g.account.casefold() == c.record.data.get("User", "").casefold()
        and c.record.host.casefold() in {h.casefold() for h in g.hosts}
        and any(
            s.action == c.action
            and s.input_path.casefold() == c.input_path
            and (s.output_path.casefold() if s.output_path else None) == c.output_path
            for s in g.grants
        )
    ]
    valid = [g for g in exact if g.valid_from <= c.record.time < g.valid_until]
    if valid:
        return Reason(
            code="permission_without_independent_benign_evidence",
            evidence_ids=sorted(_approval_id(g) for g in valid),
        )
    if exact:
        return Reason(
            code="documented_window_conflict_needs_behavior",
            evidence_ids=sorted(_approval_id(g) for g in exact),
        )
    return Reason(code="authorization_does_not_establish_intent", evidence_ids=[])


def chain_support(c: Candidate, rows: Reply, complete: bool) -> list[str]:
    if not complete:
        return []
    records = [r for r in rows if isinstance(r, Record) and r.source == "sysmon"]
    by_id = {r.id: r for r in records}
    for discover, archive in sorted(bench.chain_edges(records)):
        if c.record.id not in {discover, archive}:
            continue
        d, a = by_id[discover], by_id[archive]
        parents = [
            r
            for r in records
            if r.event_id == 1
            and r.data.get("ProcessGuid") == d.data.get("ParentProcessGuid")
            and r.host.casefold() == d.host.casefold()
            and r.data.get("User", "").casefold() == d.data.get("User", "").casefold()
            and r.data.get("LogonId")
            and r.data["LogonId"].casefold() == d.data.get("LogonId", "").casefold()
            and r.time <= d.time
        ]
        parsed = bench.candidate(a)
        files = [
            r
            for r in records
            if r.event_id == 11
            and parsed is not None
            and r.host.casefold() == a.host.casefold()
            and r.data.get("ProcessGuid") == a.data.get("ProcessGuid")
            and r.data.get("TargetFilename", "").casefold() == parsed.output_path
            and r.time >= a.time
        ]
        if len(parents) == 1 and files:
            return sorted(
                {discover, archive, parents[0].id, min(files, key=lambda r: (r.time, r.id)).id}
            )
    return []


def _scope(c: Candidate, lineage: bool = False) -> tuple[str, ...]:
    fields = [c.record.host, c.record.data.get("User", "")]
    if lineage:
        fields.extend(
            [c.record.data.get("LogonId", ""), c.record.data.get("ParentProcessGuid", "")]
        )
    if not all(fields):
        return ("uncacheable", c.record.id)
    # Broker parent-birth lookup is raw equality; its sibling predicate alone
    # case-folds GUIDs. Preserve the stricter lookup in the reuse scope.
    if lineage:
        return (*[x.casefold() for x in fields[:-1]], fields[-1])
    return tuple(x.casefold() for x in fields)


def investigate(items: list[Candidate], query: Query, policy: ProofPolicy, budget: int) -> ProofRun:
    """Neither snapshot, private labels, target positions nor profile names enter here."""
    if policy not in {"proof_guard", "proof_adaptive"} or type(budget) is not int or budget < 0:
        raise ValueError("Invalid policy or budget")
    if len({c.record.id for c in items}) != len(items):
        raise ValueError("Duplicate public candidate")
    trace: list[Receipt] = []
    reasons: dict[str, Reason] = {}
    decisions = {c.record.id: "unresolved" for c in items}

    def ask(c: Candidate, kind: str) -> tuple[Reply, bool]:
        if len(trace) >= budget:
            return [], False
        rows, complete = query(c, kind)
        trace.append(
            Receipt(
                kind=kind,
                candidate=c.record.id,
                returned_ids=[r.id if isinstance(r, Record) else _approval_id(r) for r in rows],
                response_bytes=bench.size([r.model_dump(mode="json") for r in rows]),
                complete=complete,
            )
        )
        return rows, complete

    def conclude(c: Candidate, rows: Reply, complete: bool) -> None:
        key = c.record.id
        if reasons[key].code != "documented_window_conflict_needs_behavior":
            return
        support = chain_support(c, rows, complete)
        if support:
            decisions[key] = "escalate"
            reasons[key] = Reason(
                code="documented_window_conflict",
                evidence_ids=sorted(set(support + reasons[key].evidence_ids)),
            )

    if policy == "proof_guard":
        # Exact reference schedule, including its permission early exit. Only the
        # conclusion changes; absent/partial permission still triggers its pivot.
        for c in items:
            rows, complete = ask(c, "authorization")
            reasons[c.record.id] = authorization(c, rows, complete)
            if complete and bench.authorized(c, rows):
                continue
            records, complete = ask(c, "lineage")
            conclude(c, records, complete)
    else:
        permissions: dict[tuple[str, ...], Reply] = {}
        for c in items:
            scope = _scope(c)
            if scope in permissions:
                rows, complete = permissions[scope], True
            else:
                rows, complete = ask(c, "authorization")
                if complete:
                    permissions[scope] = rows
            reasons[c.record.id] = authorization(c, rows, complete)
        lineage: dict[tuple[str, ...], Reply] = {}
        for c in items:
            if reasons[c.record.id].code != "documented_window_conflict_needs_behavior":
                continue
            scope = _scope(c, lineage=True)
            if scope in lineage:
                rows, complete = lineage[scope], True
            else:
                rows, complete = ask(c, "lineage")
                if complete:
                    lineage[scope] = rows
            conclude(c, rows, complete)
    return ProofRun(
        result=Result(
            policy=policy,
            budget=budget,
            candidates=[c.record.id for c in items],
            decisions=decisions,
            groups=sorted([[c.record.id] for c in items]),
            trace=trace,
            scanned_records=len(items),
            scanned_bytes=bench.size([c.model_dump(mode="json") for c in items]),
        ),
        reasons=reasons,
    )
