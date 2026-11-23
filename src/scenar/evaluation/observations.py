"""Bounded history-based triage. Routine resemblance is a risk choice, not proof of intent."""

import re

from . import bench, proof
from .models import Candidate, Model, Receipt, Record, Result

UPLOAD = re.compile(
    r"powershell\.exe -NoProfile -Command Invoke-WebRequest -Uri https://"
    r"(?P<destination>[0-9.]+)/archive -Method Post -InFile (?P<path>[A-Z]:\\[^\s]+)",
    re.I,
)


def group(c: Candidate, records: list[Record]) -> list[Record]:
    births = [
        r
        for r in records
        if r.source == "sysmon" and r.event_id == 1 and bench.same_lineage(c.record, r)
    ]
    guids = {r.data.get("ProcessGuid", "").casefold() for r in births} - {""}
    return [
        r
        for r in records
        if r.source == "sysmon"
        and r.host.casefold() == c.record.host.casefold()
        and (
            (
                r.event_id == 1
                and (
                    r.data.get("ProcessGuid", "").casefold() in guids
                    or r.data.get("ProcessGuid", "").casefold()
                    == c.record.data.get("ParentProcessGuid", "").casefold()
                )
            )
            or (r.event_id in {3, 11} and r.data.get("ProcessGuid", "").casefold() in guids)
        )
    ]


class Broker(bench.Broker):
    def query(self, c: Candidate, kind: str) -> tuple[proof.Reply, bool]:
        if kind not in {"observations", "history"}:
            return super().query(c, kind)
        if len(self.trace) >= self.budget:
            return [], False
        records = [r for r in self.snapshot.records if r.time <= self.snapshot.as_of]
        if kind == "observations":
            rows = group(c, records)
        else:
            records = [r for r in records if r.time < self.snapshot.start]
            peers = [
                p
                for r in records
                if (p := bench.candidate(r)) is not None
                and p.record.host.casefold() == c.record.host.casefold()
                and p.record.data.get("User", "").casefold()
                == c.record.data.get("User", "").casefold()
                and p.input_path == c.input_path
            ]
            rows = list({r.id: r for p in peers for r in group(p, records)}.values())
        rows.sort(key=lambda r: (r.time, r.id))
        returned = []
        payload = []
        for r in rows:
            encoded = r.model_dump(mode="json")
            if (
                len(returned) >= bench.PAGE_RECORDS
                or bench.size([*payload, encoded]) > bench.PAGE_BYTES
            ):
                break
            returned.append(r)
            payload.append(encoded)
        complete = len(returned) == len(rows)
        self.trace.append(
            Receipt(
                kind=kind,
                candidate=c.record.id,
                returned_ids=[r.id for r in returned],
                response_bytes=bench.size(payload),
                complete=complete,
            )
        )
        return returned, complete


class Chain(Model):
    parent: str
    archive: str
    uploader: str
    contact: str
    input_path: str
    output_path: str
    destination: str
    evidence_ids: list[str]


def describe(c: Candidate, rows: proof.Reply) -> Chain | None:
    records = [r for r in rows if isinstance(r, Record) and r.source == "sysmon"]
    births = [
        (r.host.casefold(), r.data.get("ProcessGuid", "").casefold())
        for r in records
        if r.event_id == 1
    ]
    if any(not guid for _, guid in births) or len(births) != len(set(births)):
        return None
    edges = [e for e in bench.chain_edges(records) if c.record.id in e]
    if len(edges) != 1:
        return None
    by_id = {r.id: r for r in records}
    a = bench.candidate(by_id[edges[0][1]])
    support = proof.chain_support(c, rows, True)
    if a is None or not support:
        return None
    files = [by_id[i] for i in support if by_id[i].event_id == 11]
    contacts = []
    for r in records:
        if r.event_id != 1 or not bench.same_lineage(a.record, r):
            continue
        match = UPLOAD.fullmatch(r.data.get("CommandLine", ""))
        if not match or match["path"].casefold() != a.output_path or r.time < files[0].time:
            continue
        sockets = [
            n
            for n in records
            if n.event_id == 3
            and n.host.casefold() == r.host.casefold()
            and n.data.get("ProcessGuid") == r.data.get("ProcessGuid")
            and n.data.get("DestinationIp") == match["destination"]
            and n.data.get("DestinationPort") == "443"
            and n.time >= r.time
        ]
        if len(sockets) == 1:
            contacts.append((r, sockets[0], match["destination"]))
    if len(contacts) != 1:
        return None
    upload, socket, endpoint = contacts[0]
    return Chain(
        parent=a.record.data["ParentProcessGuid"],
        archive=a.record.data["ProcessGuid"],
        uploader=upload.data["ProcessGuid"],
        contact=socket.id,
        input_path=a.input_path,
        output_path=a.output_path,
        destination=endpoint,
        evidence_ids=sorted(set(support + [upload.id, socket.id])),
    )


def investigate(items: list[Candidate], query: proof.Query, budget: int) -> proof.ProofRun:
    if type(budget) is not int or budget < 0 or len({c.record.id for c in items}) != len(items):
        raise ValueError("Invalid candidates or budget")
    trace = []
    cache = {}
    decisions = {c.record.id: "unresolved" for c in items}
    reasons = {
        c.record.id: proof.Reason(code="insufficient_observations", evidence_ids=[]) for c in items
    }

    def ask(c: Candidate, kind: str) -> tuple[proof.Reply, bool]:
        scope = (
            kind,
            *(
                proof._scope(c, lineage=True)
                if kind == "observations"
                else (*proof._scope(c), c.input_path)
            ),
        )
        if scope in cache:
            return cache[scope], True
        if len(trace) >= budget:
            return [], False
        rows, complete = query(c, kind)
        trace.append(
            Receipt(
                kind=kind,
                candidate=c.record.id,
                returned_ids=[r.id for r in rows],
                response_bytes=bench.size([r.model_dump(mode="json") for r in rows]),
                complete=complete,
            )
        )
        if complete:
            cache[scope] = rows
        return rows, complete

    for c in items:
        rows, complete = ask(c, "observations")
        current = describe(c, rows) if complete else None
        if current is None:
            continue
        history, complete = ask(c, "history")
        if not complete:
            continue
        chains = {}
        for r in history:
            if not isinstance(r, Record) or (past := bench.candidate(r)) is None:
                continue
            chain = describe(past, history)
            if (
                chain
                and chain.input_path == current.input_path
                and chain.output_path == current.output_path
            ):
                chains[(chain.parent, chain.archive)] = chain
        # Distinct native parents and archives, not duplicate row IDs or two actions of one run.
        if (
            len(chains) < 2
            or len({p for p, _ in chains}) != len(chains)
            or len({a for _, a in chains}) != len(chains)
        ):
            continue
        if current.parent in {p for p, _ in chains} or current.archive in {a for _, a in chains}:
            continue
        identities = [*chains.values(), current]
        if any(
            len({getattr(chain, field) for chain in identities}) != len(identities)
            for field in ("uploader", "contact")
        ):
            continue
        destinations = {chain.destination for chain in chains.values()}
        if len(destinations) != 1:
            continue
        routine = current.destination in destinations
        decisions[c.record.id] = "clear" if routine else "escalate"
        reasons[c.record.id] = proof.Reason(
            code="routine_observed" if routine else "new_observed_destination",
            evidence_ids=sorted(
                set(
                    current.evidence_ids
                    + [i for chain in chains.values() for i in chain.evidence_ids]
                )
            ),
        )
    return proof.ProofRun(
        result=Result(
            policy="history_risk",
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
