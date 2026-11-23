"""Reference evaluation preserved from the Detect experiment; see extraction provenance."""

import copy
import gzip
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import bench, models, native, pack
from .audit import read_records, verify


def broker_snapshot(
    records: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    protocol: dict[str, Any],
    visibility: str,
) -> models.Snapshot:
    available = copy.deepcopy(approvals)
    if visibility == "withheld":
        available = []
    elif visibility == "late":
        for approval in available:
            approval["available_at"] = (
                datetime.fromisoformat(protocol["as_of"].replace("Z", "+00:00"))
                + timedelta(minutes=1)
            ).isoformat()
    return models.Snapshot(
        start=protocol["start"], as_of=protocol["as_of"], records=records, approvals=available
    )


def evaluate_capture(
    folder: Path, case: dict[str, Any], protocol: dict[str, Any]
) -> list[dict[str, Any]]:
    try:
        return _evaluate_capture(folder, case, protocol)
    except Exception as exc:
        path = folder / "eligibility.json"
        status = json.loads(path.read_text()) if path.exists() else {"errors": []}
        status["eligible"] = False
        status["errors"].append(f"{type(exc).__name__}: {exc}")
        pack.write(path, status)
        raise


def _evaluate_capture(
    folder: Path, case: dict[str, Any], protocol: dict[str, Any]
) -> list[dict[str, Any]]:
    protocol = {**protocol, **{k: case[k] for k in ("start", "as_of") if k in case}}
    records, hashes = read_records(folder / "bundle")
    # Broker replay state is NOT an investigator input. Only candidate-feed is public.
    snapshots = {
        v: broker_snapshot(records, case["approvals"], protocol, v) for v in protocol["contexts"]
    }
    for visibility, snapshot in snapshots.items():
        with gzip.open(folder / f"broker-snapshot-{visibility}.json.gz", "wt") as stream:
            stream.write(snapshot.model_dump_json())
    pack.write(folder / "candidate-feed.json", bench.candidate_feed(snapshots["available"]))
    quality = json.loads((folder / "quality.stdout").read_text())
    if type(quality.get("acceptance_passed")) is not bool:
        raise ValueError("Missing or invalid Forge acceptance verdict")
    quality_status = {k: quality[k] for k in ("acceptance_passed", "overall_score", "flags")}
    truth = json.loads((folder / "bundle/GROUND_TRUTH.json").read_text())
    checks = [verify(truth, records, audit) for audit in case["audits"]]
    errors = [e for check in checks for e in check["errors"]]
    pack.write(
        folder / "eligibility.json",
        {
            "eligible": False,
            "native_eligible": False,
            "errors": errors,
            "checks": checks,
            "source_hashes": hashes,
            "quality": quality_status,
        },
    )
    if errors:
        return []
    oracle, index = native.reconcile_case(truth, snapshots["available"].records, case, hashes)
    oracle.useful_evidence = sorted(
        set(oracle.useful_evidence) | {i for c in checks for i in c["evidence_ids"]}
    )
    pack.write(folder / "private-oracle.json", oracle.model_dump(mode="json"))
    pack.write(
        folder / "eligibility.json",
        {
            "eligible": quality["acceptance_passed"],
            "native_eligible": True,
            "errors": []
            if quality["acceptance_passed"]
            else ["Forge hard acceptance criteria failed"],
            "checks": checks,
            "source_hashes": hashes,
            "quality": quality_status,
        },
    )
    pack.write(
        folder / "private-observation-index.json",
        {
            "scope": "Required authored process births only; native supporting references below; not a general occurrence index",
            "observations": index,
            "supporting_native_ids": oracle.useful_evidence,
            "omissions": [e for e in truth["events"] if e.get("emitted") is not True],
            "truth_sha256": pack.digest(folder / "bundle/GROUND_TRUTH.json"),
        },
    )
    results = []
    for visibility, snapshot in snapshots.items():
        # A candidate is generated from every matching observable command, not the private index.
        population = [c.record.id for c in bench.candidates(snapshot)]
        for policy in protocol["policies"]:
            for budget in protocol["budgets"]:
                begin = time.perf_counter()
                output = bench.investigate(snapshot, policy, budget)
                if output.candidates != population:
                    raise ValueError("Candidate population changed")
                name = f"{visibility}-{policy}-{budget}.json"
                pack.write(folder / name, output.model_dump(mode="json"))
                results.append(
                    {
                        "case": case["id"],
                        "family": case["family"],
                        "seed": case["seed"],
                        "context": visibility,
                        "policy": policy,
                        "budget": budget,
                        "diagnostic_only": not quality["acceptance_passed"],
                        "elapsed_seconds": time.perf_counter() - begin,
                        "result": name,
                        "result_sha256": pack.digest(folder / name),
                        "metrics": bench.grade(output, oracle),
                    }
                )
    return results


def summarize(
    protocol: dict[str, Any], attempts: list[dict[str, Any]], results: list[dict[str, Any]]
) -> dict[str, Any]:
    expected = {
        (c["id"], v, p, b)
        for c in protocol["cases"]
        for v in protocol["contexts"]
        for p in protocol["policies"]
        for b in protocol["budgets"]
    }
    actual = [(r["case"], r["context"], r["policy"], r["budget"]) for r in results]
    attempt_ids = [a["id"] for a in attempts]
    expected_ids = {c["id"] for c in protocol["cases"]}
    attempts_complete = len(attempt_ids) == len(expected_ids) and set(attempt_ids) == expected_ids
    complete = (
        attempts_complete
        and all(a["eligible"] for a in attempts)
        and len(actual) == len(expected)
        and set(actual) == expected
    )
    return {
        "execution_complete": complete,
        "attempts_complete": attempts_complete,
        "qualified_captures": sum(a["eligible"] for a in attempts),
        "native_captures": sum(a.get("native_eligible", a["eligible"]) for a in attempts),
        "matrix_complete": attempts_complete
        and len(actual) == len(expected)
        and set(actual) == expected,
        "planned_captures": len(protocol["cases"]),
        "planned_comparisons": len(expected),
        "completed_comparisons": len(results),
        "attempts": attempts,
        "results": results,
    }
