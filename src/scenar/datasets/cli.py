"""CLI for dataset preparation and generation, independent of detector runtimes."""

import json
import sys
from pathlib import Path


def add_parser(commands) -> None:
    parser = commands.add_parser(
        "dataset", help="Build and generate controlled synthetic dataset matrices"
    )
    sub = parser.add_subparsers(dest="dataset_action", required=True)
    prepare = sub.add_parser("prepare", help="Freeze recipes, variants, visibility and seeds")
    prepare.add_argument("spec", type=Path)
    prepare.add_argument("--output", "-o", type=Path, required=True)
    prepare.add_argument("--backend", type=Path)
    prepare.add_argument("--pin", type=Path)
    prepare.add_argument("--catalog", type=Path)
    run = sub.add_parser("run", help="Generate every frozen slot and audit native effects")
    run.add_argument("run", type=Path)
    run.add_argument("--backend", type=Path)
    run.add_argument("--publish-to")
    resume = sub.add_parser(
        "resume", help="Reuse verified captures in a new run; retain prior failures"
    )
    resume.add_argument("source", type=Path)
    resume.add_argument("--output", "-o", type=Path, required=True)
    resume.add_argument("--backend", type=Path)
    resume.add_argument("--publish-to")
    inspect = sub.add_parser("inspect", help="Verify frozen inputs and summarize a dataset")
    inspect.add_argument("run", type=Path)
    lineage = sub.add_parser("lineage", help="Print restricted capture ancestry and related cases")
    lineage.add_argument("run", type=Path)
    splits = sub.add_parser(
        "check-splits", help="Validate complete private development/test assignments"
    )
    splits.add_argument("assignments", type=Path)
    smoke = sub.add_parser(
        "smoke", help="Run fresh native family/control tests and verified delivery"
    )
    smoke.add_argument("--output", "-o", type=Path, required=True)
    smoke.add_argument("--backend", type=Path)
    smoke.add_argument("--pin", type=Path)
    smoke.add_argument("--s3-store")
    smoke.add_argument("--stage-timeout-seconds", type=int, default=1800)
    preflight = sub.add_parser(
        "preflight", help="Check pinned backend, host prerequisites and free space"
    )
    preflight.add_argument("run", type=Path)
    preflight.add_argument("--backend", type=Path)
    preflight.add_argument("--min-free-bytes", type=int, default=0)
    timings = sub.add_parser(
        "timings", help="Measured stage/output ranges from comparable verified captures"
    )
    timings.add_argument(
        "capture", type=Path, help="Raw generation or dataset private/attempts/CASE directory"
    )
    timings.add_argument(
        "--history",
        type=Path,
        action="append",
        required=True,
        help="Raw generation or whole dataset; repeat for multiple histories",
    )
    schema = sub.add_parser("schema")
    schema.add_argument("contract", choices=["spec", "visibility", "expectations"])


def dispatch(args) -> int:
    from ..backend import read_pin
    from .matrix import DatasetSpec, load_dataset, prepare_dataset, read_spec, run_dataset

    if args.dataset_action == "preflight":
        from ..backend import backend_path
        from .diagnostics import preflight

        plan = load_dataset(args.run)
        report = preflight(
            backend_path(args.backend), plan.backend, args.run, min_free_bytes=args.min_free_bytes
        )
        print(report.model_dump_json(by_alias=True, indent=2))
        return 0 if report.ready else 1
    elif args.dataset_action == "timings":
        from .diagnostics import timing_report

        print(json.dumps(timing_report(args.capture, args.history), indent=2))
    elif args.dataset_action == "lineage":
        from .lineage import dataset_lineage

        print(dataset_lineage(args.run).model_dump_json(by_alias=True, indent=2))
    elif args.dataset_action == "check-splits":
        from .lineage import validate_splits

        print(json.dumps(validate_splits(json.loads(args.assignments.read_bytes())), indent=2))
    elif args.dataset_action == "smoke":
        from .smoke import run_smoke

        report = run_smoke(
            args.output,
            backend=args.backend,
            pin=read_pin(args.pin) if args.pin else None,
            s3_store=args.s3_store,
            stage_timeout_seconds=args.stage_timeout_seconds,
            progress=_progress,
        )
        print(report.model_dump_json(by_alias=True, indent=2))
        return 0 if report.passed else 1
    elif args.dataset_action == "prepare":
        plan = prepare_dataset(
            read_spec(args.spec),
            args.output,
            backend=args.backend,
            pin=read_pin(args.pin) if args.pin else None,
            catalog_path=args.catalog,
        )
        print(json.dumps({"output": str(args.output), "planned": len(plan.cases)}, indent=2))
    elif args.dataset_action in {"run", "resume"}:
        if args.dataset_action == "resume":
            from .resume import resume_dataset

            report = resume_dataset(
                args.source, args.output, backend=args.backend, progress=_progress
            )
            destination = args.output
        else:
            report = run_dataset(args.run, backend=args.backend, progress=_progress)
            destination = args.run
        if args.publish_to:
            from ..storage import publish_bundle

            report["published"] = publish_bundle(destination, args.publish_to)
        print(json.dumps(report, indent=2))
        return 0 if report["qualified"] == report["planned"] else 1
    elif args.dataset_action == "inspect":
        plan = load_dataset(args.run)
        print(
            json.dumps(
                {
                    "planned": len(plan.cases),
                    "spec": plan.spec.model_dump(mode="json", by_alias=True),
                },
                indent=2,
            )
        )
    else:
        from .audit import EffectExpectation
        from .visibility import VisibilitySettings

        model = {
            "spec": DatasetSpec,
            "visibility": VisibilitySettings,
            "expectations": EffectExpectation,
        }[args.contract]
        print(json.dumps(model.model_json_schema(), indent=2))
    return 0


def _progress(event):
    print(
        f"[{event.completed}/{event.planned}] {event.case_id}: {event.state}",
        file=sys.stderr,
        flush=True,
    )
