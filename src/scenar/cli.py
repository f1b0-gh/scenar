"""Scenar's Python command line."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import __version__, attack_cli
from .authoring import build
from .backend import (
    active_pin,
    backend_command,
    backend_path,
    check_backend,
    compare_backends,
    inspect_backend,
    read_pin,
)
from .background import BackgroundActivity
from .io import write_json
from .replay import replay_run, verify_bundle
from .runner import prepare_run, run_all
from .storage import (
    default_store,
    export_public,
    initialize_store,
    list_bundles,
    publish_bundle,
    pull_bundle,
)
from .truth import GroundTruth, IntentPredictions


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scenar", description="Reproducible synthetic detection datasets"
    )
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    attack_cli.add_parser(commands)
    from .datasets import cli as dataset_cli

    dataset_cli.add_parser(commands)
    for name in ("build", "validate", "generate"):
        cmd = commands.add_parser(name)
        cmd.add_argument("source", type=Path)
        cmd.add_argument("overrides", nargs="*")
        cmd.add_argument("--output", "-o", type=Path)
        cmd.add_argument("--catalog", type=Path)
        cmd.add_argument("--ground-truth", type=Path, help="Private GroundTruth JSON file")
        cmd.add_argument("--background", choices=["quiet", "office", "server"])
        cmd.add_argument("--intensity", choices=["low", "medium", "high"])
        cmd.add_argument("--noise-only", action="store_true")
        if name != "build":
            cmd.add_argument("--backend", type=Path)
            cmd.add_argument("--pin", type=Path, help="Explicit alternative backend pin")
        if name == "generate":
            cmd.add_argument("--seed", type=int)
            cmd.add_argument(
                "--stage-timeout-seconds",
                type=int,
                default=300,
                help="Time limit for each backend stage (default: 300); also adjust caller deadlines",
            )
    cmd = commands.add_parser("prepare")
    cmd.add_argument("pack", choices=["investigation-episodes"])
    cmd.add_argument("--output", "-o", type=Path, required=True)
    cmd.add_argument("--backend", type=Path)
    cmd.add_argument("--family", action="append")
    cmd.add_argument("--catalog", type=Path)
    cmd.add_argument("--ground-truth", type=Path)
    cmd.add_argument("--background", choices=["quiet", "office", "server"])
    cmd.add_argument("--intensity", choices=["low", "medium", "high"])

    cmd.add_argument("--pin", type=Path, help="Explicit alternative backend pin")
    cmd = commands.add_parser("run")
    cmd.add_argument("run", type=Path)
    cmd.add_argument("--backend", type=Path)
    cmd.add_argument("--publish-to", help="Publish the qualified result to a disk store or S3 URI")
    for name in ("replay", "evaluate", "qualify"):
        cmd = commands.add_parser(name)
        cmd.add_argument("source", type=Path)
        cmd.add_argument("--output", "-o", type=Path, required=True)
        cmd.add_argument(
            "--annotate-attack",
            action="store_true",
            help="Explicitly add current pinned ATT&CK mappings when regrading",
        )
        cmd.add_argument("--catalog", type=Path)
        cmd.add_argument("--ground-truth", type=Path)
        if name == "evaluate":
            cmd.add_argument("--adapter", choices=["reference"], default="reference")
    cmd = commands.add_parser(
        "grade-intent",
        help="Grade explicit intent predictions separately from investigation decisions",
    )
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument("predictions", type=Path)
    cmd.add_argument("--output", type=Path, required=True)
    cmd = commands.add_parser("verify")
    cmd.add_argument("bundle", type=Path)
    cmd = commands.add_parser("export-public")
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument("--output", "-o", type=Path, required=True)
    cmd.add_argument("--windows-format", choices=("xml", "evtx"), default="xml")
    cmd.add_argument("--backend", type=Path, help="External EVTX encoder checkout")
    cmd.add_argument("--pin", type=Path, help="Explicit EVTX encoder identity pin")
    cmd.add_argument("--receipt", type=Path, help="Restricted receipt outside the public export")
    cmd.add_argument("--timeout", type=float, default=300, help="Seconds per EVTX encoding")
    cmd = commands.add_parser("publish")
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument("destination", nargs="?", help="Local store directory or s3://bucket/prefix")
    cmd.add_argument("--diagnostic", action="store_true")
    cmd = commands.add_parser("pull")
    cmd.add_argument("source")
    cmd.add_argument("destination", type=Path)
    cmd = commands.add_parser("list")
    cmd.add_argument("store", nargs="?")
    cmd = commands.add_parser("init-store", help="Create a local store or S3/RustFS bucket")
    cmd.add_argument("store", nargs="?")
    cmd = commands.add_parser("c2-query", help="Scan a public JSON view for linked workflows")
    cmd.add_argument("source", type=Path)
    cmd.add_argument(
        "--start", required=True, help="Observation window start (timezone-aware ISO timestamp)"
    )
    cmd = commands.add_parser("backend")
    sub = cmd.add_subparsers(dest="backend_action", required=True)
    for name in ("inspect", "check", "compare", "schema"):
        item = sub.add_parser(name)
        item.add_argument("--backend", type=Path)
        if name == "check":
            item.add_argument("--pin", required=True, type=Path)
        if name == "compare":
            item.add_argument("candidate", type=Path)
            item.add_argument("--matrix-output", type=Path)
    return p


def dispatch(args) -> int:
    if args.command == "dataset":
        from .datasets.cli import dispatch as dispatch_dataset

        return dispatch_dataset(args)
    if args.command == "attack":
        return attack_cli.dispatch(args)
    if args.command in ("build", "validate", "generate", "prepare"):
        if args.intensity and not args.background:
            raise ValueError("--intensity requires --background")
        background = (
            BackgroundActivity(profile=args.background, intensity=args.intensity or "medium")
            if args.background
            else None
        )
        truth = (
            GroundTruth.model_validate_json(args.ground_truth.read_bytes())
            if args.ground_truth
            else None
        )
    if args.command in ("build", "validate", "generate"):
        out = args.output or Path("build") / args.source.stem
        if args.command == "generate":
            from .generation import generate_scenario

            print(
                generate_scenario(
                    args.source,
                    out,
                    backend=args.backend,
                    pin=read_pin(args.pin) if args.pin else None,
                    background=background,
                    ground_truth=truth,
                    noise_only=args.noise_only,
                    seed=args.seed,
                    stage_timeout_seconds=args.stage_timeout_seconds,
                    catalog_path=args.catalog,
                    overrides=args.overrides,
                )
            )
            return 0
        scenario = build(
            args.source,
            out,
            args.overrides,
            catalog_path=args.catalog,
            background=background,
            ground_truth=truth,
            noise_only=args.noise_only,
        )
        if args.command != "build":
            root = backend_path(args.backend)
            check_backend(root, read_pin(args.pin) if args.pin else active_pin())
            write_json(out / "sources/backend.json", inspect_backend(root).model_dump())
            status = subprocess.run(
                backend_command(root, "validate", str(scenario.resolve())), cwd=root
            ).returncode
            if status:
                return status
        print(out)
    elif args.command == "prepare":
        options = {"families": tuple(args.family)} if args.family else {}
        result = prepare_run(
            args.pack,
            args.output,
            backend=args.backend,
            pin=read_pin(args.pin) if args.pin else None,
            catalog_path=args.catalog,
            ground_truth=truth,
            background=background,
            **options,
        )
        print(json.dumps({"run": str(args.output), "planned_captures": len(result.cases)}))
    elif args.command == "run":
        result = run_all(args.run, backend=args.backend)
        print(json.dumps({k: v for k, v in result.items() if k not in ("attempts", "results")}))
        if args.publish_to and result["execution_complete"]:
            print(publish_bundle(args.run, args.publish_to))
        return 0 if result["execution_complete"] else 1
    elif args.command in ("replay", "evaluate", "qualify"):
        result = replay_run(
            args.source,
            args.output,
            annotate_attack=args.annotate_attack,
            catalog_path=args.catalog,
            ground_truth=GroundTruth.model_validate_json(args.ground_truth.read_bytes())
            if args.ground_truth
            else None,
        )
        print(
            json.dumps(
                {
                    "run": str(args.output),
                    "captures": len(result.captures),
                    "qualified": sum(c.qualified for c in result.captures),
                    "regenerated": False,
                }
            )
        )
        return 0 if result.qualified else 1
    elif args.command == "grade-intent":
        from .analysis_reports import grade_bundle_intent

        raw = json.loads(args.predictions.read_bytes())
        if not isinstance(raw, dict):
            raise ValueError("Predictions must map capture IDs to intent predictions")
        predictions = {id: IntentPredictions.model_validate(value) for id, value in raw.items()}
        grade_bundle_intent(args.bundle, predictions, args.output)
        print(args.output)
    elif args.command == "verify":
        manifest = verify_bundle(args.bundle)
        print(json.dumps({"bundle_id": manifest.bundle_id, "verified_files": len(manifest.files)}))
    elif args.command == "publish":
        print(publish_bundle(args.bundle, args.destination or default_store(), args.diagnostic))
    elif args.command == "pull":
        print(pull_bundle(args.source, args.destination).bundle_id)
    elif args.command == "list":
        print("\n".join(list_bundles(args.store or default_store())))
    elif args.command == "init-store":
        print(initialize_store(args.store or default_store()))
    elif args.command == "c2-query":
        import gzip

        from .evaluation.c2 import find_chains

        opener = gzip.open if args.source.suffix == ".gz" else open
        with opener(args.source, "rt") as stream:
            print(json.dumps(find_chains(json.load(stream), args.start), indent=2))
    elif args.command == "export-public":
        export_public(
            args.bundle,
            args.output,
            windows_format=args.windows_format,
            backend=args.backend,
            pin=read_pin(args.pin) if args.pin else None,
            receipt=args.receipt,
            timeout=args.timeout,
        )
        print(args.output)
    elif args.command == "backend":
        root = backend_path(args.backend)
        if args.backend_action == "check":
            check_backend(root, read_pin(args.pin))
            print("Backend identity matches pin")
        elif args.backend_action == "inspect":
            print(inspect_backend(root).model_dump_json(indent=2))
        elif args.backend_action == "schema":
            from .compatibility import export_schema

            print(json.dumps(export_schema(root), indent=2))
        else:
            if args.matrix_output:
                from .compatibility import check_candidate

                result = check_candidate(root, args.candidate, args.matrix_output)
            else:
                result = compare_backends(root, args.candidate)
            print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    from botocore.exceptions import BotoCoreError, ClientError

    args = parser().parse_args(argv)
    try:
        return dispatch(args)
    except (
        ValueError,
        OSError,
        KeyError,
        RuntimeError,
        BotoCoreError,
        ClientError,
        subprocess.TimeoutExpired,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"scenar: {exc}", file=sys.stderr)
        return 2
