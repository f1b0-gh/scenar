"""CLI for explicit catalogue maintenance and restricted ATT&CK reports."""

import json
from pathlib import Path

from .attack import Catalog, TechniqueSelection, import_catalog, load_catalog
from .coverage import Detections, navigator
from .io import write_json


def add_parser(commands) -> None:
    parser = commands.add_parser(
        "attack", help="Pinned MITRE ATT&CK catalogues and evidence coverage"
    )
    sub = parser.add_subparsers(dest="attack_action", required=True)
    p = sub.add_parser("import")
    p.add_argument("source", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--domain", choices=["enterprise-attack", "mobile-attack", "ics-attack"], required=True
    )
    p.add_argument("--release")
    p.add_argument("--sha256")
    p.add_argument("--source-url")
    for name in ("inspect", "list", "show", "export"):
        p = sub.add_parser(name)
        p.add_argument("--catalog", type=Path)
        if name == "list":
            p.add_argument("--tactic")
            p.add_argument("--platform")
            p.add_argument("--include-retired", action="store_true")
        if name == "show":
            p.add_argument("technique")
        if name == "export":
            p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("coverage")
    p.add_argument("bundle", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--detections", type=Path)
    p = sub.add_parser("navigator")
    p.add_argument("report", type=Path)
    p.add_argument("--stage", choices=["authored", "observed", "detected"], default="authored")
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("schema")
    p.add_argument("contract", choices=["scenario", "ground-truth", "background", "catalog"])


def dispatch(args) -> int:
    if args.attack_action == "import":
        catalog = import_catalog(
            args.source,
            args.output,
            domain=args.domain,
            expected_sha256=args.sha256,
            release=args.release,
            source_url=args.source_url,
        )
        print(
            json.dumps(
                {
                    "release": catalog.release,
                    "domain": catalog.domain,
                    "techniques": len(catalog.techniques),
                    "catalog_sha256": catalog.sha256,
                }
            )
        )
    elif args.attack_action == "coverage":
        from .analysis_reports import bundle_coverage

        detections = (
            Detections.model_validate_json(args.detections.read_bytes())
            if args.detections
            else None
        )
        result = bundle_coverage(args.bundle, args.output, detections=detections)
        print(
            json.dumps(
                {
                    "cases": len(result["cases"]),
                    "techniques": len(result["techniques"]),
                    "output": str(args.output),
                }
            )
        )
    elif args.attack_action == "navigator":
        if args.output.exists():
            raise FileExistsError(args.output)
        write_json(args.output, navigator(json.loads(args.report.read_bytes()), args.stage))
        print(args.output)
    elif args.attack_action == "schema":
        from .background import BackgroundActivity
        from .scenario import ScenarioDocument
        from .truth import GroundTruth

        print(
            json.dumps(
                {
                    "scenario": ScenarioDocument,
                    "ground-truth": GroundTruth,
                    "background": BackgroundActivity,
                    "catalog": Catalog,
                }[args.contract].model_json_schema(),
                indent=2,
            )
        )
    else:
        catalog = load_catalog(args.catalog)
        if args.attack_action == "inspect":
            print(
                json.dumps(
                    {
                        "domain": catalog.domain,
                        "release": catalog.release,
                        "source_sha256": catalog.source_sha256,
                        "catalog_sha256": catalog.sha256,
                        "techniques": len(catalog.techniques),
                        "tactics": len(catalog.tactics),
                    },
                    indent=2,
                )
            )
        elif args.attack_action == "show":
            print(
                catalog.resolve(
                    TechniqueSelection(technique=args.technique), allow_retired=True
                ).model_dump_json(indent=2)
            )
        elif args.attack_action == "list":
            values = []
            for t in catalog.techniques.values():
                if not args.include_retired and (t.revoked or t.deprecated):
                    continue
                if args.tactic and args.tactic not in t.tactics:
                    continue
                if args.platform and args.platform not in t.platforms:
                    continue
                values.append(t.model_dump(mode="json"))
            print(json.dumps(sorted(values, key=lambda x: x["id"]), indent=2))
        else:
            if args.output.exists():
                raise FileExistsError(args.output)
            # Imported bundles export exact original STIX; packaged projection is clearly typed.
            if args.catalog and (args.catalog / "source.stix.json").exists():
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_bytes((args.catalog / "source.stix.json").read_bytes())
            else:
                write_json(args.output, catalog.model_dump(mode="json"))
            print(args.output)
    return 0
