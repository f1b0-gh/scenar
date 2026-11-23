"""Generate Nickel contracts for EvidenceForge storyline event specs.

Reads the Pydantic JSON Schema of an installed EvidenceForge and writes
generated/ef_events.ncl, so Nickel catches unknown event types, unknown
fields and wrong field shapes before EvidenceForge ever sees the YAML.
EvidenceForge's own `eforge validate` stays the authority for semantics
(ranges, cross-references, causality).

Usage (from an EvidenceForge checkout):
    uv run python /path/to/scenar/tools/gen_ef_contracts.py \
        > /path/to/scenar/generated/ef_events.ncl
"""

from __future__ import annotations

import hashlib
import json
import sys

SIMPLE = {
    "string": "String",
    "integer": "std.number.Integer",
    "number": "Number",
    "boolean": "Bool",
}


def nickel_str(s: str) -> str:
    return json.dumps(s)


def field_contract(prop: dict) -> tuple[str, bool]:
    """Return (contract, nullable)."""
    nullable = False
    if "anyOf" in prop:
        variants = [v for v in prop["anyOf"] if v.get("type") != "null"]
        nullable = len(variants) != len(prop["anyOf"])
        if nullable:
            # Nickel's partial frontend must not reject backend-valid nulls.
            # Full union/reference validation remains EvidenceForge's responsibility.
            return "Dyn", True
        if len(variants) == 1:
            inner, _ = field_contract(variants[0])
            return inner, nullable
        return "Dyn", nullable
    if "enum" in prop:
        return (
            f"(OneOf [{', '.join(nickel_str(v) for v in prop['enum'] if isinstance(v, str))}])",
            nullable,
        )
    if "const" in prop:
        return f"(OneOf [{nickel_str(prop['const'])}])", nullable
    t = prop.get("type")
    if t in SIMPLE:
        return SIMPLE[t], nullable
    if t == "array":
        items = prop.get("items", {})
        inner, _ = field_contract(items) if items else ("Dyn", False)
        return f"(Array {inner})", nullable
    return "Dyn", nullable


def main() -> None:
    from evidenceforge import __version__ as EF_VERSION
    from evidenceforge.models.scenario import Scenario

    schema = Scenario.model_json_schema()
    schema_hash = hashlib.sha256(
        json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    defs = schema["$defs"]
    mapping = defs["StorylineEvent"]["properties"]["events"]["items"]["discriminator"]["mapping"]
    out: list[str] = []
    w = out.append
    w(f"# GENERATED from EvidenceForge {EF_VERSION} by tools/gen_ef_contracts.py — do not edit.")
    w(f"# Scenario JSON Schema sha256: {schema_hash}")
    w("# Nullable, reference and unsupported union constraints are delegated to eforge validate.")
    w(
        "let OneOf = fun allowed => std.contract.from_predicate (fun v => std.array.elem v allowed) in"
    )
    w("let by_type = {")
    for type_name, ref in sorted(mapping.items()):
        spec = defs[ref.rsplit("/", 1)[1]]
        required = set(spec.get("required", []))
        w(f"  {type_name} = {{")
        for fname, prop in spec["properties"].items():
            contract, _ = field_contract(prop)
            if fname == "type":
                contract = f"(OneOf [{nickel_str(type_name)}])"
            opt = "" if fname in required else " | optional"
            w(f"    {nickel_str(fname)} | {contract}{opt},")
        w("  },")
    w("} in")
    w("{")
    w("  types = std.record.fields by_type,")
    w("  # One storyline event: dispatches on `type` to the matching closed record contract.")
    w("  EventSpec = std.contract.custom (fun label value =>")
    w("    if std.typeof value != 'Record then")
    w('      \'Error { message = "EvidenceForge event must be a record" }')
    w('    else if !(std.record.has_field "type" value) then')
    w('      \'Error { message = "EvidenceForge event is missing `type`" }')
    w("    else if !(std.record.has_field value.type by_type) then")
    w("      'Error {")
    w('        message = "unknown EvidenceForge event type `%{value.type}`",')
    w(f"        notes = [{nickel_str('known types: ' + ', '.join(sorted(mapping)))}],")
    w("      }")
    w("    else")
    w('      \'Ok (std.contract.apply by_type."%{value.type}" label value)),')
    w("}")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
