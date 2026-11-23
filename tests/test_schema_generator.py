import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "ef_contracts", Path(__file__).parents[1] / "tools/gen_ef_contracts.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_nullable_is_delegated_instead_of_rejecting_valid_null():
    assert module.field_contract({"anyOf": [{"type": "string"}, {"type": "null"}]}) == ("Dyn", True)


def test_nested_references_are_explicitly_delegated():
    assert module.field_contract({"$ref": "#/$defs/Nested"}) == ("Dyn", False)
    assert module.field_contract({"type": "array", "items": {"$ref": "#/$defs/Nested"}}) == (
        "(Array Dyn)",
        False,
    )


def test_supported_scalar_contracts_remain_checked():
    assert module.field_contract({"type": "integer"}) == ("std.number.Integer", False)
