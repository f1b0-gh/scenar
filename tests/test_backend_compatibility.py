from scenar.backend import compare_backends
from scenar.compatibility import compare_schemas
from tests.test_backend import checkout


def test_comparison_reports_change_without_claiming_compatibility(tmp_path):
    left = checkout(tmp_path / "left")
    right = checkout(tmp_path / "right")
    (right / "src/evidenceforge/config/generation_behavior.yaml").write_text(
        "current_revision: 163\n"
    )
    report = compare_backends(left, right)
    assert "behavior_revision" in report["changed"]
    assert report["compatible"] is None


def test_nested_schema_changes_are_visible():
    before = {"properties": {"event": {"type": "string"}, "old": {"type": "integer"}}}
    after = {
        "properties": {
            "event": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "new": {"$ref": "#/$defs/Thing"},
        }
    }
    change = compare_schemas(before, after)
    assert "properties.old" in change["removed"]
    assert "properties.new" in change["added"]
    assert "properties.event.type" in change["removed"]
    assert "properties.event.anyOf" in change["added"]
