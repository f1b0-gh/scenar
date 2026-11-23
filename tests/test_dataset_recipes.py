"""Recipes must preserve intent boundaries and emit reproducible, linked workloads."""

from datetime import UTC, datetime

import pytest

from scenar.datasets.recipes import build_recipe
from scenar.scenario import authored_events

START = datetime(2024, 5, 27, 12, tzinfo=UTC)
FAMILIES = ["inventory_archive", "remote_access", "persistence", "credential_access", "c2"]


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("variant", ["normal", "benign", "malicious", "mixed", "ambiguous"])
def test_recipes_are_deterministic_and_every_authored_action_has_private_truth(family, variant):
    recipe = build_recipe(family, variant, "small", start=START)
    assert recipe.model_dump() == build_recipe(family, variant, "small", start=START).model_dump()
    events = authored_events(recipe.document.evidenceforge)
    assert set(events) == set(recipe.document.ground_truth.labels)
    intents = {label.intent for label in recipe.document.ground_truth.labels.values()}
    assert (
        intents
        == {
            "normal": {"benign"},
            "benign": {"benign"},
            "malicious": {"benign", "malicious"},
            "mixed": {"benign", "malicious"},
            "ambiguous": {"benign", "unknown"},
        }[variant]
    )
    assert recipe.expectations
    assert all(e.authored_event_id in events for e in recipe.expectations)


@pytest.mark.parametrize(
    "size,hosts,users", [("small", 3, 2), ("medium", 10, 8), ("large", 30, 28)]
)
def test_role_based_environment_has_no_dangling_references(size, hosts, users):
    recipe = build_recipe("remote_access", "mixed", size, start=START)
    env = recipe.document.evidenceforge["environment"]
    hostnames = {host["hostname"] for host in env["systems"]}
    usernames = {user["username"] for user in env["users"]}
    assert len(hostnames) == hosts and len(usernames) == users
    assert {"domain_controller", "file_server"} <= {
        role for host in env["systems"] for role in host.get("roles", [])
    }
    assert all(user["primary_system"] in hostnames for user in env["users"])
    assert all(
        host.get("assigned_user") in usernames for host in env["systems"] if "assigned_user" in host
    )
    assert all(set(segment["systems"]) <= hostnames for segment in env["network"]["segments"])
    assert all(
        step["actor"] in usernames | set(env["service_accounts"]) and step["system"] in hostnames
        for step in recipe.document.evidenceforge["storyline"]
    )


@pytest.mark.parametrize("family", FAMILIES)
def test_pairs_keep_tools_paths_and_identifiers_neutral_and_ambiguity_explicit(family):
    benign = build_recipe(family, "benign", "small", start=START)
    malicious = build_recipe(family, "malicious", "small", start=START)
    ambiguous = build_recipe(family, "ambiguous", "small", start=START)
    assert benign.document.evidenceforge == ambiguous.document.evidenceforge
    assert benign.document.evidenceforge != malicious.document.evidenceforge
    left = authored_events(benign.document.evidenceforge)
    right = authored_events(malicious.document.evidenceforge)
    assert left.keys() == right.keys()
    for key in left:
        for field in (
            "process_name",
            "command_line",
            "task_name",
            "service_name",
            "target_process",
            "dst_ip",
        ):
            assert left[key].get(field) == right[key].get(field)
    assert ambiguous.metadata["observation_equivalence"] == "benign_recipe_only"


def test_routine_cycles_schedule_sessions_admin_backup_and_unusual_legitimate_work():
    recipe = build_recipe("inventory_archive", "normal", "small", start=START, routine_cycles=3)
    routines = recipe.metadata["routines"]
    assert {r["kind"] for r in routines} == {"session", "administration", "backup", "diagnostics"}
    assert all(
        sum(r["kind"] == kind for r in routines) == 3 for kind in {r["kind"] for r in routines}
    )
    assert len({r["time"] for r in routines}) == 12
    assert recipe.document.evidenceforge["baseline_activity"]["intensity"] == "low"


def test_credential_effect_requires_exact_source_process_and_session_identity():
    recipe = build_recipe("credential_access", "malicious", "small", start=START)
    effects = {e.id: e for e in recipe.expectations}
    assert effects["w00-access"].relationship.expectation_id == "w00-1"
    assert effects["w00-access"].relationship.field == "SourceProcessGUID"
    assert effects["w00-1"].relationship.expectation_id == "w00-session"
    assert effects["w00-1"].relationship.kind == "logon_id"


def test_persistence_effects_bind_installer_account_and_remote_session():
    recipe = build_recipe("persistence", "malicious", "small", start=START)
    effects = {e.id: e for e in recipe.expectations}
    for id in ("w00-task", "w00-service"):
        assert effects[id].fields["SubjectUserName"] == "operator01"
        assert effects[id].fields["SubjectDomainName"] == "OFFICE"
        assert effects[id].relationship.expectation_id == "w00-session"
        assert effects[id].relationship.field == "SubjectLogonId"
        assert effects[id].relationship.kind == "logon_id"


@pytest.mark.parametrize("pattern", ["periodic", "burst", "sparse", "rotating"])
def test_c2_patterns_have_supported_beacons_and_all_ticks_inside_capture(pattern):
    recipe = build_recipe("c2", "malicious", "small", start=START, c2_pattern=pattern)
    beacons = [
        e for e in authored_events(recipe.document.evidenceforge).values() if e["type"] == "beacon"
    ]
    assert beacons and all(e["count"] >= 2 and e["jitter"] == 0 for e in beacons)
    if pattern == "rotating":
        assert len({e["dst_ip"] for e in beacons}) == 3
    for effect in recipe.expectations:
        assert START <= datetime.fromisoformat(effect.time) < START.replace(hour=13)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"duration_minutes": 0},
        {"duration_minutes": True},
        {"routine_cycles": 0},
        {"routine_cycles": 300},
        {"c2_pattern": "persistent"},
        {"start": datetime(2024, 1, 1)},
    ],
)
def test_invalid_recipe_options_fail_before_building(kwargs):
    with pytest.raises(ValueError):
        build_recipe("c2", "benign", "small", **({"start": START} | kwargs))


def test_overfull_routine_schedule_reserves_room_for_native_timestamp_jitter():
    with pytest.raises(ValueError):
        build_recipe(
            "remote_access", "normal", "small", start=START, duration_minutes=10, routine_cycles=5
        )
