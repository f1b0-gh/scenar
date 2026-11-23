"""Visibility must preserve authored truth and target actual collection sources."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from scenar.datasets.visibility import VisibilitySettings, apply_visibility


@pytest.fixture
def scenario():
    return {
        "name": "visibility-test",
        "environment": {
            "systems": [
                {"hostname": "WIN-01", "os": "Windows 11", "roles": ["workstation"]},
                {"hostname": "WIN-02", "os": "Windows Server 2022", "roles": []},
                {"hostname": "LIN-01", "os": "Ubuntu Linux", "roles": ["web_server"]},
            ],
            "network": {"sensors": [{"name": "EDGE", "type": "network", "log_formats": ["zeek"]}]},
        },
        "output": {
            "logs": [
                {"format": "windows"},
                {"format": "syslog"},
                {"format": "bash_history"},
                {"format": "web_access"},
                {"format": "zeek_conn"},
            ]
        },
        "scenario": [{"name": "activity", "steps": [{"action": "process", "intent": "benign"}]}],
        "ground_truth": {"intent": "benign"},
    }


@pytest.mark.parametrize(
    "settings",
    [
        {"mode": "lossy", "probability": True},
        {"mode": "lossy", "probability": "0.5"},
        {"mode": "lossy", "probability": float("nan")},
        {"mode": "lossy", "probability": float("inf")},
        {"mode": "lossy", "probability": -0.1},
        {"mode": "lossy", "probability": 1.1},
        {"mode": "lossy"},
        {"mode": "delayed", "delay_us": True},
        {"mode": "delayed", "delay_us": 12.5},
        {"mode": "delayed", "delay_us": "12"},
        {"mode": "delayed", "delay_us": 0},
        {"mode": "delayed"},
        {"mode": "complete", "probability": 0.5},
        {"mode": "lossy", "probability": 0.5, "delay_us": 10},
        {"mode": "missing_endpoint"},
        {"mode": "complete", "source_instances": ["sysmon:*"]},
        {"mode": "complete", "source_instances": []},
        {"mode": "complete", "source_instances": ["sysmon:win-01", "SYSMON:WIN-01"]},
        {"mode": "complete", "hosts": ["WIN-01", "win-01"]},
        {"mode": "complete", "hosts": [True]},
        {"mode": "complete", "hosts": ["*"]},
        {"mode": "complete", "source_instances": ["sysmon:win-01"], "hosts": ["WIN-01"]},
        {"mode": "complete", "surprise": True},
    ],
)
def test_rejects_inexact_or_ineffective_settings(settings):
    with pytest.raises(ValidationError):
        VisibilitySettings.model_validate(settings)


def test_complete_preserves_existing_overrides_and_deep_copies(scenario):
    scenario["environment"]["observation_overrides"] = [
        {"source_instance": "sysmon:win-01", "missingness": 0.4}
    ]
    original = deepcopy(scenario)
    result = apply_visibility(scenario, VisibilitySettings())
    assert result == original
    result["scenario"][0]["steps"].clear()
    assert scenario == original


def test_lossy_targets_actual_sources_and_preserves_intent(scenario):
    original = deepcopy(scenario)
    result = apply_visibility(scenario, VisibilitySettings(mode="lossy", probability=0.25))
    overrides = result["environment"].pop("observation_overrides")
    assert result == original
    assert scenario == original
    assert {item["source_instance"] for item in overrides} == {
        "sysmon:win-01",
        "sysmon:win-02",
        "windows_security:win-01",
        "windows_security:win-02",
        "syslog:lin-01",
        "bash_history:lin-01",
        "web:lin-01",
        "zeek:edge",
    }
    assert all(item["missingness"] == 0.25 for item in overrides)


def test_delayed_uses_exact_microseconds_and_merges_unrelated_properties(scenario):
    scenario["environment"]["observation_overrides"] = [
        {"source_instance": "sysmon:win-01", "missingness": 0.4},
        {"source_instance": "zeek:edge", "enabled": False},
    ]
    original = deepcopy(scenario)
    result = apply_visibility(
        scenario,
        VisibilitySettings(
            mode="delayed", delay_us=9007199254740993, source_instances=["SYSMON:WIN-01"]
        ),
    )
    assert scenario == original
    assert result["environment"]["observation_overrides"] == [
        {
            "source_instance": "sysmon:win-01",
            "missingness": 0.4,
            "batching": {"enabled": True, "interval_us": 9007199254740993, "max_records": 0},
        },
        {"source_instance": "zeek:edge", "enabled": False},
    ]


@pytest.mark.parametrize(
    "selection", [{"hosts": ["WIN-01"]}, {"source_instances": ["sysmon:win-01"]}]
)
def test_missing_endpoint_disables_both_windows_sources_only(scenario, selection):
    original = deepcopy(scenario)
    result = apply_visibility(scenario, VisibilitySettings(mode="missing_endpoint", **selection))
    assert scenario == original
    assert result["environment"].pop("observation_overrides") == [
        {"source_instance": "sysmon:win-01", "enabled": False},
        {"source_instance": "windows_security:win-01", "enabled": False},
    ]
    assert result == original


@pytest.mark.parametrize(
    "selection",
    [
        {"source_instances": ["sysmon:unknown"]},
        {"source_instances": ["sysmon:lin-01"]},
        {"source_instances": ["ecar:win-01"]},
        {"source_instances": ["sysmon:win-01:host-agent"]},
        {"hosts": ["unknown"]},
    ],
)
def test_rejects_undeployed_sources_even_for_complete(scenario, selection):
    with pytest.raises(ValueError, match="(unknown|undeployed)"):
        apply_visibility(scenario, VisibilitySettings(**selection))


@pytest.mark.parametrize("selection", [{"hosts": ["LIN-01"]}, {"source_instances": ["zeek:edge"]}])
def test_missing_endpoint_rejects_non_windows_selection(scenario, selection):
    with pytest.raises(ValueError, match="(Windows|endpoint)"):
        apply_visibility(scenario, VisibilitySettings(mode="missing_endpoint", **selection))


def test_missing_endpoint_requires_both_sources_deployed(scenario):
    scenario["output"]["logs"] = [{"format": "windows_event_sysmon"}]
    with pytest.raises(ValueError, match="(both|deployed)"):
        apply_visibility(scenario, VisibilitySettings(mode="missing_endpoint", hosts=["WIN-01"]))


@pytest.mark.parametrize(
    "existing",
    [
        [{"source_instance": "sysmon:win-01", "missingness": 0.4}],
        [
            {"source_instance": "sysmon:win-01", "missingness": 0.4},
            {"source_instance": "SYSMON:WIN-01", "enabled": True},
        ],
        [{"source_instance": "sysmon:unknown", "enabled": True}],
    ],
)
def test_rejects_conflicts_duplicates_and_unknown_existing_overrides(scenario, existing):
    scenario["environment"]["observation_overrides"] = existing
    original = deepcopy(scenario)
    with pytest.raises(ValueError, match="(conflict|duplicate|unknown|undeployed)"):
        apply_visibility(scenario, VisibilitySettings(mode="lossy", probability=0.25))
    assert scenario == original


def test_host_selection_does_not_affect_other_hosts_or_network(scenario):
    result = apply_visibility(
        scenario, VisibilitySettings(mode="lossy", probability=1, hosts=["WIN-02"])
    )
    assert result["environment"]["observation_overrides"] == [
        {"source_instance": "sysmon:win-02", "missingness": 1.0},
        {"source_instance": "windows_security:win-02", "missingness": 1.0},
    ]


def test_sensor_uses_backend_default_zeek_formats(scenario):
    del scenario["environment"]["network"]["sensors"][0]["log_formats"]
    result = apply_visibility(
        scenario,
        VisibilitySettings(mode="lossy", probability=0.5, source_instances=["zeek:edge"]),
    )
    assert result["environment"]["observation_overrides"] == [
        {"source_instance": "zeek:edge", "missingness": 0.5}
    ]
