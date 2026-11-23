"""Normal ambient activity compiled into the unchanged Forge baseline generator."""

import copy
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from .attack import Model

Level = Literal["low", "medium", "high"]
Traffic = Literal[
    "user_activity",
    "web",
    "dns_interval",
    "ntp",
    "smb_interval",
    "kerberos",
    "ldap",
    "persona_connections",
]
Rate = Annotated[int, Field(strict=True, gt=0, le=50000)]
PROFILES = {
    "quiet": {"user_activity": "low", "web": "low", "persona_connections": "low"},
    "office": {
        "user_activity": "medium",
        "web": "medium",
        "dns_interval": "medium",
        "kerberos": "medium",
        "persona_connections": "medium",
    },
    "server": {
        "user_activity": "low",
        "web": "high",
        "smb_interval": "medium",
        "ldap": "medium",
        "persona_connections": "medium",
    },
}


class BackgroundActivity(Model):
    profile: Literal["quiet", "office", "server"] = "office"
    intensity: Level = "medium"
    variation: Level = "medium"
    suspicious_noise: Literal["low", "medium", "high", "ludicrous"] = "low"
    traffic_rates: dict[Traffic, Rate | tuple[Rate, Rate] | Level] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ranges(self) -> Self:
        if any(isinstance(v, tuple) and v[0] > v[1] for v in self.traffic_rates.values()):
            raise ValueError("Traffic rate range must be ordered")
        return self


def apply_background(
    scenario: dict, config: BackgroundActivity, *, noise_only: bool = False
) -> dict:
    """Deterministic configuration; Forge's capture seed controls emitted randomness."""
    result = copy.deepcopy(scenario)
    baseline = copy.deepcopy(result.get("baseline_activity", {}))
    levels = ["low", "medium", "high"]
    profile_rates = {
        key: levels[max(0, min(2, levels.index(config.intensity) + levels.index(level) - 1))]
        for key, level in PROFILES[config.profile].items()
    }
    baseline.update(
        description=f"Normal synthetic {config.profile} background activity",
        intensity=config.intensity,
        variation=config.variation,
        suspicious_noise=config.suspicious_noise,
        traffic_rates={
            **profile_rates,
            **config.model_dump(mode="json")["traffic_rates"],
        },
    )
    result["baseline_activity"] = baseline
    if noise_only:
        result["storyline"] = []
        result["red_herrings"] = []
    return result
