"""Conservative independence checks for explicitly declared evaluation cohorts."""

from typing import Literal, Self

from pydantic import Field, model_validator

from .bundle import Model


class Cohort(Model):
    capture: str = Field(min_length=1)
    family: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    time_block: str = Field(min_length=1)
    partition: Literal["development", "test"]
    exposed: bool = Field(strict=True)

    @model_validator(mode="after")
    def holdout(self) -> Self:
        if self.exposed and self.partition == "test":
            raise ValueError("Previously exposed cohorts cannot be labeled test holdouts")
        return self


def check_partitions(cohorts: list[Cohort]) -> None:
    """Reject leakage along any declared axis; do not infer independence from filenames."""
    for axis in ("capture", "family", "environment", "time_block"):
        seen: dict[str, str] = {}
        for cohort in cohorts:
            value = getattr(cohort, axis)
            if value in seen and seen[value] != cohort.partition:
                raise ValueError(f"Related {axis} crosses partitions: {value}")
            seen[value] = cohort.partition
