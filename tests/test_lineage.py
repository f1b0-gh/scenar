import pytest
from pydantic import ValidationError

from scenar.lineage import Cohort, check_partitions


def row(**changes):
    return Cohort.model_validate(
        {
            "capture": "a",
            "family": "f",
            "environment": "lab",
            "time_block": "2024-05",
            "partition": "development",
            "exposed": True,
            **changes,
        }
    )


@pytest.mark.parametrize("field", ["capture", "family", "environment", "time_block"])
def test_related_views_cannot_cross_partitions(field):
    first = row()
    other = dict(
        capture="b",
        family="g",
        environment="other",
        time_block="2024-06",
        partition="test",
        exposed=False,
    )
    other[field] = getattr(first, field)
    with pytest.raises(ValueError, match=field):
        check_partitions([first, row(**other)])


def test_exposed_cohort_cannot_be_declared_holdout():
    with pytest.raises(ValidationError, match="exposed"):
        row(partition="test")


def test_disjoint_partitions_are_allowed():
    check_partitions(
        [
            row(),
            row(
                capture="b",
                family="g",
                environment="other",
                time_block="2024-06",
                partition="test",
                exposed=False,
            ),
        ]
    )
