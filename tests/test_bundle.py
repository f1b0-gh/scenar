import pytest
from pydantic import ValidationError

from scenar.bundle import Artifact, BundleManifest, Qualification, QualityReport


def test_eligibility_requires_both_native_and_backend_acceptance():
    assert Qualification(native_passed=True, backend_passed=True).eligible
    assert not Qualification(native_passed=True, backend_passed=False).eligible
    assert not Qualification(native_passed=False, backend_passed=True).eligible
    with pytest.raises(ValidationError):
        Qualification(native_passed="true", backend_passed=True)


@pytest.mark.parametrize(
    "payload", ["{}", '{"acceptance_passed":"false"}', '{"acceptance_passed":0}']
)
def test_invalid_quality_verdict_is_rejected(payload):
    with pytest.raises(ValidationError):
        QualityReport.model_validate_json(payload)


@pytest.mark.parametrize(
    "path", ["../secret", "/tmp/secret", "public/../private/label", "public//a", "C:/secret"]
)
def test_manifest_cannot_escape_root(path):
    with pytest.raises(ValidationError):
        Artifact(path=path, sha256="a" * 64, size=1)


def test_future_schema_and_duplicate_artifacts_are_rejected():
    item = Artifact(path="public/events.json", sha256="a" * 64, size=1)
    with pytest.raises(ValidationError):
        BundleManifest(bundle_id="b", files=[item, item])
    with pytest.raises(ValidationError):
        BundleManifest(schema="scenar/bundle/v2", bundle_id="b", files=[])
