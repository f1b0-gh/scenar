import io

import pytest
from botocore.exceptions import ClientError

from scenar import storage
from tests.test_storage import bundle


class ObjectStore:
    """In-memory S3 transport double; production serialization and checksums stay real."""

    def __init__(self):
        self.objects = {}
        self.fail_on = None

    def put_object(self, *, Bucket, Key, Body, IfNoneMatch=None):
        if self.fail_on and self.fail_on in Key:
            raise OSError("interrupted upload")
        if IfNoneMatch == "*" and (Bucket, Key) in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[Bucket, Key] = Body
        return {}

    def get_object(self, *, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[Bucket, Key])}


def test_s3_roundtrip_is_verified_and_build_identity_cannot_be_reused(tmp_path, monkeypatch):
    api = ObjectStore()
    monkeypatch.setattr(storage, "client", lambda: api)
    root = bundle(tmp_path)
    storage.publish_bundle(root, "s3://test/datasets")
    result = storage.pull_bundle("s3://test/datasets", tmp_path / "download")
    assert result.bundle_id == "build1"
    assert (tmp_path / "download/public/feed.json").read_bytes() == (
        root / "public/feed.json"
    ).read_bytes()
    with pytest.raises(ClientError):
        storage.publish_bundle(root, "s3://test/datasets")
    api.objects["test", "datasets/builds/build1/public/feed.json"] = b"corrupt"
    with pytest.raises(ValueError, match="checksum"):
        storage.pull_bundle("s3://test/datasets", tmp_path / "bad")
    assert not (tmp_path / "bad").exists()


def test_partial_upload_does_not_advance_pointer(tmp_path, monkeypatch):
    api = ObjectStore()
    api.fail_on = "truth.json"
    monkeypatch.setattr(storage, "client", lambda: api)
    with pytest.raises(OSError):
        storage.publish_bundle(bundle(tmp_path), "s3://test/datasets")
    assert ("test", "datasets/latest.json") not in api.objects
    assert ("test", "datasets/builds/build1/manifest.json") not in api.objects


def test_corrupt_upload_is_not_committed(tmp_path, monkeypatch):
    api = ObjectStore()
    original = api.get_object

    def corrupted(**kwargs):
        if kwargs["Key"].endswith("feed.json"):
            return {"Body": io.BytesIO(b"corrupt")}
        return original(**kwargs)

    monkeypatch.setattr(api, "get_object", corrupted)
    monkeypatch.setattr(storage, "client", lambda: api)
    with pytest.raises(ValueError, match="checksum"):
        storage.publish_bundle(bundle(tmp_path), "s3://test/datasets")
    assert ("test", "datasets/builds/build1/manifest.json") not in api.objects
    assert ("test", "datasets/latest.json") not in api.objects


def test_bucket_initialization_creates_missing_bucket(monkeypatch):
    calls = []

    class BucketAPI:
        def head_bucket(self, **kwargs):
            raise ClientError({"Error": {"Code": "404"}}, "HeadBucket")

        def create_bucket(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(storage, "client", BucketAPI)
    assert storage.initialize_store("s3://scenar/runs") == "s3://scenar/runs"
    assert calls == [{"Bucket": "scenar"}]


def test_bucket_initialization_does_not_hide_permission_errors(monkeypatch):
    class BucketAPI:
        def head_bucket(self, **kwargs):
            raise ClientError({"Error": {"Code": "403"}}, "HeadBucket")

    monkeypatch.setattr(storage, "client", BucketAPI)
    with pytest.raises(ClientError):
        storage.initialize_store("s3://scenar")
