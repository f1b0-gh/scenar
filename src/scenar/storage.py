"""Immutable local/S3 bundles, checksum-verified retrieval, and public-only exports."""

import json
import os
import shutil
import tempfile
import warnings
from pathlib import Path
from urllib.parse import urlsplit

from .bundle import Artifact, BundleManifest, CaptureResult, Qualification, QualityReport
from .io import canonical, digest, files, safe_path, write_json
from .replay import verify_bundle


def default_store() -> str:
    bucket = os.environ.get("SCENAR_BUCKET")
    if not bucket and os.environ.get("LOOKOUT_BUCKET"):
        warnings.warn("LOOKOUT_BUCKET is deprecated; use SCENAR_BUCKET", stacklevel=2)
        bucket = os.environ["LOOKOUT_BUCKET"]
    if not bucket:
        raise ValueError("Pass a store directory or S3 URI, or set SCENAR_BUCKET")
    return "s3://" + bucket


def initialize_store(destination: str) -> str:
    """Create a local store or an absent S3 bucket; never overwrite or change policy."""
    if not destination.startswith("s3://"):
        Path(destination).mkdir(parents=True, exist_ok=True)
        return str(Path(destination).resolve())
    from botocore.exceptions import ClientError

    bucket, _ = s3_location(destination)
    api = client()
    try:
        api.head_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket", "NotFound"):
            raise
        options = {"Bucket": bucket}
        region = (
            os.environ.get("RUSTFS_REGION")
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
        )
        if region and region != "us-east-1" and not os.environ.get("RUSTFS_ENDPOINT"):
            options["CreateBucketConfiguration"] = {"LocationConstraint": region}
        api.create_bucket(**options)
    return destination


def client():
    import boto3
    from botocore.config import Config

    kwargs = {"config": Config(s3={"addressing_style": "path"}, signature_version="s3v4")}
    for env, key in (
        ("RUSTFS_ENDPOINT", "endpoint_url"),
        ("RUSTFS_ACCESS_KEY", "aws_access_key_id"),
        ("RUSTFS_SECRET_KEY", "aws_secret_access_key"),
        ("RUSTFS_REGION", "region_name"),
    ):
        if os.environ.get(env):
            kwargs[key] = os.environ[env]
    return boto3.client("s3", **kwargs)


def s3_location(uri: str) -> tuple[str, str]:
    parsed = urlsplit(uri)
    if parsed.scheme != "s3" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("Expected s3://bucket/prefix")
    prefix = parsed.path.strip("/")
    if prefix:
        safe_path(Path("/__scenar_s3__"), prefix)
    return parsed.netloc, prefix


def join(prefix: str, name: str) -> str:
    return f"{prefix}/{name}" if prefix else name


def parse_manifest(raw: bytes) -> BundleManifest:
    value = json.loads(raw)
    if value.get("schema") == "lookout-scenar/manifest/v1":
        # Legacy manifests have no trustworthy qualification or public-only export.
        return BundleManifest(
            bundle_id=value["build_id"],
            provenance="imported",
            files=[Artifact.model_validate(f) for f in value["files"]],
        )
    return BundleManifest.model_validate(value)


def publish_bundle(bundle: Path, destination: str, diagnostic: bool = False) -> str:
    manifest = verify_bundle(bundle)
    if not manifest.qualified and not diagnostic:
        raise ValueError(
            "Only fully qualified bundles may be published; use explicit diagnostic mode"
        )
    if not diagnostic:
        verify_promotion(bundle, manifest)
    namespace = "diagnostics" if diagnostic else "builds"
    if destination.startswith("s3://"):
        bucket, prefix = s3_location(destination)
        api = client()
        base = join(prefix, f"{namespace}/{manifest.bundle_id}")
        # Persistent reservation ensures a partial or complete build ID cannot be reused.
        api.put_object(Bucket=bucket, Key=base + "/_reservation", Body=b"", IfNoneMatch="*")
        for artifact in manifest.files:
            path = safe_path(bundle, artifact.path)
            data = path.read_bytes()
            import hashlib

            if len(data) != artifact.size or hashlib.sha256(data).hexdigest() != artifact.sha256:
                raise ValueError("Source changed during publication")
            api.put_object(
                Bucket=bucket, Key=base + "/" + artifact.path, Body=data, IfNoneMatch="*"
            )
        raw = manifest.model_dump_json(by_alias=True).encode()
        # Commit the manifest only after every payload has been read back and verified.
        import hashlib

        for a in manifest.files:
            data = api.get_object(Bucket=bucket, Key=base + "/" + a.path)["Body"].read()
            if len(data) != a.size or hashlib.sha256(data).hexdigest() != a.sha256:
                raise ValueError("Uploaded checksum mismatch")
        api.put_object(Bucket=bucket, Key=base + "/manifest.json", Body=raw, IfNoneMatch="*")
        if api.get_object(Bucket=bucket, Key=base + "/manifest.json")["Body"].read() != raw:
            raise ValueError("Uploaded manifest checksum mismatch")
        if not diagnostic:
            api.put_object(
                Bucket=bucket,
                Key=join(prefix, "latest.json"),
                Body=json.dumps(
                    {
                        "path": f"{namespace}/{manifest.bundle_id}",
                        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ).encode(),
            )
        return f"s3://{bucket}/{base}"
    store = Path(destination)
    store.mkdir(parents=True, exist_ok=True)
    target = safe_path(store, f"{namespace}/{manifest.bundle_id}")
    target.parent.mkdir(parents=True, exist_ok=True)
    reservation = target.parent / (manifest.bundle_id + ".reserved")
    with reservation.open("x"):
        pass
    stage = Path(tempfile.mkdtemp(prefix=".upload-", dir=target.parent))
    try:
        for a in manifest.files:
            path = safe_path(stage, a.path)
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(safe_path(bundle, a.path), path)
        write_json(stage / "manifest.json", manifest.model_dump(mode="json", by_alias=True))
        verify_bundle(stage)
        if target.exists():
            raise FileExistsError(target)
        stage.rename(target)
        if not diagnostic:
            write_json(
                store / "latest.json",
                {
                    "path": f"{namespace}/{manifest.bundle_id}",
                    "manifest_sha256": digest(target / "manifest.json"),
                },
            )
        return str(target.resolve())
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def pull_bundle(uri: str, destination: Path) -> BundleManifest:
    if destination.exists():
        raise FileExistsError(destination)
    pointer = None
    if uri.startswith("s3://"):
        bucket, prefix = s3_location(uri)
        api = client()

        def get(name):
            return api.get_object(Bucket=bucket, Key=join(prefix, name))["Body"].read()

        from botocore.exceptions import ClientError

        try:
            raw = get("manifest.json")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchKey", "404"):
                raise
            pointer = json.loads(get("latest.json"))
            part = pointer.get("path", pointer.get("build_id"))
            safe_path(Path("/__scenar_s3__"), part)
            prefix = join(prefix, part)
            raw = get("manifest.json")
    else:
        root = Path(uri)
        if not (root / "manifest.json").exists():
            pointer = json.loads((root / "latest.json").read_bytes())
            root = safe_path(root, pointer.get("path", pointer.get("build_id")))

        def get(name):
            return safe_path(root, name).read_bytes()

        raw = get("manifest.json")
    import hashlib

    if (
        pointer
        and pointer.get("manifest_sha256")
        and hashlib.sha256(raw).hexdigest() != pointer["manifest_sha256"]
    ):
        raise ValueError("Manifest checksum mismatch")
    manifest = parse_manifest(raw)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".pull-", dir=destination.parent))
    try:
        for a in manifest.files:
            if a.path == "manifest.json":
                raise ValueError("Manifest cannot overwrite itself")
            path = safe_path(stage, a.path)
            data = get(a.path)
            if len(data) != a.size or hashlib.sha256(data).hexdigest() != a.sha256:
                raise ValueError(f"Download checksum mismatch: {a.path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        # Preserve the original manifest byte-for-byte, including legacy identity.
        (stage / "manifest.json").write_bytes(raw)
        if destination.exists():
            raise FileExistsError(destination)
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return manifest


def export_public(bundle: Path, destination: Path) -> None:
    manifest = verify_bundle(bundle)
    if (bundle / "dataset.json").exists():
        from .datasets.matrix import verify_dataset_public

        verify_dataset_public(bundle)
    if destination.exists():
        raise FileExistsError(destination)
    destination.mkdir(parents=True)
    for a in manifest.files:
        if a.path.startswith("public/"):
            target = safe_path(destination, a.path.removeprefix("public/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(safe_path(bundle, a.path), target)


def list_bundles(destination: str) -> list[str]:
    def committed(relative: str) -> bool:
        parts = relative.split("/")
        return (
            len(parts) == 3
            and parts[0] in ("builds", "diagnostics")
            and parts[-1] == "manifest.json"
        ) or (len(parts) == 2 and parts[-1] == "manifest.json")

    if destination.startswith("s3://"):
        bucket, prefix = s3_location(destination)
        api = client()
        root_prefix = prefix + "/" if prefix else ""
        return sorted(
            [
                f"s3://{bucket}/{obj['Key'].removesuffix('/manifest.json')}"
                for page in api.get_paginator("list_objects_v2").paginate(
                    Bucket=bucket, Prefix=root_prefix
                )
                for obj in page.get("Contents", [])
                if committed(obj["Key"].removeprefix(root_prefix))
            ]
        )
    root = Path(destination)
    return [
        str(p.parent.resolve())
        for p in sorted(root.rglob("manifest.json"))
        if committed(p.relative_to(root).as_posix())
    ]


def verify_promotion(bundle: Path, manifest: BundleManifest) -> None:
    """Require qualification records for every frozen attempt, not manifest flags alone."""

    if (bundle / "dataset.json").exists():
        from .datasets.matrix import verify_dataset_promotion

        verify_dataset_promotion(bundle, manifest)
        return

    from .runner import load_protocol

    protocol = load_protocol(bundle)
    if {c.id for c in protocol.cases} != {c.id for c in manifest.captures}:
        raise ValueError("Qualified population differs from the frozen protocol")
    for capture in manifest.captures:
        verify_capture_qualification(bundle, capture)


def verify_capture_qualification(bundle: Path, capture) -> None:
    """Check a single capture independently, including in partially qualified bundles."""
    import hashlib

    folder = safe_path(bundle, f"private/attempts/{capture.id}")
    attempt = CaptureResult.model_validate_json((folder / "attempt.json").read_bytes())
    qualification = Qualification.model_validate_json((folder / "qualification.json").read_bytes())
    quality = QualityReport.model_validate_json((folder / "quality.stdout").read_bytes())
    if (
        attempt.id != capture.id
        or not attempt.eligible
        or not attempt.native_eligible
        or not qualification.eligible
        or not quality.acceptance_passed
        or [s.stage for s in attempt.stages] != ["validate", "generate", "quality"]
        or any(s.exit != 0 for s in attempt.stages)
    ):
        raise ValueError(f"Capture lacks successful qualification: {capture.id}")
    if hashlib.sha256(canonical(files(folder / "bundle"))).hexdigest() != capture.source_sha256:
        raise ValueError(f"Capture identity differs from qualified native bytes: {capture.id}")
