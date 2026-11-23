# Storage and public exports

A run is always staged on disk so failures and native source bytes are retained.
Use a disk store or an S3 URI for the published output:

```sh
uv run --locked scenar init-store ./datasets
uv run --locked scenar publish runs/first ./datasets
uv run --locked scenar list ./datasets
uv run --locked scenar pull ./datasets downloads/latest

uv run --locked scenar publish runs/first s3://scenar/experiments
uv run --locked scenar pull s3://scenar/experiments downloads/s3-latest

# Publish automatically only after the whole run qualifies:
uv run --locked scenar run runs/prepared --publish-to s3://scenar/experiments
```

Publication reserves a unique build identity, verifies all payloads, commits the
manifest and only then advances `latest.json`. Reusing an identity is rejected.
An interrupted upload keeps its reservation; use a newly sealed/replayed bundle
rather than overwriting it. `--diagnostic` explicitly publishes failed runs under
`diagnostics/` and never advances the qualified pointer. Pull verifies paths,
sizes and SHA-256 before exposing the destination. An explicit build URI remains
immutable even when a later publication changes `latest.json`.

### Included RustFS

```sh
cp .env.example .env
# Edit .env with local credentials, then export them for the Python client.
set -a
. ./.env
set +a
docker compose up -d
# Once RustFS is listening:
uv run --locked scenar init-store
uv run --locked scenar publish runs/first
uv run --locked scenar list
```

The console is `http://localhost:9001`, S3 is `http://localhost:9000`; ports bind to
loopback. Data persists in the Compose volume. `SCENAR_BUCKET` supplies the bucket
when a publish/list/init-store destination is omitted. `RUSTFS_ENDPOINT`,
`RUSTFS_ACCESS_KEY`, `RUSTFS_SECRET_KEY` and optional `RUSTFS_REGION` configure the
client; otherwise boto3 uses normal AWS configuration. Scenar does not implicitly
load `.env`. `init-store` creates an absent bucket, without changing its policy.
The supplied `latest` image is a development convenience; pin an image digest
for reproducible deployments. Stop with `docker compose down` (preserves data).

The **whole bundle is restricted**: it includes private truth, scenarios, scores
and provider state. Give downstream normalization only an `export-public` directory.
The reference investigation harness also uses a restricted query provider.
A directory layout is not an operating-system or S3 access-control boundary.
Do not give consumers credentials for the full store.

