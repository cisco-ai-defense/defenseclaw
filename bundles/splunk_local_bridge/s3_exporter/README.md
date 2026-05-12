# Splunk Local S3 Exporter

This optional sidecar exports local DefenseClaw/OpenClaw events from the bundled local Splunk bridge to S3-compatible object storage. It is intended for demo and development handoff workflows where another team needs files in S3. It is not a production archival product, not SmartStore, not an ES dependency, and not a replacement for the existing HEC ingest path.

The existing local bridge behavior remains unchanged:

- DefenseClaw/OpenClaw events continue to land in the local Splunk index `defenseclaw_local`.
- The Splunk app remains `defenseclaw_local_mode`.
- HEC remains on port `8088` with the local bridge token from `splunk/default.yml`.
- The exporter talks to local Splunk management at `https://splunk:8089` inside the compose network.

## How It Works

When `S3_EXPORT_ENABLED=true`, the bridge starts a `splunk-s3-exporter` sidecar. The sidecar:

1. Calls Splunk `/services/search/jobs/export`.
2. Queries a bounded time window from `index=defenseclaw_local`.
3. Normalizes rows into a JSONL envelope.
4. Uploads a compressed `.jsonl.gz` object to S3.
5. Writes a companion manifest under `_manifests/`.
6. Saves a checkpoint in `/state/checkpoint.json`.

The exporter uses at-least-once semantics. It re-reads a small overlap window on each run so late-arriving events are less likely to be missed. Duplicate events are possible across batches; downstream consumers can dedupe using `export_event_id`.

## Configuration

All configuration is environment-driven.

```bash
S3_EXPORT_ENABLED=true
S3_EXPORT_ONCE=false

S3_BUCKET=agentwatch-demo-bucket
S3_PREFIX=agentwatch/defenseclaw
AWS_REGION=us-west-2
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_SESSION_TOKEN=
S3_ENDPOINT_URL=
S3_SSE=AES256

SPLUNK_BASE_URL=https://splunk:8089
SPLUNK_VERIFY_TLS=false

S3_EXPORT_INTERVAL_SECONDS=60
S3_EXPORT_WINDOW_SECONDS=300
S3_EXPORT_LOOKBACK_SECONDS=30
S3_EXPORT_CHECKPOINT_FILE=/state/checkpoint.json

TENANT_ID=c3-demo-tenant
WORKSPACE_ID=workspace-demo
DEPLOYMENT_ENVIRONMENT=local
```

If `S3_EXPORT_ENABLED` is unset or false, the sidecar profile is not started by `bin/splunk-claw-bridge`. If the container is run directly while disabled, it exits successfully with a compact status message.

No Splunk credentials are needed for the bundled local bridge; the exporter
uses the local bridge defaults automatically.

## AWS S3 Example

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

defenseclaw setup splunk --s3-export \
  --s3-bucket agentwatch-demo \
  --s3-prefix agentwatch/defenseclaw \
  --aws-region us-west-2 \
  --accept-splunk-license \
  --non-interactive
```

For a faster demo handoff, tighten the interval while keeping the overlap:

```bash
export S3_EXPORT_INTERVAL_SECONDS=30
export S3_EXPORT_WINDOW_SECONDS=120
export S3_EXPORT_LOOKBACK_SECONDS=30
```

With those settings, a newly indexed event is normally exported on the next
poll, so the expected delay is roughly the polling interval plus Splunk index
visibility time. For the local demo path, that is usually around 30 seconds
after Splunk can return the event.

## Localstack or MinIO Example

```bash
export S3_EXPORT_ENABLED=true
export S3_EXPORT_ONCE=true
export S3_BUCKET=agentwatch-demo
export S3_PREFIX=agentwatch/defenseclaw
export S3_ENDPOINT_URL=http://host.docker.internal:4566
export AWS_REGION=us-west-2
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

bin/splunk-claw-bridge up
```

## Object Layout

Data objects are written to:

```text
s3://<bucket>/<prefix>/tenant_id=<tenant>/workspace_id=<workspace>/dt=YYYY-MM-DD/hour=HH/defenseclaw-splunk-local-<start>-<end>.jsonl.gz
```

Manifest objects are written to:

```text
s3://<bucket>/<prefix>/_manifests/manifest-<end>.json
```

Validate a run by checking that a manifest exists and that `record_count` matches the number of lines in the uncompressed JSONL object.

## Operating Notes

- Data files are partitioned by `tenant_id`, `workspace_id`, `dt`, and `hour`; they are not all written to one flat folder.
- The manifest is written once per non-empty batch under `_manifests/` and points at the exact data object for that batch.
- The checkpoint advances after successful upload. If S3 upload fails, the checkpoint is not advanced and the next run retries the window.
- The exporter is at-least-once, not exactly-once. The lookback window can create duplicates across adjacent files; use stable `export_event_id` for dedupe.
- If no events match a window, no data object or manifest is written, but the checkpoint still advances so the sidecar does not scan old empty windows forever.
- If Splunk is temporarily unavailable, the run fails and the next loop tries again after `S3_EXPORT_INTERVAL_SECONDS`.
- `_raw` is parsed into `event.parsed` when it is valid JSON. Invalid JSON is still preserved in `raw` with `event` set to null.

## Security Notes

Exported objects can include raw logs, prompts, responses, tool names, destinations, and policy decisions depending on producer-side redaction. Use a private bucket, least-privilege credentials, short-lived credentials where possible, and demo-safe data.

Do not put AWS credentials in the Splunk app. Keep credentials in the exporter environment or in your container secret mechanism.

## Local Tests

```bash
cd bundles/splunk_local_bridge/s3_exporter
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

The tests use fake Splunk and fake S3 clients. They do not require real AWS or a running Splunk instance.
