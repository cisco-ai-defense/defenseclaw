# Splunk Local S3 Exporter Plan

## Goal

Add an optional S3 exporter sidecar to `bundles/splunk_local_bridge` without changing the existing HEC/local Splunk ingest path.

## Scope

- Add `s3_exporter/` with a Dockerized Python exporter.
- Query local Splunk through `/services/search/jobs/export`.
- Normalize rows to JSONL, gzip batches, upload data objects and manifests to S3-compatible storage.
- Maintain at-least-once checkpointing with lookback.
- Add tests that use fakes/stubs and do not require AWS or Splunk.
- Document local/demo positioning and security caveats.

## Decisions

- Keep the search inline in the exporter for sidecar portability.
- Add a Splunk macro for debugging the same base query in local Splunk.
- Keep exporter disabled by default through `S3_EXPORT_ENABLED`.
- Persist checkpoint state in a named Docker volume.
- Preserve shell environment S3/AWS overrides when the bridge script sources
  `.env.example`, so `S3_EXPORT_ENABLED=true ... bin/splunk-claw-bridge up`
  works without editing the env file.
- Add `defenseclaw setup splunk --s3-export --s3-bucket ...` as the
  CLI path while keeping env-only bridge usage available.

## Validation

- `pytest -q` from `bundles/splunk_local_bridge/s3_exporter` passed with 15 tests.
- `python -m compileall -q export_splunk_to_s3.py tests` passed.
- `bash -n bin/splunk-claw-bridge` passed.
- `docker compose --env-file env/.env.example -f compose/docker-compose.local.yml config --profiles`
  reports the optional `s3-export` profile.
- Rendering compose with `COMPOSE_PROFILES=s3-export S3_EXPORT_ENABLED=true`
  includes the `splunk-s3-exporter` service, env contract, and checkpoint volume.
- `PYTHONPATH=cli pytest cli/tests/test_cmd_misc.py -q -k "setup_splunk"`
  passed with 24 selected tests, including direct coverage for
  `_bootstrap_bridge(..., s3_export=True)`.
- `defenseclaw setup splunk --help` shows the S3 export flags.
- The CI compose file also renders the optional `s3-export` profile.
- Local MinIO smoke test passed: built `defenseclaw-splunk-s3-exporter:dev`,
  exported from local Splunk to a MinIO bucket, verified the manifest, data
  object layout, raw payload preservation, tenant/workspace fields, scalar
  correlation fields, and stable `export_event_id` presence.
- Re-ran the MinIO smoke test without setting Splunk username/password in the
  exporter environment; the exporter used local bridge defaults and succeeded.
- `docker build -t defenseclaw-splunk-s3-exporter:dev .` could not run because
  the local Docker/Colima socket was unavailable during the first pass; after
  starting Colima, the build passed.
