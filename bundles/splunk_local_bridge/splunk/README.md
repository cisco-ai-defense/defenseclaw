# splunk

This directory contains the local-mode Splunk configuration bundle.

Using this bundle to start local Splunk means the operator is representing that
they have reviewed and accepted the then-current Splunk General Terms,
available at:

- https://www.splunk.com/en_us/legal/splunk-general-terms.html

If there is a separately negotiated agreement with Splunk that expressly
supersedes those terms, that agreement governs instead. Otherwise, by
accessing or using Splunk software through this bundle, the operator is
agreeing to the Splunk General Terms posted at the time of access and use and
acknowledging their applicability to the Splunk software.

If the operator does not agree to the Splunk General Terms, they must not
download, start, access, or use the software.

This bundle is intended only for local, single-instance workflows. Existing
Splunk license limits still apply. It is not an endorsed path to multi-instance
or long-term deployment, it does not promise a seamless upgrade or migration
path, it does not guarantee all Splunk Enterprise capabilities in every license
mode, and it does not proxy or replace a direct O11y integration.

The optional `s3_exporter/` sidecar follows the same local/demo positioning. It
can copy local `defenseclaw_local` events to S3-compatible storage for handoff
testing, but it is not SmartStore, not an ES dependency, and not a supported
long-term archival or customer-managed production path.

## Main Files

- [default.yml](default.yml)
  - standalone bootstrap
  - starts Splunk in Free mode from day 1 through the container env contract
  - direct HEC configuration
  - local index contract
  - retention and runtime guardrails
- `apps/defenseclaw_local_mode/`
  - source for the local landing app
  - nav, macros, eventtypes, saved searches, and phase-based observability dashboards
  - experimental local-only banner text
- `build/`
  - generated app archive location
- [package_local_mode_app.sh](package_local_mode_app.sh)
  - packages the app source into `build/defenseclaw_local_mode.tgz`
- `../s3_exporter/`
  - optional local sidecar that exports batches from local Splunk to S3 as
    normalized JSONL.GZ plus manifests
  - disabled by default through `S3_EXPORT_ENABLED=false`
  - can be started from the CLI with `defenseclaw setup splunk --s3-export --s3-bucket <bucket>`

## Optional S3 Export

The quickest demo path is:

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

For a short demo loop, set `S3_EXPORT_INTERVAL_SECONDS=30` before running setup.
The exporter writes JSONL.GZ data objects by tenant/workspace/day/hour partition
and writes one companion manifest for each non-empty batch. See
`../s3_exporter/README.md` for MinIO/Localstack examples, manifest shape,
expected delay, and edge cases.

## Supported Pattern

This repo uses the native `docker-splunk` / `splunk-ansible` bootstrap path first:

- app installation uses `splunk.apps_location`
- config files are emitted from `default.yml`
- the remaining custom Ansible is limited to product telemetry and support-layer sync

That is intentional. If a future change can be expressed through `docker-splunk` or `splunk-ansible` configuration, prefer that over new custom tasks.

## Free-From-Day-1 Behavior

The bundled DefenseClaw local profile starts Splunk directly in **Free mode**.

That means:

- no temporary 60-day trial period
- alerts are disabled in Free mode
- no local Splunk user bootstrap inside the bundle
- no credential prompt for Splunk Web in the default local profile
- if someone needs Enterprise behavior later, they must install a real Enterprise license

For more detail on the Free-tier behavior and limits, see
[About Splunk Free](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configure-splunk-licenses/about-splunk-free).
