# compose

This directory contains developer-local and CI compose profiles for the local Splunk bridge.

The preferred operational interface is [bin/splunk-claw-bridge](../bin/splunk-claw-bridge). Use the compose files directly only when debugging the bootstrap path or changing repo internals.

## Profiles

- `docker-compose.local.yml`
  - persisted developer-local profile
  - binds `127.0.0.1:8000` and `127.0.0.1:8088`
  - uses named volumes for both `/opt/splunk/etc` and `/opt/splunk/var`
- `docker-compose.ci.yml`
  - disposable CI and harness profile
  - binds the same loopback ports
  - uses anonymous volumes and is expected to be torn down with `down -v`

## Shared Behavior

- both profiles resolve the image from `SPLUNK_IMAGE` in `env/.env.example`
- both profiles resolve the container env file from `SPLUNK_ENV_FILE`, which the public entrypoint sets automatically
- both profiles mount [splunk/default.yml](../splunk/default.yml) into `/tmp/defaults/default.yml`
- both profiles mount the public [splunk](../splunk) tree into `/opt/splunk-claw-bridge/splunk`
- neither profile publishes `8089` on the host

## Important Note

Package the local-mode app before starting either profile:

```bash
bash splunk/package_local_mode_app.sh
```

Or use the public entrypoint, which does that automatically:

```bash
bin/splunk-claw-bridge up
```
