# splunk

This directory contains the local-mode Splunk configuration bundle.

## Main Files

- [default.yml](default.yml)
  - standalone bootstrap
  - direct HEC configuration
  - local index contract
  - retention and runtime guardrails
  - restricted role definition
  - default namespace for the restricted user
- `apps/defenseclaw_local_mode/`
  - source for the local landing app
  - nav, macros, eventtypes, saved searches, and phase-based observability dashboards
  - experimental local-only banner text
- `build/`
  - generated app archive location
- [package_local_mode_app.sh](package_local_mode_app.sh)
  - packages the app source into `build/defenseclaw_local_mode.tgz`
- `ansible/create_local_user.yml`
  - creates or updates `defenseclaw_local_user`
  - assigns the restricted role
  - sets `defaultApp=defenseclaw_local_mode`

## Supported Pattern

This repo uses the native `docker-splunk` / `splunk-ansible` bootstrap path first:

- app installation uses `splunk.apps_location`
- config files are emitted from `default.yml`
- the remaining custom Ansible is limited to the restricted local user bootstrap

That is intentional. If a future change can be expressed through `docker-splunk` or `splunk-ansible` configuration, prefer that over new custom tasks.
