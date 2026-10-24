# Observability, audit, error codes, redaction, docs and changelog

Open this when: you add an audit action, error code, telemetry field or destination, handle sensitive data in events, write or change docs-site pages, change CLI commands that docs reference, or edit the changelog.

## Requirements

IDs live only in `reference/checklist.md`. These rows add detail and carry no IDs.

| Rule | Why | How to check | Evidence |
|---|---|---|---|
| Define audit actions once in Go and mirror them in Python and the schema enum. Production Go code uses typed constants, never raw `Action: "..."` literals. | Splunk, the REST API and the TUI rely on the stable enum. | `make check-audit-actions check-audit-no-raw-literals` | `internal/audit/actions.go`, `cli/defenseclaw/audit_actions.py`, `schemas/audit-event.json` |
| Add gateway error codes and subsystems as typed constants in Go and mirror them in Python. | The parity script fails when the sets differ. | `make check-error-codes` | `internal/gatewaylog/error_codes.go`, `cli/defenseclaw/gateway_error_codes.py` |
| Telemetry changes start in `schemas/telemetry/v8/*.yaml`, then `make telemetry-generate`; commit the generated runtime assets and `zz_generated_telemetry_*.go`. Never hand-edit generated files or create a generated tree. | `make telemetry-check` rejects stale outputs. | `make telemetry-check` | `scripts/generate_telemetry_registry.py`, `schemas/README.md`, `schemas/telemetry/runtime` |
| Do not reintroduce the retired v7 observability runtime. v7 may appear only at upgrade and recovery boundaries. | The hard-cut gate fails on retired APIs and paths. | `make check-observability-v8-hard-cut` | `scripts/check_observability_v8_hard_cut.py` |
| Redact once at the projection boundary per destination, using redaction profiles. No ad-hoc masking in dashboards or emitters. State each new field's privacy class and effective profile. The fresh-config default profile is `none`, so say so for any new export leg. | Dashboards are not a redaction boundary; unredacted legs leak prompts and arguments. | `go test ./internal/redaction ./internal/observability`; `defenseclaw observability plan` | `internal/redaction/redaction.go`, `docs-site/content/docs/reference/observability/redaction.mdx`, `schemas/telemetry/v8/redaction` |
| Credentials never go into `config.yaml`, logs, audit rows, telemetry, fixtures or PR bodies. Write secret-bearing files through `internal/safefile`, not bare `os.WriteFile` with loose modes. | Doctor and managed gates check modes and owners. | `pytest cli/tests/test_secure_write_permissions.py`; `go test ./internal/safefile` | `internal/safefile`, `docs-site/content/docs/reference/configuration/keys.mdx` |
| Every new failure mode on a hook or guardrail path resolves through the effective fail mode, with a test and an entry in `docs-site/content/docs/reference/configuration/fail-modes.mdx`. | A failure path that opens silently is a policy bypass. | `go test ./internal/gateway/... -run FailMode` | `docs-site/content/docs/reference/configuration/fail-modes.mdx`, `internal/envvars/registry.json` |
| Operator-facing behavior goes in `docs-site/content/docs` (MDX with title, description, keywords). Repository Markdown is for contributor, implementation, schema or historical material only. | The website is canonical; duplicates go stale. | review the diff; `pytest cli/tests/test_install_docs_static.py` | `CONTRIBUTING.md`, `docs-site/README.md` |
| Every runnable shell fence and inline `defenseclaw ...` command in docs parses against the real CLI; `defenseclaw-gateway ...` commands parse against Cobra; shell fences pass `bash -n`. Never document a flag that does not exist. | These checks fail the PR. | `pytest cli/tests/test_docs_cli_commands.py`; `go test ./internal/cli -run 'Documented\|Docs'`; `cd docs-site && npm run validate-snippets` | `scripts/check_docs_cli_commands.py`, `internal/cli/docs_commands_test.go` |
| Internal links and anchors resolve. Register new pages in the relevant `meta.json`. | The docs workflow runs link validation and the build; an unlisted page is invisible. | `cd docs-site && npm run validate-links && npm run build` | `docs-site/scripts/validate-links.ts`, `docs-site/content/docs/meta.json` |
| Do not hand-edit generated docs: the env-var reference (use `scripts/gen_envvars_docs.py`), `docs-site/data/policy-*.json`, and any generated wiki pages. | CI diff-checks generated assets. | `python scripts/gen_envvars_docs.py --check`; `git diff --exit-code docs-site/data` | `scripts/gen_envvars_docs.py`, `.github/workflows/docs-site.yml` |
| Pin connector and platform claims in docs with a test, and review hand-maintained lists of all connectors by grep. | An unpinned claim drifts from the code without failing any test. | `pytest cli/tests/test_windows_release_claims.py cli/tests/test_connector_surface_parity.py` | `docs-site/data/capability-matrix.json`, `.claude/skills/defenseclaw-add-connector/reference/docs-tests-ci.md` |
| Update `CHANGELOG.md` under Unreleased for operator-visible changes: a bold lead sentence naming the symptom and the fix. No line numbers. Standalone-only changes need no entry unless per-user installs change. | It is a development rollup. | review the diff | `CHANGELOG.md` |
| Add a doctor check or status field for any new observability destination: configured, reachable, redaction profile. | Operators must see a dead exporter. | `defenseclaw doctor` | `cli/defenseclaw/commands/cmd_doctor.py` |
| Add dashboards only under `bundles/local_observability_stack/grafana/dashboards` and keep the packaged copy in sync; queries must use metrics that exist. | The checker rejects queries that render plausible zeroes. | `make check-grafana-dashboards` | `scripts/check_grafana_dashboards.py` |
| Use plain imperative sentences; keep a Details table for requirements. | Consistency. | read the page | `docs-site/content/docs/get-started/install.mdx` |

## Checklist: new audit action

1. Add the constant in `internal/audit/actions.go`. 2. Mirror it in `cli/defenseclaw/audit_actions.py`. 3. Add to the enum in `schemas/audit-event.json`. 4. Use the constant at the call site. 5. `make check-audit-actions check-audit-no-raw-literals check-schemas`.

## Checklist: new telemetry field

1. Edit the registry YAML. 2. State privacy class and redaction behavior. 3. `make telemetry-generate`. 4. Commit generated outputs. 5. `make telemetry-check`. 6. Update the docs page under `docs-site/content/docs/reference/observability/`.

## Where it lives

`internal/audit/`, `internal/gatewaylog/`, `internal/observability/`, `internal/redaction/`, `schemas/`, `bundles/local_observability_stack/`, `docs-site/`, `scripts/check_*.py`, `CHANGELOG.md`.

## How to verify

`make check`, `make telemetry-check`, `pytest cli/tests/test_docs_cli_commands.py`, and the docs-site npm steps.

## Common mistakes

- Putting a prompt or tool argument into an event without naming its privacy class.
- Editing `docs/ENV-VARS.md` (a pointer) and expecting the generator check to pass.
- Adding a docs page without a `meta.json` entry.
- Using retired connector names outside the allowed files; build them from fragments in tests.
- Describing fail-open behavior from an older transport-only description.
