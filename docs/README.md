# Repository documentation

Installation, setup, configuration, command reference, and operator workflows
are maintained on the
[DefenseClaw documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/).
Stable pointer files remain in this directory for old repository links, but do
not duplicate the public guides.

Repository Markdown is reserved for material that must be reviewed beside code:
implementation contracts and architecture boundaries, contributor and release
procedures, package-local notes, generated schema references, and test fixtures.

## Active engineering references

| Area | Repository documentation | Implementation authority |
| --- | --- | --- |
| System boundaries | [`ARCHITECTURE.md`](ARCHITECTURE.md) | `cli/`, `cmd/`, `internal/`, `extensions/defenseclaw/` |
| Guardrail | [`GUARDRAIL.md`](GUARDRAIL.md), [`GUARDRAIL_RULE_PACKS.md`](GUARDRAIL_RULE_PACKS.md) | `internal/gateway/`, `internal/guardrail/`, `policies/` |
| Observability v8 | [`OBSERVABILITY.md`](OBSERVABILITY.md) | `schemas/telemetry/v8/`, `schemas/config/v8/`, `internal/observability/` |
| Gateway | [`reference/GATEWAY_SPEC.md`](reference/GATEWAY_SPEC.md) | `internal/gateway/` |
| Private upstream security | [`reference/PRIVATE_UPSTREAMS.md`](reference/PRIVATE_UPSTREAMS.md) | `internal/netguard/`, `internal/gateway/provider.go` |
| Testing | [`TESTING.md`](TESTING.md), [`E2E.md`](E2E.md) | `Makefile`, `.github/workflows/`, component tests |
| Release engineering | [`RELEASE_RUNBOOK.md`](RELEASE_RUNBOOK.md), [`RELEASE_VALIDATION.md`](RELEASE_VALIDATION.md), [`RELEASE_CHANNEL.md`](RELEASE_CHANNEL.md) | `.github/workflows/release.yaml`, release scripts |
| Schemas | [`../schemas/README.md`](../schemas/README.md) | `schemas/config/v8/`, `schemas/telemetry/v8/`, generators |
| Native Windows | [`WINDOWS-NATIVE-INSTALLER.md`](WINDOWS-NATIVE-INSTALLER.md), [`WINDOWS-NATIVE-CI.md`](WINDOWS-NATIVE-CI.md), [`WINDOWS_RESCUE.md`](WINDOWS_RESCUE.md) | `packaging/windows/`, Windows scripts and workflows |

Package-local READMEs stay beside the bundle, package, example, or fixture they
describe.

## Public pointer pages

These files intentionally contain links rather than a second guide:
[`INSTALL.md`](INSTALL.md), [`QUICKSTART.md`](QUICKSTART.md),
[`CLI.md`](CLI.md), [`API.md`](API.md),
[`CONFIG_FILES.md`](CONFIG_FILES.md), [`ENV-VARS.md`](ENV-VARS.md),
[`CONNECTOR-MATRIX.md`](CONNECTOR-MATRIX.md),
[`REGISTRIES.md`](REGISTRIES.md), and [`SPLUNK_APP.md`](SPLUNK_APP.md).

## Repository-only scope

Code-level contracts and historical context remain only when current
implementation or verification depends on them. Superseded planning records are
available through Git history rather than being indexed as current
documentation. Current behavior is determined by code, schemas, tests, and the
published website.
