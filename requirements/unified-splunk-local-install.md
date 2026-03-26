# Unified Splunk Local Install Requirements

Status: Planning baseline  
Date: 2026-03-26  
Repository: `defenseclaw`

This document is the canonical requirements baseline for the local Splunk
install story inside `DefenseClaw`.

Related tracking documents:

- [Decision Log](./decision-log.md)
- [Work Log](./work-log.md)
- [Execution Plan](./unified-splunk-local-install-execution-plan.md)

## Purpose

Make `DefenseClaw` the only customer-facing repo for the local Splunk
experience. A customer with `OpenClaw` already deployed should enable local
Splunk through a `DefenseClaw` command without cloning or operating a second
repo.

## Locked Requirements

| ID | Status | Requirement | Acceptance signal |
| --- | --- | --- | --- |
| DCS-001 | Locked | `DefenseClaw` shall own install, start, stop, and configuration for the local Splunk bridge workflow. | A documented `DefenseClaw` CLI flow exists for enabling and disabling the local bridge path. |
| DCS-002 | Locked | The local Splunk bridge runtime needed for this flow shall be bundled inside the `DefenseClaw` repo. | The default customer path works without a separate `splunk-claw-bridge` checkout. |
| DCS-003 | Locked | `defenseclaw setup splunk-local --non-interactive` shall bootstrap the bundled local bridge by default. | The command starts the local bridge and persists the returned contract. |
| DCS-004 | Locked | The local bridge HEC token shall be persisted in `DefenseClaw` config for the bundled local path. | The normal local flow does not require a manual `DEFENSECLAW_SPLUNK_HEC_TOKEN` shell export. |
| DCS-005 | Locked | A manual fallback path may remain for debugging, but it shall not be the preferred customer workflow. | `--no-bootstrap-bridge` or equivalent remains available without becoming the primary doc path. |
| DCS-006 | Locked | The workstream shall keep an explicit decision log and work log in-repo. | `requirements/decision-log.md` and `requirements/work-log.md` exist and are maintained. |
| DCS-007 | Locked | This workstream shall preserve the existing O11y integration as an explicit opt-in path rather than a mandatory dependency of local Splunk enablement. | A customer can complete the local Splunk workflow without configuring OTLP/O11y. |
| DCS-008 | Locked | When O11y is not enabled, DefenseClaw shall still surface runtime traces and metrics through Splunk so the Splunk-only customer path remains complete. | The Splunk-only path still provides searchable runtime health, latency, and usage signals without OTLP/O11y. |
| DCS-009 | Locked | When O11y is enabled, Splunk shall remain the primary logs path while OTLP/O11y may carry traces and metrics as an additional opt-in integration. | Enabling O11y does not remove the baseline Splunk logs story. |
| DCS-010 | Locked | `defenseclaw setup splunk-local` shall bootstrap the local DefenseClaw config and audit store when they do not already exist. | A clean install can run the local Splunk setup command without requiring a separate prior `defenseclaw init` step. |

## Phase 1 Locked Slice

The first implementation slice shall:

1. bundle the minimum bridge runtime assets into `DefenseClaw`
2. make `setup splunk-local` bootstrap that bundle by default
3. persist the returned contract, including the local HEC token
4. provide a stop or disable path
5. add focused command tests

This slice does not complete the broader Splunk-only traces and metrics story by
itself. That remains a follow-on implementation requirement under `DCS-008`.

## Open Decisions

- whether bundle refresh from the upstream bridge source should be manual or
  script-assisted
- how much of the current bridge test and harness surface should also move into
  `DefenseClaw`
- whether the full current Splunk app surface should be narrowed or the live
  producer contract expanded
