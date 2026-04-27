# DefenseClaw macOS App Settings User Flows

This document defines the settings UX contract for the native macOS control plane.
The app should not expose every setting to every user up front. It should guide
users by job-to-be-done, then expose advanced config/policy editors when needed.

## UX Principles

- Most users start from a workflow, not from `config.yaml`.
- A setting belongs in exactly one primary flow, even if it is also discoverable
  through search or raw config editing.
- The app should own install, secrets intake, validation, diagnostics, and repair.
- Raw YAML/JSON/Rego editors are advanced escape hatches, not the default path.
- Every mutation must show validation, restart impact, and whether the backend
  accepted the change.
- Empty states must explain whether data is actually empty, still loading, or the
  backend could not be reached.

## Personas

| Persona | Goal | Default Surface | Advanced Surface |
| --- | --- | --- | --- |
| First-time evaluator | Install app, add keys, enable basic protection | Setup | Diagnostics, Config Files |
| Developer/operator | Protect local coding-agent usage without learning all settings | Home, Setup, Guardrails | Config Files |
| Security admin | Tune policies, suppressions, allow/block decisions | Policy, Enforcement, Guardrails | Raw policy editor |
| Platform operator | Keep helper, gateway, scanners, and local runtime healthy | Diagnostics, Gateway, Scanners | Logs, Config Files |
| SecOps engineer | Send telemetry to Splunk/OTel/Datadog-style sinks and investigate events | Observability setup, Alerts, Logs | Config Files |
| Incident responder | Review alert, decide action, export evidence | Alerts, Enforcement, Policy, Logs | Config Files |

## Flow 1: First Launch and Backend Install

**User intent:** Download the macOS app and get DefenseClaw running without using
the terminal.

**Required settings and state**

- `data_dir`, `audit_db`, `quarantine_dir`, `plugin_dir`, `policy_dir`
- bundled helper install state
- bundled/default policy install state
- `gateway.api_bind`, `gateway.api_port`, `gateway.token_env`
- secrets storage or `.env` bootstrap

**Happy path**

1. User opens the app.
2. App initializes `~/.defenseclaw` and policy assets if missing.
3. App starts or repairs the sidecar/backend.
4. App checks helper health and version compatibility.
5. User sees Home with healthy backend status.

**Failure path**

1. Helper cannot start or health cannot be decoded.
2. App routes to Diagnostics with exact error, logs, Run Doctor, and repair path.
3. User can return to Setup to install/repair backend.

**Current app assessment**

- Has initialization and sidecar start helpers.
- Diagnostics now shows health, `/status`, Run Doctor, logs, and repair links.
- Still needs a polished install/repair wizard that treats the bundled backend as
  first-class, including version skew and rollback.

## Flow 2: Secrets Intake

**User intent:** Add required API keys without editing files or exposing raw values.

**Required settings**

- `inspect_llm.api_key_env`
- `cisco_ai_defense.api_key_env`
- `guardrail.api_key_env`
- `guardrail.judge.api_key_env`
- `splunk.hec_token_env`
- gateway auth token env

**Happy path**

1. User opens Setup from Settings Overview.
2. App lists missing secrets by feature: DefenseClaw LLM, Cisco AI Defense,
   Guardrail judge, Splunk/OTel.
3. User enters secret values into secure controls.
4. App stores secrets in macOS credential storage or managed `.env` fallback.
5. App validates only presence/connectivity and never displays raw secret values.

**Failure path**

1. Validation fails.
2. App shows which feature is blocked and how to repair it.
3. User can retry without losing unrelated setup progress.

**Current app assessment**

- Setup has secure fields and config-backed fields.
- Sidecar client now reads token env values from `~/.defenseclaw/.env`, which fixes
  GUI environment issues.
- Remaining gap: dedicated Secrets page and macOS Keychain storage are still needed.

## Flow 3: Connect Coding Agents and Gateway

**User intent:** Connect OpenClaw/coding agents to the DefenseClaw gateway.

**Required settings**

- `claw.mode`, `claw.home_dir`, `claw.config_file`
- `gateway.host`, `gateway.port`
- `gateway.api_bind`, `gateway.api_port`
- `gateway.token_env`
- `gateway.auto_approve_safe`
- `gateway.reconnect_ms`, `gateway.max_reconnect_ms`, `gateway.approval_timeout_s`

**Happy path**

1. User chooses “Connect Coding Agents” in Settings Overview.
2. App shows gateway health, OpenClaw connection, ports, and restart controls.
3. User changes only common connection settings.
4. App validates and restarts affected services.

**Failure path**

1. OpenClaw config is missing or gateway health is degraded.
2. App offers Setup/Diagnostics path rather than dumping raw config.

**Current app assessment**

- Gateway screen covers host, API port, WebSocket port, auto-start, restart.
- Diagnostics exposes backend state.
- Remaining gap: connection wizard should detect each supported coding agent and
  show a checklist per integration.

## Flow 4: Enable Guardrail Protection

**User intent:** Turn on observe/action protection and tune runtime blocking.

**Required settings**

- `guardrail.enabled`
- `guardrail.mode`
- `guardrail.scanner_mode`
- `guardrail.host`, `guardrail.port`
- `guardrail.model`, `guardrail.model_name`, `guardrail.original_model`
- `guardrail.block_message`
- `guardrail.judge.*`

**Happy path**

1. User selects “Turn On Protection”.
2. App explains Observe vs Action mode in terms of effect, not implementation.
3. User enables guardrail, chooses scanner mode, configures judge if needed.
4. App applies live mode if backend is online or saves and marks restart required.
5. User can test prompt/tool-call evaluation before leaving.

**Failure path**

1. Backend is offline or judge key is missing.
2. App routes to Diagnostics or Secrets intake.

**Current app assessment**

- Guardrail screen covers enable, live mode, scanner mode.
- Policy screen covers guardrail rule packs, suppressions, regex rules, judge files.
- Remaining gap: in-app test evaluator should be integrated into Guardrails instead
  of requiring raw policy context.

## Flow 5: Configure Scanners

**User intent:** Configure skill, MCP, plugin, and code scanners.

**Required settings**

- `scanners.skill_scanner.binary`
- `scanners.skill_scanner.policy`
- `scanners.skill_scanner.lenient`
- `scanners.skill_scanner.use_llm`
- `scanners.skill_scanner.use_behavioral`
- `scanners.skill_scanner.enable_meta`
- `scanners.skill_scanner.use_trigger`
- `scanners.skill_scanner.use_virustotal`
- `scanners.skill_scanner.use_aidefense`
- `scanners.skill_scanner.llm_consensus_runs`
- `scanners.mcp_scanner.binary`
- `scanners.mcp_scanner.analyzers`
- `scanners.mcp_scanner.scan_prompts`
- `scanners.mcp_scanner.scan_resources`
- `scanners.mcp_scanner.scan_instructions`
- `scanners.plugin_scanner`
- `scanners.codeguard`

**Happy path**

1. User opens Scanners from Settings Overview or Setup.
2. App shows installed/missing scanner binaries and recommended defaults.
3. User can run a probe scan for each scanner.
4. App saves scanner settings and shows coverage in Home.

**Failure path**

1. Scanner binary is missing or incompatible.
2. App offers install/repair workflow and shows exact command output in-app.

**Current app assessment**

- Scanners screen currently covers binary paths.
- Setup has broader scanner workflow parity.
- Remaining gap: Scanners needs full options, test probes, and install detection.

## Flow 6: Configure Enforcement

**User intent:** Decide what to block, allow, unblock, or quarantine.

**Required settings/state**

- block list
- allow list
- `skill_actions.*`
- `mcp_actions.*`
- `plugin_actions.*`
- inventory state for skills, MCPs, plugins, tools
- quarantine state

**Happy path**

1. User enters Enforcement from Settings Overview or an alert detail.
2. App shows merged inventory plus explicit allow/block entries.
3. User filters by blocked, allowed, quarantined, monitored.
4. User acts inline and the backend confirms mutation.
5. App refreshes counts and audit/log state.

**Failure path**

1. Runtime inventory endpoint is unavailable.
2. App still shows explicit allow/block lists and explains partial data.

**Current app assessment**

- Enforcement now merges skills, MCPs, tools, explicit allow/block lists.
- Empty state was fixed; UUID enforcement records now decode correctly.
- Remaining gap: plugin inventory endpoint and quarantine restore flows should be
  added as first-class backend APIs.

## Flow 7: Edit Policy, Suppressions, and Regex Rules

**User intent:** Tune DefenseClaw decisions without opening a terminal editor.

**Required settings/files**

- admission policy files
- scanner policy files
- firewall policy
- sandbox/OpenShell policy
- Rego files
- guardrail suppressions
- guardrail regex rule packs
- judge prompt files

**Happy path**

1. User opens Policy from Home, Alerts, or Settings Overview.
2. App lets the user choose policy domain: admission, guardrail rules,
   suppressions, regex rules, Rego, firewall, sandbox.
3. User edits a runtime file with validation.
4. User evaluates a target before saving/reloading.
5. App reloads runtime policy and shows result.

**Failure path**

1. User selects a bundled read-only file.
2. App clearly marks it read-only and should offer “copy to runtime” when needed.

**Current app assessment**

- Policy editor includes all policy files and a Guardrail Rules tab.
- Shared editor now has filters, metadata, validation, and read-only status.
- Remaining gap: copy-to-runtime and domain-specific policy templates.

## Flow 8: Configure Observability

**User intent:** Send evidence and metrics to security tools.

**Required settings**

- `splunk.enabled`
- `splunk.hec_endpoint`
- `splunk.hec_token_env`
- `splunk.index`
- `splunk.source`
- `splunk.sourcetype`
- `splunk.verify_tls`
- `splunk.batch_size`
- `splunk.flush_interval_s`
- `otel.enabled`
- `otel.protocol`
- `otel.endpoint`
- bundled local observability stack config
- Datadog-style sink through OTel/exporter config

**Happy path**

1. User chooses observability setup from Settings Overview.
2. App asks target: local stack, Splunk, OTel, Datadog-compatible exporter.
3. User enters endpoint and secret reference.
4. App sends a test event and reports success/failure.
5. App shows active sink status in Diagnostics/Home.

**Failure path**

1. Endpoint rejects event or TLS fails.
2. App shows response details and points to logs.

**Current app assessment**

- Config editor can edit observability files.
- Setup mentions sinks/webhooks/local observability.
- Remaining gap: dedicated Observability settings screen with probes and secret intake.

## Flow 9: Alerts and Incident Triage

**User intent:** Understand an alert and choose the next action.

**Required state**

- active alerts
- audit event details
- target inventory
- policy verdict
- enforcement actions
- exportable logs/evidence

**Happy path**

1. User opens an alert from Home or Alerts.
2. App shows severity, action, target, details, actor, timestamp.
3. User opens related policy/enforcement/logs without losing context.
4. User allows, blocks, suppresses, or exports evidence.

**Failure path**

1. Alerts endpoint cannot load.
2. App shows backend error and routes to Diagnostics/Logs.

**Current app assessment**

- Alerts page now distinguishes active empty vs load error and shows details.
- Remaining gap: alert-to-policy/enforcement deep links and historical audit search.

## Flow 10: System Diagnosis and Repair

**User intent:** Fix broken backend, missing data, or failed setup.

**Required state**

- helper health
- `/status` payload
- gateway/watchdog/app logs
- doctor output
- config/policy/secrets file locations

**Happy path**

1. User opens Diagnostics when any page reports failure.
2. App shows health cards, subsystem state, raw status, doctor, and local files.
3. User can run Doctor, export logs, open Logs, or go to Setup.

**Failure path**

1. Backend is fully offline.
2. App still shows repair and logs path.

**Current app assessment**

- Diagnostics was upgraded to an actionable page.
- Remaining gap: one-click backend reinstall/rollback and update compatibility checks.

## Flow 11: Advanced Raw Config Editing

**User intent:** Power user needs every setting and companion config file.

**Required files**

- DefenseClaw runtime config
- OpenClaw/coding agent JSON
- scanner config
- guardrail runtime config
- local observability bundles
- Splunk bridge config
- policy/scanner companion files

**Happy path**

1. User opens Config Files from Advanced.
2. User filters by category/source/format.
3. User edits runtime files with validation.
4. User saves and then follows any restart-required prompt.

**Failure path**

1. User opens read-only bundled/project file.
2. App marks it read-only and should offer safe copy-to-runtime.

**Current app assessment**

- Config editor can discover and edit a broad set of files.
- Shared editor is improved, but still raw.
- Remaining gap: settings schema forms for common settings and restart-impact banners.

## App Changes Made in This Pass

- Added Settings Overview as the default settings entry point.
- Grouped settings by workflow and role instead of opening raw config first.
- Linked common paths to Setup, Gateway, Guardrails, Enforcement, Scanners,
  Diagnostics, Policy, Alerts, Logs, and Config Files.
- Kept Config Files as the advanced complete editor for every discovered YAML,
  JSON, and Rego file.

## Release-Gating UX Checks

- A first-time user can install and repair the backend without terminal use.
- A security admin can edit guardrail suppressions and regex rules without finding
  the raw path manually.
- A platform operator can see why Diagnostics is broken and act from inside the app.
- An incident responder can move from alert to enforcement/policy/logs.
- A SecOps user can configure and test Splunk/OTel/Datadog-compatible telemetry.
- A power user can still access every raw config/policy file.
