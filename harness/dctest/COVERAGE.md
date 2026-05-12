# dctest coverage matrix

This document tracks how the shipped YAML test cases map to the publicly advertised feature surface of DefenseClaw. Update this file whenever a new feature appears in [`docs-site/content/docs/`](../../docs-site/content/docs/).

## How to read this table

- **Surface** is the case YAML's `surface` field.
- **Feature** lines up with the case YAML's `feature` (dotted).
- **Cases** lists representative case ids that exercise the feature; not exhaustive — run `pytest harness/dctest/tests/test_case_loader.py -k loader -q` then `dctest matrix list` to enumerate the full surface.
- **Docs site refs** are the canonical user-facing docs each feature shows up under.

## CLI (Python `defenseclaw`)

| Feature                | Cases                                   | Docs site refs |
| ---------------------- | --------------------------------------- | -------------- |
| `cli.version`          | `cli-py.version.basic`, `cli-py.version.json` | reference/cli.mdx |
| `cli.status`           | `cli-py.status.basic`, `cli-py.status.json`, `cli-py.status.sidecar-down` | reference/cli.mdx |
| `cli.config`           | `cli-py.config.{path,show,validate,show-json}` | reference/config.mdx |
| `skill.list`           | `cli-py.skill.list.{basic,json}`        | setup/skill-scanner.mdx |
| `skill.scan`           | `cli-py.skill.scan.{benign,malicious,missing-path}` | setup/skill-scanner.mdx |
| `skill.enforce`        | `cli-py.skill.block.unblock`            | reference/enforce.mdx |
| `skill.info`           | `cli-py.skill.info.bad-id`              | reference/cli.mdx |
| `plugin.list`          | `cli-py.plugin.list.{basic,json}`       | reference/cli.mdx |
| `plugin.scan`          | `cli-py.plugin.scan.{fixture,missing-path}` | reference/cli.mdx |
| `plugin.info`          | `cli-py.plugin.info.bad-id`             | reference/cli.mdx |
| `mcp.list`             | `cli-py.mcp.list.{basic,json}`          | setup/mcp-scanner.mdx |
| `mcp.scan`             | `cli-py.mcp.scan.{fixture,missing-config}` | setup/mcp-scanner.mdx |
| `mcp.toggle`           | `cli-py.mcp.set-unset`                  | reference/cli.mdx |
| `policy.{list,show,validate,test,create}` | `cli-py.policy.*`         | policies.mdx |
| `registry.{list,crud,sync,add}` | `cli-py.registry.*`            | setup/registries.mdx |
| `agent.{discover,usage,processes,components,confidence,signatures}` | `cli-py.agent.*` | ai-discovery.mdx |
| `audit.log-activity`   | `cli-py.audit.log-activity`             | reference/cli.mdx |
| `alerts.{list,lifecycle}` | `cli-py.alerts.*`                    | reference/cli.mdx |
| `codeguard.status`     | `cli-py.codeguard.status`               | reference/cli.mdx |
| `aibom.scan`           | `cli-py.aibom.scan.json`                | ai-discovery.mdx |
| `guardrail.{status,toggle,fail-mode}` | `cli-py.guardrail.*`         | reference/fail-modes.mdx |
| `tool.{list,status,resolve,admission}` | `cli-py.tool.*`             | hitl.mdx |
| `keys.list`            | `cli-py.keys.list.*`                    | reference/keys.mdx |
| `settings.save`        | `cli-py.settings.save.idempotent`       | reference/cli.mdx |
| `doctor.basic`         | `cli-py.doctor.{read-only,json}`        | reference/cli.mdx |
| `migrations.{status,dry-run}` | `cli-py.migrations.*`            | reference/cli.mdx |
| `setup.{gateway,notifications,observability,webhook,redaction}` | `cli-py.setup.*` | observability/index.mdx, setup/webhooks.mdx, reference/redaction.mdx |
| `help.basic`           | `cli-py.help.top`, `cli-py.unknown-command` | reference/cli.mdx |

## CLI (Go `defenseclaw-gateway`)

| Feature                  | Cases                                    | Docs site refs |
| ------------------------ | ---------------------------------------- | -------------- |
| `cli.version`            | `cli-go.version.basic`                   | reference/cli.mdx |
| `cli.status`             | `cli-go.status.basic`                    | reference/cli.mdx |
| `policy.{validate,show,domains,evaluate,firewall,reload}` | `cli-go.policy.*` | policies.mdx |
| `gateway.lifecycle`      | `cli-go.start.short`                     | reference/gateway.mdx |
| `gateway.connector.{verify,teardown}` | `cli-go.connector.*`        | reference/cli.mdx |
| `gateway.audit`          | `cli-go.audit.*`, `cli-py.audit.log-activity` | reference/cli.mdx |
| `scanning.codeguard`     | `cli-go.scan.code.{benign,seeded,schema,missing-path}` | reference/cli.mdx |
| `help.basic`             | `cli-go.help.top`, `cli-go.unknown-command` | reference/cli.mdx |

## Lifecycle (state-mutating)

| Feature                  | Cases                                    | Docs site refs |
| ------------------------ | ---------------------------------------- | -------------- |
| `lifecycle.init`         | `lifecycle.init.{cold-start,idempotent}` | quickstart.mdx |
| `lifecycle.quickstart`   | `lifecycle.quickstart.{dry-run,execute}` | quickstart.mdx |
| `lifecycle.uninstall`    | `lifecycle.uninstall.{basic,preserve-keys}` | reference/cli.mdx |
| `lifecycle.upgrade`      | `lifecycle.upgrade.{dry-run,execute}`    | reference/cli.mdx |
| `lifecycle.reset`        | `lifecycle.reset.basic`                  | reference/cli.mdx |
| `lifecycle.sidecar`      | `lifecycle.sidecar.{start,restart,stop}` | reference/cli.mdx |
| `lifecycle.watcher`      | `lifecycle.watcher.start-stop`           | setup/watcher.mdx |
| `lifecycle.watchdog`     | `lifecycle.watchdog.start-stop`          | reference/cli.mdx |
| `lifecycle.keys.rotate`  | `lifecycle.keys.rotate-token`            | reference/keys.mdx |
| `lifecycle.keys.migrate` | `lifecycle.keys.migrate-{llm,splunk}`    | reference/keys.mdx |

## Skills (cross-connector pipelines)

| Feature                  | Cases                                    | Docs site refs |
| ------------------------ | ---------------------------------------- | -------------- |
| `scanning.clawshield.local` | `skills.clawshield.local-pack.trigger` | setup/skill-scanner.mdx |
| `scanning.clawshield.bifrost` | `skills.clawshield.bifrost.trigger` | setup/skill-scanner.mdx |
| `scanning.clawshield`    | `skills.clawshield.benign-no-finding`    | setup/skill-scanner.mdx |
| `scanning.codeguard`     | `skills.codeguard.{benign,seeded,aibom-mode}` | reference/cli.mdx |
| `guardrail.opa`          | `skills.opa.{permissive,default,strict}.*` | defaults.mdx |
| `guardrail.firewall`     | `skills.opa.firewall.{allow,block}-domain` | defaults.mdx |
| `guardrail.judge`        | `skills.judge.{match-on-prompt-injection,match-on-secrets,cache-hit-on-repeat}` | guardrail/judge.mdx |
| `observability.otlp`     | `skills.observability.otlp.local-bundle` | observability/index.mdx |
| `observability.jsonl`    | `skills.observability.audit-jsonl`       | observability/index.mdx |
| `observability.splunk`   | `skills.observability.splunk-triad`      | observability/splunk.mdx |
| `observability.webhook`  | `skills.observability.webhook.delivery`, `skills.observability.webhook.ssrf-block` | setup/webhooks.mdx |
| `hitl.approval`          | `skills.hitl.approval-required`, `skills.hitl.alert-emitted` | hitl.mdx |
| `fail-mode.open` / `fail-mode.closed` | `skills.fail-mode.*`        | reference/fail-modes.mdx |
| `sandbox.scanner`        | `skills.sandbox.python-subprocess.exec`  | reference/architecture.mdx |
| `redaction`              | `skills.redaction.config`                | reference/redaction.mdx |

## Connectors

| Connector       | Required cases                            | Docs site refs |
| --------------- | ----------------------------------------- | -------------- |
| codex (required)| `connectors.codex.{install,verify,run-flagged-prompt,teardown}` | connectors/codex.mdx |
| claudecode (required) | `connectors.claudecode.{install,verify,runtime,teardown}` | connectors/claude-code.mdx |
| openclaw (required) | `connectors.openclaw.{install,verify,before-tool-call,teardown}` | connectors/openclaw.mdx |
| zeptoclaw (optional) | `connectors.zeptoclaw.install`         | connectors/zeptoclaw.mdx |
| cursor (optional)    | `connectors.cursor.install`            | connectors/cursor.mdx |
| copilot (optional)   | `connectors.copilot.install`           | connectors/copilot.mdx |
| geminicli (optional) | `connectors.geminicli.install`         | connectors/gemini-cli.mdx |
| windsurf (optional)  | `connectors.windsurf.install`          | (no public page yet) |
| hermes (optional)    | `connectors.hermes.install`            | connectors/hermes.mdx |

## Gateway HTTP API

| Endpoint                                       | Cases                                          | Docs site refs |
| ---------------------------------------------- | ---------------------------------------------- | -------------- |
| `POST /api/v1/inspect/tool` (allow / deny / csrf) | `gateway-api.inspect.tool.*`                | reference/gateway-api.mdx |
| `POST /api/v1/scan/code`                       | `gateway-api.scan.code.{basic,seeded}`         | reference/gateway-api.mdx |
| `POST /api/v1/policy/evaluate-firewall`        | `gateway-api.network-egress.allow`              | reference/gateway-api.mdx |
| `POST /api/v1/policy/evaluate`                 | `gateway-api.policy.evaluate.deny`              | reference/gateway-api.mdx |
| `POST /api/v1/policy/reload`                   | `gateway-api.policy.reload`                    | reference/gateway-api.mdx |
| `POST /api/v1/admin/*` (bearer auth)           | `gateway-api.bearer.required`                  | reference/gateway-api.mdx |
| `POST /v1/traces` (OTLP)                       | `gateway-api.otlp.ingest`                      | observability/index.mdx |

## Stories (end-to-end scenarios)

| Story                                | Cases                                    | Docs site refs |
| ------------------------------------ | ---------------------------------------- | -------------- |
| observe-claude-code                  | `stories.observe-claude-code.end-to-end` | getting-started/observe-claude-code.mdx |
| prompt-injection-codex               | `stories.prompt-injection-codex.end-to-end` | getting-started/prompt-injection.mdx |
| cursor-secret-exfil                  | `stories.cursor-secret-exfil.detect`     | hitl.mdx |
| local-observability                  | `stories.local-observability.docker-compose` | observability/index.mdx |
| switch-connectors                    | `stories.switch-connectors.codex-to-claudecode` | connectors/index.mdx |

## Error paths (negative tests)

| Error                                | Cases                                    |
| ------------------------------------ | ---------------------------------------- |
| bad config yaml                      | `errors.bad-config.surface-clear-message` |
| sidecar down                         | `errors.sidecar-down.curl-rejection`     |
| token mismatch                       | `errors.token-mismatch.401`              |
| missing LLM key                      | `errors.missing-llm-key.guardrail-block` |
| malformed Rego                       | `errors.malformed-rego`                  |
| port in use                          | `errors.port-in-use`                     |
| scanner missing on PATH              | `errors.scanner-missing-on-path`         |
| fail-mode toggle mid-flight          | `errors.fail-mode-toggle-mid-flight`     |
| registry metadata-only degradation   | `errors.registry-metadata-only`          |
| webhook SSRF block                   | `errors.webhook.ssrf-blocked`            |

## How to add coverage

1. Add a `cases/<surface>/<feature>.yaml` file or a new `cases:` entry.
2. Append a row to the relevant section of this file.
3. `harness/dctest/.venv/bin/python -m pytest harness/dctest/tests -q` to validate ids are unique and expectations are present.
4. `dctest matrix list --include-optional` to confirm the new case appears under the connectors you expect.
