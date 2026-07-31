# Hermes Agent macOS connector research and acceptance matrix

Last verified: **2026-07-30**

DefenseClaw status: **preview / uncertified**

Latest official version: **Hermes Agent 0.19.1**, release tag
[`v2026.7.30`](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.7.30),
commit
[`cc4cab2f592e60a197e796506de9168f74baf3ea`](https://github.com/NousResearch/hermes-agent/commit/cc4cab2f592e60a197e796506de9168f74baf3ea).

## Version decision

- **OUTDATED:** No. DefenseClaw's macOS range is `>=0.19.0, <0.20.0`, and the
  latest stable upstream release is `0.19.1`. Windows deliberately preserves
  the earlier `>=0.19.0` range without a ceiling.
- **CURRENT:** Yes. The tagged `VALID_HOOKS` inventory is exactly the 23 events
  in `hermes-hooks-v1`; the shell bridge still uses JSON stdin/stdout,
  `shlex.split`, synchronous `subprocess.run(..., shell=False)`, and the same
  three response-bearing roles.
- **UNCERTIFIED:** Yes. The macOS `last_validated_version` remains empty. The
  genuine-client driver is durable workflow coverage, but no packaged plus
  official-client run URL exists yet.

Hermes 0.18 source contains the same 23 event names. DefenseClaw does not lower
the floor from 0.19.0 on that observation alone because the full lifecycle,
packaging, and Windows-preservation evidence has not been run for 0.18.

## Primary-source inventory

| Surface | Official source | DefenseClaw result |
| --- | --- | --- |
| Latest release/version | [GitHub release](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.7.30), [`pyproject.toml`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/pyproject.toml) | `0.19.1`; current within macOS `>=0.19.0, <0.20.0`. Windows remains unbounded above. |
| macOS installation | [Platform support](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/getting-started/platform-support.md), [installation](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/getting-started/installation.md) | macOS is official; CLI install uses `install.sh`. DefenseClaw remains preview until its own certification closes. |
| Home/config | [`hermes_constants.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_constants.py), [configuration guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/user-guide/configuration.md) | `HERMES_HOME` wins; macOS defaults to `~/.hermes`; effective config is `config.yaml`. |
| Hook inventory/process | [`VALID_HOOKS`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/plugins.py), [`agent/shell_hooks.py`](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/agent/shell_hooks.py), [hook guide](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/user-guide/features/hooks.md) | All 23 events; only `pre_tool_call` blocks, `pre_llm_call` injects context, and `pre_verify` continues verification. Hermes tokenizes the absolute POSIX command and runs it synchronously with `shell=False`; failures remain open. |
| MCP | [MCP config reference](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/reference/mcp-config-reference.md) | Canonical top-level `mcp_servers` is read and written. Older DefenseClaw shapes remain read-only fallbacks. |
| Skills/plugins/instructions | [Skills](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/website/docs/user-guide/features/skills.md), [plugins](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/hermes_cli/plugins.py), [context files](https://github.com/NousResearch/hermes-agent/blob/v2026.7.30/agent/context_files.py) | Skills are read/write opt-in. Plugins, hook packages, `SOUL.md`, and workspace instruction/rule files are inventoried read-only. |

## 12 acceptance surfaces

| # | Surface | macOS result |
| --- | --- | --- |
| 1 | Registry, discovery, version, platform | **Implemented:** aliases, trusted discovery, `HERMES_HOME`, macOS `>=0.19.0, <0.20.0`; the Windows overlay remains `>=0.19.0` without a ceiling. **Uncertified:** explicit macOS preview. |
| 2 | CLI/help/aliases | **Implemented:** `setup hermes`, guardrail flags, status, teardown, verify, repair. |
| 3 | TUI/setup/status/repair | **Implemented:** shared registry/status/Doctor expose preview, fail-open, no-ask constraints. |
| 4 | Full `HERMES_HOME` Setup lifecycle | **Implemented:** only resolved `config.yaml` is patched; unchanged state restores exact bytes or absence. On drift, teardown removes owned hooks and three-way restores `hooks_auto_accept` while preserving unrelated edits. |
| 5 | Hook contract | **Implemented:** all 23 events, correct matchers, timeout, and per-event response authority. |
| 6 | Native process/provenance | **Implemented:** absolute executable POSIX hook asset; no registered PATH or compatibility-shell fallback. |
| 7 | Gateway/auth/lifecycle | **Implemented:** scoped token, route, readiness, restart, reconciliation, teardown, revocation. |
| 8 | Doctor/tamper/repair | **Implemented:** YAML, inventory, auto-accept, exact command, executable ownership, lock/hash/version drift, passive repair. |
| 9 | OTEL/audit/correlation | **Implemented downstream:** hook-derived policy signals and canonical correlation/export. Hermes 0.19.1 also has optional native OTLP gateway-health/diagnostic signals; DefenseClaw does not configure or claim those as policy telemetry. |
| 10 | Assets | **Implemented:** config, canonical MCP, local/external skills, read-only user plugins. Explicit N/A categories follow. |
| 11 | Docs/matrix/limits | **Implemented:** connector page, compatibility/capability matrices, evidence record. |
| 12 | Deterministic/packaged/live/manual evidence | **Implemented:** unit, lifecycle, Doctor, contract smoke, official-client macOS workflow driver. **Blocked:** no durable passing packaged + genuine-client run. |

## Complete asset disposition

| Official Hermes asset/category | DefenseClaw disposition |
| --- | --- |
| `$HERMES_HOME/config.yaml` shell hooks | **Managed:** hook entries plus `hooks_auto_accept`; exact restoration when unchanged and owned-key three-way restoration on drift. |
| `mcp_servers` | **Read/write:** canonical v0.19 schema with atomic backup-safe mutation. |
| `$HERMES_HOME/skills` | **Read/write opt-in:** inventory and install target. |
| `skills.external_dirs` | **Read-only:** existing expanded directories are inventoried. |
| `$HERMES_HOME/skill-bundles` | **N/A:** bundles reference skills but are Hermes-owned command aliases, not installable DefenseClaw skill packages. |
| `skills/.hub`, `.bundled_manifest`, `.no-bundled-skills`, `pending/skills` | **N/A for direct mutation:** Hermes owns registry provenance, quarantine, seeding, and approval state. |
| `$HERMES_HOME/plugins` | **Read-only:** inventory/scanning only. |
| Workspace `.hermes/plugins` and `HERMES_ENABLE_PROJECT_PLUGINS` | **Read-only:** inventoried without enabling project-plugin trust. |
| Python `hermes_agent.plugins` entry points | **N/A:** these have no connector-owned filesystem asset root and remain under Hermes package discovery. |
| `shell-hooks-allowlist.json` | **N/A for direct mutation:** Hermes owns consent persistence; DefenseClaw sets documented `hooks_auto_accept` only. |
| `$HERMES_HOME/agent-hooks`, `$HERMES_HOME/hooks/*/HOOK.yaml` | **Read-only:** inventoried; connector enforcement continues to use shell hooks. |
| `.env`, `auth.json`, secret-source/vault config | **N/A:** credentials remain Hermes-owned and are neither inventoried nor mutated. |
| `SOUL.md`, `BOOT.md`, workspace `.hermes.md`/`HERMES.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.cursor/rules` | **Read-only:** inventoried as instruction/rule inputs; never mutated. |
| memories, sessions, state database, delivery ledger | **N/A:** conversation and operational state are not connector extension assets. |
| cron, profiles, pairing, platform/gateway channel config | **N/A:** operational Hermes lifecycle state is outside connector asset policy. |
| bundled install-tree plugins/skills | **N/A for direct scanning:** DefenseClaw does not crawl or modify the upstream checkout. |
| agents/microagents | **N/A:** no separate supported filesystem extension category is documented. |
| CodeGuard | **Explicit opt-in only:** installable as a skill; connector setup does not auto-install it. |
| `monitoring.export.otlp` native OTLP | **Upstream-owned:** optional content-free gateway health, diagnostics, and cron signals; DefenseClaw neither configures it nor substitutes it for hook-derived policy telemetry. |

## Certification blocker

Do not populate `last_validated_version` or promote macOS beyond preview until a
durable run validates a packaged DefenseClaw artifact with the genuine latest
Hermes client, records its version and run URL, proves allow/block plus
Doctor/tamper/restoration checks, and receives maintainer review.
