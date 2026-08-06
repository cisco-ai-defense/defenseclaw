# Legacy Cascade native Windows research gate

Research date: **2026-07-31**. Result: **legacy Cascade is eligible for a
connector-scoped native Windows x64 preview**. The connector is
**not certified** and does not cover Devin Local, cloud agents, ACP, or their
separate lifecycle hooks.

This gate evaluates only the legacy Cascade agent in Devin Desktop. It requires
the upstream desktop client, configuration, hook transport,
and enforcement response to run as direct Windows processes with Windows
paths. WSL, Docker, a VM, Bash, Git Bash, Cygwin, and MSYS are not qualifying
paths and are not used by the implementation.

## Authoritative official sources

The former Windsurf URLs redirect to the current Devin Desktop documentation.
Both sides are recorded so later reviewers can distinguish an authoritative
vendor rename from an unrelated mirror.

| Evidence | Former URL | Authoritative destination | Version/date observed | Finding |
| --- | --- | --- | --- | --- |
| Native download | `https://windsurf.com/download` | `https://devin.ai/download` | checked 2026-07-31 | Native Windows x64 and arm64 downloads; minimum Windows 10 64-bit. The page states Devin Desktop is the new name for Windsurf and that the OTA update retains settings and extensions. This record does not certify either architecture. |
| Install/uninstall and native paths | `https://docs.windsurf.com/windsurf/getting-started` | `https://docs.devin.ai/desktop/getting-started` | checked 2026-07-31 | Devin Desktop supports Windows. Official install roots include `C:\Program Files\Windsurf` and `%LOCALAPPDATA%\Programs\Windsurf`; the legacy per-user Cascade configuration remains under `%USERPROFILE%\.codeium\windsurf`. |
| Cascade hooks | `https://docs.windsurf.com/windsurf/cascade/hooks` | `https://docs.devin.ai/desktop/cascade/hooks` | checked 2026-07-31 | Cascade has the native Windows hook transport, twelve-event schema, JSON/stdin, output streams, exit behavior, merge order, and limitations described below. The page distinguishes Cascade from Devin Local lifecycle hooks. |
| Devin Local | — | `https://docs.devin.ai/desktop/devin-local` | checked 2026-07-31 | Devin Local is the primary local agent and the default for new tabs when no preference is set. Its lifecycle hooks, MCP files, rules, and skills differ from Cascade. It is unsupported by this connector. |
| Cascade rules and `AGENTS.md` | — | `https://docs.devin.ai/desktop/cascade/memories` and `https://docs.devin.ai/desktop/cascade/agents-md` | checked 2026-07-31 | Cascade reads the user global rule, preferred `.devin/rules`, legacy `.windsurf/rules` and `.windsurfrules`, and recursive/ancestor `AGENTS.md` files. Enterprise/system rule sources are documented separately and are excluded here. |
| Cascade skills | — | `https://docs.devin.ai/desktop/cascade/skills` | checked 2026-07-31 | Non-enterprise roots include workspace and user `.windsurf/skills` and cross-agent `.agents/skills`. Optional Claude compatibility and managed/system skill layers are outside this connector. |
| Cascade MCP | — | `https://docs.devin.ai/desktop/cascade/mcp` | checked 2026-07-31 | The legacy Cascade MCP file is `%USERPROFILE%\.codeium\windsurf\mcp_config.json`. Devin Local and Team/enterprise MCP configuration are separate. |
| Release history | `https://windsurf.com/changelog` | `https://docs.devin.ai/desktop/changelog` | current **3.6.22, 2026-07-29** | Hooks arrived in **1.12.31**; user-prompt hooks in **1.12.41**, the DefenseClaw floor. **3.5.17** added hook migration, and **3.6.21** made Devin Local the default for new tabs and states Restricted Mode disables agents and hooks. |
| Release archive | — | `https://docs.devin.ai/desktop/releases` | checked 2026-07-31 | Official downloadable desktop release inventory. |

## Native hook contract

The official Cascade documentation describes system → user → workspace hook
precedence:

- system Windows: `C:\ProgramData\Windsurf\hooks.json`;
- user desktop: `%USERPROFILE%\.codeium\windsurf\hooks.json`;
- workspace: `<workspace>\.windsurf\hooks.json`.

Each handler accepts `command`, optional `powershell`, `show_output`, and
optional `working_directory`. On Windows the `powershell` value runs through
`powershell -Command`; if it is absent, `command` is used through the same
PowerShell transport. On macOS/Linux, `command` uses `bash -c` and
`powershell` is ignored. Absolute paths are supported; `~` expansion is not.
DefenseClaw therefore writes **only** `powershell` on Windows and never installs
a cross-platform `command` fallback.

The host sends a JSON object on stdin and receives the hook result through the
process exit code, stdout, and stderr. Twelve official events exist:

1. `pre_read_code`
2. `post_read_code`
3. `pre_write_code`
4. `post_write_code`
5. `pre_run_command`
6. `post_run_command`
7. `pre_mcp_tool_use`
8. `post_mcp_tool_use`
9. `pre_user_prompt`
10. `post_cascade_response`
11. `post_cascade_response_with_transcript`
12. `post_setup_worktree`

Exit `0` proceeds. Exit `2` blocks only
`pre_user_prompt`, `pre_read_code`, `pre_write_code`, `pre_run_command`, and
`pre_mcp_tool_use`, and stderr is shown to the agent. Every other exit proceeds.
Post hooks cannot block because their action already occurred. Both Cascade
response post hooks run asynchronously. The documentation warns that slow
pre-hooks delay Cascade and recommends testing a blocking exit `2`; this proves
the host waits for the pre-hook decision rather than treating it as fire and
forget.

## Eligibility and implementation boundary

For legacy Cascade, the evidence supports an eligible fully native path: native Windows desktop process →
documented `powershell -Command` hook → generated `windsurf-hook.ps1` →
exact packaged `defenseclaw-hook.exe`. The adapter copies JSON stdin and child
stdout/stderr, waits for the child, and propagates its exact exit status,
including `2`.

The connector deliberately manages only the bound user's
`.codeium\windsurf\hooks.json`. It does not install or reconcile the system
`ProgramData` file, workspace hook files, enterprise/Team policy,
cloud-dashboard settings, or MDM policy. Consequently it does not claim
authoritative hard enforcement across higher-precedence or managed layers;
their effective precedence and deployment behavior remain unverified here.
Read-only customization inventory is limited to the bound user profile and a
pinned non-enterprise workspace, uses bounded traversal without following
links or reparse points, and does not extend the enforcement boundary.

DefenseClaw fail-closed availability maps its own missing/timeout/invalid
runtime failures to exit `2`. This does not broaden vendor semantics:

- only the five official pre-hooks can block;
- arbitrary non-`2` hook failures fail open;
- post hooks never block and Cascade response hooks are asynchronous;
- Restricted Mode disables all hooks;
- Cascade exposes no hook-native ask/resume surface;
- hooks run with the user's permissions and can see sensitive prompt, code,
  command, MCP, response, and transcript data;
- system-level hooks require administrator-controlled deployment and are not
  installed by the per-user DefenseClaw package.

Official-client validation requires an interactive native Windows desktop
runner. A CLI, WSL, or shell substitute is not accepted as client evidence.
Until that gate and the packaged Windows matrix pass in the integrated branch,
the connector must not be described as release-certified. This research is a
source and implementation-boundary ledger, not live or certification evidence.

## DCWIN-012 correction ledger

The reported initial setup wrote the bound user `hooks.json` without the
expected contract lock/runtime metadata, after which Doctor inspected the
optional `mcp_config.json` as if it were hook configuration. A later unrelated
connector setup repaired shared assets, but that is not valid Windsurf setup
ownership or activation evidence.

The corrected contract is connector-local and ordered:

1. resolve the persisted/bound profile and its exact `hooks.json`;
2. capture the managed backup and write all twelve Cascade handlers;
3. verify exactly one native managed handler per event, with no Windows
   `command` fallback;
4. publish fresh `windsurf-hooks-v1` lock/runtime metadata; and
5. publish the connector as active only after the metadata succeeds.

Failure before step 5 rolls the partial connector back and does not depend on a
peer connector setup. Doctor uses the same bound `hooks.json`; missing or empty
`mcp_config.json` is optional inventory, while an active connector with no lock
is unhealthy. Doctor also reports that Restricted Mode disables all Cascade
hooks, but cannot passively read that workspace UI state.

No authentic Cascade event was observed in this correction. Zero counters do
not establish activation, failure, or certification. Shared cp1252 readiness
belongs to the integration branch and is not claimed by this connector-scoped
ledger.
