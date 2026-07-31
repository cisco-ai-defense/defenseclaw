# Windsurf native Windows research gate

Research date: **2026-07-30**. Result: **eligible for connector-scoped native
Windows x64 implementation**. Product status remains **preview / not yet
certified** until the packaged and interactive official-client gates pass.

This gate requires the upstream desktop client, configuration, hook transport,
and enforcement response to run as direct Windows processes with Windows
paths. WSL, Docker, a VM, Bash, Git Bash, Cygwin, and MSYS are not qualifying
paths and are not used by the implementation.

## Authoritative official sources

The former Windsurf URLs redirect to the current Devin Desktop documentation.
Both sides are recorded so later reviewers can distinguish an authoritative
vendor rename from an unrelated mirror.

| Evidence | Former URL | Authoritative destination | Version/date observed | Finding |
| --- | --- | --- | --- | --- |
| Native download | `https://windsurf.com/download` | `https://devin.ai/download` | checked 2026-07-30 | Native Windows x64 and arm64 downloads; minimum Windows 10 64-bit. The page states Devin Desktop is the new name for Windsurf and the OTA update retains settings and extensions. DefenseClaw certifies x64 only. |
| Install/uninstall and native paths | `https://docs.windsurf.com/windsurf/getting-started` | `https://docs.devin.ai/desktop/getting-started` | checked 2026-07-30 | Desktop IDE supports Windows. Official Windows install roots include `C:\Program Files\Windsurf` and `%LOCALAPPDATA%\Programs\Windsurf`; official user configuration is `%USERPROFILE%\.codeium\windsurf`. |
| Cascade hooks | `https://docs.windsurf.com/windsurf/cascade/hooks` | `https://docs.devin.ai/desktop/cascade/hooks` | checked 2026-07-30 | Native Windows hook transport, schema, event matrix, JSON/stdin, output streams, exit behavior, merge order, and limitations described below. |
| Release history | `https://windsurf.com/changelog` | `https://docs.devin.ai/desktop/changelog` | current **3.6.22, 2026-07-29** | Hooks introduced in **1.12.31, 2025-11-13**. User-prompt hooks added in **1.12.41, 2025-12-10**, the DefenseClaw minimum. **3.5.17, 2026-07-17** fixed the Windows updater and added Windsurf-to-Devin hook migration. **3.6.21, 2026-07-29** states hooks do not load or run in Restricted Mode. |
| Release archive | — | `https://docs.devin.ai/desktop/releases` | checked 2026-07-30 | Official downloadable desktop release inventory. |

## Native hook contract

Cascade merges hook files in system → user → workspace order:

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

The evidence proves an eligible fully native path: native Windows desktop process →
documented `powershell -Command` hook → generated `windsurf-hook.ps1` →
exact packaged `defenseclaw-hook.exe`. The adapter copies JSON stdin and child
stdout/stderr, waits for the child, and propagates its exact exit status,
including `2`.

DefenseClaw fail-closed availability maps its own missing/timeout/invalid
runtime failures to exit `2`. This does not broaden vendor semantics:

- only the five official pre-hooks can block;
- arbitrary non-`2` hook failures fail open;
- post hooks never block and Cascade response hooks are asynchronous;
- Restricted Mode disables all hooks;
- Windsurf exposes no hook-native ask/resume surface;
- hooks run with the user's permissions and can see sensitive prompt, code,
  command, MCP, response, and transcript data;
- system-level hooks require administrator-controlled deployment and are not
  installed by the per-user DefenseClaw package.

Official-client validation requires an interactive native Windows desktop
runner. A CLI, WSL, or shell substitute is not accepted as client evidence.
Until that gate and the packaged Windows matrix pass in the integrated branch,
the connector must not be described as release-certified.
