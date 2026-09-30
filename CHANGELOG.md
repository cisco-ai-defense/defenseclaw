# DefenseClaw Changelog

This file preserves development rollups and historical change notes. It is not
a complete published-release index: the release workflow stamps isolated build
checkouts, so repository source metadata and headings can lag published tags.
Use [GitHub Releases](https://github.com/cisco-ai-defense/defenseclaw/releases)
for released versions and assets, and the
[documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/)
for current behavior.

## [1.0.0] — Release-owned upgrades

1.0 replaces the 0.x upgrade system. `defenseclaw upgrade` now downloads the
latest release's installer, checks it against that release's `checksums.txt`,
and runs it, so the upgrade logic always ships with the version being
installed and a broken upgrade is fixed by the next release. See
[Upgrade DefenseClaw](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/).

### Upgrading from 0.x

Configuration and data are kept on every path.

| Installed | Run |
| --- | --- |
| 0.8.8–0.8.10 on macOS or Linux | `defenseclaw upgrade --yes` |
| 0.8.7 or older on macOS or Linux | `curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh \| bash` |
| Any 0.x on Windows | `irm https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.ps1 \| iex` |
| The 0.8.x macOS app | Download the 1.0 DMG once |

`defenseclaw upgrade` on 0.8.7 and older, and on Windows, stops with messages
such as `missing release-provenance.json; refusing before services are
stopped`. Nothing is changed; use the install command above.

### Breaking changes

- `install.sh` and `install.ps1` install, upgrade, repair and roll back the
  same way on every platform. Each run keeps the replaced install in
  `~/.defenseclaw/previous` and restores it automatically if the upgrade, the
  migration or the gateway's health check fails. `defenseclaw rollback` swaps
  back on demand.
- Windows installs directly with `install.ps1` into `%USERPROFILE%\.local\bin`
  and `%USERPROFILE%\.defenseclaw`; `DefenseClawSetup-x64.exe` is no longer
  published. The installer removes a 0.8.x native Setup installation and keeps
  its files in `previous\legacy-setup`. The enterprise Setup is unchanged.
- The macOS app no longer embeds a runtime. Install and Update run the release
  `install.sh`, which also replaces the app bundle.
- `defenseclaw migrate` replaces `defenseclaw migrations`. Config changes are
  ordered steps keyed on `config_version`; the 0.x migrations remain as a
  one-time import.
- Release assets use flat names (`defenseclaw-<v>-<os>-<arch>.tar.gz|zip`,
  `defenseclaw-<v>-py3-none-any.whl`, `defenseclaw-<v>-requirements.txt`).
  The plugin tarball, `upgrade-manifest.json`, release provenance, rescue
  scripts, wrapped artifacts, and the Intel macOS and Windows arm64 builds are
  gone.
- Python dependencies install from the hash-pinned requirements asset;
  upgrades never resolve live from PyPI.
- Signature checking: every asset is checked against `checksums.txt`, and the
  Sigstore signature on `checksums.txt` is verified when `cosign` 2.x is
  installed. Releases no longer download a pinned cosign.
- The OpenClaw gateway is restarted only when the OpenClaw connector is active.

### Added

- A once-a-day, TTY-only "new release available" notice in the CLI and TUI.
  Turn it off with `DEFENSECLAW_NO_UPDATE_CHECK=1` or `update_check: false`.

## [Unreleased] — Enterprise hardening

Entries that name the enterprise standalone profile apply only there; the
rest also reach per-user installs.

### Fixed

- **Re-running `defenseclaw setup <connector>` keeps its mode.** `--mode`
  defaulted to observe, so `defenseclaw setup opencode --yes`, which doctor
  recommends to repair the OpenCode plugin, turned an action install into
  observe without a prompt or a warning. Without `--mode`, a connector that
  is already configured keeps its mode; a new one still starts in observe.
- **Per-user AI discovery on macOS no longer reads `partial` with no
  cause.** The package manifest scan counted each folder macOS privacy
  protection keeps from the guardian's per-user worker (such as `~/.Trash`)
  as an error, and only the process and model file scans named themselves,
  so every scan ended `partial scan: `. That scan now skips those folders as
  the model file scan does, and every failing scan is named.
- **Kiro's hook file goes when its version key is gone.** Teardown still
  left `~/.kiro/hooks/defenseclaw.json` as an empty `{"hooks": []}` when the
  file had lost its `version` key (as `uninstall --purge` on macOS found in
  every Kiro-enrolled home): the ownership check read the missing key as
  `<nil>`. A file with nothing but DefenseClaw's hooks is removed with or
  without the key.
- **Windows status and verify say how to recover a pending transaction.**
  On the enterprise standalone profile, `status` showed only `not_ready`
  and the installed version, and `verify` said `run Repair`, which cannot
  recover it from an administrator shell. Both now say a transaction is
  pending and name the Setup `/ensure` command to run as LocalSystem, as a
  failed Setup does.
- **A Windows install that fails on a held API port names the holder.** On
  the enterprise standalone profile, a first install whose gateway could not
  bind `127.0.0.1:18970` reported only `enterprise readiness timed out:
  broker_ready=True gateway_ready=False ...`, and `status` could not run on
  the rolled-back computer. The result now carries `api_port_held` and
  `api_port_holders[]` with the PID, image and account of each holder.
- **Setup `/verify` says what a failure means.** A per-user Windows Setup
  whose payload or signature was changed failed `/verify` with internal text
  such as `zip: checksum error`. The message now says the file is not the
  published Setup, not to run it, and to download it again and compare its
  SHA-256 with the Sigstore-verified `checksums.txt`.
- **`defenseclaw setup` answers on a managed Windows computer.** The
  enterprise standalone payload has no per-user CLI, so
  `defenseclaw setup rotate-token` printed `unknown command "setup"` and
  suggested `stop`. It now says the computer is managed and per-user setup
  commands are not available. Other computers are unchanged.
- **`uninstall --all --binaries` ends cleanly, and its plan lists only
  what is there.** After removing everything, the command printed a
  `ModuleNotFoundError` traceback and exited 1, because the update notice
  it runs at exit had just been removed. The plan also listed launchers
  that were never installed. `defenseclaw version` before `init` shows the
  OpenClaw plugin as `(not used)` instead of `missing`.
- **Doctor names more of what it finds on Linux.** A `Sidecar API` row no
  longer passes when the process answering on the API port is not your
  verified gateway; it warns and, on Linux, names the account holding the
  port. An OpenCode plugin folder that other accounts can write (Ubuntu's
  umask 002 leaves `~/.config/opencode/plugins` at 0775), which stops the
  gateway, is named with the `chmod go-w` fix instead of `hook file not
  found`; `defenseclaw init` names it too, with the same fix as its next
  step, instead of suggesting `setup opencode`. `doctor --fix` no longer
  warns "watchdog runtime - repair is
  unavailable on platform 'linux'" on every run, the skill-scanner version
  check allows 30 seconds for a first run after install, and the OpenCode
  row mentions the Windows DACL only on Windows.
- **`defenseclaw setup opencode` finishes when OpenCode is closed.** Setup
  waited for OpenCode to report that it loaded the managed plugin after the
  gateway restart. A closed OpenCode cannot report and an open one does not
  report again, so on Linux every run failed after about two minutes with
  `connector setup did not converge` and rolled back, which also undid the
  requested mode. Setup now waits 10 seconds for the report, then finishes
  with the plugin current and tells you to restart open OpenCode sessions.
- **Config and rule-pack checks no longer run a gateway binary another
  account can replace.** Doctor, `config validate` and the observability
  and redaction commands run `defenseclaw-gateway config-v8` and
  `rulepack validate` to check the config and rule packs. On Linux and
  macOS a `defenseclaw-gateway` found on `PATH` or in `~/.local/bin` now
  needs the custody the gateway lifecycle already required (held by root or
  this account, no group- or world-writable file or parent folder); before,
  a binary in a folder any account could write was run five times per
  `doctor --fix`. `DEFENSECLAW_GATEWAY_BIN` is used as it is. The doctor
  repair names such a binary instead of reporting `binary not found`.
- **Doctor's own audit record no longer goes to another account's
  listener.** Doctor's checks refused to send the gateway token to a process
  that is not the verified gateway, but the action record it writes at the
  end still did: with another account's process on the API port, that
  process received the token on every `defenseclaw doctor` run. The record
  now goes only over a connection the verified gateway accepted, and is
  skipped otherwise.
- **`rotate-credentials` says what it did.** On the enterprise standalone
  profile on Linux and macOS, a successful rotation printed only `done`. It
  now lists the committed and the previous key by SHA-256 prefix, how many
  targets and users moved, and the reminder to restart running agents. It
  refuses at once when the gateway service is not running, instead of after
  90 seconds of silence, and an interrupted run prints the `reconcile`
  command that completes or rolls back the rotation.
- **A config change on macOS no longer leaves the gateway unloaded.** On the
  enterprise standalone profile, launchd could still be stopping the gateway
  when the lifecycle started it again; the start and its restart fallback
  failed with exit 37, the rollback failed the same way, and hooks failed
  closed until `enterprise macos repair`. The lifecycle now waits for
  launchd to remove the job before starting it again.
- **audit.db no longer corrupts beside a long-running CLI or TUI.** Opening
  the audit store fixed its permissions by opening and closing audit.db,
  which drops the process's SQLite lock. A CLI command that closed while the
  gateway was stopped then deleted the WAL under the TUI or another open
  command, and their later writes failed with "database disk image is
  malformed" or corrupted the file. The permission fix now runs before
  SQLite opens the file, and only while no other audit store in the same
  process has it open. The gateway also checks audit.db when it starts: a
  corrupt store is moved to `audit.db.corrupt-<time>` with its WAL and SHM
  files, the block/allow list is copied into a new store, and the gateway
  starts and logs a warning instead of failing. It refuses to move a store
  another process still has open.
- **Findings keep the ids of the shipped rules.** A finding from a bundled
  rule tagged `credential` (for example `PATH-AWS-CREDS`, `C2-METADATA-AWS`
  or `exfil.secret_read_and_egress_oneliner`) was stored and exported as
  `redacted.secret.id-…`, so the findings dashboards and `rule_id` filters
  could not name it. Every rule id in the default, strict and permissive
  packs is now kept; ids that only a custom pack defines are still keyed.
- **Finding and scan rows name the user.** `finding.observed` and the
  `scan.*` records now carry `user.id`, `defenseclaw.user.id_kind` and
  `defenseclaw.user.name` for the caller whose request was inspected, the
  same identity the `hook_decision` rows carry, so findings can be filtered
  by user without joining on `evaluation_id`. On the enterprise standalone
  profile only the verified caller is recorded.
- **Guardrail blocks show on spans.** A tool call a hook blocks now gets a
  tool span that ends at the decision with status `ERROR`; before, a blocked
  call left no span. Blocked, confirmed and alerted calls carry a
  `defenseclaw.guardrail.block`, `.ask` or `.alert` span event (rule,
  severity, connector, user, redacted reason) and the
  `defenseclaw.guardrail.action`, `defenseclaw.guardrail.rule_id` and
  `defenseclaw.guardrail.severity` attributes, on every trace destination
  including Galileo. Other hook decisions, such as a blocked prompt, and the
  `/api/v1/inspect/*` routes produce an `apply_guardrail` span with the same
  status, event and attributes; that span no longer reports `OK` for a block.
- **Local observability dashboards show the findings and blocks that
  happened.** The Findings tiles, top rule and per-rule activity panel count
  `finding.observed` records in Loki, because a Prometheus counter misses a
  rule's first finding; the per-rule panel no longer fails with
  `Cannot read properties of undefined (reading 'config')` on an empty
  range, and the top rule and top target tiles show the name instead of
  `Value #A`. The Blocked events **Hook surface** filter lists the hook
  surfaces the panels filter on, the recent guardrail event panels include
  `hook_decision` records, Agent360 opens on one agent instead of an **All**
  that matched nothing once two agents existed, and the AI runtime tiles and
  discovery error rate show data. The local observability guide explains
  when to set `observability.metric_policy.temporality: cumulative`.
- **OpenCode newer than 1.18.19 is supported.** OpenCode updates itself, and
  setup refused 1.18.20 and later with `detected-but-unsupported-version`, so
  enterprise deployments reported it unprotected. The reviewed range is now
  `>=1.18.10,<1.19.0`, checked against OpenCode 1.18.33.
- **The gateway reports the OpenClaw fleet client off when OpenClaw is not
  installed.** OpenClaw is the default connector, so an install without
  OpenClaw dialed `127.0.0.1:18789` without end and showed the gateway as
  reconnecting. When agent discovery found no OpenClaw and `gateway.host` is a
  loopback address, the gateway reports it disabled with "OpenClaw is not
  installed", and doctor expects that. Any other `gateway.host`, or
  `gateway.fleet_mode: enabled`, still dials.
- **`defenseclaw version` skips the OpenClaw plugin when OpenClaw is not
  configured.** On installs of other connectors the plugin row read
  `(not installed)` and `missing`, and a plugin left from an earlier OpenClaw
  setup counted as drift. The row now reads `(not used)` and `skipped`.
- **Disabling Kiro leaves an inert hook script.** Teardown replaces
  `~/.defenseclaw/hooks/kiro-hook.sh` with a stub that exits 0, as the
  Claude Code, Codex and Hermes teardowns do. A Kiro session that cached
  the path stops posting to the gateway until it restarts; setup writes
  the active script again.
- **Galileo shows guardrail decisions.** Galileo ignores the OTLP span
  status and custom attributes, so a blocked tool call appeared there with
  status code `0` and no rule. The Galileo preset now also sends the decision
  (action, rule, severity, user and `status: ERROR` for a block) as the
  OpenInference `metadata` attribute, which Galileo shows as the span's
  metadata.
- **Blocked spans keep the rule title.** The status message and block event
  of a blocked span showed a shipped rule's title as a redacted token
  (`matched: <RULE-ID>:<redacted ...>`). A reason made only of shipped rule
  IDs and their catalog titles is now kept as written; other reasons are
  still scrubbed.
- **AI discovery records name the user.** The `ai_component.discovered`,
  `changed` and `removed` records carry `user.id`,
  `defenseclaw.user.id_kind` and `defenseclaw.user.name` when the signal
  came from a user's scan, and the AI discovery dashboard's event log shows
  the user.
- **Amp traces are named after Amp.** Amp turns were named after the
  agent mode or definition kind (`invoke_agent medium`,
  `invoke_agent agent-definition`), so a search for Amp traces found none.
  They are now `invoke_agent amp`; the mode or custom agent stays in
  `gen_ai.agent.name`.
- **Amp keeps DefenseClaw's prompt notice apart from the prompt.** The
  hidden notice DefenseClaw adds when a prompt matches a rule followed the
  prompt text directly, so a prompt ending in a command could be read, and
  run, as that command with the notice's words appended. The notice now
  starts on its own lines and says it is not part of the request.
  In action mode it also no longer says DefenseClaw "would block this in
  action mode": it says the request matched a blocking rule and must not be
  carried out.
- **Amp shell commands get the same rule checks as Claude Code and Codex.**
  Amp's Bash tool sends its command as `cmd`, which the command analysis did
  not read, so every Amp command was judged only by the text-pattern
  fallback. A command that blocks in Claude Code or Codex could then run in
  Amp with a detection-only finding, for example one that writes its output
  to `~/out.txt`. Amp commands are now analyzed like the other agents'.
- **AI discovery on macOS skips the folders macOS protects.** Without Full
  Disk Access, every model file scan counted each folder macOS privacy
  protection keeps it out of (for example other apps' containers under
  `~/Library/Containers`) as a filesystem error and reported the scan as
  `partial`. Those folders are now skipped, as the macOS guide says.
- **Disabling Kiro removes DefenseClaw's hook file.** When
  `~/.kiro/hooks/defenseclaw.json` had changed since setup, teardown removed
  DefenseClaw's hooks but left the file behind as `{"hooks": []}`. A file that
  holds nothing else once those hooks are out is now removed.
- **OpenHands tool calls are inspected.** OpenHands sends PascalCase
  `event_type` values (`PreToolUse`) that DefenseClaw did not route, so
  terminal calls ran uninspected even in action mode. OpenHands payloads now
  have their own decoder, so terminal commands can be blocked.
- **Antigravity `run_command` calls match command rules.** The scheduling
  and UI arguments Antigravity sends beside the command
  (`WaitMsBeforeAsync`, `toolAction` and others) left it unproven.
  DefenseClaw now drops them when each has its expected type.
- **An upgrade whose only connector was removed stops before the swap.**
  When no configured connector ships in the new release, `defenseclaw
  migrate --check` fails before anything is replaced, names the connector
  and prints commands the installed release accepts.
- **A command rule still blocks a write to a `~/` or `$HOME/` path.** A
  redirect target the shell expands (`> ~/out.txt`) made the parse partial,
  so a CRITICAL CEL match was only detected. CEL rules that cannot depend on
  that redirect now see the command with a static target. A built-in rule's
  code check must hold with and without that target (#925).
- **Writes to `~/.ssh/authorized_keys` block in every spelling.** The
  shell expands `~/` and `$HOME/` when the command runs, so
  `>> ~/.ssh/authorized_keys`, `>> "$HOME/.ssh/authorized_keys"` and
  `tee -a ~/.ssh/authorized_keys` were allowed with no finding while the
  absolute path blocked. The authorized-keys rule now also checks the command
  with those paths resolved under the caller's home.
- **A command rule blocks every command of an `&&` or `||` list.** Any list
  made the parse partial, so a rule that blocks `<cmd>` only detected
  `cd <dir> && <cmd>` or `<cmd> || true`. A list is now judged as if all of
  its commands run: if a rule blocks any of them, the whole tool call is
  blocked (#923).
- **Agents say that DefenseClaw policy made a block.** Rule verdicts reached
  the agent as `matched: <RULE-ID>:<redacted ...>`. They now say
  `DefenseClaw policy blocked this action (rule <RULE-ID>)` and not to retry
  it in another form; the audit keeps the full reason.
- **OpenCode shows DefenseClaw blocks.** A blocked call failed with the bare
  reason or no text, so the model reported success. The plugin now fails it
  with an error that names DefenseClaw and shows an error notice; a confirm
  verdict runs with a warning notice.
- **A confirmation the agent cannot ask about names the rule.** On a hook
  that cannot ask, such as OpenCode's, a confirm verdict runs as an alert
  whose reason read `matched: <RULE-ID>:...`. It now says DefenseClaw policy
  flagged the action for review (rule <RULE-ID>), and OpenCode's notice
  starts with it. The Secure Client wording is unchanged.
- **OpenCode and Amp say to restart after a failed start-up check.** When
  the plugin's load-time check for unapproved plugins fails, its blocks say
  so and ask the user to restart the agent once DefenseClaw is available.
- **OpenCode and Amp explain a block for an unapproved plugin.** The message
  started with the internal code `enterprise_foreign_hook_blocked:`. It now
  starts with what DefenseClaw did, and the audit keeps the code. When Amp
  stops a turn for such a plugin, the message also stays in the thread
  instead of only in a notice that fades after a few seconds.
- **`defenseclaw doctor` passes a global Kiro install.** `Connector scope
  [kiro]` failed every install without `claw.workspace_dir`. It now passes
  when the global `~/.kiro/hooks/defenseclaw.json`, which recent Kiro builds
  read, holds DefenseClaw's hooks.
- **Devin on macOS after the config folder moved.** Setup writes
  `~/.config/devin/config.json`, which the Devin CLI reads, and closes the
  old `~/Library/Application Support/devin` target first instead of failing
  with "managed backup target mismatch".
- **Kiro teardown finds the agent it hooked.** Teardown and VerifyClean also
  clean the default agent named in the settings backup, even after the user
  changed `chat.defaultAgent`. An agent name with `/`, `\`, `.` or `..` is
  no longer resolved to a file.
- **The `windsurf` to `devin` rename reaches every setting.**
  `connector_hooks`, the judge and `application_protection` lists,
  `asset_policy` rules and observability selectors kept the retired ID; the
  loaders and `migrate` now rename them.
- **`defenseclaw migrate` survives a plugin manifest that is not UTF-8.** A
  Latin-1 `plugin.yaml` raised `UnicodeDecodeError` through `migrate` and
  `setup remove`; such a manifest now declares only its directory name, as
  in the gateway.
- **`defenseclaw migrate` keeps plugin connectors.** While `plugin_dir`
  holds a plugin the gateway could load, `migrate` drops no connector name,
  and the upgrade preflight asks the staged gateway whether it knows a name
  before it keeps it.
- **The gateway reads the custom-providers overlay from its data
  directory.** It now reads `DEFENSECLAW_CUSTOM_PROVIDERS_PATH`, then
  `$DEFENSECLAW_HOME/custom-providers.json`, then `~/.defenseclaw`, and
  skips a missing overlay quietly.
- **`defenseclaw-gateway status` no longer shows a disabled connector as
  enforced.** A connector with `enabled: false` now reads `Status: disabled,
  not enforced` under Connector Mode.
- **No sonic warning on stderr.** Binaries built with Go 1.27 printed
  `WARNING: sonic/ast only supports ...` on every run, which agents also
  showed as the hook-error text. The sonic dependency now supports Go 1.27.
- **`defenseclaw uninstall` works on a host with a managed deployment.** It
  stopped at its gateway-stop phase, because `stop` refuses there. A
  per-user install left over from before the managed deployment is now
  removed.
- **A Windows purge removes each account's DefenseClaw folder (enterprise
  standalone).** Setup `/uninstall PURGE=1` and `uninstall --purge`, run as
  LocalSystem, now remove each enrolled account's `%USERPROFILE%\.defenseclaw`,
  including its per-user hook tokens, whether or not the account is signed
  in. As on Linux and macOS, only the inert hook stubs a running agent may
  still call and the account's own hooks the foreign-hook policy moved aside
  stay. The `per_user_state_remaining` warning names each folder the purge
  could not remove, with the reason.
- **Amp's `async_shell_command` is inspected like its bash tool.** Commands
  an Amp release ran through `async_shell_command` got no command facts, so
  a rule that needs them was recorded but did not block.
- **Kiro CLI 2.x runs DefenseClaw's tool hooks.** The `defenseclaw` agent
  used the matcher `.*`, which kiro-cli 2.x never matches, so its tool hooks
  never ran. It now uses `*`, and an agent with the old matcher fails
  verification and is rewritten.
- **Kiro shell calls get command facts.** The `__tool_use_purpose` note
  (2.x) and the unset `cwd`, `description` and `timeout` (v3) left every Kiro
  command partly parsed, so a command rule was only detected. They are now
  dropped from the analyzed copy.
- **Audit rows name the account for per-user connector hooks.** Rejected
  connector-hook and inspect-tool rows now carry `user.id` and
  `defenseclaw.user.name` when the caller is known, like hook decision rows.
- **Kiro on native Windows blocks again.** The hook binary rejected
  `--hook-surface` and exited 1, which Kiro lets through. It now accepts the
  flag, and the Kiro commands use a PowerShell bridge that returns exit 2;
  `defenseclaw setup kiro` replaces the old entries.
- **Enterprise (standalone) Kiro follows kiro-cli self-updates.** The Linux
  and macOS guardian refused every repair after a kiro-cli update. It now
  follows updates at or above 2.24.1, the certified minimum, and in action
  mode refuses to enroll a new user below it.
- **A named pipe in place of an agent's hook config no longer hangs.**
  Setup, verify and the enterprise guardian's per-user worker waited for a
  writer (`worker for uid N timed out`). The read now fails at once with
  `<path> is a named pipe, not a regular file`.
- **Disabling Kiro keeps the user's CLI settings.** Teardown put back the
  `~/.kiro/settings/cli.json` captured at enrollment, which dropped the keys
  added since. It now removes only DefenseClaw's `chat.defaultAgent` and puts
  back the user's earlier value.
- **Disabling Hermes keeps the rest of `config.yaml`.** Teardown rewrote the
  file without its comments, and approvals in a file put back from an
  earlier enrollment stayed in `shell-hooks-allowlist.json`. It now rewrites
  only the `hooks` mapping, keeping every byte outside it, and removes all of
  DefenseClaw's approvals.
- **Disabling Devin no longer puts DefenseClaw's earlier hooks back.** A
  Devin backup captured while the config already held DefenseClaw's
  `devin-hook.sh` hooks restored them at teardown. Teardown now removes
  DefenseClaw's hooks from the restored config.
- **`defenseclaw doctor` sends the gateway token only to the gateway it
  checked.** Doctor verified which process owned the API port, then opened a
  new connection for its authenticated requests, so a process that took the
  port over in between could receive the token. Doctor now requires the
  verified gateway process to have accepted that same connection before it
  writes the request, and otherwise reports `the connected gateway endpoint is
  not served by the verified gateway process`. The Codex telemetry runtime
  check, which sent the token without checking the listener, does the same.
- **Doctor and setup run the gateway controller they checked.** Starting,
  restarting and stopping the gateway ran `defenseclaw-gateway` by path after
  checking who can write it, so the path could name another file by the time
  it ran. Linux now runs the checked file itself, Windows keeps it locked
  against replacement until the command finishes, and macOS stops the launch if
  the file or a directory above it changed. The Windows Cursor runtime probe
  does the same for PowerShell, and the Windows watchdog repair uses the
  verified gateway executable instead of the first one on `PATH`.
- **A failed first Windows standalone install rolls back accounts with
  per-user agents.** For an account whose `%USERPROFILE%\.defenseclaw` the
  install created, rollback refused the whole plan when the account had an
  Amp, Antigravity, Copilot, Devin, Hermes or OpenCode row, and left the
  folder behind. Each of these connectors now has a bounded list of the
  files its managed install writes there (runtime sidecars, hook scripts,
  scoped tokens, runtime generations, the executable selection and its own
  config backup records), and rollback removes exactly those; any other
  file, such as the backups of displaced user hooks, still keeps the folder.
  Stale OpenCode runtime generations are now also cleaned up (#927).
- **Windows standalone status names the process holding the gateway API
  port.** While another process listened on `127.0.0.1:18970` (or another
  account's wildcard listener made Windows refuse the gateway's bind),
  `enterprise windows status` and `verify` reported only `not_ready`. They
  now report `api_port_held` with each holder's PID, image and account (or
  that this account cannot identify it), list them in `api_port_holders`
  in `--json`, and say that the gateway takes the port back by itself once
  it is free, as on Linux and macOS (#929).
- **Windows Setup `/verify` accepts an authentic unsigned build.** `/verify`
  required a Cisco Authenticode signature even when the Setup's own manifest
  records an unsigned release, so the documented check failed for every
  unsigned Setup. It now checks the embedded payload against its manifest,
  requires the signing state that manifest records, and for an unsigned
  build prints its SHA-256 to compare with the release's Sigstore-verified
  `checksums.txt`. It fails only for a changed payload, a stripped signature
  or an unexpected one. The Windows install page says how to authenticate a
  0.8.x Setup whose `/verify` still reports the missing signature (#919).
- **The Windows guardian restores the managed OpenCode plugin right after a
  change to its attributes.** OpenCode's runtime needs the write-attributes
  right to load a plugin, and with it a standard account could make the
  plugin unreadable (read-only or a reparse point), so every account's
  OpenCode ran without DefenseClaw until the next pass, about a minute. The
  guardian now watches the plugin's folder and runs the same heal within
  about a second and logs a tamper line. After 12 restores in a minute it
  slows to one restore every 5 seconds, so repeated changes cannot keep the
  plugin unreadable until the next pass, which stays the backstop (#930).

### Added

- **Per-user credential rotation (enterprise standalone, Linux and macOS).**
  `defenseclaw-gateway enterprise linux|macos rotate-credentials` replaces
  the key every enrolled user's per-user credentials derive from.
  The gateway accepts the old and the new key while the guardian moves and
  verifies every user; the new key takes effect only then, and any failure
  moves every user back to the old key. Agents already running lose
  telemetry until they restart. On Windows the command refuses (exit
  `1639`); see the enterprise operations guide.
- **`defenseclaw-gateway audit export --since`, `--until` and `--newest`.**
  `--since` and `--until` take an RFC3339 time or a duration ago (`30m`,
  `2h`). With `--limit N`, `--newest` keeps the N most recent rows; output
  stays oldest first.
- **`defenseclaw-sensor-helper --version`.** The helper (shipped only in the
  enterprise archive and packages) reports its version and commit.
- **Claude Code version floor (enterprise standalone).** DefenseClaw sets
  `requiredMinimumVersion` to 2.1.154 in its own `managed-settings.d`
  drop-in. An administrator's value wins; `enterprise policy show|verify`
  report the floor, and `connectors.claudecode.version_floor` controls it.
  Claude Code reads the setting only from 2.1.163, so this floor stops no
  build older than that
  ([#920](https://github.com/cisco-ai-defense/defenseclaw/issues/920)).

### Changed

- **`defenseclaw setup rotate-token` on a managed computer.** Where the
  organization manages DefenseClaw (the standalone profile), the command
  now refuses before changing anything and names the administrator's
  rotation command, instead of failing when it tried to stop the per-user
  gateway. Other computers, Secure Client ones included, are unchanged.
- **Windows standalone lifecycle events go to a `DefenseClaw` event log
  that only administrators can write.** Any account can write
  Application-log entries under any source name, so entries under
  `DefenseClaw Enterprise` could be forged. Events 100 to 150 now go to the
  `DefenseClaw` log (source `DefenseClaw Lifecycle`), which only LocalSystem
  and Administrators can write and the Application log's readers can read;
  each run that writes an event registers it and a successful uninstall
  unregisters it. The Application-log copies continue in this release as legacy: move
  MDM detection rules and SIEM forwarding that query the Application log by
  source to the `DefenseClaw` log before a later release drops them.
  `enterprise windows events` now checks the new log, and `--application`
  the legacy copies. The lifecycle log line's `event.logs` names the logs
  that took each event (#928).
- **Plugin teardown without a backup receipt.** Removing the OpenCode or Amp
  connector (or uninstalling) deletes DefenseClaw's plugin file when its
  backup receipt is missing, as long as the file still starts with the
  `// defenseclaw-managed-plugin` marker.
- **An empty Copilot hooks file is deleted.** Teardown removes
  `<hooks>/defenseclaw.json` when nothing but its schema version is left,
  instead of rewriting it; handlers you added to it are kept.
- **Teardown no longer creates missing files.** Removing the Cursor,
  Copilot, OpenHands, Antigravity, Devin or Hermes connector for a user who
  has no config file there leaves it absent. The Cursor change also applies
  to the Secure Client profile.
- **Enterprise Kiro route.** `enterprise policy show|verify` reports Kiro as
  `per_user` on Linux and macOS, where the guardian enrolls it. A managed
  install writes each user's global Kiro hooks and the CLI 2.x `defenseclaw`
  agent only. Windows keeps `acp`.

## [Unreleased] — Hook collector unification

This rollup unifies the agent hook collector across all 8 hook-first
connectors (codex, claudecode, hermes, cursor, devin, antigravity,
copilot, openhands) onto a single declarative `HookProfile`-driven pipeline.
There are **no new environment variables** — the unification is the
default and only path; the V1 OTLP builders and the per-phase
feature flags that existed in early review iterations have been
deleted.

### Renamed and removed connectors

- **Windsurf → Devin.** Windsurf is now Devin Desktop (Cognition). The
  `windsurf` connector is gone; the `devin` connector covers Devin CLI and
  Devin Desktop's default Devin Local agent, which share one hook config.
  Configs and DefenseClaw-installed hooks move to `devin` automatically on
  `defenseclaw upgrade`, on gateway restart, or on `defenseclaw setup devin`:
  `windsurf` in `guardrail.connector`, `claw.mode`, and every per-connector
  block (`guardrail`, `asset_policy`, `application_protection`, and
  `observability` `connectors`) becomes `devin` (an existing `devin` block
  wins), the gateway
  removes only DefenseClaw's own entries from `~/.codeium/windsurf/hooks.json`,
  deletes `windsurf-hook.sh`/`.ps1` and `connector_backups/windsurf/`, clears
  the old ID from the lock and active-connector state, and logs one line
  describing the move. Devin inventory also reads the pre-rename Devin Desktop
  rule and skill locations the vendor still loads. Devin CLI and Devin Local
  are protected; conversations in Devin Desktop's legacy Cascade agent are not.
- **Gemini CLI removed.** Use the Antigravity connector instead.
  `defenseclaw upgrade` removes `geminicli` from `config.yaml` when another
  connector is configured. When it was the only one, the upgrade's preflight
  (`defenseclaw migrate --check`) stops before anything changes and names
  the command to run on the installed release. On its next start the gateway drops `geminicli` from its lock
  and active-connector state and deletes DefenseClaw's
  `hooks/geminicli-hook.sh`/`.ps1` and `hooks/.otlp-geminicli.token`; Gemini CLI
  then treats the missing hook as a non-blocking error. DefenseClaw never edits
  `~/.gemini`; clean it up once by hand, then set up Antigravity:
  1. Only if Gemini CLI was the only connector, or the package was replaced
     without `defenseclaw upgrade`: run `defenseclaw setup remove geminicli
     --yes --force` (the 0.8.x release still installed after a stopped
     upgrade refuses to remove the last connector without `--force`), set up
     another connector first, or delete `geminicli` from
     `guardrail.connectors` / `guardrail.connector` in
     `~/.defenseclaw/config.yaml`; then run the upgrade again.
  2. In `~/.gemini/settings.json` (or `$GEMINI_CLI_HOME/.gemini/settings.json`;
     on Windows `%USERPROFILE%\.gemini\settings.json`), under `hooks`, for each
     of `SessionStart`, `SessionEnd`, `BeforeAgent`, `AfterAgent`,
     `BeforeModel`, `AfterModel`, `BeforeToolSelection`, `BeforeTool`,
     `AfterTool`, `PreCompress`, and `Notification`, delete every group whose
     `hooks[]` has `"name": "defenseclaw"`. Remove any event key left empty.
  3. If `telemetry.otlpEndpoint` contains `/otlp/geminicli/`, delete the
     `telemetry` object or restore your own values.
  4. Do not touch `~/.gemini/config/` (Antigravity).
  5. Delete `~/.defenseclaw/connector_backups/geminicli/` (and the hook script
     and token above if they are still there).
  6. Run `defenseclaw-gateway restart`.
  7. Run `defenseclaw setup antigravity` (or set up any other connector).

  Until the gateway restarts after `geminicli` has left `config.yaml`, the old
  hook script still calls a removed endpoint; if it was installed with
  `guardrail.hook_fail_mode: closed`, every Gemini CLI action is blocked. The
  telemetry schemas no longer accept `geminicli`, so rows an older release
  exported with that value do not validate on re-export.
- **Connectors a build no longer ships no longer block boot.** A lock-only or
  previously active connector that no built-in connector or plugin provides
  now has its DefenseClaw lock state, hook scripts, and OTLP token dropped
  (with a WARN and an audit event); agent config files are never edited. When
  plugin discovery fails, unresolved names are kept and retried instead.
  `defenseclaw migrate` (which the installer runs on upgrade) removes such
  names from `config.yaml` when another connector remains. An unknown `guardrail.connector` still fails boot and
  points at the upgrade notes. `defenseclaw setup remove` and
  `defenseclaw uninstall` handle such names without aborting, and
  `setup remove` does not require `--force` when such a name is the last
  connector.
- **Native Windows state from pre-release builds.** Setup and the uninstaller
  accept install state from pre-release native builds that selected Windsurf;
  repair and upgrade move the selection to `devin`. Native Windows installs
  made from pre-release main builds that selected Gemini CLI must be
  uninstalled with their original build before installing this release.
- **Devin on macOS.** Devin hooks are registered in `~/.config/devin/config.json`
  (or `$XDG_CONFIG_HOME/devin`) on macOS, where the Devin CLI reads them,
  instead of `~/Library/Application Support/devin`.

### Observability v8

- Defaults an omitted `observability.local.retention_days` to a rolling seven-day
  local SQLite window. The startup-and-six-hour reaper applies that UTC cutoff
  in dependency order; it drains expired or bounded guardrail-chain dependencies
  before eligible unreferenced `correlation_events`, while preserving active
  cursors, pending operations, unexpired receipts, and their graph anchors.
  Explicit values still win,
  including `0` for unbounded retention. Deleted pages remain reusable by
  SQLite, but the database file does not shrink automatically;
  the separate OPA `audit.retention_days` policy is unchanged. This changes the
  prior omitted default from 90 days: an existing v8 configuration without an
  explicit value adopts seven days on its first upgraded gateway startup and
  deletes eligible days 8–90. Set an explicit longer value before upgrading if
  that history must be preserved.
- Replaces separate `otel`, `audit_sinks`, and global redaction policy with one
  strict `config_version: 8` `observability` graph for bucket collection,
  mandatory local SQLite history, redaction profiles, routing, retention,
  sampling, metric policy, and every optional destination.
- Fresh v8 is full fidelity: all registered logs, traces, and metrics collect;
  local SQLite stores every collected log unredacted; and an enabled destination
  with omitted `send`/`routes` exports every reviewed bucket and every signal its
  kind supports under profile `none`. General OTLP sends logs/traces/metrics,
  logs-only kinds send logs, Prometheus sends metrics, and Galileo sends traces.
- Adds centralized per-destination field-class profiles (`none`, `sensitive`,
  `content`, `strict`, and custom detect/whole/hash/remove policy), ordered
  first-match routes, and independent queue/health/accounting for multi-backend
  fan-out.
- Preserves the full root-agent/subagent/turn/workflow/model/tool lifecycle and
  the `local-observability-v1` Agent360/dashboard contract while expanding the
  generated `galileo-rich-v2` trace projection.
- One authenticated target-release resolver command automatically stages supported
  POSIX v7 installations through the published `0.8.4` protocol-2 bridge, re-execs
  under a fresh bridge controller, then backs up, converts, validates, and atomically
  activates v8. It preserves narrower v7 signal/routing/redaction behavior, promotes
  inline observability secrets to locked environment references, refreshes owned
  local-dashboard assets without resetting volumes, and restores healthy `0.8.4`
  state after a failed conversion, start, or health check. No separate migration
  apply command is required; the v8 gateway does not rewrite v7 config at startup or
  run both formats in parallel. Windows refuses before mutation because no Windows
  `0.8.4` bridge was published.

Breaking change: fresh-v8 telemetry is unredacted by default, and legacy
`otel`, `audit_sinks`, `privacy.disable_redaction`, and associated ambient OTel
policy variables are not accepted as v8 runtime policy. Review
`defenseclaw observability plan` before enabling a destination across a trust
boundary.

### Packaging / upgrade hotfix

- Kept `cisco-ai-mcp-scanner` as a core dependency and relaxed
  DefenseClaw's Click requirement to `click>=8.1.8,<9`, restoring clean
  wheel installs for releases whose MCP scanner metadata pins LiteLLM to
  a Click 8.1.x-compatible version.
- Added a pre-install wheel resolver check to the Python and shell upgrade
  paths so a dependency conflict aborts before services are stopped or
  gateway binaries are replaced.
- Security note: this hotfix intentionally accepts the MCP scanner's
  current LiteLLM pin in release-wheel metadata to preserve core MCP
  scanning. Re-tighten the LiteLLM floor after the scanner publishes
  metadata that no longer pins the older LiteLLM release.

### Behaviour changes (no flag)

- **Claude Code post-tool findings are advisory and provenance-aware**:
  `PostToolUse` and `PostToolBatch` retain findings plus shadow `would_block`
  telemetry without stopping the next model turn. Returned source text is no
  longer evaluated as an executable command or sensitive-path request; typed
  command/path enforcement remains on `PreToolUse`, and physically verified
  standalone source reads reuse the Codex low-noise source boundary.
- **Trusted-action enforcement now requires exact, same-rule proof**: raw,
  partial, parser-shadow, and unpinned evidence remains detection-only;
  ordinary sensitive reads are advisory unless paired with mutation or
  external egress, and Claude Code instruction-file mutation protection
  requires authenticated same-session load context; exact identities are
  retained, while recognized instruction paths with unprovable native identity
  fail closed only for proven canonical mutations. Parser uncertainty is
  counted separately by `defenseclaw.guardrail.parser_uncertainty`, so it does
  not inflate guardrail evaluation or block-rate metrics. Newly exact egress
  coverage includes curl FTP account/alternative operands and Telnet
  negotiation metadata on POSIX or structured argv, cross-platform SOCKS proxy
  credentials, and portable static `echo` or format-only `printf` output
  flowing into one exact external curl stdin upload. Exact static ASCII DNS
  hostname bytes are now covered only where curl or GNU Wget is proved to emit
  them: generated authority, HTTP CONNECT, remote-resolved SOCKS4a/5h
  destination fields, plaintext HTTP Host or canonical HTTPS SNI observed
  after a SOCKS handshake, and canonical HTTPS origin SNI. GNU Wget's
  canonical generated authority and origin SNI additionally require ambient
  configuration to be disabled. Every component is bound to the exact external
  origin or proxy network fact. Raw CMD/PowerShell curl now gains exact ordinary
  HTTP(S) headers, origin credentials, inline/body and file-upload projection,
  plus supported direct proxy/SOCKS credentials. Exact plaintext HTTP metadata
  and inline bodies are also bound to the external SOCKS observer when that
  exact target uses the proxy.
  PowerShell hostname projection additionally requires explicit `curl.exe` or
  `wget.exe`; its bare aliases and raw-Windows FTP control, SMTP envelope, and
  Telnet metadata remain detection-only.
  Curl `--haproxy-clientip` remains LOW and detection-only on every surface,
  including direct HTTP(S), explicit proxy/SOCKS or preproxy routes,
  `--noproxy`, multiple targets or `--next`, static or dynamic values,
  setup-preempted commands, aliases, and trusted or untrusted executable-path
  spellings. A curl 8.7.1 source and loopback-wire audit confirms that a capable
  direct build writes the PROXY preamble before the HTTP request or, for HTTPS,
  before TLS. It also establishes a 1976-byte future-projector ceiling and the
  pre-wire `--ipv4`/literal-IPv6 exclusion. Those facts are rationale, not
  current authority: the option is absent before curl 8.2.0 and is compiled out
  with `CURL_DISABLE_PROXY`, while executable spelling authenticates neither
  version nor build. [#770](https://github.com/cisco-ai-defense/defenseclaw/issues/770)
  owns the required executable-capability boundary.
  `mkfs.minix` now shares the formatter owner for raw-device targets;
  image files, help/version calls, invalid grammar, near-miss executables, and
  local-only routes or numeric destinations, non-ASCII IDN spellings,
  dynamic/config-driven
  targets, wrappers, pipelines, shell redirections, promptable authentication, unresolved
  file/TLS setup, a modeled eagerly checked compression/TLS/authentication
  capability option, a modeled final enabled capability toggle, conflicting pre-wire options, direct plaintext
  HTTP Host overrides with no remaining proxy-visible authority, an HTTPS
  proxy route without authenticated HTTPS-proxy feature facts, unsupported
  multi-hop proxy chains, and other
  ambiguous egress forms cannot mint action
  authority; they remain advisory where a compatible detector still matches and
  otherwise stay quiet.
- **Amp is now a first-class connector on macOS, Linux, and native Windows**:
  setup installs an owner-only authenticated system policy plugin for Amp's five
  documented callbacks; action mode gates `tool.call` before execution and can
  withhold unsafe `tool.result` output before model delivery. CLI, TUI, macOS
  app, native Windows setup, discovery, doctor, upgrade/uninstall, MCP, skills,
  plugins, Agent360, Galileo, audit, and hook-generated observability all share
  the same connector contract. Amp exposes no documented native OTLP,
  `traceparent`, `session.end`, or dedicated subagent lifecycle callback, so
  DefenseClaw correlates only source-backed thread events and governs delegation
  tools at their `tool.call` boundary.
- **Windows runtime custody remains verifiable while services are live**:
  detached gateway, watchdog, startup, and hook-recovery processes no longer
  use the protected data directory as their current working directory, so
  Doctor can hold its exact anti-replacement lease without weakening Windows
  sharing or ACL checks. Fresh device identities now publish an owner-private
  random provenance secret, an HMAC bound to the exact Ed25519 key bytes, and
  finally the key itself with create-new semantics. A portable relative
  `gateway.device_key_file` remains compatible by resolving strictly beneath
  the canonical absolute `data_dir`; rooted, drive-relative, ADS, traversal,
  and outside-root spellings still fail closed before read or mutation. On
  POSIX, every validated nested-directory entry is synced before deeper work
  and re-synced on retry after an interrupted attempt. Existing unprovenanced
  keys are never blessed after the fact; they remain usable but Doctor reports
  them for continuity review. After `DELETEUSERDATA=1`, post-reboot Windows
  cleanup now re-verifies the exact recorded Codex, Claude Code, and Amp homes
  through a configless child bound to the exact transaction, journal, digest,
  and Setup process instance; the child retains one stable parent handle and
  checks its creation identity and liveness before and after authorization. It
  neither recreates the deleted data root nor weakens ordinary
  `connector verify`, which still requires a valid v8 runtime configuration.
  Managed-plugin residue verification normalizes only line terminators and
  recognizes exact canonical historical marker lines, so LF- and CRLF-built
  gateways find managed residue across upgrades without matching marker-like
  suffixes or operator prose.
  Native Windows CI now requires both live
  audit-database custody and HMAC-bound device identity checks to pass.
- **`make all` is again the explicit same-checkout developer reinstall**:
  markerless or older source-owned state may advance with the checkout for
  local development. Foreign, newer, release-managed, and different-checkout
  installations still refuse before mutation, and direct install targets do
  not inherit the developer reclaim path. Running `make` or `make help` now
  explains the source-build, developer-activation, and release-upgrade paths;
  `make build` no longer directs developers into the strict install target.
- **AI Discovery inventories Lemonade and local model artifacts**: the built-in
  catalog now recognizes Lemonade Server, bounded loopback metadata reads show
  installed/loaded models, and independent filesystem discovery covers GGUF,
  MLX/safetensors, ONNX, Core ML, TFLite, Q4NX, Hugging Face caches, Ollama
  stores, and contextual PyTorch model files without opening model binaries.
- **Skill, MCP, and plugin scans now degrade cleanly when optional LLM
  credentials are unavailable**: the local/static analyzers still complete,
  the CLI and TUI show a nonfatal skip warning, and Setup/Keys identifies the
  missing credential. Auto mode adds the LLM analyzer only when its model and
  authentication are usable; local providers and Bedrock's AWS credential
  chain remain supported without a DefenseClaw API key.
- **Antigravity local surfaces now match the PR #365 contract**:
  MCP reads/writes `~/.gemini/config/mcp_config.json` and
  `<workspace>/.agents/mcp_config.json`; hooks remain global-only at
  `~/.gemini/config/hooks.json`; AgentSkills folder form is supported
  while rules and global/workspace/plugin-contained agents remain discovery-only. Antigravity
  plugins now install to Google's documented global/workspace plugin paths;
  the Antigravity CLI staging directory remains an additional discovery path.
- **W3C trace propagation is enabled for trusted hook routes**
  (`/api/v1/<connector>/hook`, `/api/v1/codex/notify`) when the
  caller is loopback and the connector route is registered. The
  gateway consumes `traceparent` / `tracestate` so hook spans root
  on the agent's parent trace; `_hardening.sh` v6 emits the headers
  from every hook script. Extraction is route-scoped via
  `shouldExtractHookTrace`; all other routes (health, REST, OTLP
  ingest) continue to mint a fresh root span regardless of what
  the caller sent.
- **Native OTLP for codex / claudecode / geminicli is spec-driven**
  through the shared `connector.NativeOTLPSpec` renderer
  (`TOMLBlock` / `EnvBlock` / `JSONBlock`). The V1 builders are
  gone; shape tests in
  `internal/gateway/connector/native_otlp_golden_test.go` lock the
  wire format codex/claudecode/gemini consume.
- **Audit `details` column always carries both forms**: the
  structured `HookAuditEnvelope` JSON (under the `details_json=`
  key) and the legacy `connector=… action=… raw_action=…` tail.
  Existing operator log greps keep matching; jq pipelines can
  parse the JSON inline. No env-var toggle.
- **Codex `/api/v1/codex/notify` synthesizes a Stop event** through
  `handleAgentHookSynthetic`. The canonical
  `codex.notify.<sanitized-type>` audit row is preserved one-per-
  inbound; the synthetic envelope is persisted under
  `audit.ActionConnectorHookSynthetic` so SIEM rules pinned on
  `codex.notify%` keep their row counts and new dashboards can
  reason about the synthesized Stop separately.
- **codex / claudecode flow through the unified `handleAgentHook`
  pipeline (full handler fold)**. Pre-PR-#284, `handleCodexHook` and
  `handleClaudeCodeHook` each re-implemented the entire pipeline
  (parse → enrich context → remember raw events → emit LLM event →
  evaluate → metrics → audit envelope → render). Adding a new
  cross-cutting concern (audit envelope refresh, dispatch metric,
  dedup, trace propagation) meant touching three handlers, and the
  F2 audit-correlation regression bit live Splunk verification when
  `handleClaudeCodeHook` skipped the envelope refresh. The bespoke
  handlers (`handleClaudeCodeHook`, `handleCodexHook`,
  `enrichClaudeCodeHookContext`, `enrichCodexHookContext`) are
  **deleted**; every connector hook route now flows through
  `handleAgentHook(name)`. The connector-specific evaluator,
  LLM-event emitter, and raw-event deduper (which probe fields like
  `req.ToolUseID`, `req.LastAssistantMessage`, `req.MCPServerName`
  that the generic `agentHookRequest` doesn't model) are kept and
  invoked via the `hookProfileRuntime` dispatch in
  `internal/gateway/hook_profile_runtime.go`. The wire JSON field
  name (`claude_code_output` / `codex_output` / `hook_output`) is
  selected by `hookOutputFieldName(connectorName)` so the agent CLIs
  keep their connector-specific response shape. Net delta: one place
  where shared concerns live. New tests
  (`TestUnifiedHookDispatch_SingleEntryPoint`,
  `TestUnifiedDispatch_PreservesConnectorWireShape`,
  `TestEnrichAgentHookContext_ClaudeCodeRefreshesEnvelope`,
  `TestEnrichAgentHookContext_CodexRefreshesEnvelope`) pin the
  contract so a future "let's reintroduce a bespoke handler for X"
  change immediately fails CI.

### Observability parity

- `defenseclaw.connector.hook.outcome` and
  `defenseclaw.connector.hook.tokens` counters added to
  `internal/telemetry/metrics.go`; emitted by every hook handler
  including the synthetic path. Dashboards can compute block rate
  and cost per connector via PromQL without joining the native
  OTLP channel.
- `defenseclaw.connector.hook.unified_dispatch` added so
  operators can confirm traffic is flowing through the unified
  pipeline (vs. an out-of-tree handler registration that bypasses
  audit/metrics).
- New audit action `connector-hook-synthetic` (Go +
  `cli/defenseclaw/audit_actions.py` + `schemas/audit-event.json`)
  for the synthetic Stop visibility row.

### F6 audit-action parity

- Registered the production audit actions discovered across sidecar,
  watcher, gateway router, guardrail, inspect, setup, doctor, API,
  sink, and operator command paths. Go, Python, the public schema, and
  the embedded gateway schema now agree on the expanded enum.
- Added `scripts/discover_unregistered_audit_actions.py` plus the
  review artifact `scripts/discovered_unregistered_audit_actions.txt`
  so future broad-parity work can reproduce the exact discovered set.
- Added `scripts/check_audit_no_raw_literals.py` to `make check-v7`
  and a Go completeness test for the discovered actions. New raw
  `audit.Event{Action: "..."}` literals now fail the parity gate.

### Connector profile surface

- **OpenHands is now a first-class hook connector.** `defenseclaw setup
  openhands` writes the documented repo-local `.openhands/hooks.json`
  native schema, registers `/api/v1/openhands/hook`, maps blocking to
  OpenHands' `decision=deny` / exit-code-2 contract, discovers
  `~/.openhands/mcp.json`, and installs current skills into
  `.agents/skills` while treating `.openhands/skills` and
  `.openhands/microagents` as deprecated discovery paths. The hook
  contract is documented against `OpenHands CLI 1.16.0` while staying
  unbounded until upstream publishes a hook-version floor.
- New `connector.HookProfile.Decode`, `MapVerdict`, and `Respond`
  function fields let codex / claudecode declare their per-event
  wire shape declaratively.
- `connector.AcceptLoopbackWithWarning` centralizes the loopback
  authentication carve-out (currently used by
  `CodexConnector.Authenticate`). The helper now panics on
  `warned == nil` so a future caller cannot silently disable the
  `[SECURITY] loopback bypass` log via a typo; operators continue
  to see one warning per process when a gateway token is configured
  but loopback is exercised.

### Security fixes folded in

- **Trace propagation route scope (H1).**
  `extractIncomingTraceContext` is now path-aware
  (`shouldExtractHookTrace`) so only hook + notify routes consume
  inbound `traceparent` into the OTel server span tree. Closes the
  regression where any caller hitting `/health` could splice a
  trace ID into the gateway's trace tree.

  Trust gates for inbound `traceparent` are intentionally layered:

  | Surface                       | Allowed when                                 | Defended by                          |
  |-------------------------------|----------------------------------------------|--------------------------------------|
  | OTel server span parent       | Loopback **and** hook/notify route           | `shouldExtractHookTrace`             |
  | Audit envelope `trace_id`     | Loopback (any route)                         | `connector.IsLoopback` in middleware |

  The audit envelope's gate is intentionally broader than the OTel
  span gate. The OTel server span propagates into every child span
  the request makes, so splicing the span tree is an amplification
  primitive; the audit envelope `trace_id` is a single per-row data
  field with no propagation, so loopback alone is a sufficient
  trust boundary. This admits the legitimate
  `agent → loopback proxy → /v1/guardrail/evaluate` hop where the
  agent's distributed trace_id needs to flow onto audit rows to
  preserve cross-system correlation in SOC dashboards.
  `correlation_middleware.go` and `correlation_middleware_test.go`
  carry the long-form rationale; the
  `TestCorrelationMiddleware_DropsInboundTraceparentOnNonLoopback`
  and `TestCorrelationMiddleware_AdoptsInboundTraceparentOnLoopback`
  tests pin the boundary.
- **Synthetic audit visibility (M1).** The synthetic codex notify
  path now persists a `HookAuditEnvelope` under
  `ActionConnectorHookSynthetic` instead of suppressing the row;
  SIEM dashboards no longer regress when codex notify fires.
- **Loopback bypass footgun (M2).** `AcceptLoopbackWithWarning`
  panics on `nil` `warned` argument so a misuse cannot silently
  re-enable silent trust of loopback callers.

### Follow-ups from live E2E testing (F1, F2, F3, F4, F5)

- **Codex `[otel]` block no longer carries `service_name` /
  `resource_attributes` (F1).** Earlier review iterations of this PR
  set both fields on `CodexConnector.HookProfile().NativeOTLPSpec` —
  but codex's documented `[otel]` schema (see codex
  config-reference) doesn't define those keys, and the published
  schema is strict
  ([openai/codex#17012](https://github.com/openai/codex/issues/17012)).
  Writing them risks codex rejecting the operator's config at
  startup.

  Codex also already emits richer intrinsic identity tags
  (`originator`, `model`, `auth_mode`, `app.version`,
  `session_source`) and uses different `service.name` values for
  its sub-processes (`codex-app-server`, `codex_exec`); forcing
  `service.name=codex` from outside would have *collapsed* the
  natural distinction. M3 (consistent resource attributes across
  connectors) therefore applies only to env-block-style connectors
  (claudecode); TOML/path-token connectors that self-identify
  (codex, geminicli) keep their upstream tags.

  `TestNativeOTLPShape_Codex` now asserts the *absence* of
  `service_name` / `resource_attributes` so a future contributor
  can't silently re-introduce the regression.
- **Hook audit rows now carry `session_id` and `agent_id` (F2).**
  `CorrelationMiddleware` snapshots the audit envelope from the
  inbound HTTP headers — but no DefenseClaw-managed hook shell
  script sets `X-DefenseClaw-Session-Id`, the session id always
  arrives in the JSON payload. Result before F2: every audit row
  written by `logConnectorHookAuditEnvelope` (`connector-hook` AND
  `connector-hook-synthetic`) landed with `session_id=NULL` and
  `agent_id=NULL`, defeating SIEM correlation between hook
  decisions and the matching LLM events.

  `enrichAgentHookContext` now refreshes the audit envelope with
  `req.SessionID` and the resolved agent identity, so both regular
  and synthetic hook rows correlate. Header-supplied identity is
  preserved when the payload doesn't override (see
  `TestRefreshAuditEnvelopeFromHook_*`).

  Operators upgrading from a prior build will see
  `session_id`/`agent_id` populate immediately on the next hook
  event; pre-existing audit rows are not back-filled.
- **`defenseclaw audit export` no longer rewrites valid actions to
  `"action"` with `legacy_action=…` (F3).** The exporter kept a
  hand-maintained copy of the audit action enum in
  `internal/cli/audit_export.go`; every action added to
  `internal/audit/actions.go` since v7 (the entire `otel.ingest.*`
  family, `connector-hook`, `connector-hook-synthetic`,
  `asset-policy`, `codex.notify` plus the dynamic
  `codex.notify.<sanitized-type>` family) was silently downgraded
  on export, so Splunk dashboards that keyed on the *real* action
  saw nothing.

  `audit_export.go` now delegates to
  `audit.IsKnownAction` + `audit.IsKnownActionPrefix`, so future
  registry additions flow through automatically with no second list
  to maintain. New test coverage in
  `internal/cli/audit_export_test.go` walks `audit.AllActions()` so a
  regression that re-introduces a local map fails CI.
- **Gemini CLI loopback OTLP exports no longer 401 after `setup
  geminicli` (F4).** The sidecar populated its in-memory
  `otlpPathTokens` map only at boot; an operator who started the
  gateway before running `defenseclaw setup geminicli` would mint a
  fresh on-disk token (written into `~/.gemini/settings.json`) that
  the running gateway never observed, so every loopback OTLP request
  returned 401 until the next restart.

  `APIServer.lookupOTLPPathToken` now performs a lazy disk reload on
  cache miss for KNOWN scopes (closed allow-list via the new
  exported `connector.IsValidOTLPScope`), bounded by a 500 ms
  per-scope rate limit so a hostile or noisy caller probing
  `/otlp/geminicli/<random>/v1/*` cannot turn the auth path into a
  disk-stampede primitive. The reload is gated on
  `scannerCfg.DataDir` being set, so tests and out-of-tree wiring
  remain panic-safe.   Five tests in
  `internal/gateway/otlp_path_token_test.go` cover the happy reload,
  unknown-scope rejection, per-scope refractory window, post-window
  retry (operator rotate flow), and empty-DataDir guard.
- **`Config.save()` no longer silently strips operator-configured
  `audit_sinks` / `otel.resource.attributes` (F5).** Surfaced while
  driving live Splunk verification for F2: switching the active
  connector with `defenseclaw setup codex` after a prior
  `defenseclaw setup splunk --logs` made the operator's HEC
  forwarding disappear without any warning, taking Splunk dashboards
  dark on every connector switch.

  Root cause: `Config.save()` was `yaml.dump(dataclasses.asdict(self))`,
  which only emits the fields the Python `Config` dataclass declares.
  `audit_sinks:` (written by the observability writer) and the nested
  `otel.resource.attributes:` map are intentionally unmodelled in the
  Python dataclass, so every `cfg.save()` call site —
  `execute_guardrail_setup`, `setup codex`, `setup claude-code`,
  `setup geminicli`, the migration helpers, ~14 sites in total —
  silently overwrote the file. The team had already detected this on
  the `setup splunk` path itself and worked around it with two
  "don't call cfg.save() here" comments in `cmd_setup.py:4870` and
  `cmd_setup.py:4946`; every other code path was still vulnerable.

  `Config.save()` now reads the existing `config.yaml`, deep-merges
  the dataclass output over it (dataclass-owned top-level keys win;
  unmodelled keys are rescued from the file; nested dicts recurse so
  `otel.resource.attributes` survives even though `otel` itself is
  modelled), and replaces the file atomically with a lock, 0600
  temp files, `O_NOFOLLOW`, `fsync`, and directory sync. The
  observability writer uses the same secure write helper. The dataclass still
  owns its keys — including the v4-migration drop of the legacy
  `splunk:` block and the byte-stability strips of empty
  `notifications` / `privacy` / `asset_policy` blocks — so
  programmatic resets through the dataclass still update the file.
  Corrupt-YAML input logs a warning, writes a 0600 `.bak`, and then
  falls back to dataclass-only write so the operator can recover via
  the next setup wizard.

  Regression tests in `cli/tests/test_config_save_roundtrip.py`
  cover: single-/multi-sink preservation, nested
  `otel.resource.attributes` preservation, legacy `splunk:` drop,
  default-`notifications:` strip honouring an operator reset,
  modeled-field overrides, first-save with no existing file,
  corrupt-YAML backup/fallback, non-mapping-YAML fallback,
  atomic-write inode change, merge helper unit tests, concurrent
  authoritative OTel dict preservation, and the end-to-end
  `setup splunk → setup codex` operator workflow. The two existing
  "no cfg.save() here" comments in `cmd_setup.py` are kept as
  single-writer hygiene (no longer correctness) and updated to
  reflect the new contract.

### Review hardening (H1-H2, M1-M6, L1-L6)

A full code review of the unification PR identified two high-priority
issues, six medium-priority issues, and six low-priority issues. All
are addressed in this rollup.

- **H1 — gofmt drift in `internal/gateway/api.go`** (CI gate). The
  reformatted file is in.
- **H2 — Panic recovery around the unified hook hot path
  (`internal/gateway/agent_hook.go`).** Pre-fold, each connector
  owned its own bespoke HTTP handler so a panic blast-radius was one
  connector. Post-fold (this PR), `handleAgentHook` is the SOLE hot
  path for every connector; an unrecovered panic in any
  raw-event deduper, LLM-event emitter, evaluator branch
  (asset-policy probe, scanner invocation, codex notify-bridge
  fan-out, …), or final audit/metrics section would take the whole
  agent estate down at once. `handleAgentHook` now has a top-level
  deferred `recover`, while `safeEvaluateHook` /
  `safeEvaluateSyntheticHook` keep the evaluator-specific contract:

  - increments `defenseclaw.panics.total{subsystem="gateway"}` so
    existing SRE alerts fire without a new metric,
  - logs the recovered value + stack to stderr (the structured
    logger may itself be the panic source, so stderr is the
    safest sink),
  - returns a fail-OPEN `agentHookResponse{action: "allow",
    would_block: true, severity: "WARN", reason: "defenseclaw
    internal evaluator error"}`. We deliberately fail-open rather
    than fail-closed because a transient evaluator bug should not
    block every agent's every tool call; `would_block=true`
    preserves the guardrail intent and the `result="panic"` label
    on `RecordConnectorHookInvocation` gives operators an alertable
    signal.

  Audit envelopes for panic-path rows carry `extra.panic=true` and
  `result=panic` so SIEM queries can separate them from policy
  decisions. `TestSafeEvaluateHook_RecoversAndReturnsFailOpen` +
  `TestHandleAgentHook_PanicReturnsSafeResponse` +
  `TestHandleAgentHook_EmitPanicReturnsSafeResponse` +
  `TestHandleAgentHook_FullChain_PanicFailsOpen` cover the unit
  helper, the HTTP-level integration, pre-evaluator emit failures,
  and the per-connector contract.

- **M1 — OTLP token cache misses rotation.** F4's lazy reload
  closed the boot-vs-setup race but left an open gap: an operator
  who rotates `~/.defenseclaw/hooks/.otlp-geminicli.token` while
  the gateway runs (security-incident response, post-compromise
  rotation policy) would see every subsequent loopback OTLP
  request 401 until restart, because the in-memory cache had no
  way to notice the on-disk change.

  `lookupOTLPPathToken` now keeps an `otlpPathTokenEntry{token,
  mtime}` per scope and runs a throttled `os.Stat` (1s
  per-scope) on the hot path; mtime drift triggers a reload, file
  disappearance evicts the cache so the next request 401s rather
  than authenticating a removed token. Stat I/O is throttled
  independently from full reloads so a flood of misses cannot
  weaponise rotation detection into a per-request disk syscall.

  Tests: `TestLookupOTLPPathToken_DetectsRotation`,
  `TestLookupOTLPPathToken_DropsCacheOnFileRemoval`, and
  `TestLookupOTLPPathToken_ConcurrentRotation` (race-detector
  smoke; 24 readers + 8 rotations).

- **M2 — Pre-redact free-form envelope fields.** The audit choke
  point (`internal/audit/logger.go` →
  `redaction.ForSinkReason`) tokenises on raw `", "` / `"; "` byte
  sequences and per-chunk redacts. The hook envelope places JSON
  next to free-form `Reason` text in a single `details` blob;
  without pre-redaction, a `Reason` containing a comma created a
  split point inside the `strconv.Quote`'d JSON value and the
  downstream pass corrupted the JSON envelope every audit sink
  writes — breaking jq/SIEM parsers.

  `renderHookAuditEnvelope` now runs free-form fields through
  `redaction.ForSinkReason` BEFORE they are folded into the JSON.
  ForSinkReason is idempotent (`isAlreadyRedacted` fast-path
  skips placeholders), so the downstream pass is a no-op for
  already-redacted material and the envelope JSON we emit is
  bit-identical to what the audit row contains. Test:
  `TestRenderHookAuditEnvelope_PreRedactsReason`.

- **M3 — Unbounded `RawPayload` on `redaction.DisableAll()`.** When
  an operator explicitly turns off all redaction, the unified
  handler previously copied the full HTTP body into the audit
  envelope's `RawPayload` field — a 10 MiB hostile POST therefore
  amplified through `json.Marshal` → `strconv.Quote` → SQLite
  insert → every audit sink (Splunk HEC, S3, file). The new
  `attachRawPayload` helper caps `RawPayload` at 64 KiB, sets
  `extra.raw_payload_truncated=true`, records the full byte count,
  and emits a SHA-256 short digest so SIEM rules can deduplicate
  replays without ingesting the full body. Tests:
  `TestAttachRawPayload_TruncatesAndAnnotates` +
  `TestAttachRawPayload_NoOpWhenRedactionEnabled`.

- **M4 — Bound `model` metric label cardinality.** The new
  `telemetry.NormalizeModelLabel` projects arbitrary
  caller-supplied model strings onto a closed allow-list of model
  families (`gpt-5`, `gpt-4o`, `gpt-4`, `gpt-3.5`, `o1`, `o3`,
  `claude-4`, `claude-opus`, …). Unknown identifiers collapse to
  `"other"`; identifiers longer than 64 chars collapse to
  `"other"` regardless of family. The fully-qualified model name
  remains on the `gen_ai.request.model` span attribute (no
  cardinality limit at the trace backend); only the metric label
  is bounded. The OTLP ingest path also bounds promoted
  `gen_ai.provider.name` and `gen_ai.operation.name` labels before
  recording GenAI histograms. Total cardinality budget asserted at
  ≤ 30 distinct values across all callers. Test:
  `TestNormalizeModelLabel_BoundsCardinality` (input-shape table
  plus budget assertion).

- **M5 — Server span leak on panic paths.** `otelHTTPServerMiddleware`
  called `span.End()` un-deferred, so any panic between
  `tracer.Start` and `End` would orphan the span at the trace
  backend and hide the failure from tracing dashboards.
  `defer span.End()` lands immediately after `Start`. The H2
  panic recovery normally catches the panic earlier, but this
  defense-in-depth catches the (theoretical) case where the
  recover itself faults or a panic originates in middleware below
  the evaluator.

- **M6 — End-to-end integration coverage per connector.** The new
  `agent_hook_e2e_test.go` drives an HTTP request through
  `handleAgentHook` for every registered connector
  (claudecode, codex, hermes, cursor, devin, antigravity, copilot, openhands)
  and asserts:

  - HTTP 200 with valid JSON,
  - canonical `action` / `severity` / `mode` fields,
  - per-connector top-level wire-shape key
    (`claude_code_output` / `codex_output` / `hook_output`),
  - benign requests resolve `action="allow"`,
  - `gen_ai.conversation.id` and `defenseclaw.connector` span
    attributes recorded.

  A registry-completeness gate at the end of the test enumerates
  `connectorHookHandlerByName` and fails if any registered
  connector lacks a test row. A second test
  (`TestConnectorRegistry_ScopeAndHookHandlerInSync`) asserts that
  every OTLP scope corresponds to a registered hook handler so the
  two registries cannot silently drift apart.

- **L1 — `shouldExtractHookTrace` was broader than its docstring
  claimed.** The check accepted any `/api/v1/<anything>/hook` URL
  shape, so an attacker hitting an unregistered route could splice
  a `traceparent` even though the mux would 404 the request. The
  function now consults `connectorHookHandlerByName` directly:
  trace extraction only happens for connectors with a registered
  handler.

- **L2 — `reason` metric label cardinality (folded into H2
  changes).** `RecordConnectorHookInvocation` previously took
  `reason = resp.Action` verbatim. Today `resp.Action` is a small
  enum, but nothing in the type system enforces that at the
  metric boundary. The new `normalizeHookReasonLabel` allow-lists
  `allow|block|alert|confirm|would_block|panic|other|none`;
  anything else collapses to `"other"`. Test:
  `TestNormalizeHookReasonLabel_BoundsCardinality`.

- **L3 — `renderHookAuditLegacyDetails` Extra-map iteration was
  nondeterministic.** Go's map iteration is intentionally
  randomized, so two consecutive calls to the legacy formatter
  emitted different orderings of `env.Extra` — breaking snapshot
  tests and confusing operator log greps. Keys are now sorted
  ascending. Test:
  `TestRenderHookAuditLegacyDetails_ExtraKeysSortedDeterministically`.

- **L4 — `AuditActionOverride` godoc was stale** and referred to
  `env.Action` rather than `env.AuditActionOverride`. Doc fixed.

- **L5 — `hook_register.go` comment drift.** The comment block
  still described the pre-full-fold "wrapper delegates to bespoke
  handler" design. Rewritten to match the current
  declarative hook-profile runtime model.

- **L6 — `subtle.ConstantTimeCompare` length-leak hardening.** All
  three gateway auth comparisons (master gateway token,
  per-source OTLP path token, guardrail-config token) now go
  through the new `constantTimeStringMatch` helper which hashes
  both inputs with SHA-256 first and compares the 32-byte
  digests in constant time. The hashing removes length
  observability entirely (the original direct compare leaked
  the expected-token length whenever inputs differed in size)
  and adds ≈microseconds to the auth path, dominated by socket
  I/O. Plain-token comparison is gone from `internal/gateway/api.go`.

### New tests folded in this rollup

- `agent_hook_panic_test.go` — safeEvaluateHook recover; reason
  + model + RawPayload label normalisation.
- `agent_hook_e2e_test.go` — full-chain per-connector integration
  + synthetic-path + panic-path coverage + registry sync.
- `otlp_path_token_test.go` (extended) — rotation, file removal,
  concurrent rotation race.
- `connector/otlp_token_test.go` — `IsValidOTLPScope` negative
  cases (path traversal, control chars, Unicode homoglyphs, …).
- `telemetry/model_label_normalize_test.go` — cardinality budget
  + family-collapse parity.
- `hook_audit_envelope_test.go` (extended) — Reason
  pre-redaction; deterministic Extra ordering.

## [Previous-Unreleased] — Codex / Claude Code hook-only enforcement (no proxy data path)

This rollup removes the LLM-proxy data path for the Codex and Claude
Code connectors and unifies them on the agent's native hook bus for
both observation and enforcement. The `PreToolUse` hook returns a
`permissionDecision: "deny"` verdict on policy hits and the agent
blocks the tool call inside its own permission flow. Codex and
Claude Code now talk directly to their native upstreams in both
`observe` and `action` mode.

### Breaking changes

- **`guardrail.codex_enforcement_enabled` removed** from
  `~/.defenseclaw/config.yaml`. The field was the on/off switch for
  the now-deleted proxy-driven enforcement path. Enforcement is now
  selected by the existing `guardrail.mode` field (`action` returns
  a PreToolUse deny verdict on policy hits; `observe` records only).
  The upgrade migration strips the field automatically — see
  "Migrations" below.
- **`guardrail.claudecode_enforcement_enabled` removed** from
  `~/.defenseclaw/config.yaml`. Same shape and rationale as the
  Codex flag above. The upgrade migration strips the field
  automatically.
- **`SetupOpts.CodexEnforcement` and `SetupOpts.ClaudeCodeEnforcement`
  removed** from the Go connector `Setup()` contract. Out-of-tree
  connector implementations that read these fields must drop the
  references; they were always observable booleans without their own
  feature surface, and `Mode` is the canonical knob now.
- **Codex / Claude Code proxy listener no longer binds** at gateway
  start when the active connector is `codex` or `claudecode`, even
  if `guardrail.mode=action`. Port 4000 stays closed — the
  enforcement path is the hook bus, not the proxy. Operators who
  relied on the proxy URL (`http://localhost:4000/...`) appearing in
  the agent config need to remove those overrides; the connectors
  patch the agent's native upstream back to its vendor default at
  upgrade time.

### Enforcement

- **`defenseclaw setup codex --mode action`** and
  **`defenseclaw setup claude-code --mode action`** newly provision
  hook-driven enforcement: the PreToolUse hook returns a deny
  verdict on policy hits and the agent blocks the tool call inside
  its own permission flow. `--mode observe` (the default) keeps the
  previous record-only behavior.
- The shared connector-alias factory used by the other hook-
  enforced connectors (`hermes`, `cursor`, `devin`, `antigravity`,
  `copilot`, `openhands`) gains the same `--mode {observe,action}`
  knob.
- The interactive wizard (`defenseclaw setup guardrail`) drops the
  Codex/Claude Code "observability-only vs. proxy" fork; the
  standard observe/action mode prompt now drives both connectors.
- The TUI overview's Enforcement row reflects the effective mode
  per connector: `<Agent> hook enforcement (action)` when
  `guardrail.mode=action`, otherwise `<Agent> hook observability
  (observe)`. `defenseclaw doctor` likewise reports `hook-enforced
  for codex (mode=action via PreToolUse deny) — proxy port
  intentionally closed` in its `Guardrail proxy` check.

### CLI plumbing

- The `_OBSERVABILITY_ONLY_CONNECTORS` set in `cli/defenseclaw/
  commands/cmd_setup.py` was split into `_PROXY_BACKED_CONNECTORS`
  (`openclaw`, `zeptoclaw`) and `_HOOK_ENFORCED_CONNECTORS`
  (everything else). The old name remains as a backstop alias so
  out-of-tree imports keep resolving. New call sites must use the
  named sets.
- `_apply_connector_observability_only` was renamed to
  `_apply_hook_connector_setup` and now takes a `mode` argument
  (defaulting to `observe`). The legacy name remains as a thin
  shim that forces `observe` for any out-of-tree callers.
- Inert helpers `_set_connector_enforcement`,
  `_connector_enforcement_flag`, and `_connector_enforcement_enabled`
  were deleted along with their last call sites.

### Migrations

- New 0.5.0 sub-step
  **`_migrate_0_5_0_strip_codex_enforcement_keys`** rewrites
  `~/.defenseclaw/config.yaml` to remove
  `guardrail.codex_enforcement_enabled` and
  `guardrail.claudecode_enforcement_enabled` if present. The strip
  is byte-level (no YAML round-trip) so operator comments, blank
  lines, and surrounding key order under `guardrail:` are preserved
  exactly. `guardrail.mode` is left untouched — the operator's
  existing enforcement posture carries through to the hook surface.
- Migration is idempotent and runs automatically on
  `defenseclaw upgrade`. Failures are logged via `defenseclaw
  doctor --fix` and never block the upgrade.
- **`defenseclaw setup codex` now heals pre-PR-#265 installs in place.**
  The legacy setup rewrote `~/.codex/config.toml`'s top-level
  `openai_base_url` to `http://127.0.0.1:<port>/c/codex`. PR #265
  deleted the matching proxy mount but left the operator's
  `config.toml` carrying a now-broken value, so every Codex turn
  failed with `stream disconnected before completion` against the
  closed loopback port. `patchCodexConfig` now strips any
  `openai_base_url` whose URL shape matches the loopback `/c/codex`
  pattern DefenseClaw itself wrote (scheme `http(s)`, host
  `127.0.0.1` / `localhost` / `::1`, path beginning `/c/codex`). An
  operator's enterprise gateway URL is preserved unchanged —
  `TestCodex_Setup_DefaultObservability_NoProxyRewrite` continues
  to gate that contract, and `TestIsDefenseClawCodexProxyRedirect`
  pins the strip detector's full accept/reject surface.
- **Known follow-up:** `Teardown` does not yet apply the same heal,
  so `defenseclaw teardown codex` against a pre-PR-#265 install can
  restore the stale `openai_base_url` from the managed-file backup
  snapshot captured at the original Setup. Operators uninstalling
  DefenseClaw should re-run `setup codex` once before `teardown`,
  or hand-strip the line. Tracked as the immediate next PR.

### Tests

- Go test suite updated:
  - `TestSetupOpts_HookFailMode_RespectsOperatorChoice` no longer
    references `CodexEnforcement` / `ClaudeCodeEnforcement`.
  - `TestProxyShouldBindForConnector` /
    `TestAPIStatusEmitsConnectorMode` /
    `TestShouldRunProviderProbeForConnector` assert the proxy stays
    unbound for codex/claudecode regardless of `Guardrail.Mode`.
  - `TestConnector_AllowedHostsProvider_ProxyBuiltinsImplement`
    (renamed from `_AllBuiltinsImplement`) only covers
    proxy-backed connectors.
  - `TestCodex_Teardown_RemovesLegacyEnvFiles` and the analogous
    Claude Code env-file tests were removed alongside the helpers
    they covered.
  - `TestModePickerModal_PreviewMatchesSetupAliases` updated for
    the new "proxy-backed connector setup" / "hook-driven
    connector setup" preview strings.
- Python CLI test suite updated:
  - `test_cmd_init.py` and `test_cmd_doctor.py` no longer assert
    on `codex_enforcement_enabled`.
  - `test_cmd_setup_observability.py`,
    `test_cmd_setup_codex_claudecode_alias.py`, and
    `test_guardrail.py` were rewritten to cover the hook-driven
    mode contract end-to-end.

## [Pre-PR-265] — PR #194 single-rollup (security floor + connector polymorphism + test parity)
## [Unreleased] — DeepSec audit closure (75 findings → 0)

This rollup closes every actionable finding from the DeepSec security
audit (`.deepsec/data/defenseclaw/reports/report.md`): 1 CRITICAL,
26 HIGH, 24 MEDIUM, 9 HIGH_BUG, and 15 BUG. The two findings tagged
"FP" by reviewers are also remediated because their underlying code
paths required changes anyway. No protections were removed; the audit
strictly tightens existing guards.

### ⚠️ Operator-visible behaviour changes (read this before upgrading)

**Newly-blocked outbound dial address ranges.** The gateway's SSRF
defenses (`internal/gateway/provider.go::isUnsafeIP`,
`internal/netguard/netguard.go::IsPrivateOrReserved`, and the webhook
dispatcher's `validateWebhookURL` predicate) now refuse to dial:

- `100.64.0.0/10` — RFC 6598 carrier-grade NAT (Tailscale mesh,
  T-Mobile/Comcast carrier NAT, AWS Cloud WAN private overlay)
- `169.254.170.2/32` — ECS task metadata endpoint (was previously
  redundantly covered by `IsLinkLocalUnicast`; now an explicit entry)
- `fd00::/8` — IPv6 Unique Local Addresses (broader than the
  `fc00::/7` subset Go's `IsPrivate()` already reported)

**If you were running a local LLM (e.g. Ollama on a NAS at
`100.64.0.5:11434`) or a webhook receiver over a Tailscale tunnel,
upgrades will start returning `HTTP 403 target host resolves to a
private address` from the chat-completion / passthrough proxy and
`hostname resolves to private IP …` from `defenseclaw config webhook
test` against those targets.**

To opt back into CGNAT dialing, set `DEFENSECLAW_ALLOW_CGNAT=1` in the
sidecar environment and restart. This drops 100.64.0.0/10 from the
deny-list and prints a one-line `[gateway] DEFENSECLAW_ALLOW_CGNAT=1
…` notice to stderr at boot so the change is auditable from the boot
log. Loopback, RFC 1918, link-local, IMDS (`169.254.169.254`), ECS
task metadata (`169.254.170.2`), and IPv6 ULA stay blocked
unconditionally — the hatch widens CGNAT only.

**No equivalent escape hatch is offered for IMDS or ECS metadata.**
Those endpoints carry IAM credentials by design; the SSRF block is
the entire point.

The webhook dispatcher's config-time validator
(`webhook.go::isPrivateIP`) was previously a separate predicate that
did NOT cover these new ranges, so a webhook URL pointing at a
Tailscale receiver would pass config validation and then fail at
dispatch time with an opaque error. The two predicates are now
unified through `isUnsafeIP`, so misconfigurations surface at
`defenseclaw config webhook add` / `update` time instead of at first
delivery. Existing valid webhook URLs (public hosts) are unaffected.

### Security — DeepSec hardening (selected highlights)

- **CRITICAL S0** Codex git-scan hardening: hostile repository config,
  external diff, and `core.fsmonitor` injection paths are sanitized
  through `internal/gitsafe`; safe-flag set audited against
  `git --help`.
- **HIGH S2** Workflow integrity: `.github/workflows/{ci,docs-site,e2e,release}.yml`
  pin every third-party action by SHA, drop unused `permissions`
  scopes, and quote / sanitize all input expansions.
- **HIGH S2** Gateway HTTP egress: `internal/gateway/proxy.go` enforces
  SSRF refusal across known/unknown branches with `ResolveAndPin`,
  exact provider matching, IP/CIDR pinned dialer, userinfo / control-
  byte rejection, and structured URL scrubbing on every log/metric
  surface.
- **HIGH S2** Connector subprocess + plugin loader: token-aware hook
  templates, plugin loader TOCTOU closed (open-then-stat pinned to the
  same fd), embedded plugin canonical token derivation.
- **HIGH S2** Gateway scanners (mcp / plugin / skill) now fail-closed
  on non-zero subprocess exit; `policy.ScanResultInput` extended so the
  policy engine sees the full scanner verdict shape.
- **HIGH S2** Watcher routes rescan + baseline through admission and
  installs recursive watches on every admitted directory; skipping a
  policy file no longer suppresses unrelated change activity.
- **HIGH S3 BUG** Sandbox cleanup is scoped to per-request directories;
  the surgical 0.3 migration replaced the destructive prior path; the
  `http_jsonl` sink retries synchronously on transient failures;
  watchdog uses flock + binary fingerprint to recognise stale
  processes; `RepairPairing` is fail-closed and atomic.
- **MEDIUM S4** Webhook URLs are hashed (`scrubURLSecrets`,
  `hashWebhookTargetURL`) on every log path; AI-discovery path
  fingerprints are HMAC-keyed; MCP scan target URLs are validated as
  loopback / private / metadata; endpoint ignore-list switched from
  prefix matching to exact hostname / loopback IP literal matching.
- **MEDIUM S4** `CorrelationMiddleware` no longer mints unauthenticated
  agent sessions: it calls `AgentRegistry.ResolvePeek`, then handlers
  call `PromoteSessionIfAuthenticated` after `tokenAuth` succeeds.
  Combined with the LRU cap on `AgentRegistry`, unauthenticated
  callers can no longer amplify in-memory state by flooding distinct
  `X-DefenseClaw-Session-Id` headers.
- **BUG S5** `cli/defenseclaw/commands/cmd_init.py` no longer runs
  notifications onboarding twice; `cli/defenseclaw/provenance.py` now
  hashes nested policy bundle files; `internal/cli/connector_cmd.go`
  discovers plugin connectors before lifecycle commands run;
  `internal/cli/{policy,status}.go` attach the gateway bearer / token
  header on outbound API calls; `internal/cli/policy_diff.go` +
  `internal/sandbox/network_policy.go` make endpoint coverage
  port-aware; `internal/cli/tui_cmd.go` treats EOF + empty input as
  decline; `internal/gateway/api_ratelimit.go` resolves a `time.Time`
  data race with `atomic.Int64`; `internal/gateway/connector/otlp_token.go`
  is now `flock`-synchronized for cross-process token minting;
  `internal/gateway/judge_store.go` + `internal/gatewaylog/events.go`
  fix `JudgeResponse.input_hash` to hash the *input* (not the response
  body), with `JudgeEmitOpts.InputContent` automatically populating
  the digest; `internal/gateway/llm_event_emit.go` + `api.go` add a
  bounded LRU cache for hook prompt correlation maps;
  `internal/gateway/provider_bifrost.go` adds a bounded LRU cache for
  per-tenant Bifrost clients with proper `Shutdown()` on eviction;
  `internal/guardrail/rulepack.go` uses slash-separated paths for
  `embed.FS` lookups; `internal/watcher/policy_files_watch.go` records
  per-file unreadable errors instead of suppressing the whole poll.

## [Unreleased] — PR #194 single-rollup (security floor + connector polymorphism + test parity)

This rollup closes the audit gaps identified in the v3 connector
review and lands PR #141's matrix in a single coherent set of
changes. Ordering: Phase A (P1 mechanical) → Phase B (S0 security
floor) → Phase C (S1/S2/S7 + matrix-TODO cleanup) → Phase E (test
parity for ZeptoClaw + Claude Code + Codex) → Phase D (test sweep +
docs).

### Security

- **S0.8** Inspect hook scan timeout tightened from 5s to 200ms; per-IP
  rate limiter (20 rps, 40 burst) applied to `/api/v1/inspect/*` so a
  malicious or runaway hook caller cannot DoS the gateway. Loopback
  callers stay exempt so dev iteration is unaffected.
- **S0.13** CSRF middleware no longer exempts `OPTIONS` from
  `Sec-Fetch-Site` checks. Cross-origin preflights are now rejected by
  default.
- **S0.12** `Connector.ProviderProbe` interface added; the gateway
  refuses to start with zero usable upstreams unless
  `cfg.Guardrail.AllowEmptyProviders` is set explicitly. ZeptoClaw,
  Codex, ClaudeCode, OpenClaw all implement the probe.
- **S0.3** ZeptoClaw `Authenticate` no longer trusts loopback
  unconditionally. Local processes must present a valid `X-DC-Auth`
  bearer once a gateway token has been provisioned. `Route` now gates
  `RawAPIKey` capture behind `isChatPath`; non-chat traffic gets
  passthrough mode and an empty key.
- **S0.2** First-boot `DEFENSECLAW_GATEWAY_TOKEN` synthesis. The
  gateway and sidecar generate a 32-byte CSPRNG hex token at startup
  (atomic `0o600` write to `~/.defenseclaw/.env`) and persist it across
  reboots. The empty-token loopback allow path was removed; an empty
  token now fails closed. `TestTokenAuth_DisabledWhenEmpty` was
  inverted and renamed `TestTokenAuth_FailsClosedWhenEmpty`.
- **S0.5** `defenseclaw setup rotate-token` CLI subcommand. Generates a
  new gateway token, rewrites `~/.defenseclaw/.env`, refreshes hook
  `.token` files, and prompts the operator to restart the agent.
- **S0.4** Hook scripts (`hooks/*.sh`) source a new
  `hooks/_hardening.sh` that pins `GIT_CONFIG_NOSYSTEM=1`, an
  ephemeral `HOME`, `ulimit -t 5 -v 524288 -n 32`, and an allow-list
  regex for payload-derived paths.
- **S0.10** Telemetry payloads carry an HMAC-SHA-256 derived from the
  device key via HKDF (`info="defenseclaw-telemetry-v1"`). The
  `redaction.AssertNoCredentials` guard panics in dev / no-ops in
  prod when a known key prefix appears in egress payloads — defense
  in depth against a future refactor accidentally adding an
  `APIKey` field.
- **S0.1 (descoped)** ed25519 plugin manifest signing is deferred. The
  existing sha256-pin + symlink containment + perm check remain the
  baseline, augmented by an owner-UID check and an audit-pipeline
  `EventPluginLoadRejected` event. ed25519 signing tracked as a
  follow-up.

#### PR #141 audit follow-ups (additive security hardening)

These items land the seven security-floor fixes introduced in
PR #141 commit `45cf241d3cea4d90606de835a6746ae6a2b3270e` against this
branch's baseline. Each is additive — there is no removed protection.

- **C1** PATCH `/v1/guardrail/config` re-validates the gateway token
  inside the handler in addition to the existing `tokenAuth`
  middleware. A future refactor that exposes the handler outside the
  middleware chain will not silently re-open the bypass — mode
  changes (`action` ↔ `observe`) require an authenticated caller
  unconditionally. Returns `403` with a clear operator-facing message
  when the token is missing or wrong.
- **H1** Codex `Authenticate()` emits a one-time `[SECURITY]` line on
  stderr the first time loopback is trusted while
  `DEFENSECLAW_GATEWAY_TOKEN` is configured. Codex remains permissive
  on loopback because the codex-cli native Rust binary has no
  fetch-interceptor seam to inject `X-DC-Auth` (see the existing
  `TestCodex_Authenticate_NativeBinaryLoopback`). The warn surfaces
  the architectural gap without breaking codex routing. ZeptoClaw was
  already strict-reject post-B1 on this branch and needs no change.
- **H2** `Registry.RegisterPlugin` now returns an error when a plugin
  declares a name that collides with a built-in connector
  (openclaw / zeptoclaw / claudecode / codex). `DiscoverPlugins`
  surfaces the rejection on stderr and continues processing the
  remaining plugins instead of failing the boot. A malicious `.so`
  dropped into the plugin directory can no longer shadow-override
  the auth seam routed via `Get(name)`.
- **H4** OPA evaluator hardening:
  `rego.UnsafeBuiltins(http.send, opa.runtime, net.lookup_ip_addr)` +
  `rego.StrictBuiltinErrors(true)`. User-supplied Rego in policy
  bundles can no longer reach an outbound network primitive or leak
  build / host info, and silent builtin failures become hard
  evaluation errors so a banned builtin cannot noop into a `pass`
  verdict.
- **H9** `deriveMasterKey()` now uses PBKDF2-SHA256 with 100k
  iterations and a 32-byte (64-hex-char) output, replacing the
  previous single-round HMAC-SHA256 truncated to 32 hex chars.
  **BREAKING for any persisted `sk-dc-` value derived under the old
  algorithm:** those will no longer match the master key the proxy
  recomputes at boot. `sk-dc-` is an internal fallback credential and
  not the supported caller-side bearer; operators relying on it must
  re-read it from `gateway.log` after upgrade. Adds direct
  `golang.org/x/crypto` dep (was indirect).
- **M1** `isPrivateHost()` resolves hostnames through `net.LookupHost`
  and inspects every returned address before deciding whether to
  flag the host. The previous "skip hostnames" branch was a DNS-
  rebinding hole — an attacker-controlled DNS record could resolve
  to `127.0.0.1` / `169.254.169.254` and bypass the IP-literal guard.
  Lookup failures continue to fail-open (return `false`) to prevent
  legitimate-LLM-endpoint over-block; callers needing a hard
  guarantee must layer a network-level egress allowlist on top.
- **M5/M6** `redaction.ForSinkReason` is now applied to the
  `Details` field of `guardrail-inspection` rows the proxy writes
  directly to the audit store. The TUI still renders the unredacted
  reason via the logger path (operator local intent), but third-party
  sinks (Splunk forwarder, Loki, Cisco AID telemetry) inheriting from
  `audit.Store` no longer leak the matched literal. In `api.go` the
  `redactedReason` declaration moves above the `details` composer so
  the persisted row, the `gateway.log` line, and the sink-forwarded
  copy all carry the same redacted form.

### Connectors

- **C1 (S2.4)** Hard-coded per-connector `case` switches replaced by a
  generic `registerHookHandler` registration table. The gateway now
  iterates `HookEndpoint`-implementing connectors via
  `registerConnectorHookRoutes` instead of name-keyed dispatch in
  `api.go`. Adding a new connector is a single `registerHookHandler`
  call plus a `HookEndpoint` implementation. The follow-up move of
  the handler bodies (`claude_code_hook.go`, `codex_hook.go`) into the
  `connector/` package is deliberately split into a second commit per
  the plan's own commit-splitting guidance — the registration seam in
  `hook_register.go` already lets the relocation happen without
  touching call sites.
- **C2 (S2.5)** `HookScriptOwner` interface drives hook-script
  generation. `WriteHookScriptsForConnectorObject` is the new
  interface-driven entry point; the legacy package-level
  `connectorHookScripts` map remains as a backward-compatible shim and
  delegates through the connector registry.
- **C3** ZeptoClaw `before_tool` and Codex hook invocation are
  documented as **WONTFIX (architectural)** in
  `docs/CONNECTOR-MATRIX.md`. Both are limitations of the host agents
  (no settings-based external-script hook support); the proxy-side
  Route() path provides the actual security guarantee.
- **C4 (S1.3)** New `sidecar_watcher_matrix_test.go` exercises
  `resolveWatcherDirs` for all four connectors. The watcher correctly
  picks `~/.<connector>/skills` and `~/.<connector>/plugins` based on
  the active connector configuration.
- **C5 (S7.6)** New Python `cli/tests/test_install_smoke.py` runs
  `setup → disable → uninstall` round-trip across all four connectors
  with isolated `$HOME` contexts.
- **C6** `defenseclaw plugin list` now enumerates host-owned plugins
  for non-OpenClaw connectors. Each connector's plugin directories are
  scanned for manifest files (`plugin.json` / `package.json` /
  `plugin.yaml`); merged output labels each entry with `source:
  "defenseclaw"` or `source: "host"`.
- **C7** AIBOM (`defenseclaw aibom`) gains per-connector adapters for
  agents, tools, model providers, and memory. Filesystem-based
  enumeration only — no live tool-registry queries (deferred to a
  follow-up). Provider entries never leak raw API keys (only env-var
  names + base URLs).
- **A5** Removed dead `AgentRestarter` and `HookEventHandler`
  interfaces. Both had zero implementations across the four built-in
  connectors. Reintroduce as `S2.6`/`S2.7` if a real call site
  surfaces.

### Test Parity (Phase E)

OpenClaw's test footprint — 14+30 Go tests, 31+ Python files, a full
`scripts/test-e2e-full-stack.sh` Phase 7 — was significantly ahead of
ZeptoClaw, ClaudeCode, and Codex. This rollup brings the other three
to parity at the integration / acceptance / e2e tiers without adding
any production-code coupling between the four.

- **E1** Go integration parity: per-connector subtests added across
  `sidecar_test.go`, `proxy_test.go`, `gateway_test.go`,
  `connector_cmd_test.go`, `device_test.go`, `watcher/rescan_test.go`.
  Notable additions: `TestProxy_PerConnectorPrefixStrip`,
  `TestSwitchConnector_PerConnectorPersistsState`,
  `TestApplyRuntime_PerConnectorSwitch`,
  `TestHandleGuardrailEvent_OTelAgentName_PerConnector`,
  `TestConnectorVerify_CleanPerConnector`.
- **E2** Python CLI parity: new `test_zeptoclaw_config.py`,
  `test_claudecode_config.py`, `test_codex_config.py` exercise
  per-connector config shape, MCP enumeration, skill/plugin path
  resolution, and patch/restore round-trips. New
  `test_cmd_guardrail_matrix.py` parametrizes
  `guardrail status/enable/disable` over all four connectors with
  mocked `_restart_services`.
- **E3** Acceptance / `test/e2e/` parity: new
  `connector_lifecycle_matrix_test.go`,
  `v7_observability_connector_matrix_test.go`. Existing
  `TestConnectorVerifyCleanOnFreshDataDir` now covers all four
  connectors via `*PathOverride` seams. New
  `test/e2e/connectormatrix.go` provides the canonical
  `connectorMatrix(t)` fixture helper.
- **E3.4** S3.4 carry-overs: per-connector golden directories under
  `test/e2e/testdata/v7/golden/{openclaw,zeptoclaw,claudecode,codex}/`,
  new `goldenPathForConnector` helper, layout-locking
  `TestGoldenPerConnectorLayout` test. `assertThreeTierIdentity`
  doc comment block now enumerates all four connectors.
- **E4** Live shell e2e + GH Actions matrix:
  `scripts/test-e2e-full-stack.sh` gains `phase_connector_artifact_matrix`
  (Phase 2C) that asserts per-connector hook-script presence on disk.
  `.github/workflows/e2e.yml` gains a `connector-matrix` job with a
  `[openclaw, zeptoclaw, claudecode, codex]` matrix axis (fail-fast:
  false) that runs the four connector lifecycle / verify / OTel parity
  test packages on `ubuntu-latest`. The `e2e-required` gate enforces
  all four cells.
- **E5** Shared fixtures: new Go `internal/gateway/connector/connectortest/`
  test-only subpackage with `WithTempHome`, `SeedZeptoClawConfig`,
  `SeedClaudeCodeSettings`, `SeedCodexConfig`, `SeedSkillDir`,
  `SeedPluginDir`. New Python `cli/tests/connector_fixtures.py`
  with `make_zeptoclaw_config`, `make_claudecode_settings`,
  `make_codex_config`, `with_connector` context manager. Shared
  fixture data under `test/fixtures/connectors/<name>/`.

### Documentation

- New `docs/CONNECTOR-MATRIX.md` — canonical statement of by-design
  connector limitations (ZeptoClaw `before_tool`, Codex hook
  invocation), what the matrix supports today, and the proxy-side
  enforcement model.
- New `test/e2e/testdata/v7/golden/README.md` — explains the
  per-connector golden subdirectory layout and how it interacts with
  the connector-agnostic baseline.
- `docs/CONNECTOR-REMAINING-FIXES.md` — items resolved by this rollup
  (file locking, atomic writes, dead interface removal,
  HandleHookEvent stub) marked DONE; the remaining items continue to
  track what's deferred.

### Verification (Phase D)

The rollup is gated by a four-step verification suite:

1. `go test ./... -race -count=1` — must pass (locked-in test updates
   from Phase B already reflected in the codebase).
2. `cd cli && python -m pytest -x -q` — must pass (1419 + new tests).
3. `cd extensions/defenseclaw && npm test` — must pass (TypeScript
   plugin telemetry + correlation context).
4. **D4** S8.1/S8.2/S8.3 verification:
   - **S8.1** Codex env scoping: `~/.codex/config.toml`
     `[providers.openai].base_url` is patched; no global
     `OPENAI_BASE_URL` is exported to user shell rc.
   - **S8.2** Setup writes only the picked agent: a
     `setup guardrail --agent codex` run leaves `~/.claude/settings.json`
     byte-identical.
   - **S8.3** Observe mode: a known-block prompt under
     `cfg.Guardrail.Mode = "observe"` exits the hook with `0` and
     records a `would_have_blocked` audit entry.

   If any of the three regress, Phase F supplies a pre-staged fallback
   for re-implementation.

### Explicitly out of scope

- **ed25519 plugin manifest signing** (S0.1) — deferred.
- **ZeptoClaw `before_tool` hook wiring** — architecturally not
  feasible (host-side limitation); documented as WONTFIX in C3.
- **Codex external-script hook invocation** — host-side limitation;
  the `[hooks]` block we write is forward-compat, never invoked
  by today's `codex` binary.
- **Hook-handler body relocation into `internal/gateway/connector/`**
  (C1 second commit) — the registration seam landed; the 1.4 KLoC
  body move is staged for the follow-up to keep this rollup
  reviewable. No production-code coupling depends on the move.
- **Live tool-registry enumeration in AIBOM** — querying a running
  gateway / MCP servers for their dynamic tool listings requires a
  connected gateway, deferred.
- **Migration of `Config.ClaudeCode` / `Config.Codex` typed fields to
  a polymorphic `connectors.<name>.<settings>` keyspace** — separate
  refactor PR after this rollup lands.
- **`UninstallPlan.revert_<connector>` per-flag expansion** (E2/item 4
  literal wording) — superseded by the connector-aware
  `_connector_teardown(plan)` path that already dispatches via
  `--connector $name`. Per-connector teardown coverage lives in
  `cli/tests/test_install_smoke.py::test_smoke_matrix`.
