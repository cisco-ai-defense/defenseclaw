# DefenseClaw Changelog

This file preserves development rollups and historical change notes. It is not
a complete published-release index: the release workflow stamps isolated build
checkouts, so repository source metadata and headings can lag published tags.
Use [GitHub Releases](https://github.com/cisco-ai-defense/defenseclaw/releases)
for released versions and assets, and the
[documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/)
for current behavior.

## [Unreleased] — 1.0.4
- **Raw OpenShell MicroVM stop advice now names the gateway version that flushes the guest.** OpenShell 0.1.5 and later request a guest flush before a planned stop; on an older gateway, save the work first. A failed flush may still lose changes after the last successful disk sync.
- **Agent identity rows show only a current UPN.** Each hook replaces the row's `upn` with the UPN that the latest directory answer or guardian pass verified, or leaves it out. Profile matching is unchanged: during a directory outage it still uses the last good UPN that the Windows AD UPN cache and the guardian keep, and rows leave out that kept UPN. A later hook records the UPN again once a lookup verifies it. An unavailable lookup and an account with no verified UPN remain distinct in storage.
- **Sandbox readiness and recovery messages now reflect the current host state.** Setup and status report an ingress or egress port this daemon does not hold and name the port and restart step. Managed first-run readiness binds both listeners before installing OpenShell, so a busy port refuses without changing the account. A managed delete while sandboxes are off promptly names the administrator action needed before retrying; policy explain still shows a running-sandbox note when a healthy daemon answers slowly. Connect waits for a pull that is still starting the sandbox.
- **A disabled, unpinned OpenShell setup no longer blocks a 1.0.4 package upgrade.** Linux and macOS package ensures retain the committed config and running gateway and guardian while warning that the administrator must pin `enterprise.openshell.version` before enabling sandboxes. A committed setup change publishes its prerequisite record even when one user's LaunchAgent reports an error.
- **A plain Linux or macOS ensure no longer breaks repeat delivery of a confirmed signed bundle.** Repairing config drift records the confirmed bundle's principal and identity, and repeating the same bundle repairs an older unattributed generation even when its config bytes already match.
- **Windows restores a newly delivered signed config when its gateway never reports adopting it.** A gateway outage through the apply deadline no longer leaves that unproven candidate and an `applied` receipt pending indefinitely. A repeated confirmed bundle keeps its signed config during an outage and reports that this retry is unconfirmed.
- **Observe setup guidance now distinguishes policy findings from gateway outages.** Connector, getting-started, guardrail, profile and ACP pages explain that observe does not enforce policy findings, while default closed hooks, proxy outages and unevaluated managed ACP frames can still stop supported calls. The ZeptoClaw page also shows `--force` for removal of the last connector.
- **Windows keeps configured Claude Code, Codex and Cursor machine hooks installed with zero enrolled users.** Their protected enrollment state remains in force before the first enrollment and after the last user is removed, so an unregistered SID's hook call is refused. Reconcile restores policies left absent by older releases, including a deleted Claude Code policy or Cursor adapter without discarding still-enrolled SIDs; the guardian repairs later drift. Before Guardian activation, the lifecycle accepts authenticated, configured empty machine guards and rejects foreign or enrolled policy state. Verify machine policy after removing the last enrolled user; stop agent use until any missing policy is repaired.

- **Fresh local Edge and Splunk setup now reaches its service startup checks.** The Edge installer creates the system service account before enabling its unit, the local Splunk bundle uses a published image tag and reports registry resolution failures, and the MINIMAL Edge test reads the current policy page.
- **Connector setup and disable guidance now matches the installed hooks.** The CLI reference and hook connector pages say observe is the first-setup default and a re-run keeps the current mode. Turn-off guidance names the DefenseClaw entries or plugin removed while preserving unrelated settings, and the Claude Code page distinguishes a whole-guardrail restart from immediate connector teardown on a running gateway.
- **Cursor observe outage guidance now distinguishes registration from the running hook.** The user registration has `failClosed: false`, but the rendered hook blocks supported events during a gateway outage unless the config explicitly selects `open`. Managed Cursor registration follows the administrator's resolved fail mode.
- **Windows managed re-upgrade recovers after a committed 1.0.2 downgrade (GAP-0762).** Older Setups through 1.0.2 can leave a lifecycle journal when they encounter a prior open-mode runtime generation; a subsequent 1.0.4 Setup now retires that journal before upgrading and checks the old generation during its own cleanup. The rollback guide explains how to close managed hook fail modes before using one of those older Setups.
- **The rollback guide now distinguishes pending recovery on Windows, Linux and macOS.** Windows forces installed hooks closed only when its gateway is down and closure succeeds; Unix recovery leaves hooks on their configured outage mode. The guide names the Windows closure warning and each installer's recovery step.
- **Windows Hermes troubleshooting now states its effective hook fail mode.** It is closed by default outside Secure Client; only an explicit open mode permits a gateway outage on a managed host.
- **A downgrade to an older Windows Setup no longer fails while agents call their hooks (rel-1-0-4 GAP-0200).** The published older Setup replaces `defenseclaw-hook.exe` with one `[IO.File]::Replace` and rolls back when it fails. A running hook does not block that replace; the read-only checks 1.0.4 makes of the hook binary on each call did, because they opened it without delete sharing. They now share delete access and keep their identity checks, so hook calls stay fail-closed and the replace goes through.
- **A standalone Windows gateway does not start on an untrusted scanner runtime (rel-1-0-4 GAP-0490).** It checks the scanner Python tree before it starts, as every scan already did, and refuses to start when the tree fails that check. Install, upgrade, repair, ensure, reconcile and Setup's timeout recovery first remove such a tree before any service starts, and the run reports `scanner_runtime_untrusted_removed`; a Setup run then installs the runtime again from its signed payload.
- **Setup's recovery after `TIMEOUTSECONDS` reports only what it proved (rel-1-0-4 GAP-0501).** After it stops a timed-out lifecycle, Setup replays the pending transaction once, within 10 minutes, before it removes its staged files. It reports the recovered deployment only when no lifecycle record is left: a purge or install-rollback intent, a self-uninstall receipt, a managed-hook journal or a transaction folder is named instead, with the LocalSystem `/ensure` that recovers it.
- **A Windows install whose earlier restore was left unproven is no longer locked for good.** When a failed upgrade's restored gateway did not start, `install.ps1` kept its lifecycle record and required the recorded `config.yaml` bytes and every recorded connector, so a config fix or a removed connector blocked every later install, upgrade, repair and rollback until the record was deleted by hand. With no snapshot left, the installer now accepts those changes once the recorded binaries, the bin folder, the gateway's health and its policy digest of the live config are proven. When the gateway cannot report that digest, or a connector is gone while the config is unchanged, the error names `-AcceptCurrentInstall`, which keeps the config and connectors as they are now and still runs every other check. A connector that is not guarded although the gateway still lists it or the config still names it needs `-AcceptCurrentInstall`; a config edit does not prove its hooks. When an older release's installer replaced the recorded programs (for example `defenseclaw upgrade --version 1.0.2` run from 1.0.3), those programs are never started, and `-AcceptCurrentInstall` retires the record so the run installs its verified release over them. If the interrupted run was a first install and recorded no binaries, later added binaries are kept stopped, and `-AcceptCurrentInstall` keeps the record until the checked replacement is installed and proven; a failed or interrupted replacement still has a recovery path. The 1.0.4 installer no longer hands a version change to an installer that does not read the record while one is pending. The error's next step is a PowerShell command that works however the installer was run, including from `defenseclaw upgrade`.
- **A Windows lifecycle refused `lifecycle_busy` (1618) says to wait for the run that holds the lock (rel-1-0-4 GAP-0622).** It no longer says its recovery did not finish nor advises `/uninstall FORCE=1`, which would remove a deployment an upgrade is still changing; it names the command to run again once that run finishes.
- **Windows Setup `/repair` rebuilds a `deployment.json` that is not JSON (rel-1-0-4 GAP-0629).** Reading such a file no longer resets its permissions and reports no deployment, which left every later `status`, `ensure` and `repair` refusing them. `status` now fails, `ensure` stops with `ensure_refused` (could not read the installed deployment metadata), and Setup `/repair` rewrites the file from the installed deployment with administrator-only permissions. A `deployment.json` that parses but has drifted permissions is still refused.
- **Windows standalone Repair checks the installed gateway config before it rebuilds metadata.** When a running gateway still serves its last good policy but `config.yaml` can no longer parse, compile or satisfy the managed listener rule, Repair refuses with the services and `deployment.json` untouched. The refusal says to restore an approved, gateway-valid `config.yaml` and retry Setup `/repair`, or to run Setup `/ensure CONFIG=<approved config>` when deployment metadata is readable. The check uses the authenticated replacement gateway and also protects repairs whose metadata still parses; repairable installed config, runtime-root and bundle-store ACL drift proceeds to Repair's journaled ACL restamp and strict validation.
- **Windows Repair checks every startup config rule before stopping a running gateway.** Its rollback preflight rejects Windows managed peer-auth allowlists, unusable JSONL destinations, and untrusted policy or rule-pack paths outside Repair's ACL scope. It accepts ACL drift only on paths Repair restamps, including the protected credential store; a missing JSONL file directly under the runtime root inherits that root's repaired ACL. Refusals name the setting or path and the next step while the running deployment stays in place.
- **Windows standalone Setup /ensure refuses a non-loopback `gateway.api_bind` before any change (rel-1-0-4 GAP-0647).** Before, `0.0.0.0` was installed, failed with 1603, and its rollback and the recovering /ensure both refused the protected config while reading only its API port, so the transaction stayed pending with every service stopped.

- **Managed local scans and policy tests no longer need service-owned state.** JSON code scans use a process-local redaction key without opening the gateway audit database or correlation key; policy tests report no tests when an installed config-only policy has no Rego directory.
- **Invalid enterprise profiles keep the source version and field in diagnostics.** Non-string values are refused at `enterprise.profile` before profile resolution, and version-9 error JSON keeps `config_version: 9`.
- **Fleet policy versions always returns an array.** The empty SQLite-backed response now sends `versions: []`, matching the API contract and the in-memory backend.
- **The complete config example names its required credential inputs.** Supply the Galileo and Splunk variables before native validation, or omit those destinations.
- **The reference separates managed package commands from the per-user CLI.** It corrects policy export flags, workspace scope, discovery IDs and connector outage limits, and names the builds used for Intune delivery checks.

### Known limits

- Amp fail-open outages do not produce failure-file alerts. The fail-mode reference now distinguishes this reporting limit and the stricter managed standalone failure outcomes (GAP-0448, GAP-0451).

- On a managed standalone host with `foreign_hooks: remove`, guarded connectors (GitHub Copilot CLI, Cursor, Devin, OpenCode, Amp, Hermes) still block every tool call during a gateway outage, also under `hook_fail_mode: open`, as in 1.0.3 (GAP-0352).

### Changed
- **Guarded connectors keep the 1.0.3 outage limit (GAP-0352).** On a managed standalone host, Copilot, OpenCode, Hermes and every other foreign-hook guarded path block a call whenever the gateway cannot answer its session check, even when the administrator selected `hook_fail_mode: open`. An online allow does not authorize a later call during an outage. The gateway keeps its private session snapshots and the guardian records hook removals so an unapproved hook still blocks after removal until the agent restarts.

- `defenseclaw guardrail use-pack` re-pins a custom pack edited since it was pinned only with `--repin`, by name or by directory: it shows the pinned and the new digest, names every other connector, profile, the global pack or automatic-protection (`application_protection`) pack that shares the pin and so gets the edited pack too, lists every `config.yaml` edit it will make, and asks (`--yes` for scripts; `--json` without `--yes` refuses). It reads `config.yaml` once and saves only onto those bytes: if the file changed or was removed since, it saves nothing and says `config changed, run again`. If the file is missing or empty, it refuses. It never creates `config.yaml`. A plain `use-pack` refuses the stale pin, as in 1.0.3.
- The TUI's human-approval confirmation names the connectors in observe mode, which do not wait, and those with no native approval prompt, whose confirm verdicts raise alerts instead (Codex, for one). It asks "Set human approval to ..." instead of "Ask a human for ..." when not every connector it reaches asks a person.
- **Bare policy updates include connectors stored under an alias.** HILT, hook fail-mode and block-message commands resolve active names to their configured keys, so saved overrides and Protection center readback agree.
- **Refused action setup exits with an error before staging another mode.** Single, batch and guardrail setup keep the prior roster and hooks when action preflight fails; choose observe explicitly to stage observation.
- **The Overview gateway-down notice keeps its full recovery command at 80×24.** The approval guide also documents piped confirmation input and EOF accurately.

- **Guardrail profiles.** When several profiles are proven to match, their strictest combination applies. A request whose assignment needs an unproven identity fact is refused with that fact named. Upgrades from 1.0.0–1.0.3 keep existing `agents` assignments through a one-time migration map; no rebind step.
- **OpenShell 0.1.5.** `defenseclaw sandbox setup` and the managed `install: setup` mode now install NVIDIA OpenShell 0.1.5 (installer script and release tarballs pinned by SHA-256). What 0.1.5 also brings: a MicroVM flushes its disk before a stop, and a sandbox in OpenShell's error state (after a Docker restart, for one) can be stopped and started again, so the feed, the stop and start errors, `sandbox doctor` and the session messages now say `defenseclaw sandbox stop NAME` and `start NAME` instead of a delete. A sandbox whose provisioning timed out (`ProvisioningTimedOut`, `ImagePreparationTimedOut`), whose stop OpenShell refuses, is told to wait for OpenShell's cleanup and start again with no stop. The supervisor's OCSF log files are named `openshell-ocsf.*.jsonl` from 0.1.5; DefenseClaw does not read them. The first MicroVM start of each image after the upgrade prepares its disk again (about a minute and 5 GB); `sandbox image prune` removes the older release's disks.

### Security
- **Sandboxes run only on OpenShell 0.1.5 or later.** Before 0.1.5 the supervisor's network broker fell through to the native connect, bind, listen or send when it could not inspect a socket descriptor, so a sandbox's traffic could bypass its policy (NVIDIA/OpenShell#4494). 0.1.5 is now the oldest supported release (`SupportedMin`). DefenseClaw creates and starts no sandbox on an older gateway; it still connects to OpenShell 0.1.1 to 0.1.4 and the 0.1.5 prereleases (legacy, `LegacyMin`) only to list, stop, delete and pull from the sandboxes there, so a host DefenseClaw 1.0.0 to 1.0.3 left on one keeps their work, and the install step upgrades such a release in place instead of keeping it. The doctor's **Gateway** check fails there with the in-place upgrade as its fix; `sandbox setup` takes that upgrade by default (yes to its question, and `--yes`), `--install-openshell` runs it, and `--non-interactive` alone keeps the release and stops on the check. A sandbox that keeps running through the upgrade keeps the old supervisor, whose broker DefenseClaw cannot contain (withdrawing its proxy and the network rules DefenseClaw added does not stop the native fallback). DefenseClaw never stops such a sandbox on its own, on docker or a MicroVM: it closes its egress proxy, withdraws those rules, names it in the feed (HIGH `old_supervisor`), in `sandbox status` and in the doctor's failed **Legacy sandboxes** row as "legacy sandbox running, not protected by the 1.0.4 egress policy" with the command that ends it, and creates and starts no sandbox while it runs; `sandbox exec` and `sandbox connect` run nothing in it. The same goes for a sandbox whose 1.0.3 record names no release. Your own `sandbox stop` ends it (on a MicroVM it syncs first, since that release's stop does not flush the disk), and its next start runs the gateway's own supervisor (GAP-0415, GAP-0831). A failed stop no longer counts as a new session on the gateway's release. Managed `install: setup` hosts pinned to an older release (the `"0.1.3"` of 1.0.3) install 0.1.5 instead, each account switching once none of its sandboxes runs; in `prerequisite` mode an installed release older than 0.1.5 is a failed `ensure` row, and a user's `sandbox doctor` and `sandbox run` name it as installed and unsupported ("OpenShell 0.1.3 is installed, but that release is unsupported") instead of saying OpenShell is not installed (GAP-0266). A prerelease of 0.1.5 counts as older (0.1.5-pre.1 to pre.3 predate the fix), however it is reported (gateway, `--version`, rpm or deb version). A 0.1.5 CLI whose older gateway still answers fails the **Gateway** check too, with the gateway restart as its fix, instead of a version-skew warning that let setup finish. The automatic switch of a managed account (the pin move included), a sandbox daemon's own gateway stop and pending restart, the per-user in-place upgrade, and the gateway restarts that `sandbox doctor --fix` and `sandbox setup` make go ahead on the MicroVM driver only once OpenShell's own state reports every sandbox on the gateway stopped, deleting or gone (its VM process exited); a running, starting, stopping or unknown sandbox, a completed MicroVM and one in any other error state (its VM keeps running, with whatever its workload left running) refuse them, on every release. Nothing is inferred from elapsed time or from a stop OpenShell did not make, and DefenseClaw stops nothing itself: the refusal names each sandbox with the exact command that brings it to stopped (`defenseclaw sandbox stop`; on an older OpenShell, `delete`), and `sandbox stop` of an ended MicroVM says the same. For a completed or failed MicroVM on 0.1.5 it says what each way costs: nothing in OpenShell writes its disk back, and its start ends the VM with no flush first, so what it has not written is lost. `defenseclaw sandbox start`, `connect` and `pull` therefore refuse to start such a MicroVM, and `start --end-vm` starts it knowing that (then `stop`), or `delete` removes it with its work. Each of them checks again right before it acts: the restarts and the upgrade under a lifecycle lock, the daemon's gateway stop under its own lifecycle after a fresh read of the gateway, and a managed account's switch, stop or LaunchAgent reload under a drain that runs as the user and holds the user's lifecycle lock until the units are stopped. A check that cannot read the gateway (no registration, broken certificates, a gateway that refuses every call) refuses too, unless no MicroVM process runs as the account. From their check to the healthy gateway, those restarts and the in-place upgrade hold a lock that keeps DefenseClaw from creating or starting a sandbox.

- Windows signed-bundle rollback now requires the confirmed bundle ID and version as well as its policy and generation; a failed nested ensure cannot report a successful rollback (GAP-0445).
- Standalone Windows `enterprise windows status` fails, naming the file, while a payload file the deployment records (such as a quarantined `bin\defenseclaw.exe`) is missing or replaced, as verify does (GAP-0665).

- **Secure Client hooks use their installed fail mode.** The Antigravity, Devin, Hermes and Kiro shell hooks no longer let an agent's `DEFENSECLAW_FAIL_MODE` environment value reopen a closed installed hook. Secure Client delivery requires a root-owned macOS or SYSTEM-owned Windows installation marker; an unverified host keeps the closed posture.
- **Windows scanner Python imports require protected access lists.** Before an elevated prepare or a service scan runs Python, DefenseClaw checks every runnable file and folder in the scanner runtime, including `Lib\site-packages`, and refuses a standard user's create-file or write grant. Status reports the offending path and the standalone Setup `/repair` route.
- **A sandbox is no longer stopped or deleted under a session that attaches during the stop.** A session end, `sandbox stop`, `sandbox delete`, a pull that stops its copy again and a failed connect now count the attached sessions and call OpenShell under one per-sandbox lock that every attach also takes; an attach that comes second finds the sandbox stopped and says to run `defenseclaw sandbox connect NAME` again, and a count that cannot be made keeps the sandbox running. A gateway rollback that finds a sandbox started by raw `openshell` aborts with the active gateway files and the pending restart kept, and names `openshell sandbox stop NAME` and the command to rerun; a raw `openshell` start during a rollback is unsupported.


### Fixed
- **Recovered hook evaluator errors follow the closed panic posture on standalone managed hosts.** An administrator's `hook_fail_mode: open` applies to eligible gateway outages, not an evaluator panic. Recovered panics block advisory events too. On stop, session-end and idle events a recovered panic never makes the agent repeat the hook: Claude Code ends the turn with a visible reason, every other connector (Codex, Cursor, Copilot, Devin, Kiro, OpenCode, Antigravity) gets its neutral allow, and the audit row records the panic. A Claude Code `TeammateIdle` policy block keeps its exit-2 feedback.
- **Every native hook answers closed during a per-user install or upgrade, its early answer too (GAP-0862).** The hook command arms its answer watchdog before it resolves its runtime, and a hook registered with `--fail-mode open` prepared the fail-open answer there. When that resolution stalled past the 3.5-second answer deadline while `install.sh` or `install.ps1` held `.install.lock`, the watchdog allowed the tool call before the hook read the lock. The watchdog now reads the lock (in `DEFENSECLAW_HOME` when set) when it is armed and again at the deadline, and answers closed when the lock is held or cannot be read within 100 ms; the hook's own install check also treats a lock it cannot read as held. A Kiro hook that fails before it runs (an unknown flag) exits 2 during an install.
- **A call already waiting for the gateway when an install or upgrade starts is blocked too (GAP-0893, GAP-0894).** A per-user hook in fail mode open read `.install.lock` only when it started. When `install.sh` or `install.ps1` took the lock and stopped the gateway while a call waited for its answer, the shell hooks and the OpenCode plugin let the call run. Every hook form (the shell hooks, the native hook, and the OpenCode and Amp plugins) now checks the lock again when a failure answers: a dropped or refused connection, an HTTP error, an answer without a verdict, a payload too large to inspect, or a missing hook credential. While the lock is held the call is blocked; without it the account's fail mode still applies.
- **Per-user OpenCode and Amp name the gateway when they block during an outage (GAP-0850).** A closed per-user plugin whose gateway was stopped showed only the runtime's network error (`DefenseClaw hook failed closed (fetch failed)`, or Bun's `Unable to connect`). It now says why the gateway did not answer: an install or upgrade, a `defenseclaw-gateway stop`, a gateway that is not running, not answering in time, or answering HTTP 5xx. It also gives the command that brings the gateway back and ends with the runtime's error.

- **`defenseclaw doctor --passive` no longer fails a valid Windows Hermes registration.** Passive mode does not list processes, so Hermes hosts that may need a reload are a warning there, as on Unix; the full doctor still fails when a Hermes host is running or cannot be ruled out.
- **The Cursor and rollback guides now give the recovery steps the commands perform.** A refused Cursor action setup leaves configuration unchanged; observation requires an explicit setup command. On Windows, a failed rollback is undone, and pending recovery uses the installer command printed with its error.
- An interrupted Windows upgrade refuses to continue when gateway recovery fails, including on another retry. Restoring a snapshot now checkpoints and verifies required data and environment moves, retains recovery state on failure, and verifies an external config before reporting recovery (GAP-0444, GAP-0450).

- **A refused proxy-provider setup restores the vendor configuration.** Provider verification now runs before setup is published as ready and rolls back a failed prerequisite. Correcting a ZeptoClaw provider key and retrying no longer reuses a stale blank-key snapshot or leaves an orphaned localhost redirect.
- **Webhook tests and scoped setup report the right result.** Generic synthetic events include the sending host in the signed body. Connector-scoped adds no longer inherit global names or overwrite warnings, and a PagerDuty test with an unset routing key exits with a short error, including in a dry run.
- **Managed provenance no longer prints an empty CLI snapshot.** The Unix administrator command reads the running gateway over its protected socket and verifies the listener's kernel identity on that connection. Missing or incomplete state refuses with the deployment status command. Linux profile-validation errors explain reinstall recovery; personal gateway startup names unsafe JSONL destinations before spawning a daemon; Windows sandbox hints name the gateway executable; profile explain omits an unproven directory source for an unnamed numeric gid.
- **Hidden credential reads in MCP descriptions produce findings.** The bundled YARA pack detects instructions to read home credential files and exfiltrate their contents or conceal the access, including the managed as-user scan's previously missed description. Ordinary tool documentation has negative controls, and the scanner SDK reports the new finding as HIGH.
- **Personal Claude Code hooks decode successful responses with one parser process when jq is available.** The response must be one JSON object with a known action and structured native output. The existing jq-free path remains supported.
- **Windows standalone teardown returns kept agent config files to their owner's control.** Only verified removal releases the guardian's owner-rights restriction; failed teardown retains protection. File inspection and the DACL update use the same no-follow handle, rejecting unproven owners, reparse paths and hard links without relaxing DefenseClaw's retained state.
- **A Windows standalone uninstall refuses a lasting file holder before it commits.** A program that keeps a file in `C:\Program Files\Cisco\DefenseClaw` open for 60 s now fails the uninstall with `uninstall_in_use`, naming it, before the services and hooks are touched; before, the uninstall failed after it had removed them. Hook calls and short scans do not block it.
- **The administrator's open covers gateway outages only, for rate limits and shell hooks too.** On a managed standalone host a call the gateway answered with HTTP 429 now blocks when no verdict follows its resends, also under `hook_fail_mode: open`; before, running out of answer time after a 429 counted as an outage and let the call run. On Linux and macOS the Antigravity, Cursor, Devin, Hermes and Kiro shell hooks also block an error status, an unusable answer and input too large to inspect under `open`, as the native hook already did.
- **The fail-mode command describes its apply step accurately.** Help and the reference now explain that the default refreshes and verifies hook registrations directly where supported, and restarts a running gateway only when full connector setup is needed.
- **Sandbox hook outages leave a persistent failure log.** Shell hooks now write to the workload data home instead of the read-only runtime, including neutral Stop answers and closed prompt or tool-call failures.

- **Local Splunk setup reports a failed prerequisite.** Missing Docker, a stopped daemon or a busy port now exits nonzero in both command and wizard setup, before local Splunk configuration is written.

- **Rollback guidance explains a stopped gateway.** When both the current and saved gateway states are stopped, rollback leaves the restored gateway stopped and the upgrade guide names the command to start it, including 0.8.x round trips.

- **Local Splunk starts under a private umask.** Both packagers make the nonsecret app archive readable by the container. Setup reports ready only after the installed app, Web UI and HEC are available, and refuses incomplete startup with a repair command.

- **Local and remote Splunk credentials stay separate.** Local Splunk setup records the container it started in the destination it creates (`local_stack` in the destination's config), and only that destination is local: disable, status and a rerun of local setup act on the record, never on an address, so a remote Splunk through a loopback tunnel stays remote. Each remote Splunk destination stores its token under its own reference (`DEFENSECLAW_SPLUNK_HEC_TOKEN_<NAME>`), so one setup never changes another destination's token, and `setup splunk --enterprise` takes the token only from `--hec-token`, `DEFENSECLAW_SETUP_SPLUNK_HEC_TOKEN` or the prompt, no longer from a saved `DEFENSECLAW_SPLUNK_HEC_TOKEN`. A local destination from 1.0.3 or earlier has no record, counts as remote and keeps working; local setup will not take it over, and names the `setup observability remove` command to run first. Local setup checks the destination name against the address in the bridge's env file and checks for a shared local credential reference before it touches the stack. `setup splunk --disable --logs` does not stop the local container while an unrecorded destination is enabled; neither `--logs` nor the combined disable stops it if a destination write fails, and the command names each destination to resolve.

- **Copilot on Windows denies an invalid hook event binding.** Missing, empty, unknown or wrongly cased bindings receive both native denial shapes with the setup command before input or runtime checks. Secure Client delivery is unchanged.

- **HILT previews explain observe mode.** A connector in observe mode does not pause actions for approval; the preview distinguishes the saved policy from action-mode prompts. The connector preview also names the guardrail profiles that put the connector in a different mode or set their own HILT policy, so accounts on an action-mode profile are told they will be prompted. The preview takes the hook mode and HILT from the gateway's own resolver (`defenseclaw-gateway connector hilt-preview`), so a legacy `claude_code.mode`, `codex.mode` or `connector_hooks.<connector>.mode` that keeps a connector in action mode under an observe guardrail mode is shown as prompting. When the gateway cannot answer, the preview says so instead of guessing.

- **Rule-pack switches preserve existing pins.** Selecting a directory keeps its registered identity and refuses a stale digest through any alias. Pins used by application protection survive a global pack switch.

- **Managed macOS policy repair removes writable directory modes.** Repair strips group and other write permission even when the directory already has enough read and search permission, including after ACL repair.
- **Administrator code scans use the verified deployment's existing redaction key.** Root scans accept the proven service account's key without changing its bytes, owner or permissions. Path aliases cannot select a different key; missing or untrusted custody still refuses with the installed repair command.
- **RPM storage failures preserve the last complete package result.** The scriptlet reports a storage problem and the ensure retry command, and does not infer that no deployment is active from a missing result.
- **Windows trust-anchor refusals are audited during profile preflight.** Elevated callers on verified installed standalone hosts get the refused change event even when incompatible arguments stop the command before bundle preparation.
- **Ordinary Claude Code settings edits keep exporter custody verified.** Doctor compares the managed exporter environment and credential helper with Setup's exact snapshot; changed endpoints, headers, helpers or intentional absences still report drift.
- **Disabling an unused Local Splunk integration needs no Docker installation.** On Windows, the bundle seeded during installation does not count as a configured stack. Existing runtime credentials and configured destinations still require ownership verification before stopping anything.
- **Rejected reloads appear in local audit history.** Schema and policy generation refusals emit the mandatory `config.reload.rejected` event through the active configuration, without recording rejected values.
- **Validation errors name a profile selector once.** Structured errors carry the selector path separately from the correction text.
- **Disconnected closed hooks retain a truthful denial audit.** A client that disconnects before finalization gets the fail-mode decision in its audit row; stop events and Secure Client retain their existing behavior. A gateway decision still does not prove that the agent received it.
- **MicroVM disks of OpenShell 0.1.4 and later are found again.** From 0.1.4 OpenShell names each prepared MicroVM disk by a hash of the image ID (NVIDIA/OpenShell#4342), and `sandbox image rm`, `image prune`, teardown and the first-start disk check did not recognize those names, so the disks (about 5 GB each) stayed behind. Both naming forms are recognized now.

### Removed

- The OpenShell 0.1.3 tarball pins: the managed `install: setup` mode installs 0.1.5 for that pin (see Security), so they were unreachable.
- The managed `install: setup` mode no longer re-signs the macOS MicroVM driver ad hoc with Apple's hypervisor entitlement: every release it can install (0.1.5) ships the driver signed with it, so the shim never ran.

## [Unreleased] — 1.0.3

### Documentation website

- **Avoid loading a large search index on every page visit.** Search now initializes when opened, uses a smaller word-prefix index with compact record IDs, and has a 32 MiB decoded build limit to guard against mobile tab reloads. Page text and heading links remain searchable.

### Upgrade note for 1.0.3

- Existing managed standalone 1.0.2 configurations with webhook URLs or literal provider and destination credential headers continue to load after upgrade. `status` and `verify` warn with the affected paths and credential-reference guidance. New administrator input refuses credential-bearing headers; non-secret provider headers and webhook URLs remain supported. `defenseclaw-gateway config validate` refuses the same candidates as `ensure --config` and prints the advisory for the installed config.

### Known limits

- Managed Claude Code and Codex block a shell command with more than 512 write targets or 64 KiB of target paths. The refusal says DefenseClaw blocked the action under your organization's policy. Split the command into smaller calls. Per-user mode is not affected (GAP-0291).
- On Windows, a sustained flood of 3 to 10 hook calls a second on a disk with slow scattered writes can delay hook answers by seconds. The audit WAL now uses bounded catch-up (see Fixed), but a call that waits beyond its answer budget follows its effective fail mode: the default `closed` blocks it; a managed administrator's `open` can allow only a classified no-answer outage, and a call of a guarded connector (`foreign_hooks: remove`) still blocks (GAP-0352). Faster audit writes remain a later improvement.
- A tool call that DefenseClaw allowed while the gateway was running still runs if you approve it in the agent after the gateway stops. Every call checked while the gateway is down is blocked.

### Added

- **Sandboxes behind a TLS-inspecting proxy (#1296).** `openshell.trusted_ca_bundle` names a PEM file of CA certificates (a corporate proxy's root) that sandboxes trust besides the image's public roots: every harness image built while it is set carries them in its system store (the build's own npm, pip and uv downloads trust them too), and each sandbox points `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS` and `DENO_CERT` at OpenShell's CA bundle plus them, so Node, Python, Go, Rust, curl and git trust them. The agents' model calls are made by OpenShell's sandbox supervisor with its own trust store, so the model provider hosts must be exempt from TLS inspection; a sandbox's model provider host stays open only to the agent's own programs, and `sandbox unblock` of it says so. On a managed computer the administrator sets it in the admin `config.yaml` (an administrator-owned file) and the managed gateway hands the certificates to each user's sandbox daemon; a user cannot add one. Nothing is imported from the computer's own store. A file that cannot be used stops image builds. A new `sandbox doctor` row, Sandbox TLS trust, fails by name while a model provider host is TLS-inspected, and `sandbox setup` shows it. The image records keep the fields DefenseClaw 1.0.2 reads, so a downgrade keeps the sandbox service running. `defenseclaw upgrade --version 1.0.2` sets the key aside (1.0.2 does not have it) and a later upgrade puts it back.

### Changed

- **The audit store keys hook records in time order (rel-1-0-3 GAP-0320).** New audit rows, scan results, judge, sink and egress rows, evaluation and scan IDs and every v8 record ID are UUIDv7s instead of random UUIDv4s, so each lands at the end of its index instead of on a random page. A Claude Code `PreToolUse` now changes 14 existing pages of `audit.db` instead of 26 (WAL analysis over 100 calls after 3,000). Correlation identifier, relationship and evidence IDs keep the 1.0.3 form (a digest of their fields), so after a rollback to 1.0.3 a late delivery still attaches to the rows this release wrote. Two correlation indexes that duplicated the leading columns of a unique index (`idx_correlation_identifiers_exact`, `idx_correlation_receipts_source`) are dropped when the gateway opens the store (a Secure Client store keeps them). No table is rebuilt and the schema version does not move: an upgraded store keeps every row and its IDs, and an older binary still opens it.
- **Hook fail modes: open under Secure Client, closed everywhere else (owner rule).** Under the Secure Client profile hooks fail open: an unset `guardrail.hook_fail_mode` resolves to `open` for every connector, Codex and Claude Code included, in observe and action mode (#1163), and an explicit `closed` is kept. A Secure Client hook in open mode allows a call when its gateway is unreachable, its gateway service is stopped or its answer cannot be used, and records the failure; GitHub Copilot does too. Only an authenticated Secure Client deployment gets this: the profile the protected config resolves, and on Windows a host whose Secure Client installation, deployment record and gateway service check out; a process that only carries the Secure Client profile does not. Everywhere else an unset fail mode is `closed`, in observe mode too (per-user Cursor registers hooks by guardrail mode, while its running hook keeps the closed outage default unless the config explicitly opens it). An explicit `hook_fail_mode` (global, per connector, under `application_protection`) or ACP profile `fail_mode` is always honored, on a managed standalone host too, MDM-managed ones included: there the value is the administrator's (the managed config only root or SYSTEM can change), and the managed hook runtimes take it from administrator-owned state (the runtime descriptor on Linux and macOS, the runtime generation on Windows). Earlier 1.0.3 builds ignored `open` on a managed standalone host and warned `fail_open_ignored`; that override and its warning are removed. Refusals that are not an outage (an invalid managed runtime, an unverified gateway peer, a missing token, an unenrolled account, an unapproved hook the foreign-hook guard finds) still block. On a managed standalone host `open` applies only to an outage (the gateway service not running, still restarting, or not answering in time); oversized tool input, a gateway error status, an unusable answer and other transport errors block in every fail mode, for every connector. A guarded connector (GitHub Copilot, Cursor, Devin, OpenCode, Amp, Hermes) with `foreign_hooks: remove` blocks during an outage, including under administrator `open` (GAP-0352 above). The config_version 9 migration keeps a managed config's Cursor fail mode as written instead of rewriting it from the guardrail mode.
- **Protected-file write checks read static local AWK program files.** An `awk -f` file with a protected write is blocked even when its input operands are fixed. An unreadable or out-of-bounds program file is blocked conservatively. Nested shell `-c` calls with login options use the same write target resolver. A fixed read-only AWK program with a private-key file operand retains the private-key read rule.
- **Protected-file write decisions cover visible AWK output and PowerShell statement lines.** A dynamic AWK input no longer hides a literal protected output, a shell-expanded AWK output is treated as unproved, and PowerShell writes after a newline are checked. Git worktree updates invoked from a subdirectory are scoped to the repository root. Ordinary writes with proved destinations remain allowed. Separate script file contents are outside the tool-call write check.
- **The first 1.0.3 `ensure` restores a managed Cursor fail mode the 1.0.0-1.0.2 migration opened.** Those releases' config_version 9 migration rewrote a managed standalone Cursor `hook_fail_mode` from the guardrail mode (observe became `open`); it had no effect while managed hooks always ran closed, but 1.0.3 honors it. When `migration-v9.json` records that rewrite and `config.yaml` is still the migration's output, `ensure` (Linux, macOS, and the Windows config step) sets the value back to `closed` through the managed config writer, records it under `repaired` in `migration-v9.json` so it runs once, and says `restored guardrail.connectors.cursor.hook_fail_mode to closed: the 1.0.x v9 migration had rewritten it to open (not an admin choice)`. An `open` the administrator writes later stays; per-user and Secure Client configs, and a config a signed policy bundle installed (its config generation names the bundle, or a bundle is current), are untouched. Integrity refusals stay closed whatever the managed fail mode: a gateway refusal of the hook's credential (HTTP 401 or 403, also when its body is cut off or too large) and a Codex or GitHub Copilot call that does not match the event or contract the hook was registered for. A managed GitHub Copilot hook bound to no reviewed Copilot event answers with Copilot's `preToolUse` and `permissionRequest` denies instead of an allow, and `verify` reports a DefenseClaw Copilot policy hook registered for an event DefenseClaw does not publish (ensure rewrites it). A recovered evaluator error follows the connector's resolved fail mode, so an explicit `closed` blocks under Secure Client too. An ACP `fail_mode: open` applies only to the session whose authenticated verdict reported it, an ACP answer that fails authentication is always refused, and an observe-mode ACP profile may set `fail_mode: closed`.

### Fixed

- **The audit log stays bounded during a hook flood on a slow disk (rel-1-0-3 GAP-0320, Windows half of GAP-0136).** Once the log in use passes its 256 MiB limit, the gateway's checkpoint goes straight to a bounded hold: it waits up to 1 s for the audit writer and SQLite's write lock, so a CLI command or another process that writes `audit.db` waits too, and holds them until the log is copied into `audit.db`, at most 2 s, so the log starts again from its beginning instead of growing until the disk is full. A hold that could not finish (no free writer in time, or a copy longer than the cap), or a checkpoint pass that ran out of time while the log was over the limit, doubles the next one's wait and cap, up to 10 s and 30 s, until the log restarts. Hook writes wait that long meanwhile, and the gateway log says `audit WAL over its 256 MiB limit (N MiB): held the audit writer for ... of up to ...`. In GitHub's Windows runners the file peaked at 0.3 GB at 3 calls a second, 0.5-0.7 GB at 5 and 0.9-1.2 GB at 10, against 1.3, 4.7 and 9.5 GB for 1.0.3. Linux and macOS stay under the limit at 10 calls a second, so they never wait for it. Secure Client gateways do not run this check in 1.0.4.
- **A hook call whose audit record cannot be written is blocked (fail closed).** When the gateway could not write a verdict's audit row (a full disk, or the audit store busy past its timeout and retries), it still answered with the allow it had computed, so the call ran with no record. Such a call now follows the connector's hook fail mode, like a failed check: `closed` (the default everywhere but Secure Client) blocks a tool or prompt call with "DefenseClaw could not complete its hook check because it could not write the call's audit record"; `open` (Secure Client's default, or an explicit `open`) keeps the verdict. A block stays a block, and session-ending events and events the agent cannot block are not changed. The gateway log says `hook audit persistence failed`.
- **The Tetragon kernel controls deny again on Tetragon 1.7.0, and status no longer calls an unmarked session denied (GAP-0218, GAP-0166).** Tetragon 1.7.0 runs only the last entry of an LSM hook that a policy lists twice, and the controls and observe policies listed `file_open` twice, so only their directory selectors ran. Each DefenseClaw policy now has one `file_open` entry, lint refuses a second, and a monitor controls policy anchors at most four live sessions (`kernel_roots_over_limit` beyond). A native agent session counts as anchored only once Tetragon reported its start on the event stream; until then its user is `armed` with `kernel_unconfirmed` and `kernel_sessions_unconfirmed` counts it.
- Managed sandbox policy allow and block commands now save a host decision through the gateway. Policy explain shows the action for other sandboxes and MCP inclusion counts. Python validation checks profile sandbox limits consistently with the gateway. Relayed hook failures and trace parents reach the managed observer. Detached Claude Code continuation and OpenCode launcher refusals have actionable session messages. A saved managed allow that the organization's current profile floor no longer keeps stops applying in a running sandbox as soon as the policy change reaches it, and a sandbox that starts again runs under the current minimum profile instead of the looser one it was registered under.
- Inventory Summary now scrolls by keyboard at 80×24, Overview notices show their full action, and managed `sandbox policy explain` repeats the profile, match and agent after long settings tables.
- **A managed purge backs up a user's own DefenseClaw install from before the enrollment (Linux and macOS).** `enterprise linux|macos uninstall --purge` (and the MDM `uninstall.sh` with `DC_PURGE=1`) deleted all of an enrolled user's `~/.defenseclaw`, also the config, secrets, audit history and policies of a personal install that predated the managed deployment. When `~/.defenseclaw` holds such an install, the purge now first moves its data, as the user, to `~/.defenseclaw-backup-<UTC time>` with a `DEFENSECLAW-BACKUP.txt` that says how to restore it, and names the backup in its result; hook scripts, hook credentials and the Python environment are not kept. If the move fails, that user's state stays (#1299).
- **A purge keeps the session cache of a user whose state it keeps.** A purge that left a user's per-user state for a pending hook cleanup still deleted that user's `~/.defenseclaw/session-facts.json` (GAP-0582).
- **An enrolled user whose home folder is gone no longer blocks the managed uninstall (Linux and macOS).** A manifest row whose home was deleted or moved away (a macOS mobile account's home, say) is reported as already clean with a `per_user_hooks_remaining` warning that names the home; a row that names only that home no longer fails the hook-removal precheck, and the purge no longer asks to be rerun for it (#1287).
- **Package removal stops every signed-in user's sandbox daemon (Linux), and the macOS uninstall unloads the sandbox LaunchAgents of every signed-in account.** `apt remove`, `dnf remove` and `rpm -e` deleted the sandbox user units while an account's socket still listened, and the daemon it started failed `203/EXEC` on the deleted binary in a loop. The pre-remove script now stops the sandbox units in the user manager of every account that runs one, also when the account lookup does not answer, and removes the socket's global enable link; a user manager that still runs a unit, or does not answer, fails the removal and the package keeps its files. On macOS the uninstall, also of a package that never turned sandboxes on, boots both LaunchAgents out of the `gui` and `user` domains of every account with a running process, so none stays loaded from a deleted plist (#1210).
- **The Linux MDM purge removes the empty staging folder.** `uninstall.sh` with `DC_PURGE=1` left the empty root-only `/var/lib/defenseclaw-mdm` the wrapper created; it now removes it when it is empty and root's own directory (#1298).
- **MicroVM first starts check their actual disk headroom (GAP-0252).** Doctor and the start preflight use the observed 11 GiB first-start peak with a 12 GiB free-space floor, and the warning names that peak. This prevents a host with roughly 6–10 GiB free from reporting ready before a new MicroVM disk nearly fills it.
- **The skill and plugin watcher no longer creates vendor system folders.** A gateway running as root (for example under a privileged helper) created `/etc/codex` with mode 0700 on macOS so it could watch `/etc/codex/skills`; Codex treats an existing `/etc/codex` as an administrator policy layer and, unable to read it, paused every launch with "Organization settings could not be loaded". An absent folder under `/etc`, `/private/etc`, `/Library` (or `%ProgramData%`, `%ProgramFiles%` and `%SystemRoot%` on Windows) is now watched once an administrator or installer creates it, like an agent-owned folder (GAP-2354), and `ensureAndWatch` refuses to create one.
- An aborted Windows rollback restores hooks converted for the older release, including when the gateway was stopped. Restoration verifies the exact published file and retains recovery evidence when it cannot establish ownership.
- Windows version changes refuse active connector transactions before capturing rollback data or switching versions, so pending receipts cannot become stranded in a saved snapshot. Rollback also checks saved data before starting an older reader. Retrying a rollback after a receipt move failure keeps the live runtime and settings intact. A failed gateway restart after an installer handoff reports failure with rollback and restart instructions.
- Windows connector setup preserves ordinary NTFS extended attributes when replacing an agent's settings. Windows can invalidate its own `$Kernel.Purge.*` cache attributes after a content change; those attributes no longer make a completed replacement look like a foreign edit. File identity, permissions, content, and recovery checks remain enforced.
- A failed Windows upgrade keeps connector recovery receipts before removing the failed runtime, including when restoring the retired 0.8.x Setup installation. The installer reports the private recovery archive instead of discarding evidence for partially updated agent settings.
- Windows per-user skill scans use the scanner pinned in the current installation, so an older unrelated `skill-scanner.exe` on PATH cannot shadow the managed launcher. Broken installer identity or missing scanner files fail closed; unrelated executables are preserved.

- Per-user setup now refuses a guardrail switch to an unregistered connector, verifies every connector in a batch, and names an unsafe OpenCode plugin folder. Config writes accept finite floating-point values, and status JSON includes healthy hook connector state. Gateway token edits keep CLI audit and restart aligned with the running gateway; an unset export secret no longer strands uninstall.

- **A recovered hook evaluation error fails closed on a standalone managed device.** Before this fix an internal evaluator error followed the configured guardrail mode and fail mode, so on a standalone managed device a tool or prompt call was allowed in observe mode, or with `hook_fail_mode: open` (guardrail or `application_protection`) for every agent except Codex, Claude Code and Devin. It now gets the agent's native deny there in every guardrail mode and whatever `hook_fail_mode` says, as when the gateway gives no verdict; a stop or session-end event keeps its neutral allow. Per-user installs and the Secure Client profile are unchanged.
- **Linux and macOS MDM wrapper: a base config must match the signed bundle's guardrail block and hook modes.** A config delivered with a signed bundle is now the base config: the wrapper compares its `guardrail:` block with the bundle's (only `custom_packs.<pack>.path` may differ) and its `claude_code:`, `codex:`, `connector_hooks:` and `application_protection:` blocks (equal, or absent from both), and refuses a mismatch with `mdm_base_config_mismatch` before anything is installed. It then applies the base config before the trust anchors and the bundle, so while the first bundle is pending the hooks answer under the compared blocks. The comparison needs `tar`; without it the wrapper refuses with `mdm_tar_missing`. The comparison reads the configs as text, so the wrapper also refuses a base config that writes a top-level key other than plainly in lowercase (a tag, anchor, escape or `?` key) or continues a quoted value or a `{...}` or `[...]` on the next line. The base config must also be plain ASCII with LF or CRLF line endings (one UTF-8 byte order mark at the start is allowed): the YAML loader also starts a line at a lone CR, NEL, LS or PS, which the text comparison did not see, so the wrapper refuses any other byte, even in a comment. The Intune Windows packager compares the same hook mode blocks and applies the same byte and spelling rules, reading the raw bytes (GAP-0090). The docs give the install order: package and bundle in one script.
- **Intune Windows base installs must carry the signed bundle's guardrail policy and hook modes.** The bundle packager now refuses a missing or weaker base config, or one whose `claude_code:`, `codex:`, `connector_hooks:` or `application_protection:` block differs from the bundle's, before creating content; the Remediations health line names whether a signed bundle or the installed config enforces (GAP-0105).
- **Intune macOS script preview accepts signed bundles and Windows-edited wrappers.** The tenant helper now accepts an empty inline config when the wrapper contains a signed bundle and trust anchors, converts CRLF line endings to LF before upload and hashing, and rejects incomplete, conflicting or unsafe settings before Graph calls (GAP-0097). The macOS size guidance now states the 1,100,000-byte probe accepted and executed in one tenant on 2026-10-14, without claiming an unmeasured ceiling (GAP-0099).
- Managed gateways record a `compliance.activity` `sandbox.registration_without_guest` alert, with no outcome or decision change, when a registration bound by a build with this signal is used or reported running after grace without an accepted guest record since bind. A first accepted record ends the watch, so later guest disappearance is outside this tripwire for the simple case (GAP-0178). Registrations bound before the upgrade to 1.0.2 (for example by 1.0.1) are not watched; re-create those sandboxes after the upgrade to bring them under the signal. Root-owned attestation in a later release replaces this signal.
- The 0.x observability migration now omits the unchanged, disabled, empty `generic-otlp` installer placeholder when another exporter such as Galileo is configured. Configured exporters and resource attributes are preserved; edited destinations and inherited signal or batch settings still use normal validation.
- **Managed sandbox lifecycle and egress records now reach the audit and OTLP.** On a standalone managed computer the per-user sandbox daemon built its sandbox runtime with no telemetry recorder, so every `log.sandbox.lifecycle` and `log.egress.*` record was dropped and the Sandboxes board's lifecycle, phase, egress and top-hosts panels stayed empty. The daemon now queues those records and relays them to the managed gateway in batches (`POST sandbox/events`, new event kinds `sandbox_lifecycle` and `sandbox_egress`), and the gateway records them with its own recorder, stamped from the registration the caller owns (sandbox name and id, guardrail profile, policy digest, person) rather than from the daemon's claim (GAP-0003).
- **The relay is hardened against the user's daemon.** The daemon runs as the user, so every record it relays is treated as a claim. Telemetry needs a bound registration, and the sandbox name and id always come from it; managed sandbox phases are tracked per registration and end when the registration is revoked, removed or evicted; a revoked registration takes only shutdown phases and connection ends, for 10 minutes; payload text is stripped of control, bidi and invisible characters, and keys that collide once cleaned are refused; severity and duration are bounded; each account has a records budget and a cap on tracked sandboxes, and batches are capped at 128 records (GAP-0005 to GAP-0011, GAP-0015, GAP-0016).

## [1.0.2] — Sandboxes on managed computers

A standalone enterprise install (rpm, deb, pkg; Linux and macOS) now runs
OpenShell sandboxes for standard users, and the directory group that picks a
person's guardrail profile also picks their sandbox policy. Everything is set
in the admin `config.yaml`; there is no MDM step. See
[Sandboxes on managed computers](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/sandboxes/).

### Fixed

- **A refused sandbox profile now names the setting and the profile.** `config-v8 validate`, the gateway and Windows Setup `/ensure` reported a profile's semantic sandbox error (`allowed: false` with `required_for`, an empty egress intersection, `none` with other credentials, an unknown connector, a value below a minimum) only as "configuration could not be compiled safely" at `$`, and reported `config_version` 8 for a version 9 file. They now report `guardrail.profiles["<name>"]` with the rule text and the file's own version. New read-only `defenseclaw-gateway config validate <file>` checks a candidate before it is applied (GAP-0337, GAP-0323, GAP-0252).
- **Hook status reads the registered commands, and token changes no longer break setup audits.** After a Windows per-user upgrade from 1.0.1, status reads Claude Code's guarded hook command as doctor does instead of reporting missing hooks. It also recognizes Antigravity hooks and Devin hooks set up with a workspace. `setup openclaw --no-restart`, `setup gateway --token` and a re-run of `init` send their audit events with the token the running gateway still accepts until it restarts (GAP-0463, GAP-0464, GAP-0489, GAP-0490).
- **The 0.8.x upgrade handoff checks options before downloading.** `defenseclaw-upgrade.sh` answers `--help`, refuses an unknown option or a missing `--version` value before any download, and does not downgrade a newer install when no `--version` is given. `install.ps1` also accepts `--help`. In action mode, `doctor` warns when another OpenCode plugin beside DefenseClaw's can load later (GAP-0466, GAP-0469).
- **A managed account outage and a locked sandbox pack now give a clear refusal.** When the computer cannot look up an account, `sandbox run` says a new run cannot start, `sandbox connect` and `sandbox exec` cannot reach a running sandbox, agents already running keep working, the stop is not the organization's sandbox policy, and whom to tell if it lasts. On a standalone managed computer, config load checks a locked `openshell.pack` as a required pack for the sandbox floors that use it; `config validate`, `ensure` and `verify` refuse a pack that cannot run on a copy of the project (GAP-0505, GAP-0510).

### Added

- **A `sandbox` section in each guardrail profile.** It has the type of
  `openshell.admin` and the same assignments and `default_profile`, and it can
  only tighten the floor: `openshell.admin` is the loosest anyone gets, and the
  one key a profile replaces is `request_access`. New keys, usable in both
  places: `allowed`, `required_for`, `when_unavailable`, `user_approvals`,
  `allowed_credentials`, `on_silence`, `max_silence_after`, `process_tree`,
  `foreign_sandboxes`, `allow_upstream_telemetry`, `delete_stopped_after` and
  `request_access`. Contradictions, an unknown `required_for` connector, a pack
  outside `<policy_dir>/sandbox/` and a pack looser than the floor's are load
  errors; every `sandbox` key is refused under Secure Client. `ensure` and
  `verify` warn when `default_profile` is looser than an assigned profile.
- **`enterprise.openshell`**: `install` (`prerequisite` or `setup`, no
  bundling: DefenseClaw never ships OpenShell), `driver`, `driver_fallback`,
  `version`, `gateway_port` and, on macOS, `e2fsprogs_dir`. `ensure` renders the
  OpenShell gateway settings into a root-owned `gateway.toml` and verifies or
  reports the install.
- **Linux falls back to docker when KVM is not available.** `driver: auto` is
  the MicroVM driver where the user's KVM probe passes when a sandbox starts,
  else the docker driver; `driver: vm` falls back the same way. The probe reads
  the CPU's virtualization flags, opens `/dev/kvm` read-write as the user and
  looks for the MicroVM driver. It runs per user at sandbox start, never at
  login. The fallback needs the same Docker access as the docker driver and
  keeps every profile floor, and a running sandbox never switches driver.
  `driver_fallback: none` refuses the sandbox instead, with the reason and the
  contact. A profile may set `sandbox.driver_fallback: none` (tighten only).
  The banner (`Driver docker (fallback: KVM not available on this computer)`),
  `status`, `policy explain`, `doctor`, the registration, the audit record and
  the telemetry (`defenseclaw.sandbox.driver`, `defenseclaw.sandbox.driver_reason`)
  show the driver and why. macOS is unchanged: MicroVM only.
- **Require sandboxes per group and agent.** An agent in `required_for` that
  starts on the host is refused with a command to paste (or alerted, with
  `when_unavailable: alert`, where sandboxes cannot run: Windows, an Intel Mac,
  no OpenShell, no Docker or KVM for the user).
- **A per-user sandbox daemon and a `defenseclaw` launcher.** The daemon runs as
  the user and asks the managed gateway for the policy of each run under the
  user's verified identity; every hook the agent sends is relayed to the managed
  gateway and fails closed. The launcher (`/usr/bin/defenseclaw`,
  `/usr/local/bin/defenseclaw`) offers only the `sandbox` commands. Managed
  sandboxes work on a copy of the project.
- **Asks bounded by the administrator.** The managed gateway decides and stores
  a person's ask, unblock and "always" against `user_approvals` and
  `allow_unblock`, and records who answered. Sandboxes DefenseClaw did not
  start are stopped or alerted (`foreign_sandboxes`), and network rules it did
  not render are removed.
- **What users see.** A `Policy` banner line, `defenseclaw sandbox policy
  explain` (with `--sources`), status and doctor rows, and neutral refusal
  texts that name only the caller's own profile and end with the
  request-access contact. Administrators get `enterprise <os> sandbox list`,
  `sandbox explain --registration`, `effective.sandbox` in `profile-explain`
  and sandbox rows in `policy verify --user`.
- **MicroVM sandboxes on Linux with KVM.** On a per-user install, `sandbox
  setup` offers OpenShell's MicroVM driver on a Linux host where `/dev/kvm`
  exists, and `sandbox doctor` checks KVM access, `e2fsprogs`, the driver binary
  and the gateway service's umask (a stricter umask than `0022` made every
  MicroVM fail to start). On a managed Linux host, `enterprise.openshell.driver:
  vm` selects it; in `install: prerequisite` mode you install the driver tarball
  yourself (the recipe is on the managed sandboxes page), and DefenseClaw's own
  user unit runs the gateway in both install modes.
- **Telemetry.** New attributes (`defenseclaw.sandbox.policy.digest`,
  `.generation`, `.provisional`, `defenseclaw.sandbox.registration.id`,
  `defenseclaw.openshell.version`, `.install_mode`, `defenseclaw.subject.key`)
  and records (`log.sandbox.policy.resolved`, `.rematched`, `.foreign_rule`,
  `log.sandbox.ask.decided`, `log.sandbox.host_run_refused`,
  `.host_run_unavailable`, `.access_refused`, `.foreign_sandbox`,
  `.foreign_container`, `.settings_drift`), a managed fleet section on the
  Grafana Sandboxes board, Splunk saved searches and Splunk Observability
  charts.
- An Active Directory example, `packaging/identity/ad/sandbox-profiles.example.yaml`.
- **Administrator views.** `enterprise <os> sandbox pack-digest <pack>` prints,
  as root and offline, the digest that `required_pack_digest` pins and says
  whether the gateway would accept the file where it is. `profile-explain`
  shows an `enrollment.exempt` flag and where a matched group came from
  (directory, local group database or both). The same `enterprise windows
  sandbox` views exist from an elevated prompt on Windows, where `pack-digest`
  is the one with something to show.
- **One sandbox account at a time.** The first account to run a sandbox holds the
  sandbox ports; another account is told that sandboxes aren't available for it
  right now, without the first account's name, and it clears when that account
  has no sandbox running.
- **Reasons you can quote.** A required agent that can't be sandboxed (Windows,
  an Intel Mac, no Docker or KVM for the person, OpenShell missing) is refused
  with a short reason code (`os_unsupported`, `no_docker_group`, `no_kvm_group`,
  `prerequisite_missing` and the rest), also the `reason` of
  `log.sandbox.host_run_unavailable`. The managed sandboxes page lists every
  reason code, the `ensure` and `verify` codes and the relay refusals.
- **Documentation.** The managed sandboxes page has real screenshots of the
  refusals, the banner, `policy explain`, the driver fallback, privacy, the
  administrator views and the Windows refusal; a recipe for `setup` mode, the
  MicroVM checks per platform, and how to check a candidate config before you
  apply it. `sandbox policy explain` prints the policy and the table of every
  setting by default; `--sources` only tags each row of the summary. The
  OpenShell version and install mode are in `sandbox status` and `sandbox
  doctor`, not in `policy explain`. The support matrix lists managed sandboxes
  as supported on Linux and macOS.

### Changed

- A standalone managed install no longer refuses `defenseclaw sandbox`
  (the `managed_enterprise` refusals are gone). Sandboxes still refuse on
  Windows, under WSL2, on an Intel Mac and when run as root, and Secure Client
  is unchanged.
- The standalone managed document now refuses every non-lifecycle write from
  the Python CLI, as the Go side already did; Secure Client is untouched.
- The sandbox docs no longer say the MicroVM driver means a Mac, and the
  guide, reference, telemetry page and `docs/SANDBOX.md` describe managed
  computers.
- `exempt_users` exempts a person from enrollment and from `required_for`
  only. Their guardrail profile still inspects and blocks their calls; the
  documentation no longer says exempt calls are allowed.
- A profile's `when_unavailable: alert` loosens the default `refuse` only when
  `openshell.admin.when_unavailable` is `alert` too.
- `DEFENSECLAW_NO_SANDBOX=1` is a one-time bypass of the shell wrapper where
  the organization allows a host run. It is not an exemption: on a managed
  computer whose policy lists the agent in `required_for`, the host run is
  refused unless the account is in `enterprise.enrollment.exempt_users`, or
  sandboxes are unavailable to the account and the effective
  `when_unavailable` setting is `alert`.
- Managed `sandbox run` has no mount flag and no skip-permissions flag to
  loosen the policy: it works on a copy, `--safe` keeps the agent's prompts,
  and `--context`, `--host-port` and `--pack` are checked against the policy.
  `sandbox policy test` on a managed computer judges your own sandbox and
  takes `--sandbox NAME`; it refuses `--pack`, `--profile` and `--harness`.
- The Windows rule-pack folder is documented with a read grant for the
  gateway service's SID instead of the `Users` group, so standard users cannot
  list the packs. A bare group name in `profile_assignments` also selects a
  local group of the same name; the docs recommend the fully qualified
  spelling. macOS shows other accounts' sandbox daemons in the process list
  (no `hidepid`); the docs state this residual.
- **Behavior change: Cisco AI Defense uses the connection policy for a blank rule list.** An unset or empty `cisco_ai_defense.enabled_rules` list sends no `config` or `enabled_rules` in an API-key inspection request, so the AI Defense connection's own policy applies. A non-empty list is sent in the order configured. Before, an empty list sent an implicit built-in list of 12 cloud rules. If you relied on that list, name those cloud rules in `cisco_ai_defense.enabled_rules`. The Setup TUI hint now explains the blank-list behavior (GAP-0336).

### Removed

- The Python standalone admin-write exception, the `configwrite.ErrNotImplemented`
  sentinel that nothing returned, the managed-host refusal of `sandbox`, the
  config-wide unblocks and the "operator" approval actor on managed hosts, the
  direct reads of `openshell.admin` outside `Effective`, and the stale
  documentation statements that sandboxes do not run in `managed_enterprise`.
  Each was dead or superseded by the managed path; the 0.8.x upgrade bridge is
  kept because the 1.x line still supports upgrades from 0.8.x.

## [1.0.1] — Tetragon on managed Linux

Applies to the enterprise standalone profile on Linux, except where an entry
says otherwise. Per-user installs never connect to Tetragon.

### Added

- **Tetragon on managed Linux: consume, observe and an enforcement pilot.**
  When the computer already runs [Tetragon](https://tetragon.io), the root
  sensor helper reads its events over its root-owned Unix socket and uses
  them as Plane C's process source, with `cn_proc` and `fanotify` as the
  fallback in the same stream. One new block controls it,
  `enterprise.tetragon {mode, burn_in, enforce_ack, customer_events}`:
  - `consume` (the default mode) only reads events. It works only when Plane C
    is on (`ai_discovery.runtime.enabled` and `enable_host_plane`, both
    opt-in); with Plane C off the effective mode is `off`. Tetragon
    records the binary, arguments, user and parent at the exec, so short-lived
    processes keep their names, native Claude Code is identified by its
    executable, and a reused pid is no longer guessed from a name change.
  - `observe` also loads DefenseClaw's own `defenseclaw-*` policies: file opens
    of credential, persistence and agent-configuration paths of enrolled
    users, connects per binary (Plane B scores them even when the connection
    or the process is gone by the next poll), and two kernel controls in
    monitor mode that count what they would have denied.
  - `enforce` lets the two controls return `EPERM`: `kernel.ssh_private_key_read`
    (exact SSH private key names) and `kernel.persistence_write` (in-place
    write opens of shell profiles and user autostart entries). Nothing promotes
    on its own: it needs `mode: enforce` and an `enforce_ack` equal to the
    `kernel_policy` digest that `enterprise linux tetragon status` prints, a
    per-user burn-in measured in covered agent-hours (default 168h, which is
    about five to six working weeks for a full-time agent user; reset when
    the control set or the user's connector set changes), and a connector in
    `action` mode. `enforce_ack` takes one digest or a list of up to four, so
    a ring upgrade that changes a control does not drop users to monitor mode. Controls apply only below enrolled command-line agents of
    the user; IDE terminals, look-alike processes, other users and containers
    are observed, never denied. In this release enforcement denies only
    through a native agent binary, never by process ID, and for one user per
    computer (the lowest uid of the users who finished burn-in and have a
    native agent install): script-hosted
    agents and the other users stay in monitor mode, and status says so
    (`kernel_pid_anchor_monitor_only`, `kernel_binary_anchor_scope_limited`).
    An agent session that was already running when the controls loaded
    (`enforce` turned on, or Tetragon restarted) is monitored until it
    restarts (`kernel_sessions_predate_controls`); a pause and a resume keep
    the controls loaded and the session denied. An agent's own update (for
    example Claude Code updating itself mid-session) loads a new controls
    policy, and the already-running session is only monitored until it
    restarts; the restarted session is denied. A planned follow-up keeps the old
    controls policy loaded while the sessions it anchors are alive. At most
    eight running agent sessions are anchored in one monitor controls policy,
    because every extra
    `file_open` hook runs for every open on the computer: further sessions
    are reported as `kernel_roots_over_limit` and their user's burn-in pauses
    until every live session is measured. A new session may wait a minute
    or two for its process id to reach an enabled controls policy
    (`kernel_session_policy_pending`) and accrues no burn-in while it waits;
    the user's earlier covered time stays.
    An eligible account counts as enrolled for
    the connectors that reach it through vendor machine policy (Claude Code,
    Codex, Cursor, Copilot CLI and OpenCode) without a `targets.yaml` row, so
    the default `enterprise.enrollment.unenrolled_users` needs no change.
  - Your own Tetragon policies stay yours. In `consume`, `observe` and
    `enforce`, the events of your kprobe and LSM policies that hit an AI agent
    are forwarded as `ai.runtime.kernel_event` records (`customer_events:
    agent`, the default; `off` keeps the counts and forwards nothing), tagged
    with the policy name, its action and outcome (`observed`, `would_block` or
    `blocked`), and attributed to the agent, the user and the hook decision.
    Only typed, bounded fields cross the broker; string and byte arguments
    never do. DefenseClaw never adds, changes or deletes a policy of yours,
    and these events are not scored.
  - The helper connects only to a Unix socket that root owns and root serves,
    never to TCP, and calls only what the mode allows. It changes only policies
    it recorded loading.
  - Kernel controls digest: `sha256:08b71155b713` (first release with Tetragon
    support). Approve it with `enforce_ack`; a later release that changes a
    control changes this digest, and the release notes say so.
  - Support: RHEL 9 x86_64 with Tetragon 1.7.x supports `consume`, `observe`
    and `enforce`. Tetragon 1.6.x, Ubuntu 22.04/24.04 and arm64 support
    `consume` only. All of these are expected, not verified yet. RHEL 8 falls
    back to `cn_proc` and `fanotify`.
  - Cost: the `file_open` policies run on every open on the computer.
    Measured on a t3.xlarge with all four DefenseClaw policies in `enforce`:
    about +8 to +11 µs per open (2.3 to 2.7 times mode `off`), and +45 to 55
    percent wall time for a job that reads 60,000 files; see the guide's
    "Cost on the host".
- **Readiness check and fleet onboarding.** `enterprise linux tetragon verify
  [--ready-for consume|observe|enforce]` checks one computer, one line per
  check with the command that fixes a failure, and exits non-zero when a check
  fails. For `enforce` it prints each user's burn-in progress and estimate,
  every hit with its path and binary, and the `enforce_ack` block to approve.
  `tetragon status` gains a `Next:` line, a section for your own Tetragon
  policies and `--user`. `detect.sh --require-tetragon MODE` reports
  compliance to an MDM. A new guide,
  [Tetragon on a Linux fleet](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/tetragon),
  walks an administrator through hardening Tetragon, the rings, the approval,
  the help-desk runbook and the kill switch, with tested Ansible plays and a
  shell script under `packaging/mdm/linux/examples/tetragon/`.
- **Developers are told.** When a DefenseClaw kernel control (or, with
  `customer_events` on, one of your own enforcing policies) blocks a tool call,
  the agent's next answer says what was blocked and why, for Claude Code,
  Codex, Copilot CLI, Cursor and Devin, so `Operation not permitted` is no
  longer unexplained.
- **Kill switch and cleanup.** `enterprise linux tetragon status|pause|resume`
  (root). A pause (default 4h, at most 7d) survives restarts of the helper and
  of Tetragon; a policy you move to monitor or delete with `tetra` is never put
  back until the intent changes. Uninstall, purge, rollback and package
  downgrade delete the policies the helper loaded, before any file is removed
  (`defenseclaw-sensor-helper --tetragon-cleanup [--check]`); a rollback
  stops the helper first. Run by hand, the cleanup refuses while a helper in
  `observe` or `enforce` runs.
  `verify` fails with `kernel_policy_orphaned` for a leftover policy (and with
  `kernel_policy_load_error:<name>` for a DefenseClaw policy Tetragon reports in
  error), and warns with the new `tetragon_*` and `kernel_*` codes documented under
  [Troubleshooting](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/troubleshooting).
- **Observability.** `plane_health` gains `plane_backend`, `plane_mechanism`,
  `events_lost`, `loss_known` and `container_events`; runtime activity and
  finding records gain the user, the agent identity, `event_source`,
  `hook_seen` and, for kernel decisions, `kernel.outcome` and `kernel.control`;
  kernel denials are `log.enforcement.block.applied` records with the policy
  and the control-set digest, and reach notifications like hook blocks
  (`block_enforced`, the hook source, labelled `kernel`); and new low-volume
  families, `log.ai.runtime.kernel_policy` (each state change, and burn-in
  progress every 6 hours) and `log.ai.runtime.kernel_event` (events of your
  own Tetragon policies). Plane C `plane_health` gains fleet fields (the
  Tetragon version, helper mode, approval, users enrolled, enforced and in
  burn-in, pause, and per-cycle would-block, block and customer-event counts).
  Grafana gains a fleet table, a **Kernel controls (Linux)** row, a row for
  your Tetragon policies and kernel denials on **Blocked events**; the local
  stack gains five Prometheus alerts; and the Splunk bridge the matching
  macros and panels.
- **Surfaces.** On managed Linux, `enterprise linux discovery` shows the
  kernel sensor, the kernel controls and your Tetragon policies, and
  `defenseclaw-gateway status` ends its Subsystems list with a `Kernel sensor:`
  line. `runtime permissions` explains why a per-user install does not connect
  to Tetragon; `defenseclaw doctor` has a **Kernel sensor (Tetragon)** row that
  warns when Tetragon serves its API on TCP and, on Linux with the sandbox
  kernel feed installed, a **Sandbox kernel feed** row that prints the update
  command and warns while the feed's Tetragon stream is down;
  `defenseclaw config get --effective` lists `enterprise.tetragon.*`.
  The Python command line and TUI have no managed Tetragon lines in this
  release: only a managed gateway reports Tetragon, and the managed Linux
  packages ship no `defenseclaw` command line or TUI. A follow-up that adds the
  Python CLI and TUI to the enterprise packages re-adds the TUI Runtime
  panel's kernel lines, the `agent discovery runtime status` kernel lines and
  doctor's managed Tetragon rows.
  `/health` and `GET /api/v1/ai-usage/runtime` carry `backend` and
  `policy.kernel`; the keys are in the
  [gateway API reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/gateway-api).
- **Sandbox kernel feed (open-source Linux, opt-in root service).** On a
  computer whose administrator runs Tetragon, `sudo defenseclaw-gateway sandbox
  kernel-feed install` adds Tetragon's exec and exit records to the process
  trees of each user's docker sandboxes (`sandbox ps` says `source: kernel`;
  `sandbox.process_tree` records gain `source=tetragon`, `host_pid` and
  `exec_id`). A Claude Code hook call, DefenseClaw's hook script and the short
  system tools it starts, is one row with its tool count; a sandbox that was
  already running when the feed connected shows its calls in full until it
  is stopped and started, and `sandbox ps` says so. `sandbox ps` also counts
  the `sandbox.process_tree` records held back past 10 a second per sandbox.
  It reads only
  container process events, serves members of the `docker` group their own
  sandboxes, and loads no policy.
  `sandbox kernel-feed status|uninstall` check and remove it. See
  [Kernel feed (Tetragon)](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/linux#kernel-feed-tetragon).
- **New page: Agent segmentation, visibility and enforcement.** Which layer
  (hooks, OpenShell, the egress proxy, the runtime planes, Tetragon, the
  sandbox manager) sees and which enforces each intent on each kind of
  computer, with fail-open and fail-closed per layer.

### Fixed

- **Tetragon documentation.** The Tetragon reference moved from the Linux
  page to the new guide, and `enable-ancestors` is no longer listed as a
  requirement: DefenseClaw requests no ancestors and they cost CPU. The
  hardening steps now say that restarting Tetragon drops every policy added
  over its API, yours included; policies in `tetragon.tp.d` reload.
- **`cn_proc` needs `CAP_NET_ADMIN`.** The runtime planes documentation, the
  permissions probe and the TUI said the Linux process connector needed no
  privilege. It needs `CAP_NET_ADMIN`, so an unprivileged install got no
  process events. `runtime permissions` now probes it, and
  `runtime permissions --grant` includes it.
- **The enterprise-block refusal covers every field.** The checks that refuse
  an `enterprise` block in an open-source or Secure Client config list fields
  by hand; a reflection test now fails when a new field is missing from them,
  and `enterprise.tetragon` is covered.
- **Sandbox process trees no longer carry a Codex notify program's turn
  payload.** The notify bridge's argument (the user's prompt and the agent's
  reply) is replaced by `[argv withheld: agent turn payload]` on every
  forwarded command line.
- **Container processes no longer join host agent sessions** when Tetragon is
  the source. A program named `claude` in a devcontainer used to be scored as a
  host agent; it is now counted in `container_events` and never joined. Plane C
  findings for such hosts change accordingly.

### Changed

- The sensor helper's unit starts after `tetragon.service`, has a private
  state directory, `/var/lib/defenseclaw-sensor`, and a second runtime
  directory, `/run/defenseclaw-sensor-tetragon` (the until-reboot pause and
  the copies of its loaded policies), and keeps its runtime directories
  across stops (`RuntimeDirectoryPreserve=yes`, for the until-reboot pause);
  uninstall removes them. The first `ensure` or `repair` of this release applies them.
  A host that sets no `enterprise.tetragon` gets no new drop-in.
- The per-user Linux install ships `defenseclaw-sensor-helper` in
  `~/.local/bin` (used only by the sandbox kernel feed);
  `defenseclaw uninstall --binaries` removes it. `install.sh` and
  `defenseclaw upgrade` warn when the root sandbox kernel feed runs another
  release than the one just installed, and print the
  `sudo ... sandbox kernel-feed install` command that updates it.
- Downgrading below this release while policies are loaded: see
  [Remove the policies, or downgrade](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/tetragon#remove-the-policies-or-downgrade).

### Removed

- **`ai_discovery.runtime.acquisition` and `helper_socket`.** The closed config
  schema always rejected them and they were never in a release; the helper is
  chosen automatically (`DEFENSECLAW_SENSOR_HELPER_SOCKET` stays).
- **The claim that `cn_proc` is unprivileged** (comments, the permissions
  probe, docs and TUI copy): it was false.
- **The sandbox manager's private command-line redaction.** One shared
  implementation now serves the manager, the sensor helper and the sandbox
  kernel feed. It redacts quoted secrets, header values (including
  `--header=X-Api-Key: ...`), `user:password` arguments, URL passwords and
  key-shaped arguments, and a second pass over a redacted line changes
  nothing; the rules are listed under
  [Process command lines](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/redaction#process-command-lines).

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

- Under the derived admission gate, LOW and INFO skill findings now allow. The
  skill scanner defaults to `quiet` when a judge is configured; findings that
  need human review use the `warn` path and appear in the review queue.

- The retired top-level `otel:` configuration moves to `observability.destinations` in config_version 9.
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
- Interactive `defenseclaw init` offers `closed` as the hook fail mode on a
  new install (Enter used to pick `open`), the default `--non-interactive`,
  `quickstart` and the config already used; a re-run offers the saved value.
- `defenseclaw guardrail use-pack` removes a `guardrail.custom_packs` pin that
  no connector or profile selects after the switch (it used to stay, pointing
  at the folder after it was deleted) and names it; `use-pack DIR` pins the
  pack again.
- `defenseclaw guardrail use-pack NAME` re-pins a custom pack that was edited
  after it was pinned: it now runs while that stale pin fails the start-up
  config check (its write still validates the whole config), and
  `use-pack default` switches away. On a per-user install the mismatch error
  from the config check and the gateway names the `config set` command that
  pins the new digest.
- After a Codex update on Windows, `defenseclaw doctor`'s **Hook contract**
  and **Codex hooks** rows name `defenseclaw setup codex --yes`, which
  selects the new Codex executable. The gateway's hook guard reports a
  self-heal that keeps failing the same way once (it raised a HIGH
  guardrail-degraded alert and a log line on every 30 s check) and, on a
  per-user install, points at `defenseclaw doctor`.
- `guardrail.block_at` and `guardrail.alert_at` now decide every guardrail
  verdict that carries a severity: hook tool calls, hook prompts, tool
  responses and message content, and the LLM proxy's prompts, completions and
  tool calls. In 0.8.x they applied only to hook tool calls; hook prompts took
  the rule pack's posture and the proxy took `block_threshold` and
  `alert_threshold` from `policies/rego/data.json`. A `block_at: HIGH` you set
  for tool calls now also blocks HIGH prompts and proxy traffic. The config
  migration carries a `data.json` threshold that is stricter than the rule
  pack's default into `block_at` or `alert_at`, and adds a note to
  `migration-v9.json` whenever either was set. See
  [Thresholds](https://cisco-ai-defense.github.io/defenseclaw/docs/policies/thresholds/).

### Added

- A once-a-day, TTY-only "new release available" notice in the CLI and TUI.
  Turn it off with `DEFENSECLAW_NO_UPDATE_CHECK=1` or `update.check: false`.
- Before an upgrade, reinstall or rollback on macOS or Linux restarts the
  gateway, the installer names the OpenShell sandboxes that are running: their
  hooks fail closed until the gateway is back, so their agents' tool calls are
  refused meanwhile.

### Sandbox telemetry and destinations

- `defenseclaw sandbox destinations NAME` (and `GET
  /api/v1/sandbox/sandboxes/{name}/destinations`) lists every host a sandbox
  reached or tried to reach, through the egress proxy or around it, with its
  kind: model provider, the harness's vendor, shadow AI (another AI provider,
  or an inference-shaped host), the egress category, blocked or other. It
  shows the requests, refusals, bytes and the binary that connected (with
  the opt-in process tree on, that process and its parents), survives
  daemon restarts and stops, keeps at most 512 hosts, and is deleted with the
  sandbox. The `Egress` line of `sandbox status NAME` and the TUI's sandbox
  detail sum it up by the same kinds (`AI: 1 model provider, 1 harness
  vendor host, 2 shadow AI`); the detail lists the hosts.
- A sandbox's hook counts (`Hook traffic` and `Hook events` in `sandbox
  status NAME`, the tool calls in the TUI's Sandboxes list) survive daemon
  restarts like its destinations, so the end-of-session summary counts the
  whole session across a restart; a daemon that did not stop cleanly loses
  the last minute of them.
- New finding `shadow_ai`, also on the activity feed: an AI provider that is
  neither the sandbox's model provider nor its harness's vendor, once a
  session when the policy refuses it (LOW) and once when the sandbox reaches
  it (MEDIUM). A `--credential` binding's endpoint is its own `credential`
  destination, never shadow AI.
- New v8 records: `log.egress.completed` (bytes and duration) and
  `log.egress.failed` (upstream failures and timeouts, and `cancelled` with
  the bytes for a connection the proxy cut short) for every allowed proxy
  connection; `log.sandbox.process`, `log.sandbox.ssh` and
  `log.sandbox.inference` from OpenShell's PROC, SSH and API:INFERENCE
  records (process records are paced per sandbox; command lines are content
  class); allowed connections to host ports. Sandbox records now carry the
  binding ID (`defenseclaw.sandbox.binding.id`), the launching host user and
  the session the hooks last named (`gen_ai.conversation.id`); OpenShell's
  egress records carry the connecting binary and PID.
- `defenseclaw.egress.events` gains the `connector` label (the sandbox's
  harness).
- Refused proxy credentials are reported as degraded sandbox health
  (`openshell_egress_auth_failed`: one record per streak, counted in the
  gateway log at most once a minute, restored after a quiet minute), and refused
  telemetry records are no longer silently dropped: they are logged, counted
  on `sandbox status` and reported as degraded health
  (`openshell_telemetry_failed`).
- Removed the `binary_drift` and `tamper_attempt` sandbox finding kinds,
  which nothing produced.
- OpenShell's repeats of one finding within 10 minutes of a session are one
  sandbox finding and one feed line (the next one names how many were
  folded); "Credential-bearing traffic cannot be inspected" names the
  conversation's credential placeholder and the new-conversation step, and
  `defenseclaw alerts --show`/`--json` print a sandbox finding's details and
  next step.
- New Grafana dashboard **Sandboxes** (`defenseclaw-sandboxes`), linked from
  Overview: active sandboxes by connector, phase changes, egress by source
  (OpenShell or the DefenseClaw egress proxy) and decision, top blocked and
  allowed hosts, bytes up and down per destination, a destinations table,
  shadow-AI and other sandbox findings, integration health and the opt-in
  process starts, with Environment, Host and Sandbox variables. The local
  Collector now adds the record's sandbox name as the `defenseclaw.sandbox.name`
  log attribute (Loki structured metadata) so the variable and the filters never parse log bodies;
  the body is unchanged and sandbox names stay out of metric labels. The
  Splunk Observability bundle adds an Egress blocks by source chart to
  Security and Policy, a Sandboxes dashboard and a sandbox egress-blocks
  detector (and the local Prometheus rule
  `DefenseClawSandboxEgressBlocksSustained`), which count the sandbox egress
  sources (`openshell`, `dc-egress-proxy`) only, and drops the unused
  "Egress blocks / min" tile.

### Sandbox policy: extend packs, repository policy, record then lock, test

- A custom sandbox pack can extend one parent with `extends:` (a built-in
  pack, or a custom pack in `openshell.pack_dir` by name) and set only what
  it changes: lists such as `egress.allow`, the masks and the review list add
  to the parent's, other keys replace it. At most four ancestors; cycles are
  refused. The digest covers the chain (the parent's digest, then the file),
  so a pinned `required_pack_digest` follows a change anywhere in it. `pack
  show`, `pack list`, `pack validate` and `policy explain` show the chain.
  Packs without `extends` keep their digests.
- A project can ask for a stricter sandbox with `.defenseclaw/sandbox.yaml`:
  network and approvals floors, block entries, fewer ports, a lower
  large-upload threshold or the large-upload block, copy mode, more masks
  and review globs, the harness's prompts kept, MCP servers left behind,
  blocked MCP tools, a stop on hook tamper or on silent hooks
  (`hooks.on_silence: stop`), the process tree turned on
  (`observe.process_tree: true`). It can only tighten: a key that would
  loosen refuses the run, one line per key. The file is untrusted
  input (16 KiB, no links, strict YAML, no includes), read when the sandbox
  is created; the sandbox keeps that copy, so an edit applies to the next
  new sandbox (`sandbox run` names a changed file among what resuming the
  folder's sandbox ignores, and defaults to a new one), and the file is on
  every session's review list. The banner, `policy show` and `policy
  explain` (source `repo`) say what it tightened. It applies to runs
  started in the folder that holds it; a run in a subfolder of the
  repository warns that the root's file does not apply there.
- `defenseclaw sandbox policy suggest` now works from each sandbox's kept
  destinations (they survive daemon restarts) instead of the in-memory
  activity buffer, and suggests a pack that extends `balanced` with the hosts
  reached that balanced does not cover, each with the programs that reached
  it. Hosts only ever refused, shadow AI, blocklist-feed hosts and the
  sandbox's model provider and `--credential` endpoints are listed apart.
  Ports beyond balanced's 80 and 443 that the allowed hosts used go in
  `egress.ports`; past what a pack holds (1024 allow entries with
  balanced's, 64 KiB) the most requested hosts stay and a warning names the
  rest. `--pack-out FILE` writes the
  pack (a new file, relative paths in the current folder, checked like
  `pack validate`), `--diff` shows the
  settings it changes and the reached hosts it would block. The old
  `openshell.egress.allow` snippet output and its JSON shape are gone.
- New `defenseclaw sandbox policy test --host H [--port P] [--binary B]`
  (and `POST /api/v1/sandbox/policy/test`): the egress decision, the rule
  that decides and the setting behind it, from the same decider the proxy
  uses. `--sandbox NAME` asks the daemon (unblocks included); `--pack`,
  `--profile` and `--harness` resolve locally, with no daemon, for CI.
  `--fixture FILE` checks a YAML or JSON list of `{host, port, binary,
  expect, rule}` and exits 1 on a mismatch.
- `defenseclaw sandbox policy block --remove HOST` (and `policy allow
  --remove`) takes an entry off `openshell.egress.block` (or `allow`); only
  `config unset` could, for the whole list. An unblock refused by your own
  block list names the command.

### Sandbox documentation

- New [Sandbox telemetry](https://cisco-ai-defense.github.io/defenseclaw/docs/observability/sandbox-telemetry/)
  page: the v8 records an OpenShell sandbox writes (lifecycle, egress decisions
  with `log.egress.completed` bytes and duration, asks, policy changes,
  findings, process and inference records), the attributes that name the
  sandbox, the egress decision codes, the `openshell_*` health codes
  (`openshell_egress_auth_failed`, `openshell_telemetry_failed`), the metrics,
  what leaves the host, and how to reconstruct a session from the records.
- `sandbox doctor --output json` documents `ready`, `openshell_install`,
  `openshell_upgrade` and `openshell_install_version`; the guide's error table
  names the two new health codes; the TUI page says that sandbox components are
  their own AI Discovery rows and that an alert names its sandbox.
- The sandboxes overview gains "What you can see, and how far to trust it": for
  each signal (destinations, shadow AI, the program behind a connection, the
  process tree, discovery, hooks, the repository policy) where it comes from and
  what it cannot tell you.
- Animated replays of real sessions for the sandbox setup, a whole first session,
  the activity feed, an ask and its answer, applying and undoing a copy's work,
  record-then-lock and `policy test`.
- New or retaken screenshots from the 1.0.32 and 1.0.35 builds: the Grafana
  Sandboxes board (current panel titles), the Linux and Mac Setup wizards, the
  TUI's Activity view, sandbox details with the process tree and destinations on
  both drivers, a sandbox in the AI Discovery panel, the Linux doctor, process
  tree and status, a Linux session end with shadow AI, and a Splunk search of a
  sandbox's records. The lab account name no longer appears in any shot.

### Removed

1.0.0 is not released yet, so these are intentional breaking changes. Items
marked **0.8.x** were visible in 0.8.x; the others only ever existed in
pre-release builds. An upgrade from a released 0.8.x install still starts and
works with the leftover files, and nothing you set in `config.yaml` is dropped
without a line in `migration-v9.json`. Environment variables and command-line
options are not migrated: the entries below say what replaces each.

- **0.8.x: command-line options that did nothing.** `setup observability add
  --url-path`, `policy delete --force`, `registry add|edit --auto-sync` and
  `--sync-interval-hours`, `alerts --tui` and `--no-tui`, `quickstart
  --non-interactive` and `--yes`, `setup rotate-token --no-restart` and `init
  --sandbox` are gone. A script that still passes one now fails with a normal
  usage error instead of the option being ignored. `install.sh`, `install.ps1`
  and `install-dev.sh` no longer pass them.
- **0.8.x: wizard fields that always produced a failing or ignored command.**
  The "Refresh Hooks" toggle in the TUI Token rotation wizard, the matching
  macOS app toggle and the macOS "Webhook URL path" field.
- **0.8.x: the firewall and audit Rego policies.** `firewall.rego`,
  `audit.rego` and `data-sandbox.json`, with the `defenseclaw-gateway policy
  evaluate-firewall` and `policy domains` dry-run commands. They read the
  retired `data.json` and nothing enforced through them; network egress
  enforcement is unchanged. The `config_version` 9 migration removes the
  unmodified 0.8 copies from the policy folder, keeps a copy you edited and
  lists it in `migration-v9.json` and in `defenseclaw-gateway config migrate`
  output. On a managed standalone host the files are only reported. The
  docs-site policy creator Live Test now evaluates the admission and
  guardrail Rego only. `defenseclaw init` seeds only `.rego` files, and the
  Python wheel no longer lists Rego JSON data files.
- **0.8.x: the `skill_actions`, `mcp_actions` and `plugin_actions` config
  keys, `update_check` and the empty `privacy` section.** Use the `admission`
  section and `update.check`. `defenseclaw upgrade` moves existing values,
  records overridden severities in `migration-v9.json`, drops a leftover
  `privacy` section and notes a `privacy.disable_redaction: true` there;
  redaction follows `observability.redaction_profiles`. In a
  `config_version` 9 file any of these keys is refused with an error that
  names the key and what replaces it, or says to remove it.
- **0.8.x, breaking (telemetry): the resource attribute aliases.** DefenseClaw
  emits only canonical names: `deployment.environment` is now
  `deployment.environment.name`, `deployment.mode` is now
  `defenseclaw.deployment.mode`, and `defenseclaw.device.id` is now
  `defenseclaw.device.public_key_fingerprint`. Queries, dashboards and alerts
  on an exported backend must use the canonical names. The Prometheus labels
  follow: `deployment_environment` is now `deployment_environment_name` and
  `defenseclaw_device_id` is now `defenseclaw_device_public_key_fingerprint`.
  The bundled Grafana and Splunk Observability dashboards are updated; custom
  dashboards need a hand edit. The managed AI Defense sink output is
  unchanged: it still sends `defenseclaw.device.id` on its own resource, and
  `deployment.environment` and `deployment.mode` unless a Secure Client file
  turns `compatibility_aliases` off.
  The `local-observability-v1` profile attributes and the Splunk HEC v7 flat
  fields are not part of this change.
- **0.8.x: the config key `observability.trace_policy.compatibility_aliases`**
  (default `true`, no environment variable). The 0.8.x to 1.0 config
  migration drops it and records it as removed in `migration-v9.json`; a
  `config_version` 9 file that still contains it is refused with a message to
  remove it. A configured `observability.resource.attributes` entry
  `deployment.environment` is migrated to `deployment.environment.name`, and
  `config_version` 9 refuses the old spelling. `defenseclaw setup
  observability add ... --environment` removes a retired
  `deployment.environment`. The local observability stack collector defaults
  `deployment.environment.name` to `local-dev` when the sender supplies none.
- **0.8.x: `policy edit guardrail --add-pattern`, `--remove-pattern` and
  `--set-severity-mapping`.** Guardrail patterns and severities come from the
  rule pack now: add rules in a pack listed under `guardrail.custom_packs`, and
  change one rule's severity with `guardrail.rules.severity_overrides`. A
  script that still passes one of the options fails with `No such option`.
  `--block-threshold`, `--alert-threshold` and `--cisco-trust-level` stay.
- **0.8.x: `policies/rego/data.json` as a policy input.** Nothing outside
  Secure Client reads it any more: the admission actions, the first-party allow
  list and the guardrail thresholds live in `config.yaml` (`admission`,
  `guardrail.block_at`, `guardrail.alert_at`, `guardrail.cisco_trust_level`).
  The config migration reads the file once, renames it to
  `data.json.migrated-v9`, and lists the keys it drops (`patterns`,
  `severity_mappings` and others) under `removed` in `migration-v9.json`. A
  `data.json` you edit afterwards changes nothing, and `defenseclaw doctor`
  reports a leftover one as **Retired policy data**.
- **0.8.x: operator block and allow entries in `audit.db`.** `defenseclaw skill`,
  `mcp` and `plugin` `block` and `allow` now write `asset_policy.<type>.denied`
  and `allowed` in `config.yaml`, and the gateway hot-applies them. The config
  migration copies the operator rows of the `actions` table into those lists
  (an allow entry is pinned to the path it was recorded for) and clears the
  moved state from `audit.db` once `config.yaml` is saved. Blocks written by a
  scan verdict, and quarantine and runtime-disable state, stay in the table. A
  managed standalone host keeps its rows where they are, because the
  administrator's config is the policy.
- **0.8.x: gateway routes.** `PATCH /v1/guardrail/config` now answers `405`
  (`GET` is unchanged), and `POST /config/patch`, `POST
  /policy/evaluate/firewall`, `/policy/evaluate/audit` and
  `/policy/evaluate/skill-actions`, and the proxy's `/health/liveliness` alias
  (use `/health/liveness`) are no longer served. Change guardrail settings with
  `defenseclaw config set`. Secure Client keeps `/config/patch`,
  `/health/liveliness` and the managed refusal of `PATCH /v1/guardrail/config`.
- **0.8.x: two environment variables.** `DEFENSECLAW_JUDGE_TRACE` has no effect
  outside Secure Client: set `guardrail.judge.trace: true` in `config.yaml` (a
  managed device refuses the key). `DEFENSECLAW_JUDGE_PERSIST_QUEUE_SIZE` is
  gone: set `guardrail.judge_persist_queue_depth` (default 1024). When
  `DEFENSECLAW_JUDGE_TRACE` is set in your shell, `defenseclaw doctor` lists it
  under **Ignored environment overrides**; the other variable is ignored
  silently.
- **0.8.x: config keys that a `config_version` 9 file rejects.**
  `guardrail.rule_pack_dir` (also under `guardrail.connectors.<name>` and
  `guardrail.profiles.<name>`) is replaced by `rule_pack` and `custom_packs`.
  `watch.allow_list_bypass_scan` is replaced by
  `admission.defaults.allow_list_bypass_scan`. The scanner keys
  `scanners.skill_scanner.binary`, `scanners.mcp_scanner.binary`,
  `scanners.skill_scanner.use_virustotal`, `scanners.skill_scanner.use_aidefense`,
  `scanners.skill_scanner.virustotal_api_key` and
  `scanners.skill_scanner.virustotal_api_key_env` are replaced by
  `scanners.skill_scanner.analyzers.*` (DefenseClaw runs the scanners it ships,
  so the `binary` keys have no replacement). The config migration moves each
  value, records a disagreement in `migration-v9.json`, and moves an inline
  VirusTotal key to `.env`. A `config_version` 9 file that still holds one of
  them is refused with an error that names the key and what replaces it.
- The enterprise Unix uninstall option `--remove-service-account`. Uninstall
  already deletes the gateway service account by default;
  `--keep-service-account` keeps it.
- The hidden `--restart`, `--no-restart` and `--no-validate` options of
  `guardrail use-pack`, `protection enable|disable`, `block-at` and
  `alert-at`. They never did anything.
- Pre-release leftovers with no released equivalent: audit chain migrations,
  the Windows hook-command forms for Devin, Kiro and event-bound hooks,
  `defenseclaw migrate --yes`, dead helpers, and audit.db files from
  pre-release builds at `schema_version` 30-52, which are not migrated and
  must start from a fresh `audit.db`.

## [Unreleased] — Enterprise hardening

Entries that name the enterprise standalone profile apply only there; the
rest also reach per-user installs.

### Fixed

- **The gateway prints the local Splunk sign-in only while its web UI
  answers.** `defenseclaw-gateway start` and `restart` printed the "Splunk
  Local Mode" block (Web UI, user, where the password is) whenever the
  bridge's env file held a password, also after `setup splunk --disable`
  stopped the container or after it was removed. The fallback that read
  `DEFENSECLAW_LOCAL_USERNAME`/`DEFENSECLAW_LOCAL_PASSWORD` from
  `~/.defenseclaw/.env` is gone: no supported release writes them there
  (the local bridge reads them from its own env file).
- **A PowerShell command with several statements reaches argv block rules.**
  On Windows, where Codex runs its shell tool in PowerShell, a rule such as
  `f.commands.exists(c, "<x>" in c.argv)` only reported a detection-only
  finding for `Write-Output <x>; exit $LASTEXITCODE` or
  `Get-Location; Write-Output <x>`: the second statement left the whole
  command partial. Its statements are now judged one by one, up to the first
  one that cannot be proved, as in the body of `pwsh -Command`.
- **The `guardrail` commands confirm that the running gateway applied a
  change.** `guardrail mode`, `block-at`, `alert-at`, `use-pack`,
  `protection`, `rule` and `suppress` said the running gateway applies it now
  while, after a 0.8.x upgrade, the gateway kept the previous setting. They
  wait up to 10 seconds for it to report the saved config generation, and
  otherwise say it did not apply it and name `defenseclaw-gateway restart`
  (`mode` and the levels exit 1, `gateway: not_applied` in `--json`).
  `defenseclaw doctor`'s stale Policy row names the generation it has not
  applied.
- **`setup guardrail --connector X` refuses a connector that is not set up.**
  On an install whose `guardrail.connectors` roster lacked X it repointed the
  guardrail connector without adding X, and the gateway restart dropped the
  hooks of the connectors on the roster. It now changes nothing and names
  `defenseclaw setup <x>`, which adds a connector (or `--replace`, which
  switches).
- **`defenseclaw setup rotate-token` after a 0.8.x upgrade on Windows.** The
  upgrade gives the hook credential files 0.8.x wrote with an inherited DACL
  the owner-only DACL 1.x writes, which rotation requires. A refusal now names
  the file, the reason and the `icacls` (or `chmod`) command that fixes it.
- **No `--from-version` warning on a downgrade.** `install.sh --local` of an
  older build over a newer one printed `--from-version 1.0.31 is newer than
  this DefenseClaw`, about a flag the user never typed. The warning remains
  only where the value is read: a 0.x configuration without a migration
  record.
- **Local Splunk starts when the CLI was installed under a private umask.**
  The package's files arrived 0600 and setup copied them so into
  `~/.defenseclaw/splunk-bridge/splunk/`, which the container mounts and reads
  as non-root users, so Splunk restarted on `Permission denied:
  '/tmp/defaults/default.yml'` while `defenseclaw setup splunk --logs` waited
  four minutes. Setup and init now make that folder readable to the
  container (0755 folders, 0644 files, 0755 scripts; `env/.env` stays
  private), and the bridge stops as soon as the container keeps restarting,
  with its last log lines.
- **`defenseclaw setup splunk --disable --logs` stops the local Splunk
  container.** It ran the bridge's `down` without the env file the bridge
  requires, ignored the failure and said the container stopped; it now passes
  the file, checks the container is gone, and otherwise says why and how to
  stop it. A setup re-run no longer takes DefenseClaw's own running Splunk
  for a foreign holder of ports 8000 and 8088.
- **Security: hooks keep the gateway token and the hook payload off process
  command lines and out of child environments.** The Claude Code,
  Antigravity, Copilot, Cursor, Devin, Hermes, Kiro and OpenHands shell
  hooks, the shared `inspect-*` hooks and the OpenClaw and ZeptoClaw PATH
  shims gave curl the per-user gateway token as `-H "Authorization: Bearer …"`,
  and the connector hooks also gave it the whole hook payload (prompt or tool
  input, session id, transcript path, cwd) as `-d`, on Linux and macOS. Other
  local accounts could read both from the process list (`ps`,
  `/proc/<pid>/cmdline`), and exec monitors such as auditd, Tetragon and EDR
  agents recorded them. The enterprise standalone hooks, which send no token
  over the hook socket, still put the payload there. Every host hook now
  sends its request through one helper, `defenseclaw_gateway_post` in
  `hooks/_hardening.sh` (helper schema v8): curl reads the Authorization
  header as a config line and the body from file descriptors that the
  shell's built-in `printf` writes, as the Codex hook already did, so its
  command line carries only the descriptor paths (this works with curl
  releases older than 7.55). The PATH shims and the Hermes foreign-hook
  guard's session report do the same, and `inspect-tool` and
  `inspect-tool-response` give `jq` the tool input or output on standard
  input instead of as an argument, so an input over 128 KiB no longer stops
  `jq` from starting.
  - The hooks no longer hand the token to the programs they start (curl, jq,
    or the gateway a hook starts after a reboot) in
    `DEFENSECLAW_GATEWAY_TOKEN`, which the Codex hook already dropped, and
    they drop inherited variables named like their own (`PAYLOAD`,
    `API_TOKEN`, …), which copied the prompt or the token into the
    environment of every program they started.
  - The PATH shims keep their own values in private names. When the agent's
    environment exported `API_TOKEN`, the real npm, pip, curl, wget, ssh or
    nc, and every process it started, got the DefenseClaw gateway token in
    place of the user's own value (and the shim's values in place of
    `API_ADDR`, `ACTION`, `RESULT` and others).
  - Every gateway request from a hook, a PATH shim or the Codex notify bridge
    runs `curl -q`, so a `.curlrc` in the agent's `CURL_HOME` or
    `XDG_CONFIG_HOME` can no longer write the token and the payload to a
    trace file or turn an HTTP 401 into an allow.
  - A connector hook refuses a token that contains CR or LF as `invalid
    gateway token` and handles it like a token the gateway rejects; the
    `inspect-*` hooks fail closed on it, as on a 401. A PATH shim exits 1
    with `shim gateway token is malformed — refusing to exec <tool>`.
  - `defenseclaw doctor` reports Claude Code and Codex hooks rendered before
    this fix as stale.

  Fail modes and timeouts are otherwise unchanged. In OpenShell sandboxes
  the token transport is unchanged (it already used a descriptor); sandbox
  `inspect-tool-response` now also reads the tool output from standard input
  (no `jq` argument, no 128 KiB limit) and blocks when it cannot build the
  request body. The gateway rewrites the hooks when it starts (on enterprise
  installs the guardian does), so an upgrade applies the fix. Windows is not
  affected: its hooks run natively and the PowerShell adapters pass only
  fixed arguments.
- **Uninstall removes the uv a 0.8.x installer added, or names it.** The
  0.8.x installer ran uv's own installer without a record, so after an
  upgrade `uninstall --all --binaries` left `uv`, `uvx`, `~/.cache/uv` and
  `~/.config/uv` without saying so. The upgrade from 0.8.x now records them
  when uv's receipt, versions, file owners and timing, and a cache that holds
  only what that install downloaded, show the 0.8.x installer put them there;
  uninstall removes them while unchanged. Otherwise the uninstall plan and
  result name what they leave. uv's Python folder is never removed.
- **macOS app: the Local observability wizard no longer fails when "Configure
  audit sink" is cleared.** The field passed `--no-audit-sink`, which
  `defenseclaw setup local-observability up` does not accept, so the command
  ended with a usage error. The field is gone.
- **Amp traces in a built-in mode reach Galileo.** Galileo needs a provider
  on an agent span, and Amp names no model in its built-in modes (such as
  `medium`), so those agent spans were left out of the Galileo export and
  their traces never appeared, while the gateway reported every batch
  delivered. The Galileo view now names the connector as the provider when
  a span reports none, as other hook connectors already do; other
  destinations are unchanged.
- **Windows MDM detection no longer fails while the hook guardian writes
  its records.** On the enterprise standalone profile, verify (and so
  `detect.ps1` and `Remediate-Detect.ps1`) failed about one run in eight
  with `... being used by another process` on the guardian's state files,
  or with records from two guardian passes, while status stayed ok. Status
  and verify now re-read those records for up to two seconds until they
  describe one pass, and verify waits up to 30 seconds for the guardian to
  activate a `targets.yaml` the enumerator has just republished.
- **A rolled-back first Windows install takes back DefenseClaw's agent
  registrations and machine policy.** On the enterprise standalone profile,
  the rollback of a failed first install removed each account's
  `~\.defenseclaw`, with the backups of the agent files the install had
  changed, but left DefenseClaw's entries in them (the Amp plugin, the
  Antigravity `hooks.json`, the Hermes `config.yaml` and
  `shell-hooks-allowlist.json`) and left the Copilot and OpenCode machine
  policy, the Claude Code version floor, the hook runtime folder and the
  vendor lock files. The rollback now puts each agent file back to the bytes
  the install found, as the account, or removes it when the install created
  it, before it removes the folder, and then removes that machine policy. A
  file changed after the install wrote it stays as it is, and so do the
  files of an account that is not signed in.
- **`/uninstall PURGE=1` removes what an earlier rolled-back install left.**
  An Amp plugin or Antigravity `hooks.json` that such a rollback left was
  captured as the user's own file by the next install and put back by the
  uninstall; the uninstall now removes DefenseClaw's own plugin and hook
  entries from the file it restores, and names an Antigravity file that
  still has them. With purge, it also removes a Claude Code version floor
  drop-in that holds exactly DefenseClaw's floor but that DefenseClaw no
  longer records writing.
- **A rolled-back first Windows install leaves no event log or empty
  folder.** Its failure event registered the DefenseClaw event log and
  `C:\Program Files\Cisco` stayed empty; the event now goes to the
  Application log, as after an uninstall, and the empty folder is removed.
- **A failing Windows `verify --json` no longer reads as uninstalled.** It
  reported `installed: false`, no services and 0 targets for a running
  deployment, as a refused repair did before; it now carries the state a
  status probe reads.
- **A Linux gateway whose file was replaced while it ran can be stopped.**
  After `~/.local/bin/defenseclaw-gateway` was renamed or replaced under a
  running gateway, `defenseclaw-gateway stop` said "Gateway sidecar is not
  running" with exit 0 and dropped its PID record, `watchdog stop` refused
  after 15 seconds, and `uninstall --all` failed on that timeout; only
  `kill` recovered. Status now reports that gateway as running, `stop` asks
  its authenticated control plane to shut down (it still never signals it
  by PID), and the watchdog recognizes its own replaced file.
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
- **A Kiro hook on Windows that exits at once still blocks.** The Windows
  Kiro command started the hook with `Start-Process -Wait`, which opens its
  handle to the hook only after the hook is running; a hook that had already
  exited came back as exit 1 ("the process has exited") instead of the block
  code 2, and Kiro went ahead. The command now starts the hook with .NET
  `Process.Start`, which keeps that handle. In Constrained Language mode,
  which does not allow those calls, it runs the hook with the call operator
  and pipes its output, so PowerShell waits on the handle it started the
  hook with. Other connectors are unchanged.
- **Uninstall removes the empty OpenCode folders DefenseClaw created.** The
  gateway's install watcher creates missing `plugin`, `skill` and `skills`
  folders under `~/.config/opencode`, and a per-user uninstall left them
  behind, empty. The watcher now lists the OpenCode folders it creates in
  the DefenseClaw data directory, and the uninstall's OpenCode teardown
  removes each one that is still empty. Folders with content, folders outside the OpenCode
  config folder and folders DefenseClaw did not create stay.
- **A Windows uninstall drops a deleted account's runtime selector entry.**
  On the enterprise standalone profile, an account deleted together with its
  profile has left the enrollment manifest, so the teardown never removed its
  Claude Code or Codex runtime selector entry, and even `/uninstall PURGE=1`
  left `.defenseclaw-managed-runtime-selector.state` and its lock in the
  vendor's machine-policy folder. Uninstall now drops the entries of local
  accounts that no longer exist and whose profile folder is gone, and then
  removes a selector left empty and its lock.
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
  These helpers and doctor's gateway version check now run the checked
  file itself, as the lifecycle commands do, so a path swapped right after
  the check is not run.
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
- **One unprotected account no longer blocks `rotate-credentials`.** On the
  enterprise standalone profile on Linux and macOS, one account whose agent
  the guardian could not protect, such as an agent version without a
  verified hook contract, stopped the rotation for the whole host. The
  rotation now moves every account that holds a per-user credential and
  lists the targets that hold none as skipped: agents the guardian never
  protected, accounts that no longer exist and homes that are not available
  yet. A target that was protected before and now fails still stops the
  rotation, because it holds the current key's credentials.
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
- **`defenseclaw alerts` says how many detection-only findings it leaves
  out.** A rule that matched a call it could not decide is not an alert, so
  the list could read `No alerts. All clear.` while such calls ran. It now
  ends with how many detection-only findings the last 24 hours had, says
  `No alerts.` without `All clear`, and names
  `defenseclaw audit export --since 24h` to read them.
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
  that redirect now see the command with a static target. Built-in rules
  block these forms too: a rule's code check must hold with and without that
  target, and the path, secret-content and exact-fallback checks also judge
  the command with the static target, where only a block counts (#925).
- **Writes to `~/.ssh/authorized_keys` block in every spelling.** The
  shell expands `~/` and `$HOME/` when the command runs, so
  `>> ~/.ssh/authorized_keys`, `>> "$HOME/.ssh/authorized_keys"` and
  `tee -a ~/.ssh/authorized_keys` were allowed with no finding while the
  absolute path blocked. The authorized-keys rule now also checks the command
  with those paths resolved under the caller's home, also when another
  redirect target is a filename pattern.
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
- **`defenseclaw version` checks the OpenClaw plugin only for OpenClaw.** A
  Hermes-only or other hook-only install showed `plugin (not installed)
  missing`. Unless OpenClaw is an enabled active connector, the rule doctor
  already used, the plugin row reads `(not used)` and `skipped` and has no
  drift check; a config that cannot be read keeps the row
  ([#881](https://github.com/cisco-ai-defense/defenseclaw/issues/881)).
- **The OpenClaw gateway reads "off (OpenClaw is not installed)" instead of
  reconnecting forever.** `claw.mode` defaults to `openclaw`, so an install
  that never picked a connector (every sandbox-only install, for example)
  dialed `127.0.0.1:18789` for the life of the gateway, showed the Gateway
  subsystem `RECONNECTING`, logged a connect failure per attempt and asked
  for `OPENCLAW_GATEWAY_TOKEN`. When only `claw.mode` names OpenClaw,
  `gateway.host` is loopback, `gateway.fleet_mode` is unset or `auto`, and
  there is no `openclaw.json` (at `claw.config_file` or in `claw.home_dir`)
  and no `openclaw` binary, the gateway no longer dials: the Gateway
  subsystem is `disabled` with `OpenClaw gateway off (OpenClaw is not
  installed)` in `defenseclaw-gateway status`, the TUI and the Mac app,
  doctor reports `OpenClaw gateway: off (OpenClaw is not installed)` and no
  longer requires the OpenClaw plugin, `defenseclaw version` lists no plugin
  row, the token is not required, the watchdog stops reporting the fleet down, and
  the Secure Client service status reads ready instead of degraded. An installed or configured OpenClaw, an explicit
  `openclaw` connector, a non-loopback host or `fleet_mode: enabled` keeps
  the dial. The gateway decides when it starts; restart it after installing
  OpenClaw
  ([#958](https://github.com/cisco-ai-defense/defenseclaw/issues/958)).
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

### NVIDIA OpenShell 0.1 sandboxes

- Adds `defenseclaw sandbox`: run a coding agent in skip-permissions mode
  inside an NVIDIA OpenShell 0.1.x sandbox (Linux amd64/arm64; local gateway
  with the Docker driver; OpenShell `>=0.1.1 <0.2.0`) that sees only the
  project folder. OpenShell supplies the kernel-enforced boundary (network
  namespace, Landlock, seccomp, non-root, credential placeholders); DefenseClaw
  keeps judging every tool call through its hooks, which fail closed in a
  sandbox.
- On the Docker driver macOS cannot run sandboxes: OpenShell needs Landlock,
  and Docker Desktop's Linux VM kernel has none (measured with engine 29.1.5:
  kernel 6.12.65-linuxkit, active security modules `capability,bpf`), so
  OpenShell refuses to start any sandbox there. A Mac runs sandboxes on
  OpenShell's MicroVM driver instead (see the next section).
- Harnesses: Claude Code, Codex, OpenCode, GitHub Copilot CLI, Kiro CLI,
  Hermes, OpenHands, Antigravity and OmniGent run end to end. Cursor Agent,
  Amp and Devin CLI images build but are refused until a hook check with a
  vendor account passes. Each image pins the harness at DefenseClaw's
  reviewed hook contract, installs root-owned hooks (managed or user tier, see
  the capability matrix) and must pass a hook-fire probe before use.
- Hermes Agent on Bedrock runs `openai.gpt-oss-20b` unless `-- -m MODEL`
  picks another, and the banner names it. The managed provider named no
  model, so Hermes sent an empty one, which Mantle refuses.
- Workspace: the project is mounted live by default, with secret files
  masked, `.git/hooks` and `.git/config` read-only, a pre-session snapshot and
  `sandbox undo`, an end-of-session review of changes that can run code on the
  host, and a nested-repository guard. `--copy` works on a copy and brings
  changes back with `sandbox pull` (apply, branch or patch); worktrees and git
  directories outside the project fall back to copy mode. One sandbox at a
  time can mount a folder live.
- Network: an egress proxy on the daemon (default `api_port+2`) allows the
  web by default and blocks a curated feed of exfiltration and abuse
  destinations, private networks, this machine and cloud metadata, with
  one-command `sandbox unblock`. Asks are rare: host ports, private addresses
  and (under `balanced`/`strict`) hosts off the allowlist. Hooks arrive on a
  separate ingress listener (default `api_port+1`) with per-sandbox binding
  tokens.
- Policy packs `open` (default), `balanced` and `strict`, custom packs under
  `openshell.pack_dir`, and enterprise constraints under `openshell.admin`
  (required pack, minimum profile, yolo, mounts, host ports, unblocks, learn
  mode, allowed harnesses, egress block/allow-only lists, copy requirements,
  resources, locked keys). Refusals say "blocked by your organization's
  DefenseClaw policy" and `sandbox policy explain` shows where each value came
  from.
- Commands: `sandbox setup|doctor|run|connect|list|status|exec|logs|activity|
  stop|start|delete|undo|review|pull|approvals|approve|reject|unblock|policy|
  pack|image|enable|disable|teardown`; the daemon serves them
  under `/api/v1/sandbox/*` (master token and CSRF). The TUI gains a
  Sandboxes panel (key `7`) and a Sandbox setup wizard; the macOS app gains
  sandbox views.
- Telemetry: sandbox lifecycle, workspace, egress, approval and hook-tamper
  events in the v8 families, with a `correlation.sandbox` attribute group on
  hook verdicts.
- New configuration under `openshell:` (enabled, ports, pack/profile, yolo,
  workdir, egress, image, approvals, resources, harnesses, wrappers, mcp,
  token_delivery, admin) and new environment variables
  (`DEFENSECLAW_SANDBOX_ID`, `DEFENSECLAW_SANDBOX_NAME`,
  `DEFENSECLAW_SANDBOX_TOKEN`, `DEFENSECLAW_EGRESS_URL`,
  `DEFENSECLAW_EGRESS_BYPASS`, `DEFENSECLAW_NO_SANDBOX`); see the
  configuration and environment-variable references.
- The `openshell` commands DefenseClaw runs (sandbox connect and the harness
  terminal, copy-mode uploads, pulls, port forwards) use an ssh with
  connection sharing off. With `ControlMaster` and `ControlPath` in
  `~/.ssh/config`, OpenShell's CLI sent every sandbox's ssh session over the
  connection the first one left open, so an upload landed in, and a connect
  could attach to, another sandbox. Your ssh configuration is not changed;
  `sandbox doctor` gains an `ssh-connection-sharing` check that names the
  risk for `openshell` commands you run yourself. That ssh is used only once
  it has been seen to run from where it was put (a `/tmp` mounted `noexec`
  would have let your own ssh run instead, and moves it under the data
  directory), and not from a folder other users can change, macOS ACLs
  included. An `ssh` wrapper first on `PATH` that turns sharing back on
  with its own `ControlMaster`, `ControlPath`, `-S` or `-M` is refused, as
  `ssh -G sandbox` shows it, with the wrapper named; the doctor fails too.
  Each copy-mode upload is also checked to have arrived in the sandbox it
  named, and a baseline failure names the missing path.
- Fixes that also apply outside sandboxes:
  - The Claude Code and Codex hook scripts treated an `alert` verdict (flag
    without blocking) as an invalid reply, so a fail-closed install blocked
    the tool call. They now let it run and show the notice.
  - Shell tool calls that name their own working directory or pass extra
    control arguments (OpenCode, Hermes, Amp, Cursor, Kiro, Devin, Copilot
    CLI, Antigravity) were only partly parsed, so a matching CRITICAL command
    rule was reported but not enforced. Those calls are now judged in the
    directory they name.
- A host name on `openshell.admin.egress_block` now blocks the host and every
  subdomain (#946): `example.net` also blocks `www.example.net` in the egress
  proxy, `sandbox unblock`, approvals and `sandbox policy allow`, and
  `sandbox policy explain` lists it as `example.net, *.example.net`. `policy
  show|explain` and `sandbox doctor` no longer warn that such an entry leaves
  its subdomains open. `egress_allow_only`, `openshell.egress.block` and pack
  lists still match a host name exactly; IP addresses and CIDR prefixes are
  unchanged.
- After `sandbox unblock webhook.site`, a sandboxed agent's `curl
  https://webhook.site/...` no longer gets the `C2-WEBHOOK-SITE` notice
  ("Allowed but flagged by DefenseClaw rule C2-WEBHOOK-SITE", or a block
  under a stricter policy) while the egress proxy lets it through (#954).
  A sandbox verdict decided only by DefenseClaw's destination rules
  (`C2-WEBHOOK-SITE`, `C2-NGROK`, `C2-PIPEDREAM`, `C2-REQUESTBIN`,
  `C2-HOOKBIN`, `C2-BURP`, `C2-INTERACTSH`, `C2-OAST`, `C2-CANARY`,
  `C2-PASTEBIN`) is a plain allow, with no finding on the activity feed,
  when every host those rules name in the call is one the sandbox's proxy
  reaches because of an unblock: a sandbox unblock does this in that
  sandbox, an `--always` unblock in every sandbox. Subdomains nobody
  unblocked, names next to a shell expansion, calls another rule flags too,
  calls Cisco AI Defense or the LLM judge flags or blocks (a custom-policy
  block that names no rule included) and hosts the proxy allows for another
  reason keep their verdict. The
  audit row's reason names the rule that was not applied, and
  `extra.sandbox_egress_unblocked` the unblocks. Both drivers.
- A sandboxed agent is told why the egress proxy refused an HTTPS
  destination (#954). The proxy answers a refused `CONNECT` with a 403 whose
  body clients never show (`curl: (56) CONNECT tunnel failed, response
  403`), so the agent saw only a connection error. Now the post-tool hook of
  the sandbox's next shell or fetch tool call adds a short note to the
  model's context. It names each destination the proxy refused in the last
  two minutes and why, and gives the user's `sandbox unblock HOST --sandbox
  NAME` command when an unblock lifts the refusal, or says who can allow
  it. The note tells the agent not to try another way. An upload the
  large-upload block cut on an HTTPS tunnel, which the tool sees only as a
  broken connection (`curl: (56) Failure when receiving data from the
  peer`), is told the same way, once and in the same window: `DefenseClaw's
  egress policy cut this sandbox's upload to HOST after 996 KiB, because it
  is a destination this sandbox had not contacted before (the large-upload
  block); the upload did not complete, …`, with the unblock command when an
  unblock lifts it (a live test's agent had answered "Uploaded the file.").
  The harness hooks
  that carry it are Claude Code `PostToolUse`/`PostToolUseFailure`, Codex
  `PostToolUse`, Copilot CLI `postToolUse`/`postToolUseFailure`, Cursor
  `postToolUse` and Devin `PostToolUse`. Each refusal is told once, and only
  to the sandbox whose proxy credential made the request. A host unblocked
  since is left out; so is the unblock command from the end-of-session
  summary of a host unblocked later in that session (`✗ DefenseClaw
  blocked webhook.site (webhook catcher); unblocked since`). The audit
  row's `extra.sandbox_egress_refused` names what was told. Hermes, Kiro, OpenCode, OpenHands, Amp, Antigravity and
  OmniGent have no post-tool context field, so there only the terminal's
  live notice reports the block. Both drivers.

### OpenShell 0.1.2

- `defenseclaw sandbox setup` installs OpenShell 0.1.2 (NVIDIA's installer
  from the v0.1.2 tag; the script is byte-identical to v0.1.1's, so its
  pinned SHA-256 is unchanged). 0.1.2 fixes a supervisor bug on the path
  every sandbox connection takes: a sandbox's first request through the
  egress proxy, or a hook call, could stall until the client's own timeout.
  It also stops idle sandboxes from using about 2% of a CPU core each.
  DefenseClaw still drives OpenShell `>=0.1.1 <0.2.0`; the Go SDK pin is
  unchanged (its code is identical in 0.1.2).
- On OpenShell 0.1.1 the doctor's **OpenShell CLI** check warns (the machine
  stays ready) and setup offers the upgrade to 0.1.2 in place:
  ``Upgrade OpenShell 0.1.1 to 0.1.2 in place with NVIDIA's installer?``,
  no by default, so `--yes` and `--non-interactive` keep 0.1.1;
  `--install-openshell` upgrades. NVIDIA's installer restarts the gateway
  once it has installed the release, and setup names the running sandboxes
  first. On the docker driver they keep running and lose their connections,
  and Docker first pulls the 0.1.2 supervisor images from `ghcr.io`, which
  the restarted gateway needs to start: when it cannot, setup keeps 0.1.1
  and changes nothing. On the MicroVM driver the restart would stop running
  sandboxes without a flush, so setup keeps 0.1.1 while one runs and says to
  stop them first. An OpenShell installed another way is not upgraded; the
  check says to upgrade it the way you installed it. The TUI wizard shows the upgrade with **Install OpenShell** off.
  `sandbox doctor --json` reports `openshell_upgrade` and
  `openshell_install_version`.
- The daemon reconnects when the gateway answers with another release, so
  `sandbox status` and the doctor name the release after an upgrade.
- On Linux kernels older than 5.19 (RHEL 9 runs 5.14), OpenShell 0.1 won't
  tell a sandboxed program whom its connection goes to (`getpeername` fails
  with `EOPNOTSUPP`), and Python's `ssl` module asks before every handshake,
  so every HTTPS request of a Python program failed with
  `[Errno 95] Operation not supported`: Hermes Agent, OpenHands and OmniGent
  never reached their model. Their images now carry a workaround in the
  harness's own interpreter. Other Python programs in the sandbox, such as
  `pip`, keep failing until an OpenShell release after 0.1.2
  (NVIDIA/OpenShell #4058).
- On a Mac the first start of each harness image after the upgrade prepares
  its MicroVM disk again (about a minute and 5 GB): the explain note and
  the daemon's disk-room check count only disks the gateway's release
  prepared. `sandbox image prune` removes the disks of another release,
  which the gateway never boots.

### OpenShell sandboxes on macOS (MicroVM driver)

- Apple-silicon Macs run sandboxes on OpenShell's MicroVM (`vm`) compute
  driver, which boots each sandbox in its own VM with a kernel that runs
  Landlock. OpenShell calls the driver experimental. Intel Macs are refused
  before any sandbox command runs (`teardown` still runs). Linux, and any
  gateway on the Docker driver, behave as before.
- The daemon reads the gateway's compute driver when it connects, refuses
  one it does not drive, keeps the driver with each sandbox, and reports it
  as `gateway.driver` in the sandbox status API. What differs per driver
  lives in one table (`internal/openshell/driver.go`).
- A MicroVM mounts no host folders, so every run on a Mac works on a copy:
  `sandbox run` says so in one line before it copies, refuses `--context`,
  says `--no-snapshot` does not apply and that `--cpu`/`--memory` have no
  effect (every MicroVM gets the gateway's `vcpus` and `mem_mib`), and notes
  that the first start of an image prepares its MicroVM disk (about a
  minute). `policy explain` shows `workdir.mode = copy` from
  `openshell.gateway.compute_driver`.
- Copy-mode sessions (on every driver) that bring nothing back, without a
  terminal, with `--yes` or after a skip, end with `N files changed; nothing
  was applied` and the `sandbox pull` command, and say when they keep a
  sandbox despite `--rm`. `sandbox review` of a copy-mode sandbox previews
  its pull instead of failing. A git copy names, in one warning after the
  upload, what it leaves out because git ignores it or it is a package cache
  (`node_modules/`, `.venv/`, build output), and says to install the
  dependencies inside the sandbox. A copy above the upload cap names
  `openshell.workdir.max_upload_mb`; on a Mac a full sandbox disk names the
  MicroVM's overlay (`overlay_disk_mib`).
- Claude Code and Codex per-run managed settings are baked, root-owned and
  read-only, into a content-addressed run image instead of bind-mounted, and
  every image name sent to the MicroVM driver is under `defenseclaw.invalid/`,
  so its registry fallback cannot fetch a stand-in. After each create and
  start a check inside the sandbox proves its uid and gid, that it has no
  capabilities, and the digests of its hooks and run files.
- `sandbox setup` on a Mac asks to switch the gateway to the MicroVM driver,
  offers `brew install e2fsprogs`, and writes `compute_driver = "vm"` and the
  sandbox identity (your uid and gid) in one plan with one restart;
  `sandbox doctor` gains the `vm-driver`, `vm-identity` and `vm-resources`
  checks. On a Mac still on the Docker driver, `sandbox run` on Docker
  Desktop refuses before it builds an image or makes a sandbox (one `docker
  info`), and a run on another Docker VM that fails OpenShell's Landlock
  check names the switch too, on a line of its own (`→ …`) after
  OpenShell's output. A failing `sandbox doctor` ends with `✗ not ready for
  sandboxes: N checks failed`, as a passing one ends with `✓ ready for
  sandboxes` (every driver; `--json` is unchanged). Without Landlock in the
  Docker VM, the doctor skips Docker Desktop's host networking and file
  sharing checks, saying why, instead of asking for a setting that cannot
  help.
- With OpenShell's release binaries outside Homebrew, a gateway that answers
  on the vm driver no longer fails the doctor: `vm-driver` passes on the
  driver it runs (naming the binary when found), and `gateway-service` warns,
  saying how the gateway runs (a launchd label, or started by hand, which
  does not start at login) and that DefenseClaw cannot restart it. Setup
  uses such a gateway too, as the doctor does, on a Mac and on Linux with
  an OpenShell that came without the `openshell-gateway` user unit (whose
  gateway-service check now warns the same way): its machine line marks
  `⚠ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula` (or
  `has no openshell-gateway user service`), it warns that DefenseClaw
  cannot start or restart that gateway, and it goes on. A gateway change
  it needs (MicroVM sandbox user or resources, bind mounts, telemetry) is
  asked about as `Write this change? DefenseClaw cannot restart this
  gateway: …`, written without a restart, and ends with `restart the
  OpenShell gateway yourself, the way you started it, so it runs on the
  change above`, adding that the restart stops every sandbox on the
  gateway and, on the MicroVM driver, to first stop the running ones it
  names with `defenseclaw sandbox stop NAME`, which flushes their disks
  (DefenseClaw cannot flush them before a restart it does not make);
  teardown restores those files the same way. Until that
  restart the doctor's bind-mounts, telemetry and vm-identity checks warn
  that the gateway has not been restarted since the change (on Linux the
  gateway's start comes from `pgrep` and `ps`, as no unit reports it), and
  with no gateway process found they warn that DefenseClaw cannot tell
  whether it was, instead of reporting the change loaded. Setup stops
  only where it would have to start that gateway (none answers), with the
  doctor's fix: start it yourself, or, for a gateway DefenseClaw starts
  and restarts, remove that OpenShell and run `sandbox setup
  --install-openshell`. Before, setup refused such an OpenShell up front
  (`✗ OpenShell 0.1.1 is not from Homebrew's nvidia/openshell formula`,
  exit 1) while the doctor said `✓ ready for sandboxes`. The TUI's
  machine check says what setup says. A driver outside the formula's keg that lacks the Hypervisor entitlement
  gets a fix that names it; `doctor --fix` and setup re-sign only the
  formula's driver (`brew postinstall` signs no other).
  The doctor's disk line counts only the MicroVM disks prepared from images,
  not the driver's overlay templates and bootstrap rootfs.
- The first start of an image on MicroVMs prepares a disk of about the
  image's size (about 5 GB): `sandbox run` now refuses it before copying
  anything when the volume of the driver's image cache has less free space
  than the image plus 1 GiB (at least the doctor's 6 GiB), warns below twice
  that (at least 12 GiB), and names `sandbox image prune`; the daemon refuses
  such a create from any client (`unavailable`), and `image build` warns
  after a build. Docker-driver runs are not checked.
- `sandbox image prune` and `sandbox teardown` on a Mac give back the disk
  of what they remove: the MicroVM disk (about 5 GB) OpenShell prepared from
  each image ID they removed, in `<state_dir>/images`, and say how much they
  freed (`--dry-run`: what they would). Only `sandbox-prepared-rootfs-*`
  directories of IDs Docker no longer has and no sandbox is recorded with are
  removed, and only while the daemon (or, for teardown, the gateway) listed
  the sandboxes; OpenShell's other state stays. The doctor's disk fix names
  prune and `lsof +L1` for space a backup or indexing app still holds.
- On every driver, a harness image removed from Docker (`docker rmi`) no
  longer shows as built and hook-verified: `sandbox image list` names it
  apart from the table (`"missing": true` in JSON), `image prune` says it
  forgets its record, and the doctor's image check does not count it. That
  check also lists every harness image built for you, not only the
  configured harnesses'.
- New `sandbox image rm <harness>...` (#960) removes every image recorded
  for the named harnesses, current ones included: the harness image and, on
  a Mac, its run images and aliases and the MicroVM disks (about 5 GB each)
  OpenShell prepared from them, by prune's rules for disks. It forgets their
  records, also of images already removed with `docker rmi`, shows what it
  removes and asks first (`--yes`, `--dry-run`). It refuses, removing
  nothing, while a sandbox uses one of the images, and names the sandbox to
  delete first; it also refuses while the daemon does not answer and such
  MicroVM disks exist, so no disk is left that nothing would remove later.
  The TUI command palette offers it.
- Fixes from the macOS connector certification (every driver unless noted):
  a copy names the secret files it holds back once; a Kiro tool block names
  DefenseClaw once (host hooks too); the egress counts are destinations
  everywhere: the session summary reads `N new sites contacted · M sites
  blocked` with M matching its `✗` lines, `sandbox status` reads
  `N destinations contacted, M blocked`, and an invalid destination (a host
  without a dot) counts as blocked like the feed shows it (the status JSON
  keeps the request count as `egress.blocked_requests`). The banner's
  `Hooks` line says, per user-tier harness, what the image keeps root-owned
  and what the agent can still change (it said "the agent could edit its own
  hook settings" also for Kiro and Hermes, whose hooks are root-owned). The
  end of a session names `sandbox connect NAME -- <continue args>` last, and
  not dimmed, for Kiro CLI, Hermes Agent and OpenHands too, and says that the
  resume line the harness printed (`copilot --resume=…`, `kiro-cli
  --resume-id …`, `hermes --resume …`, `openhands --resume …`) works only
  inside the sandbox. After an apply, the next pull or session end of a
  copy-mode sandbox shows, reviews and merges only what changed since that
  apply (`… since the last apply`); with nothing new it asks nothing, and
  `sandbox delete` of the stopped sandbox does not warn about unpulled work.
  `sandbox pull` asks the same confirmation as a session's end. A new
  sandbox runs in this machine's time zone (`DEFENSECLAW_HOST_TZ`, exported
  as `TZ` where the image has the zone's file) instead of UTC. Ctrl-Z in a
  harness whose own suspend fails (Copilot CLI) is explained at once in the
  terminal's title, and the notice after it exits (and Hermes' at once) says
  there is nothing to bring back with `fg`.
- `sandbox delete` of a copy-mode sandbox says where its work last went and
  when (`fix-tests's work was last applied to ~/code/myapp at 14:03; nothing
  newer is left in it`, or the branch or patch file), and its warning about
  unpulled work names that too (#964). `sandbox stop` of a copy-mode sandbox
  that no detached run or other session is using looks at its copy first:
  after a `pull --apply` (or `--branch`, `--patch-out`) of the running
  sandbox, `delete` of the stopped one no longer warns that it "may hold work
  … it was not checked". A later pull of a state that went to a branch or
  patch file counts as brought back too. Every driver, Linux `--copy`
  included. Its question no longer names an undo point a copy does not
  have: `Delete sandbox fix-tests (its providers and credentials)?`, where
  a mount-mode sandbox's still adds `unless --keep-snapshot, its undo
  point`.
- `sandbox pull --branch`, `--branch-name` and `--patch-out FILE` are checked
  before the sandbox is started: a branch that holds other work, a patch
  file that exists and a branch for a folder without git are refused before
  "starting … to read its work", instead of after the download and review. A
  branch that already holds the work is done (`nothing to do: branch dc/<name>
  already has these changes`), with no question about its sensitive
  changes, at a session's end too. A branch that holds only the last pull is
  refused before the start too when the stopped sandbox has run since that
  pull (`… it holds <name>'s pull at 14:03, and <name> has run since, so its
  work may have changed`). A stopped sandbox whose copy has not changed since
  its last pull read it is not started: `sandbox pull` and `review` use that
  pull again (`…'s copy has not changed since its last pull at 14:03; using
  that pull instead of starting it`), which on a Mac saves booting the
  MicroVM (#965).
  Every driver.
- Node's `[UNDICI-EHPA] Warning: EnvHttpProxyAgent is experimental` no
  longer prints in a sandbox
  ([#951](https://github.com/cisco-ai-defense/defenseclaw/issues/951)). The
  Copilot launcher passes `NODE_OPTIONS=--disable-warning=UNDICI-EHPA`, as the
  Codex one does, to Copilot's npm launcher, which printed it above the TUI
  at every start (the native CLI that launcher starts does not print it). And
  every open or balanced sandbox now sets `NODE_NO_WARNINGS=1` with its proxy
  settings, so the `node`, `npm` and `npx` commands the agent runs no longer
  print it into their output either. That hides Node's other warnings as
  well, including the one that says `NODE_TLS_REJECT_UNAUTHORIZED=0` turned
  TLS certificate checks off; create a sandbox with `--env
  NODE_NO_WARNINGS=0` to keep them. Both
  drivers; the images rebuild.
- A new Antigravity sandbox starts at agy's prompt: the image completes
  agy 1.2.12's onboarding, so it no longer asks for a colour scheme, the
  terms and a data-sharing choice, and the launcher trusts the working
  directory, so it no longer asks whether to trust the folder
  ([#963](https://github.com/cisco-ai-defense/defenseclaw/issues/963)).
  DefenseClaw accepts the Google Antigravity CLI Terms of Service for the
  user with data sharing off: the "help improve Antigravity CLI" box, ticked
  by default, is never ticked, and Enable Telemetry is off. Without
  `GEMINI_API_KEY` agy still asks how to sign in. Both drivers; the
  Antigravity image rebuilds.
- The Kiro image unpacks the embedding model Kiro CLI downloads at its first
  start (`all-MiniLM-L6-v2`, 79 MiB, each file checked against the SHA-256
  the pinned `kiro-cli-chat` carries) into the image HOME, so a new Kiro
  sandbox's first session no longer downloads it. When that download fails
  or its files do not match, the image builds without the model and Kiro
  downloads it as before. The Kiro launcher sets
  `KIRO_SKIP_BINARY_PINNING=1`, so an interactive session runs the root-owned
  `kiro-cli-chat` rather than the copy Kiro makes in
  `~/.local/share/kiro-cli/run`.
- A DefenseClaw block now shows in the Hermes TUI: a root-owned module in the
  Hermes image prints the block reason under the tool's line
  (`┊ ✗ terminal blocked by DefenseClaw rule <ID>: …`), where Hermes 0.19
  printed nothing. The reason the model gets is unchanged.
- The Hermes image stamps its install the way Hermes' own image does
  (`.install_method` = `docker`), so Hermes no longer prints "pip installs are
  no longer an officially supported platform" or asks `pypi.org` for updates
  at every start, and its managed layer pins `model_catalog.enabled: false`,
  which stops the start-up fetch from `hermes-agent.nousresearch.com` and
  `nousresearch.github.io`.
- An OpenHands sandbox session no longer ends with an
  `Exception ignored in atexit callback` / `RuntimeError: App is not running`
  traceback above the session summary: a root-owned module in the OpenHands
  image runs the `SessionEnd` hooks as before and drops only the display
  event OpenHands hands to its already stopped TUI. The same module starts a
  DefenseClaw block's hook line with the block, so the collapsed line reads
  `BLOCKED by DefenseClaw rule <ID>: …` instead of
  `Status: BLOCKED - Blocked by DefenseCla...`, and it ignores the
  `AuthlibDeprecationWarning` an OpenHands dependency printed at every start.
- Interactive GitHub Copilot CLI sessions wait out Copilot's 30-second hook
  timeout on every hook in a MicroVM too (#966): OpenShell's seccomp filter
  refuses `pidfd_open` there as well. The launch banner of an interactive
  Copilot session now says so, on Linux as well; `--prompt` runs are not
  slowed. Copilot's HTTP hooks, which would avoid the wait, let a tool call
  run when the request fails, so the sandbox keeps its fail-closed command
  hooks.
- A harness that exits while a command it started still runs (OpenCode quit
  in the middle of a tool call) no longer leaves that command changing the
  sandbox while DefenseClaw pulls or reviews the work: the launcher's
  terminal-session supervisor adopts what the harness leaves, ends it before
  the session's end (two seconds' grace, then `SIGTERM` and `SIGKILL`) and
  names it. OmniGent's server and `sandbox exec` commands are kept. Both
  drivers; the images rebuild.
- An interactive OpenCode session's banner has a `Keys` line: Esc
  interrupts a turn, and Ctrl-C (OpenCode's quit key, also mid-turn) ends
  the session.
- A new OpenCode sandbox no longer downloads `@opencode-ai/plugin` and its
  dependencies (about 20 MiB from registry.npmjs.org) at start: the image
  records the pinned version as installed in `~/.config/opencode`, which
  OpenCode's install check accepts. Both drivers; the OpenCode image
  rebuilds.
- The toast for a tool call DefenseClaw blocked in an OpenCode sandbox says
  to click the tool's red line to see the reason again: OpenCode shows a
  refused call's reason only there, and its plugins cannot set the tool's
  output.
- The OpenCode launcher's refusal of a plugin, custom tool or config file
  inside the sandbox gives the commands that remove it from your machine
  (`sandbox start`, `sandbox exec <name> -- rm <file>`, `sandbox connect`),
  with the path quoted for the shell. Both drivers; the OpenCode image
  rebuilds.
- Copilot CLI sandboxes get hook tamper detection: a tool call that ran
  although DefenseClaw denied it, or whose `preToolUse` hook never reached
  DefenseClaw, now raises the `hook_tamper` finding and `hooks.on_tamper`
  applies (`stop` in `balanced` and `strict`). Until now only a silent hook
  was noticed. Copilot's hooks carry no per-call ID, so its calls are paired
  like Kiro CLI's, by session, tool name and tool arguments; measured on the
  pinned 1.0.88, a call a hook denied or the user refused sends no
  `postToolUse`. Both drivers.
- Devin CLI sandboxes get hook tamper detection too: a tool call that ran
  although DefenseClaw denied it, or whose `PreToolUse` hook never reached
  DefenseClaw, raises the `hook_tamper` finding and `hooks.on_tamper`
  applies. Devin documents no per-call ID, so its calls are paired like
  Kiro CLI's and Copilot CLI's, by session, tool name and tool input;
  measured on a logged-in Devin CLI 3000.11.3, a call a hook denied, the
  user refused or that failed before it ran sends no `PostToolUse`. The
  Devin CLI image is still unverified, so `sandbox run devin` still refuses
  it. Both drivers.
- The Kiro CLI sandbox image rebuilds: its agent hooks now set
  `timeout_ms` 30000, so a slow verdict no longer lets the tool run (see
  Kiro CLI tool hooks).
- Claude Code's `Agent` (subagent) calls are recorded in full (#957), on the
  host and in sandboxes. Claude Code 2.1.156 sends the call's `PostToolUse`
  after the subagent's own hooks. It reached the gateway, but its
  correlation failed as stale, so the audit had no decision and no end for
  the call, and the `PostToolBatch` recorded as `ClaudeCodeTool` was its
  only result. Main-agent hooks, which carry no `agent_id`, also lost their
  agent while a subagent's cursor was active (an interrupted subagent's
  stays active), and each later prompt gave the main agent a new ID. Now
  every hook is recorded and the main agent keeps one ID. Each subagent's
  calls carry the subagent's ID and type, with the main agent as parent at
  depth 1, also for parallel `Agent` calls. The correlation ledger links
  each subagent to the `Agent` call that ran it (`caused_by`,
  `spawned-agent-tool-result`). A `PostToolBatch` is recorded as a
  `tool_batch` listing its calls. Both drivers.

### OpenShell sandbox AI discovery and process tree

- AI discovery now sees inside running sandboxes: the MCP servers, skills,
  rules, plugins, AI CLIs and agents the agent installed or configured in a
  sandbox, its environment variable names (never values), shell history
  mentions and, for a copy, its package manifests. DefenseClaw reads the
  sandbox with one read-only command it builds itself, checks every path and
  file the sandbox sends back (absolute, printable, under the sandbox's home,
  projects or harness install, within what was asked and within
  `ai_discovery.max_file_bytes` a file, `max_files_per_scan` files read,
  8,192 entries listed and a 4 MiB stream),
  writes what passes as private regular files on this machine, scans them
  there and removes them (only the scan record stays). It runs once a
  sandbox is ready, every
  `ai_discovery.scan_interval_min` while it runs, and on demand with
  `defenseclaw sandbox discover NAME`; a stop keeps what was found (without
  its processes) and a delete drops it. `defenseclaw agent usage --sandbox
  NAME` shows one sandbox's components, every view tags them
  "(sandbox NAME)", the TUI's AI discovery panel keeps them apart and names
  the sandbox, and the `ai_component.*` telemetry records carry
  `defenseclaw.sandbox.id` and `defenseclaw.sandbox.name`.
- Claude Code skills and rules kept in a project (`.claude/skills`,
  `.claude/rules`) are listed by name like the ones in `~/.claude`, in a
  sandbox's project and in each `ai_discovery.scan_roots` folder.
- The AI discovery Grafana board's Sandbox box narrows only the sandbox
  signals table and the per-signal log; the sections and panels it does not
  narrow say (all names) in their titles, as on the Sandboxes board.
- Opt-in process tree: a pack's new `observe.process_tree: true` (off in
  `open`, `balanced` and `strict`) or `sandbox run --process-tree` samples the
  sandbox's processes every 5 seconds while it runs (every 15 seconds on a
  Mac when sampling its MicroVM is slow) and adds OpenShell's process launch
  and exit reports. `defenseclaw sandbox ps NAME [--tree]` and the TUI's
  sandbox detail show it, with the values of arguments that name secrets
  replaced, and new `sandbox.process_tree` records (`sandbox-process` audit
  action) report each process's start and exit with its parent and
  ancestry. Sampling misses a process that starts and ends between two
  samples, and the agent chooses its processes' names and arguments.

### OpenShell sandbox lifecycle and configuration

- `openshell.llm` (default `auto`) chooses the model credential a sandbox
  run shares, as `sandbox run --llm` does (#955). The shell wrappers, the TUI
  and the macOS app pass no `--llm`, so the runs they start now share the
  credential it names; `--llm` still overrides it for one run. A provider the
  harness has no profile for falls back to `auto` with a note, and one whose
  key is not set refuses the run, naming the key. `--llm auto` now also picks
  Amazon Bedrock (`AWS_BEARER_TOKEN_BEDROCK`) when that is the only
  credential set, after every other one, so a host with only a Bedrock key
  reaches its model without `--llm bedrock`. The key is in the Python config,
  the v8 schema, and the TUI and macOS app config editors. Both drivers.
- A headless `sandbox run` in the foreground (`--prompt`, or the harness's
  print mode, such as the shell wrapper's `claude -p`) now deletes the
  sandbox it created when it ends and nothing is left in it to bring back or
  undo, by the rules of `--rm` (#948), so one-prompt runs no longer pile up
  stopped sandboxes. Changes nobody kept in a mounted folder keep their undo
  point (`sandbox undo NAME` still reverts them), and a copy whose work was
  not brought back keeps its sandbox; the run's last line says it was
  deleted and why, or why it was kept. `--keep` (a new `sandbox run` flag)
  and `openshell.keep_headless: true` keep it. Interactive sessions,
  `--detach` runs and a run that resumes the folder's sandbox are unchanged.
  Both drivers.
- `openshell.workdir.undo_ignored` (#944) lets `sandbox undo` restore the
  dependency directories git ignores, which it only reported before
  (`undo cannot restore node_modules/ …: delete it and reinstall`). Off by
  default; with `enabled: true` each undo point of a mounted project keeps a
  copy of `dirs` (`node_modules`, `.venv` and `venv` unless set), as file
  clones where the filesystem supports them and byte copies otherwise, up to
  `max_mb` (500 MiB). A directory whose copy would pass the cap keeps none and
  is reported as before, naming the cap; review says which directories undo
  restores. Undo that cannot restore a dependency directory names the key.
  Linux mount mode only: copy mode, every sandbox on a Mac included, has no
  undo point. In the Python config, the v8 schema, and the TUI and macOS app
  config editors; the TUI's undo preview names what it restores.
- `defenseclaw config validate` names the field and what it takes for a
  value the v8 schema refuses, such as `openshell.workdir.undo_ignored.max_mb`
  (`expected a number between 0 and 1048576`) or `openshell.llm` (`expected
  one of [...]`), as the Go loader does: the canonical validator ran its
  runtime loader before the schema pass, so it only said "configuration
  could not be compiled safely" at `$`. A refusal only that loader makes
  (`openshell.binary`, an `openshell.egress` pattern) is placed by the
  Python mirror of those checks. Messages still never contain the rejected
  value.
- The daemon now does the detached-run and undo-point bookkeeping the CLI
  did alone (#947), so the TUI, the macOS app, a tamper stop
  (`hooks.on_tamper: stop`) and `undo` get it too. Every stop of a running
  sandbox marks a detached run still going interrupted (its runner is found
  by `latest.pid` and a command line naming `latest.exit`), says so on the
  activity feed (`run_interrupted`), and keeps the last 1 MiB of the run's
  log under `<data_dir>/sandboxes/<name>/runlog/` (reading only a regular
  file, bounded, after it publishes `stopping`; a tamper stop neither
  looks at the run nor keeps its log, so it waits on nothing the workload
  controls); `sandbox logs` of a
  stopped sandbox reads it from the new `GET
  /api/v1/sandbox/sandboxes/{name}/logs`, and still shows (as such) a log an earlier
  CLI kept, until the sandbox starts again. Keeping the changes at the end of a session is recorded through
  the new `POST /api/v1/sandbox/sandboxes/{name}/accept` instead of
  `cli/accepted.json` (one an earlier CLI wrote is honoured once), so the
  next start takes a new undo point whoever starts the sandbox, and the
  sandbox's snapshot carries `accepted_at` (the TUI and the macOS app say
  so). The accept names the snapshot and the sandbox's `session` (a count of
  its starts) it reviewed, so a keep answered after another start, whose
  changes nobody reviewed, is refused. A start with `--no-snapshot` now uses the acceptance up, so that
  session's changes keep the undo point at the next start; a start that fails
  before the sandbox runs keeps it. The CLI still
  asks before `sandbox stop` ends a run, and reads the same from the user's
  side. The Python client has `sandbox_run_log` and
  `accept_sandbox_changes`. Both drivers.
- `sandbox status NAME` counts the hook verdicts per hook event, under the
  harness's own event names (#956): a `Hook events` row reads `PreToolUse
  12 · PostToolUse 11 · UserPromptSubmit 3 · Stop 2`, most frequent first.
  Until now it gave only the totals (requests, tool calls, blocks), so a
  harness whose `PostToolUse` or `Stop` hooks never fired looked the same as
  one whose did. The daemon keeps the counts with the sandbox's other hook
  counters, in the API's `hooks.events` (the JSON output too), at most 48
  names a sandbox, cut to 64 bytes, with the rest in `hooks.other_events`.
  The details of the TUI Sandboxes panel and the macOS app show the same
  row. Both drivers.
- Large uploads to first-seen hosts can now be blocked, not only reported
  (#967). The egress proxy already cut such uploads when asked, but nothing
  asked. The pack key `egress.block_large_uploads`,
  `openshell.egress.block_large_uploads: true` (every sandbox; `false`, the
  default, follows the pack) and `openshell.admin.block_large_uploads: true`
  (every sandbox; a pack's `large_upload_mb: 0` gets 25 MiB, and a higher
  threshold is lowered to 25 MiB or the required pack's own) turn it on;
  each sandbox's proxy credential carries its own, and a configuration change
  reaches running sandboxes, whose feed says so. The upload is stopped before
  the chunk that crosses the threshold, and later requests to that host, or to
  other new hosts under its domain or at its address, get a 403 of category
  `large_upload`, whose reason says why the destination is blocked rather
  than repeat the upload (`This destination is blocked since this sandbox
  tried to send more than 10 MiB to it, …`; a `GET` sends nothing), as the
  run's live notice of it does (`✗ DefenseClaw blocked HOST (…)`). The feed shows a ✗ with the threshold and the unblock
  command (`✗ files.example.net (large upload blocked: this sandbox tried to
  send more than 10 MiB to a destination it had not contacted before)`) instead of
  the ⚠ report, `sandbox run` announces it, the finding is HIGH, and the
  egress audit records the cut as blocked (`SANDBOX_EGRESS_LARGE_UPLOAD`).
  Unblocked hosts and those on an allow list the user or the administrator
  wrote are only reported; an unblock lifts the block. With a threshold of 0
  there is nothing to cut, so the block is off, and `sandbox policy explain`
  says so. The ⚠ report without the block, made as the upload crosses the
  threshold, now says `more than` it (`⚠ large upload to files.example.net
  (more than 25 MiB)`, with `threshold` on the event) instead of the bytes
  sent by then, which read `(1.0 MiB)` for a 1.9 MiB upload. `sandbox policy
  explain` shows `egress.block_large_uploads` and where it came from, and
  `policy show` the threshold. In the Python config, the v8 schema, and the
  TUI and macOS app config editors, which show the key read-only under the
  administrator's switch; the TUI and app feeds name the threshold. Both
  drivers.

### OpenShell sandbox hardening

- **The check after ready runs on the docker driver too.** After every
  create and start, one exec checks that the workload runs as the uid its
  image was built for with no capabilities, that DefenseClaw's hooks,
  launcher and managed settings are the root-owned files it delivered, and,
  on docker, that the per-run settings files are on read-only mounts. A
  sandbox that fails it is refused with `policy_rejected` and is deleted
  (create) or stopped again (start), and the message now says which
  (`…; DefenseClaw deleted it`, `…; DefenseClaw stopped it again (its work is
  kept)`). It ran only on the MicroVM driver before.
- **Silent hooks stop a user-tier sandbox in balanced and strict.** New pack
  keys `hooks.on_silence` (`stop` or `alert`) and `hooks.silence_after` (a
  duration from `1m` to `24h`, `10m` in every built-in pack). When the
  harness of a user-tier sandbox (OpenCode, Kiro CLI, Amp, Devin CLI,
  Antigravity, Hermes, OpenHands), whose hook registration the agent can
  edit, works that long (an idle stretch that long starts the count over)
  without one hook request reaching DefenseClaw,
  `stop` (the default in `balanced` and `strict`) stops the sandbox the way
  a hook tamper does, and `alert` (the default in `open`) keeps it running.
  Both raise the HIGH `hook_silence` finding, whose evidence names the
  response, and a feed line that says what follows. A managed-tier harness
  only alerts. The banner's `Hooks` line, `sandbox policy explain` and the
  sandbox's `hooks.on_silence` / `hooks.silence_after` show the setting;
  with `pack` locked, a run cannot switch to a pack that alerts or waits
  longer. The threshold was a fixed 10 minutes and silence only alerted.
  A harness with switched-off hooks that works in bursts shorter than
  `silence_after`, idle at least that long between them, is not flagged;
  the sandbox guide and the policy pack reference state this limit.
- **The activity feed names its epoch.** Every activity event carries
  `epoch`, which names the daemon's in-memory feed; a restarted daemon
  numbers its events from one again under a new epoch. The TUI's Sandboxes
  panel and the macOS app compare it when they resume (instead of guessing
  from the event under the old number) and read a new feed from its start.
- **macOS setup offers to turn OpenShell's usage telemetry off.** As on
  Linux, `defenseclaw sandbox setup` asks before it sets
  `OPENSHELL_TELEMETRY_ENABLED=false` in `~/.config/openshell/gateway.env`,
  which the Homebrew service reads, in the same change and restart as the
  MicroVM settings, and records the answer in
  `openshell.upstream_telemetry`. The doctor's telemetry check runs on a Mac
  too (it was skipped), and `--fix` repairs a mismatch. The TUI's and the
  macOS app's Sandbox wizards ask it on a Mac too (**OpenShell Telemetry
  Off**). A Mac gateway that no Homebrew service runs is still left alone.
- **The banner says how the model hosts are reached.** A new line under
  `Model` states that OpenShell opens them to the harness's own program
  directly, around the egress proxy, and that for an npm or Python harness
  that program is its `node` or `python`, so a script it runs reaches them
  too. The sandbox guide and the network page say the same.

### Legacy OpenShell standalone sandbox removed

- **Breaking:** removes the legacy standalone sandbox integration for the
  `openshell-sandbox` 0.0.x binary. It was Linux- and OpenClaw-only: a network
  namespace and veth pair (`10.200.0.1` host, `10.200.0.2` sandbox), iptables
  NAT rules, root `openshell-sandbox.service` / `defenseclaw-sandbox.target`
  units, launcher scripts under `/usr/local/lib/defenseclaw/`, a `sandbox`
  Linux user, and ownership/ACL changes on `~/.openclaw`. The Go wrappers
  called OpenShell CLI verbs that do not exist, and the generated
  per-connector sandbox policy was never enforced. The NVIDIA OpenShell 0.1
  sandboxes above replace it.
- **Breaking:** removed commands: `defenseclaw sandbox init`, the old
  `defenseclaw sandbox setup` flags (`--disable`, `--sandbox-ip`, `--policy`
  and the others; `sandbox setup` now sets up OpenShell 0.1),
  `defenseclaw-gateway sandbox start|stop|restart|status|exec|shell`, and
  `defenseclaw-gateway sandbox policy diff`.
- Removed files: `policies/openshell/*`, `policies/rego/sandbox.rego`
  (`policies/rego/data-sandbox.json` stays; it carries firewall data),
  `internal/sandbox/`, `internal/cli/sandbox.go`, `internal/cli/policy_diff.go`,
  `cli/defenseclaw/commands/cmd_init_sandbox.py`,
  `cli/defenseclaw/commands/cmd_setup_sandbox.py`,
  `scripts/bundle-sandbox-test.sh`, `scripts/test-e2e-sandbox*.sh`,
  `scripts/test-e2e-tool-block-sandbox.sh`, `scripts/test-proxy-sandbox.py`,
  `scripts/fix-sandbox-acls.sh` and `scripts/install-openshell-sandbox.sh`.
- `defenseclaw init --sandbox`, which was hidden and deprecated, is removed: it
  is now a usage error.
- **Breaking:** `install.sh --sandbox` is a usage error: the installer stops
  before installing anything (exit 1) and points at `defenseclaw sandbox setup`
  and `defenseclaw sandbox legacy-cleanup`.
- **Breaking:** OpenClaw and ZeptoClaw subprocess policy is now `shims` on
  every platform. Earlier docs claimed Linux installed an enforced
  Landlock/seccomp OpenShell policy with shims as a supplement; that policy was
  never enforced.
- **Breaking:** no cleanup command and no bind shim: the upgrade resets the
  config instead. The `config_version` 9 migration (run by the upgrade, by
  `defenseclaw migrate`, and in memory when the gateway loads a v8 file)
  drops `openshell.mode`, `openshell.sandbox_home` and
  `claw.openclaw_home_original` (the OpenClaw home pin, named in a migration
  note when set) from every config and, on one that said
  `openshell.mode: standalone`, the non-loopback
  `guardrail.host` and `gateway.host` (the veth addresses), which take their
  defaults. An upgraded standalone host's gateway API so binds on loopback,
  where the upgrade, watchdog and status probes and the CLI dial it, instead
  of on `10.200.0.1`; `migration-v9.json` lists the removed keys, and running
  the migration again changes nothing. `/health` reports no `sandbox`
  subsystem for such a host, and `doctor`, `status` and `status --json`
  (whose `sandbox` object loses `legacy_standalone`) say nothing of it. The
  root units, launchers, network namespace, NAT rules and `sandbox` user are
  removed by hand: see
  [remove a retired standalone sandbox](https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/guide/#remove-a-retired-standalone-sandbox).
  `defenseclaw init --sandbox`, `install.sh --sandbox` and the
  `install-openshell-sandbox.sh` stub point there. A
  `defenseclaw sandbox legacy-cleanup` command was in unreleased 1.0 builds
  only and is gone.
- Config: the `openshell:` legacy sub-keys `policy_dir`, `version`,
  `auto_pair`, and `host_networking` stay accepted by the v8 schema and are
  ignored; `mode` and `sandbox_home` are removed by the `config_version` 9
  migration.
- **Breaking:** telemetry and audit: removes the `metric.defenseclaw.openshell.exit`
  metric family (instrument `defenseclaw.openshell.exit`) and its
  `defenseclaw.metric.command` attribute, and retires the `init-sandbox` audit
  action. A route selector that still names the `init-sandbox` action or the
  `defenseclaw.openshell.exit` event name keeps compiling: the value stays in
  the selector, where it matches nothing, and the effective plan carries a
  `retired_selector_value` warning so it can be removed.
- Removes the seven environment variables whose only consumers were deleted:
  the legacy installer's binary-digest, manifest-digest, and unpinned-download
  variables; the launcher scripts' broad-regex namespace cleanup opt-in and
  install-directory variable; the `sandbox setup` pre-pairing device-key trust
  override; and the sandbox proxy test harness's bearer token.

### Kiro CLI tool hooks

- Fixes the Kiro CLI 2.x agent hooks (`~/.kiro/agents/defenseclaw.json`, and
  the operator's own default agent when `chat.defaultAgent` names one):
  setup registered `preToolUse` and `postToolUse` with the matcher `.*`.
  Kiro CLI reads matchers as globs, so `.*` matched no tool and no tool call
  on the host was ever checked. Setup now writes `*`. The gateway runs
  connector setup at every start, so the first start after an upgrade
  rewrites DefenseClaw's own entries in place; entries the operator added
  are left as they are. Measured against kiro-cli 2.24.1 on Linux.
- Kiro CLI 2.x: a DefenseClaw verdict that took longer than about ten
  seconds let the tool run, on the host and in a Kiro sandbox. DefenseClaw's
  agent hooks set no `timeout_ms`, and Kiro ignores a hook past its default
  timeout (measured on 2.24.1: a `preToolUse` hook that took 12 s to block
  did not stop the tool). Every DefenseClaw agent hook now sets
  `timeout_ms` 30000; the gateway rewrites a host agent at its next start,
  and the Kiro sandbox image rebuilds.
- Kiro CLI on the host: an agent that Kiro upgraded to its universal (V2 +
  V3) format, which `kiro-cli --v3` offers at start and `/upgrade-agent`
  does, lost the hooks you had added to it at DefenseClaw's next setup, and
  teardown left DefenseClaw's entries in it. Setup, verification and
  teardown now read that format and change only DefenseClaw's own entries.

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
