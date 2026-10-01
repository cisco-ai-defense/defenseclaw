# Enterprise test plan (Windows, Linux, macOS)

This is the manual test plan for DefenseClaw's `managed_enterprise`
deployment mode. It covers the vendor-neutral standalone profile on Windows,
Linux and macOS, which any MDM, package manager or administrator shell can
deploy; the Cisco Secure Client profile, which must not change; and the
normal per-user mode, which must not change either. A test team with no
earlier context can follow it end to end. It says what to build, which hosts
and accounts to prepare, how to drive each step, what each step must show,
and how to record and report the result. It repeats, as reproducible rows,
the checks the maintainers ran by hand on real hosts before release.

The plan complements, and does not replace:

- the automated lanes in [TESTING.md](TESTING.md) (enterprise install lanes,
  install lifecycle lanes, unit and integration suites);
- the threat models: [ENTERPRISE-THREAT-MODEL.md](ENTERPRISE-THREAT-MODEL.md)
  (rows `R1`…`R31`), [WINDOWS-ENTERPRISE-THREAT-MODEL.md](WINDOWS-ENTERPRISE-THREAT-MODEL.md)
  (`W-01`…), [LINUX-ENTERPRISE-THREAT-MODEL.md](LINUX-ENTERPRISE-THREAT-MODEL.md)
  (`L-01`…) and [MACOS-ENTERPRISE-THREAT-MODEL.md](MACOS-ENTERPRISE-THREAT-MODEL.md)
  (`M-01`…), which define every documented residual this plan refers to;
- the public enterprise guide
  ([overview](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise),
  [lifecycle](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/lifecycle),
  [operations](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/operations),
  [troubleshooting](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/troubleshooting),
  [MDM](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm)),
  whose commands the install rows follow as written.

[WINDOWS-ENTERPRISE-CERTIFICATION.md](WINDOWS-ENTERPRISE-CERTIFICATION.md)
certifies the Secure Client profile with its own harness. That harness has no
standalone profile, so do not use it for a standalone run.

Run every host-changing row on a disposable host (a virtual machine you can
revert, or a test machine with a separate administrator recovery path). The
lifecycle installs system services, service accounts and vendor machine
policy for every account on the host. Never run this plan on a production
workstation, a shared developer machine or a CI runner.

## Purpose and pass criteria

The plan answers one question per platform: does the build under test deploy,
enforce, repair and remove the standalone profile as documented, so that a
standard account cannot weaken it outside a documented residual, while the
Secure Client profile and per-user mode behave exactly as before?

A release candidate passes on a platform when all of these hold:

1. Every applicable row has a verdict (`PASS`, `FAIL`, `N/A` or `NOT_RUN`)
   and evidence. Every `N/A` and `NOT_RUN` names its reason. A missing agent
   sign-in, license, plan or model is a `NOT_RUN` with that reason, never a
   pass.
2. No standard account can weaken enforcement outside a residual the threat
   models already document. A documented residual that behaves exactly as its
   row says is recorded as `residual <id>, seen`, not as a new pass and not as
   a new bug.
3. Every lifecycle action (install, ensure, status, verify, repair,
   reconcile, upgrade, uninstall, purge) returns the documented exit code and
   one result document, a repeated `ensure` is a no-op, and every failure
   rolls back to the previous deployment.
4. Every repair of a user's own registration finishes within its documented
   bound (see [Timing bounds](#timing-bounds)), and calls made during the
   repair window are still inspected or blocked, or match a named residual.
5. Audit rows attribute every tool call to the account that made it.
6. Administrator-owned vendor policy is byte-identical before install, after
   repair and after uninstall, except for the entries DefenseClaw owns.
7. Every blocking finding is fixed and retested interactively with its
   original steps. An automated test does not replace the live retest.
8. Each retained host ends the run in a healthy state: `status` and `verify`
   succeed, and `std1` and `std2` are enrolled. Decommissioned hosts end with
   PUR-01 and CLN-05 evidence instead.
9. Per-user mode and the Secure Client profile show no behavior change except
   the intended ones listed in [Per-user mode regression](#per-user-mode-regression)
   and [Secure Client non-regression](#secure-client-non-regression).
10. A real MDM tenant deployment, if run, is reported separately from the
    execution-context simulation rows. The simulation rows do not prove that
    a tenant assigned, installed, detected and remediated the product.

A row is `FAIL` when the observed result, recovery time or CLI diagnostic
differs from its expected result. Severity:

| Severity | Meaning | Examples |
| --- | --- | --- |
| Blocker | A standard account weakens enforcement outside a documented residual, or the lifecycle leaves a host broken or unrecoverable | A supported client runs the block marker with its ordinary configuration; a standard account changes administrator-owned policy; a call is attributed to another account; a failed upgrade leaves no working deployment |
| Major | Documented behavior is wrong but enforcement holds | A repair exceeds its bound; an exit code misleads an MDM (success reported for a failure); `verify` passes with a real problem |
| Minor | UX or documentation | An unclear or missing next step, an internal path or reason code in a user-facing message, a documented command that does not work |

### Timing bounds

| What | Documented bound |
| --- | --- |
| Guardian repair of a user's own DefenseClaw registration | Seconds (file watching); at most one reconcile interval, one minute |
| Foreign-hook cleanup of user-level hook files | About every five minutes; allow up to about 5.5 minutes. The hook-time guard blocks affected calls in the meantime |
| Enumerator cycle (new account, agent install or version change) | Every five minutes, and once at service start |
| Revocation of a deleted account (Linux, macOS) | The third consecutive definitive miss, 10 to 15 minutes; `enterprise <os> repair` removes it at once |
| Lifecycle lock wait | Linux and macOS: 5 s by default (`--lock-wait` up to 15 m), then exit `75`; package scripts and the config-apply trigger wait up to 10 minutes. Windows: about 30 s, then exit `1618` |
| Config apply after an in-place edit | Linux path unit: within about 10 s. macOS apply daemon: at most once every 30 s |
| Daily verify | Linux timer: daily with up to one hour of random delay. macOS: 03:17 local time |
| Windows per-user writes | Only while that user has an active session (R17). Signed-out users are handled at their next sign-in |
| Foreign-hook session hold | Until the agent restarts, for up to seven days |
| Sensor helper planned restart | Up to about 15 s after an enrollment change; `status` waits it out |

### Stage order

Run the stages in this order on each host. Keep each stage's evidence in its
own folder.

| Stage | Who | Sections |
| --- | --- | --- |
| S0 Preflight | Admin account | [Build under test](#build-under-test), [Environment](#environment), [Preflight](#preflight) |
| S1a Clean-host channels | Admin account | Run each clean-host install or MDM row on a separate snapshot, reverting to the clean snapshot after each. Run removal and purge rows only in S5 or S8 |
| S1b Final install | Admin account | Install V1 by the package channel (Windows: INS-W-01), apply the test config and PACK-01, then run non-removal [Install and lifecycle](#install-and-lifecycle) and [MDM execution contexts](#mdm-execution-contexts) rows. Exit with `std1` and `std2` enrolled and healthy `status` and `verify` |
| S2 Standard accounts | std1, std2 | [Standard-account rows](#standard-account-rows), [Multi-user isolation and enrollment](#multi-user-isolation-and-enrollment), [Standard-user hardening checks](#standard-user-hardening-checks) |
| S3 Connectors | std1, std2, admin account | [Admin CLI](#admin-cli), [Connectors](#connectors), [Rule engine and guardrails](#rule-engine-and-guardrails), [Foreign-hook guard](#foreign-hook-guard), [Claude Code version floor](#claude-code-version-floor) |
| S4 Enrollment | Admin account, new account, excluded account | [Enrollment](#enrollment) |
| S5 Upgrade, repair, removal | Admin account | [Upgrade, repair, uninstall and purge](#upgrade-repair-uninstall-and-purge), then F4 and the named S2/S3 spot-check |
| S6 Failure drills | Admin account | [Failure drills](#failure-drills) |
| S7 Regression | Any | [Per-user mode regression](#per-user-mode-regression), [Secure Client non-regression](#secure-client-non-regression), [Regression checklist](#regression-checklist), [UX checklist](#ux-checklist) |
| S8 Cleanup | Admin account | [Cleanup](#cleanup) |

## Build under test

For PR #924, the initial product build is commit
`a60d1822c639f43cac19c2b506293733974f5e54`, source tree
`9d6cdeffd7782ab4a4437e6e6e300c6935b5eb87`. The Kiro teardown fix is
commit `2084f9263`; record the final test commit and tree after the plan fixes.

Record the exact source before building anything. Every result in the run
refers to this record.

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| BUT-01 | A clean clone of `cisco-ai-defense/defenseclaw` | `git fetch origin pull/924/head:pr-924`; `git checkout <recorded PR commit>`; then `git status --porcelain`, `git rev-parse HEAD`, `git rev-parse 'HEAD^{tree}'` and `git log -1 --format='%H %cI %s'` | `git status --porcelain` prints nothing. Record the commit, tree hash, PR and date. After a squash merge, use the merge commit and its tree rather than the old PR head |
| BUT-02 | BUT-01 | Build a lower and a higher version (this plan uses `9.9.9` as V1 and `9.9.10` as V2; see [Build and packaging](#build-and-packaging)). Record the SHA-256 of every artifact. For hook re-render checks use a V1 source commit with different hook bytes; same-source V1/V2 scripts can be byte-identical | Two artifacts per platform. V2 is strictly greater than V1; record both source commits and trees |
| BUT-03 | A host installed from BUT-02 | As the admin account, run `status --json` (see [Admin CLI](#admin-cli)) and `defenseclaw-gateway --version` from the install's `bin` folder | `installed_version` matches the artifact; the version names the commit |
| BUT-04 | Agents installed | For each agent under test, record the exact version and how it was installed | One line per agent, account and OS. Pin or disable auto-update for the run (agents that update themselves mid-run leave their verified hook contract) |

Record the build block at the top of every results file:

```text
commit:        <40 hex>
tree:          <40 hex>
source:        <branch or pull request>
V1 / V2:       9.9.9 / 9.9.10  (or the release versions under test)
artifacts:     <file name>  sha256:<64 hex>   (one line per artifact)
hosts:         <generic host label>  <OS name and version>  <arch>
```

## Environment

### Hosts

Use one disposable host per row of this table. The maintainers' manual pass
covered these; add others the team supports.

| OS | Versions | Architecture | Artifact |
| --- | --- | --- | --- |
| Ubuntu | 24.04 LTS | amd64 or arm64 | `.deb`, plus the payload tarball once |
| RHEL | 9 with SELinux enforcing; RHEL 8 optional (systemd 239 path) | x86_64 | `.rpm` |
| macOS | 13 or later (the certification used 15) | Apple silicon only | `.pkg`, plus the darwin payload tarball once |
| Windows | Windows 11 or Windows 10 22H2 x64; Windows Server 2022/2025 x64 for local testing | x64 only (ARM64 and x64 emulation on ARM64 are refused) | `DefenseClawSetup-Enterprise-Standalone-x64.exe` |

A real Intune pilot needs a Windows client edition: Intune cannot enroll
Windows Server. Keep a separate clean host per OS for the
[per-user mode regression](#per-user-mode-regression), and a host with a
Secure Client DefenseClaw deployment if the team has a Secure Client build.

### Accounts

Create local test accounts literally named `std1`, `std2`, `dcexcluded` and
`dcnew`, so the commands and evidence use the same neutral names. Never record
passwords or directory identities in evidence.

| Label | Linux | macOS | Windows |
| --- | --- | --- | --- |
| admin account | A user with `sudo` (root for lifecycle commands) | An administrator (`sudo`) | A local administrator, used from PowerShell 7 started with "Run as administrator" |
| std1, std2 | uid at or above `UID_MIN` (usually 1000), a login shell, home under `/home`, home not group- or other-writable | uid 501 or above, home under `/Users` | Local standard users. Each must sign in once so its profile exists, and have an active session (console or RDP) when the guardian writes its files |
| excluded account | A standard account listed in `enterprise.enrollment.exclude_users` | Same | Same |
| new account | Created by the admin during [Enrollment](#enrollment) | Same | Same; it enrolls after its first real sign-in |
| Optional | A directory account (SSSD/LDAP), an account whose home is under an extra `home_roots` entry, a systemd-userdb account | A directory or mobile account | A domain or Entra ID account (enrolled only after sign-in) |

Service accounts the lifecycle creates: `defenseclaw` (Linux), `_defenseclaw`
(macOS), and the `NT SERVICE\DefenseClawGateway` virtual account (Windows).

### Prerequisites

| Item | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Service manager | systemd 239 or later as PID 1. Containers and WSL without systemd as PID 1 are refused (`service_manager_unavailable`); WSL with systemd passes this check, and the lifecycle then refuses a new install (`wsl_distribution`, L-29). Check `systemctl --version` and `ps -p 1 -o comm=` | launchd | Service Control Manager |
| Privileges | Root for everything except `enterprise linux status` | Root for everything except `enterprise macos status` | An elevated administrator token or LocalSystem. Setup exits `1603` without elevation |
| Platform | amd64 or arm64; SELinux enforcing is supported (the lifecycle relabels after each change) | macOS 13 or later, Apple silicon | Native x64 |
| PowerShell | - | - | Stable PowerShell 7 x64 from Microsoft's MSI, registered under `HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`, installed under Program Files, with a valid Microsoft signature on `pwsh.exe` (PATH is ignored; preview builds are refused). Use 7.4 or later: the MDM wrapper and Intune packager require it. FullLanguage mode (under WDAC or AppLocker, allow the DefenseClaw signer). Check with `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\*' \| Select-Object SemanticVersion, InstallLocation` and `$ExecutionContext.SessionState.LanguageMode` |
| Signing | Packages are unsigned unless built with a GPG key | The local pkg is unsigned unless built with signing identities; `pkgutil --check-signature <pkg>` reports no signature | The default Setup is unsigned and hash-pinned (`standalone-unsigned`) |
| Clean state | No Secure Client DefenseClaw (`/opt/cisco/secureclient/defenseclaw`), no per-user DefenseClaw for any account, nothing listening on `127.0.0.1:18970` (`sudo ss -ltnp 'sport = :18970'`) | No Secure Client DefenseClaw (`/opt/cisco/secureclient/defenseclaw`, `com.cisco.secureclient.defenseclaw*` LaunchDaemons), no per-user DefenseClaw, nothing on 18970 (`sudo lsof -nP -iTCP:18970 -sTCP:LISTEN`) | No Secure Client DefenseClaw services, no per-user DefenseClaw, nothing on 18970 (`Get-NetTCPConnection -LocalPort 18970 -State Listen`, or `netstat -ano` from a remote shell). `HKLM\SOFTWARE\Policies\ClaudeCode\Settings` empty or absent: a non-empty value stops DefenseClaw from publishing its Claude Code drop-in |

Remove a per-user DefenseClaw install as that user with
`defenseclaw uninstall --binaries --yes` (add `--all` to delete
`~/.defenseclaw`). Also check that nothing listens on the OpenClaw fleet port
`127.0.0.1:18789`.

### Agent CLIs and model access

The enumerator enrolls a user for a per-user connector only when it finds the
agent installed for that user and can read a version with a verified hook
contract (`cli/defenseclaw/inventory/hook_contracts.json`). Install versions
inside these ranges, and one version outside a range as a negative test.

| Connector | Verified versions | Notes |
| --- | --- | --- |
| Claude Code (`claudecode`) | 2.1.154 and later | Windows floor 2.1.154. Anthropic sign-in or a provider configured through Claude Code's settings |
| Codex (`codex`) | 0.124.0 and later (0.145 and later is the current contract) | Windows floor 0.131.0. The Microsoft Store app is not discovered. ChatGPT sign-in or a provider in `~/.codex/config.toml` |
| GitHub Copilot CLI (`copilot`) | 1.0.18 and later | GitHub sign-in with Copilot, or bring-your-own-key provider variables |
| Cursor (`cursor`) | Desktop 2.4.0 up to 4.0.0, or reviewed Agent CLI build `2026.07.23-e383d2b` (see the [Cursor page](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/cursor)) | Needs a plan that applies enterprise hooks, with usage credits (R23) |
| OpenCode (`opencode`) | 1.18.10 up to 1.19.0 | Configure a model provider in the user's OpenCode config |
| Amp (`amp`) | 0.0.1785334225 and later | Amp sign-in |
| Devin (`devin`) | Exactly 3000.4.25 on every OS; 3000.11.3 on Linux only | Windows: the official signed `%LOCALAPPDATA%\devin\cli\bin\devin.exe` at 3000.4.25 only. Devin sign-in |
| Antigravity (`antigravity`, `agy`) | 1.1.8 and later | Self-updating. A Google sign-in and the vendor's consent screens, which the account's owner accepts |
| Hermes (`hermes`) | 0.19.0 up to 0.22.0 | Self-updating: do not update during a run. Configure a model provider with `hermes setup` |
| OpenHands (`openhands`) | 1.12.0 and later; Linux and macOS only | `uv tool install openhands==<version>`; set the LLM in the user's OpenHands settings |
| OmniGent (`omnigent`) | 0.7.0 up to 0.14.0; Linux and macOS only | `uv tool install --python 3.12 omnigent==0.13.0` (a default install gets a newer, unverified release) |
| Kiro (`kiro`) | kiro-cli 2.24.1 and later in the standalone profile; Linux and macOS through the guardian, Windows through ACP only | Kiro sign-in (`kiro-cli login`) |

Where discovery looks: on Linux and macOS, each agent's usual per-user
location, nvm, fnm, Volta, asdf, mise, pnpm and yarn globals, the npm prefix in
`~/.npmrc`, `/usr/local`, `/usr`, `/opt/homebrew` and
`enterprise.enrollment.agent_prefixes` (outside the home, every folder on the
path must be owned by root or the user and not writable by others). On
Windows, `%APPDATA%\npm`, nvm-windows, fnm, Volta, pnpm, yarn, the npm prefix
in `%USERPROFILE%\.npmrc`, native per-user installers, Cursor under
`C:\Program Files\Cursor`, the Cursor Agent CLI under
`%LOCALAPPDATA%\cursor-agent\versions`, and machine-scope WinGet. An agent
installed anywhere else is neither enrolled nor reported (R19).

Practical setup: install Node.js LTS machine-wide; as each standard account
install the npm-based agents with `npm install -g` (on Windows add
`%APPDATA%\npm` to that user's PATH); install the others with their vendor
installers as that account. Arrange every sign-in, license, plan and model
provider per account before the test window: Antigravity, Amp, Kiro, Devin,
Cursor, Copilot, Codex and Claude Code all need an interactive, human sign-in
or terms acceptance. On Windows and macOS some sign-ins need the account's own
desktop session. Keep credentials in each account's own store; never share one
login between accounts, and never copy a credential into evidence.

### Paths and commands

This plan writes `<G>` for the administrator CLI and `<os>` for the platform
word. Every admin command runs as the admin account (Linux and macOS: through
`sudo`; Windows: in an elevated PowerShell 7).

| Item | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `<G>` admin CLI | `/opt/defenseclaw/bin/defenseclaw-gateway` (not on root's PATH or in sudo's `secure_path`: use the full path) | `/opt/cisco/defenseclaw/bin/defenseclaw-gateway` | `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe` (in PowerShell, `$Cli`) |
| `<os>` | `linux` | `macos` | `windows` (lifecycle commands also take `--profile standalone`) |
| Hook binary | `/opt/defenseclaw/bin/defenseclaw-hook` | `/opt/cisco/defenseclaw/bin/defenseclaw-hook` | `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe` |
| Managed config | `/etc/defenseclaw/config.yaml` | `/opt/cisco/defenseclaw/etc/config.yaml` | `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml` |
| Policies (rule packs) | `/etc/defenseclaw/policies/guardrail/<name>` | `/opt/cisco/defenseclaw/etc/policies/guardrail/<name>` | `C:\ProgramData\Cisco\DefenseClaw\policies\guardrail\<name>` |
| Protected credentials | `/etc/defenseclaw/secrets` | `/opt/cisco/defenseclaw/etc/secrets` | `C:\ProgramData\Cisco\DefenseClaw\secrets` |
| Target manifest | `/etc/defenseclaw/hook-guardian/targets.yaml` | `/opt/cisco/defenseclaw/etc/hook-guardian/targets.yaml` | `C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml` |
| Lifecycle state | `/var/lib/defenseclaw-enterprise` | `/opt/cisco/defenseclaw/lifecycle` | `C:\ProgramData\Cisco\DefenseClaw\install`, logs in `%WINDIR%\Logs\DefenseClaw` |
| Gateway data | `/var/lib/defenseclaw` | `/opt/cisco/defenseclaw/runtime` | `C:\ProgramData\Cisco\DefenseClaw\runtime` |
| Hook transport | `/run/defenseclaw-hook/hook.sock` | `/opt/cisco/defenseclaw/run/hook.sock` | `127.0.0.1:18970`, with the hook checking the listener is the SCM gateway process |
| Machine-policy summary (read by hooks) | `/etc/defenseclaw/machine-policy.json` | `/opt/cisco/defenseclaw/etc/machine-policy.json` | `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\machine-policy.json` |
| Services | `defenseclaw-gateway.service` (+ `defenseclaw-gateway-api.socket`, `defenseclaw-gateway-hook.socket`), `defenseclaw-hook-guardian.service`, `defenseclaw-hook-enumerator.service`, `defenseclaw-sensor-helper.service`, `defenseclaw-enterprise-apply.path`, `defenseclaw-enterprise-apply.service`, `defenseclaw-enterprise-verify.timer`, `defenseclaw-enterprise-verify.service`, `defenseclaw-hook-guardian-reconcile.service` (the three named `.service` oneshots are static) | `com.cisco.defenseclaw.gateway`, `.hook-guardian`, `.hook-enumerator`, `.sensor-helper`, `.apply`, `.verify` | `DefenseClawGateway`, `DefenseClawSensorHelper`, `DefenseClawHookGuardian`, `DefenseClawHookEnumerator` |
| Service logs | `journalctl -u <unit>` | `/Library/Logs/Cisco/DefenseClaw` (gateway logs in `gateway/`) | `C:\ProgramData\Cisco\DefenseClaw\logs`, and `<G> enterprise windows events` |

In PowerShell, set these once per elevated session:

```powershell
$Cli   = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe'
$Stage = 'C:\ProgramData\DefenseClaw-Staging'
$SetupV1 = "$Stage\v1\DefenseClawSetup-Enterprise-Standalone-x64.exe"
$SetupV2 = "$Stage\v2\DefenseClawSetup-Enterprise-Standalone-x64.exe"
$Setup = $SetupV1  # switch to $SetupV2 for upgrade rows
```

Set `G` in every Linux/macOS admin or standard-user terminal that runs a
`$G` row; set `$Cli` again in each Windows standard-user PowerShell. Variables
from the elevated session do not carry over.

On Linux and macOS:

```bash
G=/opt/defenseclaw/bin/defenseclaw-gateway            # macOS: /opt/cisco/defenseclaw/bin/defenseclaw-gateway
```

No environment variable is needed for the admin commands: for root (and for an
elevated administrator or LocalSystem on Windows) `status`, `audit`,
`enterprise hooks` and `enterprise policy` find the managed config, data
directory and manifest themselves. Do not set `DEFENSECLAW_CONFIG` or
`DEFENSECLAW_HOME` in an admin session: on Windows an explicit value turns
that automatic selection off for the rest of the session. Some enterprise pages
still show `DEFENSECLAW_CONFIG=...` in examples; record the mismatch under [UX checklist](#ux-checklist).

## How to test

### Rules for every row

1. **Interactive only.** Type every command into a live terminal of the
   account the row names, and use every agent through its own interactive
   TUI (or its desktop app, only where the app has a different hook surface).
   Type the prompt, answer the agent's trust and permission prompts the way a
   developer would, and read the screen. Headless agent modes (`-p`, `exec`,
   `--no-interactive`), invoking hook binaries directly, piping payloads into
   hooks, and batch case scripts do not establish a pass.
2. **DefenseClaw through its CLI.** Install, upgrade, repair, status,
   verify, policy, secret, audit review and uninstall all go through the
   installed CLI or the packaged installer. Read results from the CLI output,
   not by opening DefenseClaw's files, unless the row is about a file's
   permissions or bytes. OS permission listings, process ownership and
   package metadata may corroborate a result.
3. **Judge a tool call by its side effect and the audit, never by the
   model's words.** Make every marker command write a file at an absolute
   path. A blocked call passes only when the file does not exist and the audit
   has a block row for that account. Several agents let the model claim
   success after a block, and some models re-encode a blocked command; judge
   whether the literal marker command ran, and record any retry as UX.
4. **One account per session.** Keep each standard account in its own
   session and the admin account in a separate elevated terminal:
   - Linux: a separate login session per account (console or SSH); a
     terminal multiplexer inside that session is fine. Start agents with
     `TMUX` unset if they take over an enclosing tmux server.
   - macOS: each standard account signed in at the console (fast user
     switching or Screen Sharing), using Terminal in that account's own GUI
     session. The admin account works in a separate Terminal window
     (`su -l <admin account>`, then `sudo`). Sign one account out before
     signing the next in if the login window resets input.
   - Windows: each standard account signed in with its own console or RDP
     session. runas, scheduled tasks and remote shells are not sessions: the
     guardian does not enroll or repair a user through them. Admin steps run
     in PowerShell 7 opened with "Run as administrator" through the normal UAC
     prompt. A remote administrative shell (for example SSH) is usually the
     built-in Administrator, already elevated: do not use it for user steps,
     because files it creates in user paths are Administrators-owned and
     DefenseClaw refuses them.
5. **Harmless markers only.** Blocked-call rows use the marker rule pack in
   [Marker rule pack](#marker-rule-pack), never a real attack sample.
6. **Restore every change.** Undo each user-side change after its result is
   captured, from a backup you took first, and wait for the guardian's
   restore before the next row. A user-made break in the user's own home (a
   file where a folder belongs, `chmod 000`, a link) keeps that account's
   target unrepaired until undone.
7. **Create and remove only test-owned files.** Use disposable project
   folders (for example `~/dc-test-proj`) and test files named `dctest-*`.
8. **No secrets in evidence.** Redact credentials, tokens, personal
   identifiers and private endpoints before saving a capture. Check files that
   hold credentials only with `sha256sum`, `stat` and `ls -l`.

Protocol diagnostics D2, E2, REG-1-3-04, REG-1-3-05 and REG-1-4-01 are
exceptions to rule 1: a direct request is needed to test the gateway boundary.
Use `curl --unix-socket /run/defenseclaw-hook/hook.sock --config
<owner-only-request-options> http://localhost/api/v1/<connector>/hook` on
Linux, the platform hook socket on macOS, or
`http://127.0.0.1:18970/config/patch` for D2. The owner-only curl options
file supplies `X-DefenseClaw-Client: <client from the installed hook source>`
and the scoped bearer; never type or capture the bearer. Save only HTTP
status, side effect and sanitized audit. These diagnostics supplement the
interactive TUI verdict; a scripted request alone does not pass a connector.

### Preflight

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| PRE-01 | Host reserved for the run | Record the OS version, architecture, signed-in sessions and every installed DefenseClaw or agent | Inventory saved; no other tester's session or background job on the host can alter the deployment |
| PRE-02 | PRE-01 | Check the clean-state items in [Prerequisites](#prerequisites) | No Secure Client deployment, no per-user DefenseClaw, nothing on `127.0.0.1:18970` or `127.0.0.1:18789` |
| PRE-03 | Disposable host and administrator-owned vendor fixtures | Seed one harmless admin entry each in Codex requirements, Claude Code managed settings, Cursor hooks, Copilot `policy.d` and OpenCode managed config. On Linux use `/etc/codex/requirements.toml`, Claude `managed-settings.d/10-admin.json`, `/etc/cursor/hooks.json`, and the installed Copilot and OpenCode vendor paths; use the equivalent protected paths from [Paths and commands](#paths-and-commands) on macOS/Windows. Hash before install, after repair, upgrade and uninstall | All admin entries remain byte-identical; only DefenseClaw-owned entries change. FM4 is mandatory on each OS |
| PRE-04 | Agents installed for std1 and std2 | Record each agent's version per account ([BUT-04](#build-under-test)); turn auto-update off where the agent allows it | Versions inside the verified ranges |
| PRE-05 | Windows | Check free space on `C:` and the PowerShell 7 registration | Enough space for staged Setups; PowerShell 7 x64 stable registered |
| PRE-06 | Linux | Keep test homes under `/home`, and point build and test `TMPDIR` at an owner-only folder | No home, data directory or `TMPDIR` under a world-writable or ACL-carrying `/tmp` (the lifecycle refuses those) |

### Evidence

Keep one evidence folder per host and stage, for example
`evidence/<os>/<stage>/<row>-<account>.txt`. For every row save:

- the typed command or prompt, exactly as typed (no secrets);
- the terminal transcript or a screenshot of the agent's screen;
- the CLI output and exit code; for lifecycle rows the key result fields:
  `ok`, `action`, `noop`, `noop_reason`, `installed_version`,
  `coverage_complete`, `security_complete`, `errors[].code`,
  `warnings[].code`;
- the elapsed time for every timed repair or cleanup (poll by file
  modification time and SHA-256, not by size: the guardian writes the current
  generation, which can differ by a few bytes);
- before and after hashes for rows that touch administrator-owned files;
- the verdict and, for a `FAIL`, the finding id.

Capture agent screens every one or two seconds after Enter on connectors
whose notices fade (OpenCode about 4 to 10 s, Amp about 2 s). Save the screen
before an agent clears it.

Result record (one JSON line per row and account; a Markdown table is in
[Appendix: templates](#appendix-templates)):

```json
{"os":"linux","stage":"S3","account":"std1","row":"C1","connector":"amp","route":"per-user","action":"edited own DefenseClaw plugin","expected":"restored within one reconcile cycle; calls inspected meanwhile","observed":"restored in 2 s; block marker still blocked","result":"PASS","seconds":2,"evidence":"S3/C1-amp-std1.txt"}
```

Use `PASS`, `FAIL`, `N/A` or `NOT_RUN` in `result`. Put `DENIED`, `REFUSED`,
`RESTORED in <seconds>`, `BLOCKED` or `residual <id>, seen` in `observed`.

### Filing a finding

Record every difference from the expected result as a finding, including UX
and documentation problems where enforcement works:

```json
{"id":"LINUX-F01","kind":"functional|ux|docs","severity":"blocker|major|minor","summary":"one reproducible sentence","steps":"interactive steps with neutral markers","expected":"...","observed":"exact sanitized output and exit code","evidence":"S2/A3-std1.txt","status":"open|fixed and verified|residual|not-a-bug"}
```

- First check [Known residuals and open issues](#known-residuals-and-open-issues).
  A behavior that matches a documented residual exactly is recorded as
  `residual <id>, seen`, not filed.
- A way for a standard account to weaken enforcement that no documented
  residual covers is a security finding: report it privately through GitHub's
  private vulnerability reporting, as [SECURITY.md](../SECURITY.md) describes,
  not in a public issue.
- File other functional, UX and documentation findings as GitHub issues. For
  the standalone profile, search the follow-up tracking issue #910 and its
  sub-issues first, and file new standalone follow-ups as sub-issues of #910.
  Include the build block, OS, account label, connector and version, route,
  the typed steps, the sanitized output with its exit code, and the evidence
  file name.
- When a fix lands, keep the pre-fix evidence, retest with the original
  interactive steps, and record the new result next to the old one.

A UX finding includes: an unclear or missing reason or next step; a
misleading success or exit code; missing `--help`; a confusing permission
prompt; a long silence or a hang; a raw stack trace, reason code, internal
command line, token or internal path in user-facing output; a block notice that
does not name DefenseClaw or the rule; and documentation that names a command
that does not work. Record the exact wording, the delay and the screen.

## Build and packaging

Build from the clean checkout of [Build under test](#build-under-test). All
local builds are unsigned (hash-pinned trust on Windows). Build V1 and V2 of
each artifact so the upgrade, downgrade and rollback rows can run.

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| BLD-L1 | Go (the `go.mod` toolchain), Python 3 and GoReleaser v2 at the pinned version: `go install github.com/goreleaser/goreleaser/v2@v2.15.4` | `GORELEASER_CURRENT_TAG=v9.9.9 make packaging-linux-enterprise`, then read the version from `dist/metadata.json` and `ls dist/defenseclaw-enterprise-*`. Copy `dist/` away, then repeat with `v9.9.10` (the target cleans `dist/`) | `defenseclaw-enterprise-<v>-linux-<arch>.deb`, `.rpm`, `defenseclaw-enterprise-<v>-linux-<arch>.tar.gz` and `defenseclaw-enterprise-<v>-darwin-arm64.tar.gz`; `<v>` is `9.9.9-SNAPSHOT-<commit>`. One run builds both amd64 and arm64; install the matching file |
| BLD-M1 | A Mac with Go and the Xcode command line tools; darwin payload tarball from BLD-L1 | `make packaging-macos-enterprise VERSION=9.9.9`, then `make packaging-macos-enterprise VERSION=9.9.10` | `dist/defenseclaw-enterprise-<v>-darwin-arm64.pkg`, identifier `com.cisco.defenseclaw.enterprise`. Always pass `VERSION`: the Makefile default is an old release number and the pkg refuses to install over a newer deployment |
| BLD-W1 | macOS or Linux with bash, git and Go | `packaging/windows/standalone/build-setup.sh --version 9.9.9`, then `--version 9.9.10` | `dist/windows-standalone-<v>/` holds `DefenseClawSetup-Enterprise-Standalone-x64.exe`, its `.sha256` and `payload-manifest.json`. Record the SHA-256: it is the pin for the MDM wrapper (`-Sha256`) and the Intune package. There is no Makefile target for this Setup |
| BLD-W2 | BLD-W1 | Run the script again while `cmd/defenseclaw-enterprise-setup/payload` holds a payload | Refused ("already holds a payload; remove it before building"); the script cleans that folder on exit |
| BLD-R1 | Testing a published release instead | Verify `checksums.txt` with `cosign verify-blob` against the release workflow identity (see [Released artifacts](#released-artifacts)), then check each artifact against it | Signature verified; each hash matches. Record whether the pkg and Setup are signed |

`DefenseClawSetup-Enterprise-x64.exe` is the Secure Client Setup, a
different artifact; do not use it for standalone rows.

```bash
# Linux packages, V1 then V2
GORELEASER_CURRENT_TAG=v9.9.9 make packaging-linux-enterprise
v=$(python3 -c 'import json; print(json.load(open("dist/metadata.json"))["version"])')
echo "$v"
ls dist/defenseclaw-enterprise-*
mv dist dist-v1
GORELEASER_CURRENT_TAG=v9.9.10 make packaging-linux-enterprise

# macOS pkg (on a Mac)
make packaging-macos-enterprise VERSION=9.9.9
make packaging-macos-enterprise VERSION=9.9.10

# Windows standalone Setup (on macOS or Linux)
packaging/windows/standalone/build-setup.sh --version 9.9.9
packaging/windows/standalone/build-setup.sh --version 9.9.10
cat dist/windows-standalone-9.9.9/DefenseClawSetup-Enterprise-Standalone-x64.exe.sha256
```

### Released artifacts

Set `VERSION` to the version in the released artifact name before these commands.

```bash
cosign verify-blob --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing -c checksums.txt
pkgutil --check-signature "defenseclaw-enterprise-${VERSION}-darwin-arm64.pkg"
```

```powershell
(Get-FileHash .\DefenseClawSetup-Enterprise-Standalone-x64.exe -Algorithm SHA256).Hash.ToLower()
Select-String -Path .\checksums.txt -Pattern 'DefenseClawSetup-Enterprise-Standalone-x64\.exe$'
(Get-AuthenticodeSignature -LiteralPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe).Status
# Valid: signed (authenticode trust); NotSigned: hash-pinned build
```

### Optional automated smoke

Before the manual pass, the enterprise install lanes in [TESTING.md](TESTING.md)
can smoke-test the same artifacts on a disposable host (they install and
remove services):

```bash
# v is the Linux version from BLD-L1; ARCH is amd64 or arm64
sudo bash scripts/test-enterprise-unix-install.sh --package "dist/defenseclaw-enterprise-${v}-linux-${ARCH}.deb" --version "$v"
sudo bash scripts/test-enterprise-unix-install.sh --package dist/defenseclaw-enterprise-9.9.9-darwin-arm64.pkg --version 9.9.9
```

```powershell
pwsh -NoProfile -File scripts\test-enterprise-windows-install.ps1 -Setup <path to Setup> -Version 9.9.9
```

A lane pass is not a manual row pass. Revert the host before S1.

## Install and lifecycle

Each mutating lifecycle action is a transaction on every OS: take the
lifecycle lock, snapshot, apply, start the services in order, verify, and roll
back on any failure. `ensure` is the one action an MDM runs: it installs,
upgrades, repairs drift, applies a changed config, or does nothing.

### Sample configs

Use the disposable local account `dcexcluded` for the exclusion filter in
both test configs. Keep the original administrator config for restoration.

Every standalone config needs `config_version: 8`,
`deployment_mode: managed_enterprise` and `enterprise.profile: standalone`.
Always set the profile: left unset, the policy commands treat a Windows or
macOS host as Secure Client. On Linux and macOS, `data_dir` must be exactly
`/var/lib/defenseclaw` or `/opt/cisco/defenseclaw/runtime` (or unset). On
Windows leave `data_dir` and `policy_dir` unset. `gateway.api_bind` must be
`127.0.0.1`, and on Linux and macOS `gateway.api_port` must be `18970` if set.
Quote `ownership: "off"` (YAML reads a bare `off` as false).

Minimal config (Linux; the enterprise overview page has the same config per
OS, and the install rows use it verbatim):

```yaml
config_version: 8
deployment_mode: managed_enterprise
data_dir: /var/lib/defenseclaw
policy_dir: /etc/defenseclaw/policies
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
    claudecode: {}
```

macOS: the same with `data_dir: /opt/cisco/defenseclaw/runtime` and
`policy_dir: /opt/cisco/defenseclaw/etc/policies`. Windows: omit `data_dir`
and `policy_dir`.

Test config for Linux and macOS (every connector, enrollment filters):

```yaml
config_version: 8
deployment_mode: managed_enterprise
data_dir: /var/lib/defenseclaw            # macOS: /opt/cisco/defenseclaw/runtime
policy_dir: /etc/defenseclaw/policies     # macOS: /opt/cisco/defenseclaw/etc/policies
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
    claudecode: {}
    cursor: {}
    copilot: {}
    opencode: {}
    devin: {}
    antigravity: {}
    hermes: {}
    amp: {}
    openhands: {}
    omnigent: {}
    kiro: {}
enterprise:
  profile: standalone
  inspection:
    ai_defense:
      enabled: false
      credential: ai-defense-api-key
  enrollment:
    mode: auto
    exclude_users: [dcexcluded]
    unenrolled_users: inspect
    root: inspect
  machine_policy:
    default:
      ownership: merge
      managed_hooks_only: enforce
      foreign_hooks: remove
      higher_precedence_sources: fail
  coexistence:
    disable_self_update: true
```

Test config for Windows:

```yaml
config_version: 8
deployment_mode: managed_enterprise
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
    claudecode: {}
    cursor: {}
    copilot: {}
    opencode: {}
    devin: {}
    antigravity: {}
    hermes: {}
    amp: {}
enterprise:
  profile: standalone
  inspection:
    ai_defense:
      enabled: false
      credential: ai-defense-api-key
  enrollment:
    include_users: []
    exclude_users: [dcexcluded]
  machine_policy:
    default:
      foreign_hooks: remove
  coexistence:
    disable_self_update: true
```

OpenHands and OmniGent are not managed on Windows, and Kiro is covered there
only through `defenseclaw-gateway enterprise acp` (see
[Kiro](#per-connector-procedure)). Windows ignores `unenrolled_users`, `root` and the uid limits.
On Linux and macOS, the machine-policy connectors (Claude Code, Codex, Cursor,
Copilot, OpenCode) get per-user targets only with `unenrolled_users: deny`, so
`enrollment.targets` counts per-user connectors; run once with
`unenrolled_users: deny` to see per-user rows for them too.

Negative configs, one per run (used by [LC-08](#post-install-health) and the
failure drills). The Windows result is for Setup `/ensure CONFIG=<file>`:

| Change | Linux and macOS (`ensure --config <file> --json`) | Windows |
| --- | --- | --- |
| `data_dir: /tmp/x` | Exit `1`, `config_invalid`; installed config unchanged | N/A (leave `data_dir` unset) |
| `guardrail.mode: blockall` | Exit `1`, `config_invalid` | Exit `1639` before any change: "the gateway cannot load `<file>` at `<path>`: `<reason>`; fix the config and run again (nothing was changed)" |
| `gateway.api_bind: 0.0.0.0` | Exit `1`, `config_invalid` | Refused; record whether Setup's preflight (`1639`) or the lifecycle (`1603`, rolled back) refuses it |
| `enterprise.profile: secure_client` on a standalone host | Refused (`config_invalid` or `profile_conflict`); record which | Refused: the profile cannot change in place |
| An inline `cisco_ai_defense.api_key` | Refused | Refused; the Intune packager also refuses a config with an `api_key:` line |
| `enterprise.trust.mode: authenticode` with the unsigned Setup | Accepted, not used | Exit `1639`; the message names the fix |
| `enterprise.trust.mode: ""` | Accepted (empty means not set) | Accepted |
| `guardrail.rule_pack_dir: /nonexistent` | Exit `1`, refused | Exit `1639` |
| No `config_version` | Refused; the error names the file passed with `--config` and says to add `config_version: 8` (it does not suggest `defenseclaw migrate`, which the enterprise package does not ship) | Refused (`1639`) |
| No `guardrail.connectors` | Installs; `status` warns `no_connectors_enabled` when there are eligible users; `security_complete: false` | Installs; `security_complete: false` |

### Linux install

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| INS-L-01 | Clean Ubuntu or RHEL host; V1 package; test config | Stage the config first, then install the package (commands below). Read the package result | apt or dnf prints `defenseclaw-enterprise: the managed deployment is active.`; `last-package-result.json` has `"ok": true`. The postinstall always exits 0, so apt and dnf report success even when the lifecycle failed: `ok: true` is the pass condition. The config is re-owned `root:defenseclaw 0640` |
| INS-L-02 | INS-L-01 | `systemctl list-unit-files 'defenseclaw*'`, `systemctl list-timers defenseclaw-enterprise-verify.timer`, `getent passwd defenseclaw`, `stat -c '%U:%G %a' /etc/defenseclaw/secrets` | All units from [Paths and commands](#paths-and-commands) present; `defenseclaw-enterprise-apply.service`, `defenseclaw-enterprise-verify.service` and `defenseclaw-hook-guardian-reconcile.service` are static; scheduled units are enabled; the service account exists. Secrets directory `root:root 700` on systemd 247 and later, `root:defenseclaw 750` on 239 to 246 |
| INS-L-03 | A host without a staged config | Install the package, then `sudo $G enterprise linux status --json` | Activated with the built-in default config (observe mode, no connectors). Staging the config first, or the MDM wrapper's `--config-file`, avoids this window |
| INS-L-04 | Clean host; V1 payload tarball | Payload channel (commands below) | Installed; units in `/etc/systemd/system` (the package uses `/usr/lib/systemd/system`) |
| INS-L-05 | Payload staged | Make the payload folder group-writable (`sudo chmod g+w "$PAYLOAD"`) and rerun `ensure --payload` | Exit `1`, `payload_invalid`; nothing changed. Restore `chmod -R go-w` |
| INS-L-06 | Package host | `sudo "$PAYLOAD/defenseclaw-gateway" enterprise linux upgrade --payload "$PAYLOAD" --json` | Exit `1`, `package_owned_binaries` |
| INS-L-07 | Payload staged | Run `ensure --payload "$PAYLOAD" --product-version 9.9.8 --json`; then `ensure --config relative.yaml --json` | First: refused, the payload is another version. Second: exit `2`, `invalid_arguments` ("--config must be an absolute path") |
| INS-L-08 | A hand-built layout under the product paths | `ensure --payload "$PAYLOAD" --json`, then the same with `--adopt-existing` | First: `unmanaged_layout_present`. Second: succeeds, backs the layout up under `/var/lib/defenseclaw-enterprise`, warning `adopted_existing_layout` |

```bash
# INS-L-01: package channel
v="<version read from BLD-L1 dist/metadata.json>"
ARCH=amd64  # or arm64; Go architecture names also apply to RHEL package filenames
sudo install -d -o root -g root -m 0755 /etc/defenseclaw
sudo install -o root -g root -m 0640 config.yaml /etc/defenseclaw/config.yaml
sudo apt install "./defenseclaw-enterprise-${v}-linux-${ARCH}.deb"      # Ubuntu
sudo dnf install "./defenseclaw-enterprise-${v}-linux-${ARCH}.rpm"      # RHEL
sudo cat /var/lib/defenseclaw-enterprise/last-package-result.json

# INS-L-04: payload channel
PAYLOAD="/root/defenseclaw-enterprise-${v}"
sudo install -d -o root -g root -m 0700 "$PAYLOAD"
sudo tar -xzf "defenseclaw-enterprise-${v}-linux-${ARCH}.tar.gz" \
  -C "$PAYLOAD" --no-same-owner --no-same-permissions
sudo chmod -R go-w "$PAYLOAD"
sudo "$PAYLOAD/defenseclaw-gateway" enterprise linux ensure --payload "$PAYLOAD" --json
```

### macOS install

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| INS-M-01 | Clean Mac; V1 pkg; test config | Stage the config, run `installer`, read the package result and the receipt (commands below) | `installer` exits 0; `last-package-result.json` has `"ok": true`; `pkgutil --pkg-info com.cisco.defenseclaw.enterprise` shows the version. A failed apply fails `installer` (non-zero) and is rolled back |
| INS-M-02 | INS-M-01 | `dscl . -read /Users/_defenseclaw UniqueID UserShell NFSHomeDirectory`; `ls -l /Library/LaunchDaemons/com.cisco.defenseclaw.*` | `_defenseclaw` with the highest free id in 300-499, shell `/usr/bin/false`, home `/var/empty`; six root-owned `0644` plists |
| INS-M-03 | A Mac without a staged config | Install the pkg; then copy the test config to `/opt/cisco/defenseclaw/etc/config.yaml`, or run `sudo $G enterprise macos ensure --from-package --config "$PWD/config.yaml" --json` | The pkg installs the built-in default (observe, no connectors). The copied config is applied by the apply daemon within about 30 s; the explicit `ensure` applies it at once |
| INS-M-04 | Clean Mac; darwin payload tarball | Payload channel (commands below) | Installed. The tarball binaries are never Developer ID-signed |

```bash
# INS-M-01: pkg channel
sudo install -d -o root -g wheel -m 0755 /opt/cisco/defenseclaw/etc
sudo install -o root -g wheel -m 0640 config.yaml /opt/cisco/defenseclaw/etc/config.yaml
sudo installer -pkg defenseclaw-enterprise-9.9.9-darwin-arm64.pkg -target /
echo "exit=$?"
sudo cat /opt/cisco/defenseclaw/lifecycle/last-package-result.json
pkgutil --pkg-info com.cisco.defenseclaw.enterprise

# INS-M-04: payload channel
v="<version read from BLD-L1 dist/metadata.json>"
PAYLOAD="/var/root/defenseclaw-enterprise-${v}"
sudo install -d -o root -g wheel -m 0700 "$PAYLOAD"
sudo tar -xzf "defenseclaw-enterprise-${v}-darwin-arm64.tar.gz" \
  -C "$PAYLOAD" --no-same-owner --no-same-permissions
sudo chmod -R go-w "$PAYLOAD"
sudo "$PAYLOAD/defenseclaw-gateway" enterprise macos ensure --payload "$PAYLOAD" --json
```

### Windows install

Stage the config and Setup in a folder only SYSTEM and Administrators can
write. On client editions a new folder under `C:\` inherits Authenticated
Users: Modify, which Setup refuses.

```powershell
New-Item -ItemType Directory -Path $Stage -Force | Out-Null
icacls $Stage /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Copy-Item .\config.yaml "$Stage\config.yaml"
New-Item -ItemType Directory -Path "$Stage\v1", "$Stage\v2" -Force | Out-Null
Copy-Item <V1 Setup path> $SetupV1
Copy-Item <V2 Setup path> $SetupV2
& $Setup /ensure JSON=1 "CONFIG=$Stage\config.yaml"
$LASTEXITCODE
```

Setup takes `NAME=value` properties (case-insensitive, dashes ignored) and
stops parsing at the first unknown argument, so put `JSON=1` early:

| Property | Meaning |
| --- | --- |
| `/ensure` `/install` `/upgrade` `/repair` `/reconcile` `/status` `/verify` `/uninstall` | The action. `/install` needs `CONFIG=` and `MANIFEST=`; prefer `/ensure` |
| `CONFIG=<absolute path>` | Needed for the first install; later runs reuse the installed config |
| `MANIFEST=<absolute path>` | Target manifest; needed for `/install`, and for a first install with `enrollment.mode: manifest` |
| `ALLOWEDSIGNERS=<sha256>,...` | Signed Setup only |
| `JSON=1` | Print the result document |
| `NOSTART=1` | Services stopped and disabled; `/repair` starts them |
| `PURGE=1` | With `/uninstall`: also remove `C:\ProgramData\Cisco\DefenseClaw` |
| `TIMEOUTSECONDS=<60..7200>` | Default 1800 |
| `ATTESTCLAUDEEFFECTIVEPOLICY=1` | With `/repair`: record the Claude Code attestation ([CLI-12](#admin-cli)) |
| `/quiet`, `/norestart`, `/?`, `/help` | Accepted; the first two do nothing |

Setup and the MDM wrapper print nothing for two to three minutes while they
work. Wait before calling it a hang, and record the silence as UX.

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| INS-W-01 | Clean Windows x64 host; std1 and std2 signed in; V1 Setup and test config staged | `& $SetupV1 /ensure JSON=1 "CONFIG=$Stage\config.yaml"` from the elevated admin prompt | Exit `0`; one result document with action `ensure`, warning `ensure_install`, `installed_version` V1. Application log event 112 |
| INS-W-02 | INS-W-01 | Check what the install created (table below) | Every item present with the expected identity and values |
| INS-W-03 | INS-W-01 | From the installed CLI, elevated, with no `--trust-mode`: `& $Cli enterprise windows status --profile standalone --json`, then `verify`, `repair` and `ensure` with the same flags; then read the marker's `TrustMode` | Each succeeds with no signature ("NotSigned") refusal; `TrustMode` stays `hash_pinned` after each |
| INS-W-04 | A staged copy of the test config with `enterprise.trust.mode: authenticode` | `& $Setup /ensure JSON=1 "CONFIG=$Stage\config-authenticode.yaml"`; then the same config with `mode` empty and with `hash_pinned` | First: exit `1639`, the message names the fix, nothing changed. Then: success |
| INS-W-05 | INS-W-04 | Give `trust.allowed_signers` in the config and a different list in `ALLOWEDSIGNERS=` | Exit `1639` |
| INS-W-06 | Fresh host with no other Cisco software; before the first install | As std1 in std1's session, create a folder under the vendor parent (`mkdir C:\ProgramData\Cisco\dctest`); then, as admin, `& $Setup /ensure JSON=1 "CONFIG=$Stage\config.yaml"` | Install succeeds. The user-created tree is moved aside intact to `C:\ProgramData\Cisco.untrusted-<UTC time>-<random>` (check `Get-ChildItem C:\ProgramData -Filter 'Cisco.untrusted-*' -Force` and that `dctest` is inside). Record where the move is reported (result document, warning or lifecycle log). A root that holds administrator-owned content is never moved; if the user holds a handle on the tree, install fails with `root_squatted` (`1603`) |
| INS-W-07 | Payload-folder CLI path (only for custom re-signing pipelines) | `& "$Payload\defenseclaw.exe" enterprise windows ensure --profile standalone --config "$Stage\config.yaml" --trust-mode hash_pinned --payload-manifest <file> --json` | Installed. `--payload-manifest` takes `{"schema_version":1,"files":{"<file name>":"<sha256>"}}`; the release `...payload-manifest.json` has a different format |

What a Windows install creates:

| Item | Check | Expected |
| --- | --- | --- |
| Binaries | `Get-ChildItem 'C:\Program Files\Cisco\DefenseClaw\bin'`, `...\libexec` | Five executables; `install-enterprise.ps1` and `DefenseClawEnterprise.psm1` |
| Services | `Get-Service DefenseClaw* \| Select-Object Name, Status, StartType` | `DefenseClawGateway`, `DefenseClawSensorHelper`, `DefenseClawHookGuardian`, `DefenseClawHookEnumerator`: Running, Automatic |
| Service identities | `Get-CimInstance Win32_Service -Filter "Name LIKE 'DefenseClaw%'" \| Select-Object Name, StartName, PathName` | Gateway `NT SERVICE\DefenseClawGateway`; the others LocalSystem |
| Deployment marker | `Get-ItemProperty 'HKLM:\SOFTWARE\Cisco\DefenseClaw\Enterprise' \| Select-Object Profile, ProductVersion, InstallRoot, StateRoot, TrustMode, UpdatedAt, DisableSelfUpdate` | `Profile` `standalone`; `TrustMode` `hash_pinned` for the unsigned Setup |
| Add/Remove Programs | `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CiscoDefenseClawEnterprise' \| Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString` | `QuietUninstallString` is `"C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe" enterprise windows uninstall --profile standalone --json` |
| Self-update policy | `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Cisco\DefenseClaw'` | `DisableSelfUpdate = 1` (written only when absent; removed at uninstall only if the lifecycle wrote it) |
| Lifecycle log | `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log`, `last-result.json` | One JSON record per run |
| Machine policy | `%ProgramData%\OpenAI\Codex\requirements.toml`; `C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json`; `%ProgramData%\GitHub\Copilot\policy.d\90-defenseclaw.json`; `%ProgramData%\opencode\opencode.json`; `%ProgramData%\Cursor\hooks.json` | Codex and Claude Code files once a Codex or Claude Code row is enrolled; the Cursor file only while at least one user is enrolled for Cursor at a verified version |
| Hook runtime | `C:\ProgramData\Cisco\DefenseClaw-HookRuntime` | Present, including `machine-policy.json` |

### Post-install health

Windows hash-pinned trust and removal are covered by INS-W-03, INS-W-04,
INS-W-06, MDM-W-05–W-07 and REM-01. Run the registered
`QuietUninstallString` during the removal stage, after saving its value in
the INS-W-02 evidence.

### Lifecycle drills

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| LC-01 | Installed | `status --json` and plain `status` (commands below) | Healthy fields as in [Healthy result](#healthy-result); exit `0`. Text output starts with `✓ status: done` (Linux, macOS) or `DefenseClaw Windows enterprise status (standalone): OK` |
| LC-02 | LC-01 | `verify --json` | Exit `0`, `ok: true`. On Ubuntu 24.04 and RHEL 9 the only expected warning is `unprivileged_user_namespaces` (R20) |
| LC-03 | LC-02 | Run `ensure` again with the same inputs (Linux and macOS `ensure --from-package --json` on a package host, or `--payload <dir>`; Windows `& $Setup /ensure JSON=1`) | `noop: true`, exit `0`, `noop_reason` `up_to_date` (Linux, macOS) or `compliant` (Windows); Windows event 111. No change to administrator policy hashes |
| LC-04 | LC-01 | Run LC-03 a third time | Still a no-op (idempotent) |
| LC-05 | Linux | Replace the config (for example add `devin: {}`) with `sudo install -o root -g root -m 0640 new.yaml /etc/defenseclaw/config.yaml`; read `journalctl -u defenseclaw-enterprise-apply.service -n 20 --no-pager`; run `status` | The path unit runs `ensure --reason path` within about 10 s; `status` shows the change; `systemctl --failed` lists no DefenseClaw unit |
| LC-06 | Linux or macOS | `sudo $G enterprise <os> ensure --config /root/new.yaml --json` | Validated, installed with the layout's owner and mode, applied; services restarted with rollback on failure |
| LC-07 | Linux or macOS | Edit the installed `config.yaml` in place with an invalid value; wait for the apply run; run `status` and `verify`; then push a corrected config | The apply run rejects it and puts the last applied config back; `rejected-config.yaml` appears in the lifecycle state folder; `status` warns and `verify` fails with `config_rejected` (and `config_reverted`); the corrected push clears both |
| LC-08 | Linux or macOS | Apply each negative config from [Sample configs](#sample-configs) with `ensure --config <file> --json`, one per run | Each refused with the listed code; installed config unchanged; `status` still healthy and lists the running deployment's services and readiness (not an empty service list) |
| LC-09 | macOS | Replace `/opt/cisco/defenseclaw/etc/config.yaml`; read `/Library/Logs/Cisco/DefenseClaw/lifecycle.log` | `com.cisco.defenseclaw.apply` runs `ensure` at most once per 30 s; the change is applied |
| LC-10 | Windows | `& $Setup /ensure JSON=1 "CONFIG=$Stage\new.yaml"` (same or newer Setup); then the installed CLI's `& $Cli enterprise windows ensure --profile standalone --config "$Stage\new.yaml" --json` | Setup: applied, event 112, a warning naming the chosen action and reason (`ensure_upgrade` or `ensure_repair`, reason `drift:<what>`; record the exact text). Installed CLI: exit `1639`, it says ensure must reapply and needs the payload files |
| LC-11 | Linux or macOS | Add or remove a top-level file in `secrets` or `policies`; then change a file in a subfolder | The first triggers an apply run; the second does not (in-place rule pack edits need a gateway restart, LC-15) |
| LC-12 | Any | Change `enterprise.network.https_proxy` and apply | Takes effect only on a gateway restart; the Linux and macOS lifecycle apply restarts the services |
| LC-13 | Clean host with staged payload | Install with `--no-start` (Linux and macOS `sudo "$PAYLOAD/defenseclaw-gateway" enterprise <os> ensure --payload "$PAYLOAD" --no-start --json`; Windows `& $Setup /ensure JSON=1 NOSTART=1 "CONFIG=$Stage\config.yaml"`); then `repair` | Services staged but stopped (Linux and macOS warning `not_started`; Windows services stopped and disabled); `repair` starts them and the host is healthy. `--no-start` with `status`, `verify` or `uninstall`: exit `2` (Linux, macOS) or `1639` (Windows) |
| LC-14 | Rule pack unset | Create `<policy_dir>/guardrail/default` after install and run `ensure` | `ensure` applies it and restarts the gateway; it does not say `up_to_date` while the gateway still uses the vendor pack |
| LC-15 | Installed | Restart only the gateway with the managed command: Linux `sudo systemctl restart defenseclaw-gateway.service`; macOS `sudo launchctl kickstart -k system/com.cisco.defenseclaw.gateway`; Windows `& $Setup /repair JSON=1` | Healthy afterwards. Linux keeps the sockets in PID 1 so hooks wait; on macOS hooks fail closed during the restart (macOS residual 2) |
| LC-16 | Installed | As root, `sudo $G restart` and `sudo $G start`; as std1, `$G start` | Refused on a managed host. The root refusal names `systemctl restart defenseclaw-gateway.service` (Linux) or `launchctl kickstart -k system/com.cisco.defenseclaw.gateway` (macOS), plus `enterprise <os> repair` and `enterprise <os> status`. `systemctl start defenseclaw-hook-guardian.service` has no effect (it always runs); use `reconcile` |
| LC-17 | Two admin sessions | Start `ensure --config <changed file>` (or `upgrade`) in one, and at once `repair` in the other (Windows: two elevated prompts or two SYSTEM tasks running Setup) | The second waits 5 s, then exits `75` `lifecycle_busy` (Linux, macOS); with `--lock-wait 5m` it waits and then runs. Windows: the second exits `1618` `lifecycle_busy` after about 30 s, event 140 |
| LC-18 | Linux or macOS | Start `ensure` or `upgrade`, then run `verify` at once | `verify` waits up to 5 s, then exits `75` `lifecycle_busy` and skips its checks. `defenseclaw-enterprise-verify.service` accepts `75`, so a daily verify during a lifecycle run leaves no failed unit and no `unit_failed` warning; macOS writes `lifecycle_busy` to `verify.log` |
| LC-19 | Windows | Run `verify` while another run's transaction is pending | `1603` while the transaction is pending (Windows `verify` does not wait); healthy when rerun after it finishes |
| LC-20 | Linux or macOS | Write a new `config.yaml` while an `ensure` holds the lock | The follow-up run applies it (`input_changed`); it is not dropped or overwritten by older bytes |
| LC-21 | Any | Argument errors: `ensure --bogus`; `ensure --lock-wait 16m`; `enterprise linux` on macOS (and the reverse); `--payload` with `--from-package`; `upgrade` with neither; a first `ensure` with neither; `--purge` on a non-uninstall action; `--remove-service-account` without `--purge`; `--no-start` on status/verify/uninstall; `--config` on `status`; relative `--config`; missing channel | Linux and macOS flag-parse errors exit `2` and print `Error: ...` on stderr without a JSON result, even with `--json`. Semantic checks (both channels, relative config, missing channel) return a document with `invalid_arguments`, exit `2`. Record the missing JSON document as UX. Windows argument errors exit `1639` |
| LC-22 | Clean host (nothing installed) | `status --json` and `verify --json` | Linux and macOS: `status` exits `0` with `installed: false` (warning `unmanaged_leftovers` when state was left behind); `verify` exits `1` with `not_installed`. Windows: record the exit code and error of `status` (expected `not_installed`, `1603`); the MDM detection scripts handle this case themselves |

```bash
# Linux (macOS: G=/opt/cisco/defenseclaw/bin/defenseclaw-gateway and "macos")
sudo $G enterprise linux status --json
sudo $G enterprise linux status
sudo $G enterprise linux verify --json; echo "exit=$?"
sudo $G enterprise linux ensure --from-package --json     # package host: expect noop
systemctl list-timers defenseclaw-enterprise-verify.timer
```

```powershell
& $Cli enterprise windows status --profile standalone --json
& $Cli enterprise windows verify --profile standalone --json; $LASTEXITCODE
& $Setup /ensure JSON=1; $LASTEXITCODE                    # expect noop
```

#### Healthy result

The result document follows `packaging/mdm/contract/lifecycle-result.schema.json`
(schema version 2). Required fields: `schema_version`, `ok`, `action`,
`noop`, `profile`, `platform`, `product_version`, `installed`,
`transaction_pending`, `services`, `readiness`, `inspection`,
`machine_policy`, `enrollment`, `coverage_complete`, `security_complete`,
`errors`, `exit_code`; optional `noop_reason`, `installed_version`,
`warnings`, `log_path`. `product_version` is the payload version the action
used (empty for read-only actions); `installed_version` is what MDM detection
compares.

| Field | Healthy value |
| --- | --- |
| `ok` | `true`, only when `errors` is empty |
| `exit_code` | `0`, matching the process exit code |
| `installed`, `installed_version` | `true`, the deployed version |
| `transaction_pending` | `false` |
| `services[]` | Every managed unit, daemon or service with its state (on-demand macOS jobs read in full, for example "on demand, idle") |
| `readiness` | `gateway`, `guardian`, `enumerator`, `sensor_helper` all `true` |
| `coverage_complete` | `true` |
| `security_complete` | `true`. Windows with a Claude Code row: `false` until the attestation ([CLI-12](#admin-cli)) |
| `machine_policy.<connector>` | `ownership`, `lock`, `effective_lock`, `owned_entries`, `foreign_entries`; `conflicts` and `higher_precedence` empty |
| `enrollment` | `targets`, `pending`, `failed`, `exempt` (meanings below) |
| `inspection` | `local` and `ai_defense` (meanings below) |
| `errors[]` | Empty |
| `warnings[]` | None, or only expected ones |

What the summary fields mean:

| Field | Linux and macOS | Windows |
| --- | --- | --- |
| `coverage_complete` | The gateway answers health on the hook socket and reports its API listener on `127.0.0.1:18970` up; the guardian is active with a fresh authorization ledger; the enumerator is active | Installed, guardian ready, no transaction pending |
| `security_complete` | Coverage complete, sensor helper active, no errors, no `agent_unprotected` or `hook_contract_unverified`, no `guardian_target_failed`, and at least one connector enabled when there are eligible users | Installed and healthy, at least one enabled Codex, Claude Code or Cursor row in the target manifest, no `agent_unprotected` or `hook_contract_unverified`, and the Claude Code attestation recorded when a Claude Code row is enabled |
| `enrollment` | From the guardian ledger. `exempt` is always 0; `targets` counts per-user connectors | Rows of the target manifest. `pending` counts only targets waiting for a session (0 when every enrolled account is signed in); `exempt` counts disabled rows; `failed` is always 0 |
| `inspection` | Read from the gateway's health: `local` is `active`, `disabled` or `unknown`; `ai_defense` is `disabled`, `ok`, `unavailable:<code>` or `unknown` | `ai_defense` is `disabled`, `ok` (enabled and the gateway ready; the key is not tested), `unavailable:gateway_not_ready` or `unknown` |

`status` reports state and runs the basic checks; each problem is an error and
a non-zero exit. `verify` runs every check (Linux and macOS: file digests,
owners, modes, config and credentials against the last applied, runtime
descriptor, service account, services, gateway health and guardian ledger;
Windows: files, DACLs, service settings, mode pin and readiness). `verify`
turns `machine_policy_incomplete`, `hook_contract_unverified`,
`guardian_target_failed`, `config_rejected` and `agent_unprotected` into
errors. `verify` does not require the Windows Claude Code attestation. Fleet
`security_complete` is read from `status --json` (Linux, macOS) or
`last-result.json` (Windows); `verify` and the detection scripts do not
include it.

Text output formats. Linux and macOS: a first line `✓ <action>: done`,
`✓ <action>: nothing to do (<reason>)`, `! <action>: done with N warnings`,
`! <action>: nothing to do (<reason>), N warnings` or
`✗ <action> failed`; then `  ! <code>: <message>` per warning and
`  ✗ <code>: <message>` per error, each problem printed once; `status` and
`verify` add
`installed=<bool> version=<v> gateway_ready=<bool> guardian_ready=<bool> enumerator_ready=<bool> sensor_helper_ready=<bool>`
and one line per service. Windows: `DefenseClaw Windows enterprise <action> (standalone): OK|FAILED`,
then `  No change: <reason>`, `  Installed version: <v>`,
`  <service> (<kind>): <state>`, `  error <code>: <message>`,
`  warning <code>: <message>` and `  Log: <path>`.

## MDM execution contexts

Validate each OS the way an MDM agent runs DefenseClaw: as root or SYSTEM, with
no terminal, no inherited environment and no password prompt. For every run,
record the exit code, stdout (one result document or one detection line),
stderr, and whether the document matches the schema. The kit is in
`packaging/mdm` at the commit under test: `linux/` and `macos/` hold
`defenseclaw-enterprise.sh`, `detect.sh` and `uninstall.sh`; `windows/`
holds `Invoke-DefenseClawEnterprise.ps1`, `detect.ps1` and `uninstall.ps1`;
`intune/windows/` holds the Intune packager, launcher and remediation
scripts. `contract/` holds the result schema, the exit-code table and the
detection contract.

These rows simulate the execution context. They do not prove a tenant
deployment; see [Real MDM pilot](#real-mdm-pilot).

### Linux MDM context

Stage the wrapper and inputs root-owned and not group- or other-writable:

```bash
sudo install -d -o root -g root -m 0700 /var/cache/mdm
sudo install -o root -g root -m 0600 ./defenseclaw-enterprise-<v>-linux-<arch>.deb /var/cache/mdm/
sudo install -o root -g root -m 0700 packaging/mdm/linux/defenseclaw-enterprise.sh packaging/mdm/linux/detect.sh packaging/mdm/linux/uninstall.sh /var/cache/mdm/
sudo install -d -o root -g root -m 0755 /etc/mdm/defenseclaw
sudo install -o root -g root -m 0600 config.yaml /etc/mdm/defenseclaw/config.yaml
PIN=$(sudo sha256sum /var/cache/mdm/defenseclaw-enterprise-<v>-linux-<arch>.deb | cut -d' ' -f1)
install -d -m 0700 "$HOME/dctest-mdm"

# No controlling terminal (setsid), no inherited environment (env -i), no stdin, no password prompt (sudo -n)
sudo -n setsid -w env -i /bin/sh /var/cache/mdm/defenseclaw-enterprise.sh \
  --source /var/cache/mdm/defenseclaw-enterprise-<v>-linux-<arch>.deb --sha256 "$PIN" \
  --config-file /etc/mdm/defenseclaw/config.yaml < /dev/null > "$HOME/dctest-mdm/result.json" 2> "$HOME/dctest-mdm/stderr.txt"
echo "exit=$?"
sudo -n setsid -w env -i /bin/sh /var/cache/mdm/defenseclaw-enterprise.sh --action status < /dev/null
sudo -n setsid -w env -i /bin/sh /var/cache/mdm/defenseclaw-enterprise.sh --action verify < /dev/null; echo "exit=$?"
sudo -n setsid -w env -i /bin/sh /var/cache/mdm/detect.sh --format value < /dev/null
sudo -n setsid -w env -i /bin/sh /var/cache/mdm/detect.sh --min-version <v> --require-healthy < /dev/null; echo "exit=$?"
```

`sudo -n` needs a root shell or NOPASSWD and proves no password prompt is
used; `setsid -w` drops the controlling terminal. The documented form is
`sudo env -i /bin/sh ./defenseclaw-enterprise.sh --action status < /dev/null > result.json 2> stderr.txt`.
`detect.sh --min-version X` treats a `X-SNAPSHOT-<commit>` build as older than
`X`, so pass the exact snapshot version (or a lower one) for local builds.

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| MDM-L-01 | Clean Linux host; wrapper staged | Run the ensure command above | Exit `0`; stdout is exactly one schema-v2 document; stderr empty or advisory; `/var/log/defenseclaw-enterprise-mdm.log` (root `0600`) appended |
| MDM-L-02 | MDM-L-01 | Repeat the same ensure | Exit `0`, `noop: true` |
| MDM-L-03 | MDM-L-01 | `--action status`, `--action verify`, `detect.sh --format value`, `detect.sh --min-version <v> --require-healthy` | Status and verify documents healthy; detection prints the version and exits `0` (formats `value` and `jamf` always exit `0`) |
| MDM-L-04 | MDM-L-01 | Start two wrapper ensures at once with a changed config | One applies; the other exits `75` (`lifecycle_busy`, or `mdm_package_manager_busy` while dpkg or rpm holds its lock) |
| MDM-L-05 | Script-only form | Copy the wrapper, edit its settings block (`DC_SOURCE`, `DC_SOURCE_SHA256`, `DC_CONFIG_FILE`) or paste YAML between the `DEFENSECLAW_CONFIG` markers in `dc_inline_config`, and run it with no arguments in the same context | Same result as MDM-L-01 |
| MDM-L-06 | V2 package staged | Wrapper ensure with the V2 `--source` and its `--sha256` | Warning `package_upgraded` with the versions, then the `ensure` result; `installed_version` V2 |
| MDM-L-07 | Installed | `sudo -n setsid -w env -i /bin/sh /var/cache/mdm/uninstall.sh < /dev/null`; run it again; then with `--purge` on a separate cycle | Runs the lifecycle `uninstall`, then removes the package (unless `--keep-package`); the service account stays. The second run is a no-op with exit `0` |
| MDM-L-08 | Wrapper staged | Each failure case below, one per run | Each prints one document; nothing is installed or changed |
| MDM-L-09 | Clean RHEL snapshot; matching V1 rpm staged root-only | Repeat MDM-L-01 with the `.rpm` source and its `sudo sha256sum` pin, then MDM-L-02/03 | Wrapper uses rpm/dnf path, prints one document and reports a healthy install; detection matches installed version |

| Failure case | Expected |
| --- | --- |
| Wrong `--sha256` | `mdm_hash_mismatch`, exit `1` |
| Config file writable by others (`chmod 0666`), or a parent folder group-writable | `mdm_untrusted_input`, exit `1` |
| Config larger than 1 MiB | `mdm_input_too_large`, exit `2` |
| `--product-version 9.9.8` with a 9.9.9 package | `mdm_version_mismatch`, exit `1`; the package manager does not run |
| The Linux wrapper run on macOS | `mdm_wrong_platform`, exit `2` |
| Run as std1 | `mdm_not_root`, exit `1` |
| An unknown flag or a positional argument | `mdm_invalid_arguments`, exit `2` |
| Another apt or dnf holds the package lock | `mdm_package_manager_busy`, exit `75` |
| `--action verify --source <file>` | Refused (status and verify take no source), exit `2` |
| `ensure` with no source on a clean host | `mdm_not_installed`, exit `1` |
| `--secret-file` writable by others | `mdm_untrusted_input`. A valid file whose `secret set` fails after apply: `mdm_secret_failed` with the `secret set` exit code |

Wrapper options: `--action ensure|status|verify`, `--source FILE` or
`--source-url https://...`, `--sha256 HEX`, `--trust-mode hash_pinned|signed`,
`--allowed-team-id ID` (macOS, repeatable), `--gpg-keyring FILE` with
`--signature FILE` or `--signature-url URL` (Linux), `--config-file`,
`--config-stdin`, `--secret-name` with `--secret-file` or `--secret-stdin`,
`--product-version X.Y.Z`, `--https-proxy URL` (download only), `--log FILE`.

### macOS MDM context

Stage the pkg under root-owned `/Library/Caches/mdm` (mode `0700`) and the wrapper, detection script
and config under `/Library/Management/defenseclaw`, root-owned and not group-
or other-writable, and set `PIN` to the pkg's SHA-256
(`PIN=$(sudo shasum -a 256 /Library/Caches/mdm/defenseclaw-enterprise-9.9.9-darwin-arm64.pkg | cut -d' ' -f1)`). Run each row twice: (a) with std1 signed in at the
console, (b) with every user signed out and the Mac at the login window,
driven from an admin shell (for example SSH as the admin account).

```bash
install -d -m 0700 "$HOME/dctest-mdm"
sudo installer -pkg /Library/Caches/mdm/defenseclaw-enterprise-9.9.9-darwin-arm64.pkg -target / ; echo "exit=$?"
sudo cat /opt/cisco/defenseclaw/lifecycle/last-package-result.json
sudo -n env -i /bin/sh /Library/Management/defenseclaw/defenseclaw-enterprise.sh \
  --source /Library/Caches/mdm/defenseclaw-enterprise-9.9.9-darwin-arm64.pkg --sha256 "$PIN" \
  --config-file /Library/Management/defenseclaw/config.yaml < /dev/null > "$HOME/dctest-mdm/result.json" 2> "$HOME/dctest-mdm/stderr.txt"; echo "exit=$?"
sudo -n env -i /bin/sh /Library/Management/defenseclaw/detect.sh --format jamf < /dev/null
```

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| MDM-M-01 | Clean Mac; std1 signed in | `installer -pkg` as root, then `status --json` | Exit `0`; `_defenseclaw` created; daemons running; no user prompt (no PPPC or TCC profile is needed) |
| MDM-M-02 | Clean Mac; nobody signed in | Same as MDM-M-01 | Same result. Accounts with uid 501 and above are enumerated from the local directory; std1 and std2 enroll once their agents are discovered, and per-user repair runs through a worker as each user |
| MDM-M-03 | MDM-M-01 or 02 | The wrapper ensure (above), twice | First applies the config; second `noop: true`. Both contexts converge to the same healthy state. Record any difference as a finding |
| MDM-M-04 | Installed | `detect.sh --format jamf` | Exit `0`, one `<result>...</result>` line |
| MDM-M-05 | Unsigned pkg; test signing team ID | Wrapper with `--trust-mode signed --allowed-team-id <TEAMID>` | Refused before install: `mdm_signature_invalid`, exit `1`. A non-pkg source produces `mdm_signature_unsupported` |
| MDM-M-06 | Jamf-style run | Use the config staging script from the [Jamf recipe](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/jamf) (it writes `/Library/Management/DefenseClaw/config.yaml` and, if absent, `/opt/cisco/defenseclaw/etc/config.yaml` `root:wheel 0640`), then the wrapper with `DC_ACTION=ensure` and `DC_CONFIG_FILE=...` in its settings block, then detection with `DC_FORMAT="jamf"` | Installed and healthy; detection always exits `0` with `<result>...</result>` |
| MDM-M-07 | Installed | `sudo -n env -i /bin/sh /Library/Management/defenseclaw/uninstall.sh < /dev/null`, twice | First removes the deployment and forgets the receipt; second is a no-op with exit `0` |
| MDM-M-08 | V1 package managed by wrapper; V2 pkg staged | Run wrapper ensure with V2 pkg and its pinned hash; run `detect.sh --min-version <v2> --require-healthy` | Upgrade reports V2 and detection exits healthy only after `verify` passes |
| MDM-M-09 | Wrapper and clean snapshot | In separate runs use a wrong hash, untrusted config mode, signed mode with unsigned pkg and a wrong product version | Respectively `mdm_hash_mismatch`, `mdm_untrusted_input`, `mdm_signature_invalid` and `mdm_version_mismatch`; each leaves the prior deployment intact |

### Windows MDM context

The Intune Management Extension is a 32-bit process, and detection and
Remediations run in Windows PowerShell 5.1. Reproduce that with a one-shot
scheduled task that runs as SYSTEM and starts a 32-bit parent. Stage
everything in an admin-only folder:

```powershell
$sim = 'C:\DcSim'
New-Item -ItemType Directory -Path $sim -Force | Out-Null
icacls $sim /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
# Copy in: the Setup, config.yaml, packaging\mdm\windows\*.ps1, packaging\mdm\intune\windows\*.ps1

$parent  = Join-Path $env:WINDIR 'SysWOW64\cmd.exe'                              # 32-bit parent
$ps51x86 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe' # 32-bit Windows PowerShell 5.1
$body    = "`"$ps51x86`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $sim\detect.ps1 -MinimumVersion 9.9.9"

$action    = New-ScheduledTaskAction -Execute $parent -Argument "/c `"$body 1>$sim\stdout.txt 2>$sim\stderr.txt`""
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'DefenseClaw MDM simulation' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'DefenseClaw MDM simulation'
Start-Sleep -Seconds 3
while ((Get-ScheduledTask -TaskName 'DefenseClaw MDM simulation').State -eq 'Running') { Start-Sleep -Seconds 2 }
"exit=$((Get-ScheduledTaskInfo -TaskName 'DefenseClaw MDM simulation').LastTaskResult)"
Get-Content "$sim\stdout.txt", "$sim\stderr.txt"
Unregister-ScheduledTask -TaskName 'DefenseClaw MDM simulation' -Confirm:$false
```

Change only `$body` per row, and repeat the detection rows with the 64-bit
engine (`System32\WindowsPowerShell\v1.0\powershell.exe`).

| Row | `$body` | Expected result |
| --- | --- | --- |
| MDM-W-01 Setup as SYSTEM | `"$sim\DefenseClawSetup-Enterprise-Standalone-x64.exe" /ensure JSON=1 CONFIG=$sim\config.yaml` | Exit `0`; one result document; the first run installs, the second is `noop`. Every signed-in user enrolls |
| MDM-W-02 PowerShell 7 wrapper as SYSTEM | `"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -NonInteractive -File $sim\Invoke-DefenseClawEnterprise.ps1 -SetupPath $sim\DefenseClawSetup-Enterprise-Standalone-x64.exe -Sha256 <pin> -ConfigPath $sim\config.yaml` | Exit `0`; the wrapper prints Setup's result; `%WINDIR%\Logs\DefenseClaw\mdm-wrapper.log` appended. A failure's next step names the admin's `-ConfigPath` (not the wrapper's temporary copy) |
| MDM-W-03 Wrapper under Windows PowerShell 5.1 | The same script run by `$ps51x86` | Stops at `#Requires -Version 7.4` with exit `1` and no result document (documented) |
| MDM-W-04 Wrapper argument error | MDM-W-02 with both `-ProductVersion` and `-SetupPath` | `mdm_invalid_arguments`, exit `1639` |
| MDM-W-05 Detection | `"$ps51x86" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $sim\detect.ps1 -MinimumVersion 9.9.9`, then with `-RequireHealthy` | Detected: exit `0`, stdout `DefenseClaw Enterprise 9.9.9`, empty stderr. Not detected: exit `1`, reason on stderr |
| MDM-W-06 Remediation detect | `"$ps51x86" ... -File $sim\Remediate-Detect.ps1` | Exit `0` healthy (`DefenseClaw <v>: healthy`) or not installed (`DefenseClaw: not installed (the Win32 app installs it)`); exit `1` `verify failed (<codes>)` after an admin-side break |
| MDM-W-07 Remediation fix | `"$ps51x86" ... -File $sim\Remediate-Fix.ps1` | Runs the installed CLI's `enterprise windows ensure --profile standalone --json` and exits with its code, with one short line; no `mdm_untrusted_install` |
| MDM-W-11 Intune package | On the admin workstation run the packager command below with a new `$sim\intune` output directory, then copy its `content` directory to the test host under the same protected `$sim\intune` path | `content\` holds the Setup, config, launcher and `intune-package.json`; a reused output directory is refused |
| MDM-W-08 Intune launcher | From a 32-bit cmd parent, `cd /d $sim\intune\content && %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1` after MDM-W-11 | Exit is Setup's code. With a changed byte in `content\`: `mdm_hash_mismatch` or `mdm_package_incomplete` (`1603`) |
| MDM-W-09 Removal | `"$ps51x86" ... -File $sim\uninstall.ps1`, then again, then `-Purge` on a separate cycle | One result document each; the second is a no-op. `mdm_untrusted_install` (`1603`) if the installed CLI or its folders are not admin-only |
| MDM-W-10 No user signed in | MDM-W-01 with every user signed out | Install succeeds; per-user writes wait for sessions (R17); an uninstall as SYSTEM with users signed out leaves their registrations and warns `user_registrations_pending` |

Registry detection (the Intune detection rule): key
`HKEY_LOCAL_MACHINE\SOFTWARE\Cisco\DefenseClaw\Enterprise`, value
`ProductVersion`, version comparison "greater than or equal to", "Associated
with a 32-bit app on 64-bit clients" set to No. From the 32-bit engine, check
that the 64-bit view is read:

```powershell
[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64').OpenSubKey('SOFTWARE\Cisco\DefenseClaw\Enterprise').GetValue('ProductVersion')
```

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| MDM-W-12 | Installed through MDM-W-08 | Run the registry check above from the 32-bit engine; compare `config_sha256` in `intune-package.json` with the installed config's SHA-256 (the custom detection script in the Intune guide does this) | The version is read from the 64-bit view; the hashes match |
| MDM-W-13 | Installed | Two SYSTEM tasks running Setup `/ensure` with a changed config at once | The second exits `1618` (`lifecycle_busy`) after about 30 s; event 140. Intune retries `1618` |
| MDM-W-14 | Disposable pending-transaction snapshot | Interrupt a SYSTEM `/ensure` after intent is recorded; rerun it as LocalSystem through the 32-bit parent | Pending transaction recovers or rolls back to one coherent version; verify passes and the result names recovery |
| MDM-W-15 | Hash-pinned standalone deployment; signed test Setup available | Run wrapper with `-TrustMode Authenticode` against the signed fixture; compare with an unsigned fixture and the installed trust record | Signed fixture follows signer validation; unsigned fixture is refused; neither silently changes the recorded hash-pinned trust mode |

```powershell
./packaging/mdm/intune/windows/New-DefenseClawIntunePackage.ps1 `
  -SetupPath .\DefenseClawSetup-Enterprise-Standalone-x64.exe `
  -Sha256 '<setup sha256>' `
  -ConfigPath .\config.yaml `
  -OutputDirectory "$sim\intune" `
  -ProductVersion 9.9.9
# optional: -IntuneWinAppUtil <path to IntuneWinAppUtil.exe> builds the .intunewin
```

In Intune the install command is
`%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1`
and the uninstall command is
`DefenseClawSetup-Enterprise-Standalone-x64.exe /uninstall JSON=1`.

Windows failure paths (Setup from the elevated prompt unless noted):

| Case | Expected |
| --- | --- |
| `CONFIG=relative\config.yaml`, `CONFIG=%TEMP%\config.yaml`, a padded or UNC `CONFIG=` | `1639` |
| An unknown property (`FOO=1`) | `1639` |
| First `/ensure` without `CONFIG=` | `1639` |
| `/install` without both `CONFIG=` and `MANIFEST=` | `1639` |
| `TIMEOUTSECONDS=30` | `1639` |
| A config in a folder std1 can write, or a `CONFIG=` that is a link | `1603` (Setup); `mdm_untrusted_input` (wrapper) |
| `/ensure` from a non-elevated prompt | `1603` |
| V1 Setup `/ensure` over V2 | `1603`, `downgrade_refused` |
| Wrong `-Sha256` to the wrapper | `mdm_hash_mismatch`, `1603` |
| Setup `/?` | Prints usage. Record whether it shows the `/ensure ... CONFIG= MANIFEST= PURGE= JSON=` property form (the usage a Setup user needs) |

With `JSON=1`, Setup's own refusals print a short `schema_version: 1` document
with an `error` string.

### Real MDM pilot

A tenant pilot is optional and reported separately. It needs a licensed
tenant and a supported client: a Windows client edition (not Windows
Server) for Intune; macOS enrollment may need a GUI approval; Linux Intune
enrollment needs a supported desktop and the Intune app. Jamf package and
script support depend on the Jamf product. Follow the MDM guide for the
product, keep a separate evidence set, and record what the tenant reported
(assignment, install status, detection, remediation) next to the host's own
`status` and `verify`.

## Admin CLI

Run these as the admin account after S3 where a row needs enrollment or agent
activity; run install-only rows after S1. They are read-only unless noted.

| Row | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| CLI-01 | Installed | `status` and `verify`, text and `--json` ([Post-install health](#post-install-health)) | Healthy as in [Healthy result](#healthy-result); `status` and `verify` describe the same problems the same way when the host is unhealthy |
| CLI-02 | Linux or macOS | `sudo $G status` | Gateway health, subsystems, connectors and modes of the managed deployment (no per-user config error). A connector set `enabled: false` shows "Status: disabled, not enforced"; the fleet uplink shows disabled for the managed profile |
| CLI-03 | Installed | Provoke each warning or error in the table below once, then undo it | The listed code, exit code and message; the message names a next step |
| CLI-04 | Installed | `enterprise policy show`, `--json`, `--connector <c>`, and `--user std1 --project <std1's test project>` | One block per connector: route, covered, lock and effective lock, foreign-hook mode, owned and foreign entries, files, conflicts and notes. `--user` adds that user's own agent-config scan; for an excluded, exempt or root account it prints an `enrollment:` line. `ownership: "off"` shows `ownership off: machine policy not managed` |
| CLI-05 | Installed | `enterprise policy export --connector codex --format toml`; `--connector claudecode --format version-floor`; `--connector copilot`; macOS also `--format plist` for codex and claudecode | The administrator's copy of each file, printed; nothing written. Formats: codex `toml` (default), `plist`; claudecode `json` (default), `claude-hklm-json`, `reg`, `plist`, `intune-settings-catalog`, `version-floor`; cursor, copilot, opencode `json` |
| CLI-06 | Installed | `enterprise policy verify --json; echo "exit=$?"` | Exit `0` when every machine-policy connector is covered; `1` while any is not covered, or when `--user` finds a foreign hook that would be blocked. `policy verify --user` lists connectors in name order |
| CLI-07 | Linux or macOS; std1 enrolled for Codex and Claude Code | `enterprise policy verify --live --user std1 --connector codex --agent-binary <absolute path to std1's codex> --json`, then the same for `claudecode` | Live proof passes; for Claude Code the proof is the gateway's `tool.invocation.requested` record of a canary tool call. Missing `--user`, `--connector` or `--agent-binary`: "--live needs --user, --connector (codex or claudecode) and --agent-binary". `--connector cursor`: "live verification is implemented for codex and claudecode, not cursor", exit `1`. Relative binary: "live verification requires an absolute --agent-binary path", exit `1` |
| CLI-08 | Windows | `& $Cli enterprise policy verify --live --user std1 --connector codex --agent-binary <path> ` | Refused up front: "enterprise policy verify --live is not available on a managed Windows host: ...". Use [CLI-12](#admin-cli) instead |
| CLI-09 | Installed | `enterprise secret set`, `status` and `remove` (commands below), including every refusal in the exit-code table | Behavior and exit codes as in the tables below. `status` shows only the name, a 12-hex SHA-256 prefix, the mode (Linux, macOS) and the time: never the value. The prefix equals the first 12 hex characters of the value's SHA-256 |
| CLI-10 | Linux or macOS | `sudo $G enterprise hooks status`, `--json`; `sudo $G enterprise hooks verify --json`; `sudo $G enterprise hooks enumerate --dry-run --json` | Guardian summary and an Enrollment section, one line per account with each connector's state (enrolled, pending, failed); JSON adds an `enrollment` array. `verify` checks every enabled target without changing anything; `enumerate --dry-run` prints the manifest it would publish and publishes nothing. Do not run the service-internal subcommands (`watch`, `reconcile`, `install`, `uninstall`, `scrub`, `remove-all`, `apply-target`, `revoke-gone`, or `enumerate` without `--dry-run`) |
| CLI-11 | Installed; some agent activity | `audit export --since 2h --connector claudecode --output <new file>`; `audit export --limit 20 --newest`; `audit export --since <RFC3339 time> --until 30m -o -`; `audit findings --limit 50` | Rows filtered by time and connector; `--newest` keeps the most recent N, still written oldest first; `--output` refuses an existing file. Linux and macOS open the gateway's audit store read-only (no "untrusted owner" error). Windows needs an elevated prompt or SYSTEM |
| CLI-12 | Windows; Claude Code enabled; std1 enrolled | After install: `status --json` shows `security_complete: false`. As std1 in std1's session, start Claude Code interactively and make one tool call. Elevated: create `C:\DcEvidence` and restrict it as for `$Stage`; run `& $Cli audit export --connector claudecode -o C:\DcEvidence\audit-claudecode.jsonl` (the file must not exist) and find std1's row. Then `& $Cli enterprise windows repair --profile standalone --attest-claude-effective-policy --json` (Setup form: `/repair ATTESTCLAUDEEFFECTIVEPOLICY=1 JSON=1`) and `status --json` | `security_complete: true` after the attestation. After every upgrade it returns to `false` until these steps are repeated |
| CLI-13 | Windows | `& $Cli enterprise windows events`, `--max 0`, `--json`; then, as std1, run `[System.Diagnostics.EventLog]::WriteEntry('DefenseClaw Lifecycle','dctest std1','Information',999)` and `[System.Diagnostics.EventLog]::WriteEntry('DefenseClaw Enterprise','dctest std1','Information',999)`, and run `events` and `events --application` again as admin | Newest 20 entries by default (`--max 0` for all); any account can run it. std1's write to the `DefenseClaw` log (source `DefenseClaw Lifecycle`) is refused (access denied); `events` checks that log. Event ids: 100 installed, 101 upgraded, 102 repaired or reconciled, 110 uninstalled, 111 ensure no-op, 112 ensure applied, 120 status or verify unhealthy, 130 action failed, 140 busy, 150 refused. A healthy `status` or `verify` writes no event. std1's Application-log entry is flagged as not DefenseClaw's and `events --application` exits `1` |
| CLI-14 | Installed | In each standard session set `$G` to the full platform gateway path, or `$Cli` to the full Windows CLI path from [Paths and commands](#paths-and-commands). As std1 (Linux, macOS): `$G stop`, bare `$G`, `$G start`, `DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise $G start`, `$G enterprise hooks status`, `$G enterprise secret status`, `$G enterprise <os> status`. As std1 (Windows): `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' stop; $LASTEXITCODE`, `& $Cli enterprise policy show`, `& $Cli audit export`, `& $Cli enterprise secret status`, `& $Cli enterprise windows status --profile standalone` | Lifecycle mutations refuse with non-zero exit before side effects (no `~/.defenseclaw/audit.db`). Standard-user status may report `state_unreadable` on Linux/macOS or `preflight_failed` on Windows; record those as existing UX findings. Windows policy and audit refuse elevation with the explicit admin or MDM message. The gateway stop must show the managed-host refusal, not "command not recognized" |
| ENR-01 | Enrolled agent at a verified version | Upgrade that agent within its verified range; wait one enumerator and guardian cycle; run C0b | Version and hooks follow the new binary; marker still blocked |
| ENR-02 | Separate snapshot with an out-of-range agent | Upgrade to an unverified version; run status/verify and C0b | Last verified version is retained where available; `hook_contract_unverified` names the new version and coverage is incomplete |
| ENR-03 | Windows Codex account | Test 0.130.x, then 0.131.0 or later from the same install channel | Earlier build is below the Windows hook floor; supported build enrolls and blocks C0b |
| ENR-04 | macOS or Windows Devin account | Present Devin 3000.11.3, then the supported 3000.4.25 on a separate snapshot | 3000.11.3 remains unverified with `security_complete: false`; supported version enrolls |

Warnings and errors to provoke once (CLI-03):

| Code | How to provoke it | Expected |
| --- | --- | --- |
| `not_root` | `$G enterprise linux verify` as std1 | Exit `1` |
| `lifecycle_busy` | [LC-17](#post-install-health) | Exit `75` / `1618` |
| `already_installed` | `install` on an installed host | Exit `1` |
| `not_installed` | `repair`, `reconcile` or `verify` on a clean host | Exit `1` / `1603` |
| `config_invalid`, `config_rejected`, `config_reverted` | [LC-07](#post-install-health), [LC-08](#post-install-health) | As listed there |
| `downgrade_refused` | An older payload, package or Setup | Refused, nothing changed |
| `payload_invalid` | A group-writable payload folder; `repair` after a binary no longer matches the record | Exit `1`; `repair --payload <dir>` with the same release fixes the second |
| `not_started` | `ensure --no-start` | Warning |
| `unmanaged_leftovers` | `status` after `uninstall` without `--purge` | Warning with the next step (`apt remove`, `dnf remove`, `uninstall --purge`, or `ensure --from-package --config <file>`) |
| `no_connectors_enabled` | Install with no `guardrail.connectors` on a host with eligible users | Warning; `security_complete: false` |
| `hook_contract_unverified` | Install an out-of-range agent version for std2 | `status` warns naming the connector, version and user; `verify` fails |
| `agent_unprotected` | An agent in a shared prefix another account controls | Reported as unprotected with "(not run: ...)"; discovery does not run it |
| `guardian_target_account_removed` | Delete an enrolled account ([Enrollment](#enrollment)) | Warning; `verify` and `reconcile` stay healthy until revocation or `repair` |
| `guardian_target_user_path` | As std1, replace an agent config folder with a link, or `chmod 000 ~/.kiro` | Warning only, naming the account, connector and path; `verify` and `reconcile` exit `0`; `security_complete` stays true |
| `unit_failed` | A DefenseClaw unit left in the failed state (Linux) | Warning; clear with `systemctl reset-failed <unit>` |
| `claude_version_floor_missing` | Delete DefenseClaw's Claude Code floor drop-in | Warning; `verify` still passes; `policy verify` exits `1`; the next `ensure`, `repair` or `reconcile` writes it back |
| `machine_policy_incomplete` | Remove DefenseClaw's block from `/etc/codex/requirements.toml` | `verify` fails naming the connector, the file and the repair command |
| `user_registrations_pending` | Windows uninstall from an elevated prompt (not SYSTEM), or with a user signed out | Warning listing connector and SID |
| `enrollment_pending_account_folder` | Windows: an account that ran an agent (for example through runas) before it was enrolled | `status` exits `0` with the warning; `repair` exits `0`; the first real sign-in adopts the folder |
| `deleted_account_rows` | Windows: delete a local account but keep its profile folder | Warning; the rows drop after the profile is removed |

```bash
# CLI-09, Linux (macOS: /opt/cisco/defenseclaw/bin/defenseclaw-gateway)
read -rs AID_KEY
printf '%s' "$AID_KEY" | sudo $G enterprise secret set --name ai-defense-api-key --from-stdin --json
sudo install -m 0600 /dev/null /root/ai-defense.key
printf '%s' "$AID_KEY" | sudo dd of=/root/ai-defense.key status=none
unset AID_KEY
sudo $G enterprise secret set --name ai-defense-api-key --from-file /root/ai-defense.key --json
sudo shred -u /root/ai-defense.key
sudo $G enterprise secret status
sudo $G enterprise secret status --json
sudo $G enterprise secret remove --name ai-defense-api-key --json
```

```powershell
# CLI-09, Windows: the key file lives in an admin-only folder
New-Item -ItemType Directory -Path C:\Admin -Force | Out-Null
icacls C:\Admin /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
$key = Read-Host -AsSecureString -Prompt 'Disposable test API key'
[IO.File]::WriteAllText('C:\Admin\ai-defense-api-key.txt', (ConvertFrom-SecureString -SecureString $key -AsPlainText))
& $Cli enterprise secret set --name ai-defense-api-key --from-file C:\Admin\ai-defense-api-key.txt --json
Remove-Item C:\Admin\ai-defense-api-key.txt
ConvertFrom-SecureString -SecureString $key -AsPlainText | & $Cli enterprise secret set --name ai-defense-api-key --from-stdin
& $Cli enterprise secret status --json
& $Cli enterprise secret remove --name ai-defense-api-key
```

Secret names are lowercase letters, digits and dashes, starting with a letter
or digit, up to 63 characters. A value is one line, at most 16 KiB, with no
NUL. Enable AI Defense with `enterprise.inspection.ai_defense.enabled: true`
and `credential: ai-defense-api-key`, then check `status --json`
`inspection.ai_defense`. Rotate by setting the same name again, and revoke the
old key after `status` shows the new digest.

| Behavior | Linux and macOS | Windows |
| --- | --- | --- |
| Before install | `set` refuses: "DefenseClaw enterprise is not installed (no service account)" | `set` and `remove`: "no standalone managed deployment is installed; run `enterprise windows ensure --profile standalone` first" |
| Privilege | Root for `set` and `remove`; `status` as non-root fails "listing the protected credentials requires administrator rights; run: sudo ... enterprise secret status" | Elevation for all three, `status` included ("run this command from an elevated Administrator prompt or the MDM agent") |
| After `set` or `remove` | Runs `ensure --reason secret` under the lifecycle lock and prints that result (the gateway restarts) | Restarts `DefenseClawGateway` if running; JSON `{"schema_version":1,"ok":true,"action":"set","name":...,"gateway_restarted":true}` |
| `status` output | `<name> sha256:<12 hex>… mode <mode> modified <time>` | `<name> sha256:<prefix>… modified <time>` (no mode) |
| Files | `/etc/defenseclaw/secrets/<name>` (systemd 247 and later: root `0600`, folder `0700`; older: `root:defenseclaw 0640`, folder `0750`); macOS `/opt/cisco/defenseclaw/etc/secrets/<name>` `root:_defenseclaw 0640`, folder `0750` | `C:\ProgramData\Cisco\DefenseClaw\secrets\<name>`: owner Administrators, protected DACL, SYSTEM and Administrators full, `NT SERVICE\DefenseClawGateway` read |
| Whitespace | One trailing line ending removed | Leading and trailing whitespace trimmed |

| Secret result | Linux and macOS exit | Windows exit |
| --- | --- | --- |
| Stored, listed, removed | `0` | `0` |
| Both or neither of `--from-stdin` and `--from-file`; an empty, multi-line or oversized value | `2` | `1639` |
| Invalid name | `1` | `1639` |
| Not root or elevated, not installed, write failed | `1` | `1603` |
| Follow-up `ensure` failed (rolled back) | `1` | N/A |
| Lifecycle lock held | `75` | N/A |
| Gateway restart failed after storing | N/A | `1603` |
| `--from-file` writable by non-admins | Not checked by the CLI (the MDM wrapper refuses it with `mdm_untrusted_input`) | `1639` |

### Exit codes

| Component | Success | Failure | Invalid arguments | Busy | Notes |
| --- | --- | --- | --- | --- | --- |
| Linux and macOS lifecycle (`enterprise linux\|macos`) | `0` (also no-op) | `1` (rolled back; `status` and `verify` unhealthy) | `2` | `75` (after `--lock-wait`, default 5 s; `verify` too) | |
| Windows standalone lifecycle (Setup, `enterprise windows --profile standalone`) | `0` | `1603` | `1639` (including a config the gateway cannot load at install or ensure) | `1618` (after about 30 s) | `3010` is reserved and never returned |
| Windows Secure Client Setup | `0` | `1603` (also for bad arguments) | - | - | |
| Linux and macOS `enterprise secret` | `0` | `1` | `2` | `75` | Invalid name: `1` |
| Windows `enterprise secret` | `0` | `1603` | `1639` | - | |
| `enterprise policy verify` | `0` covered | `1` | - | - | `--live` refused on managed Windows |
| `enterprise windows events` | `0` all entries verified | `1` | - | - | |
| Linux and macOS MDM wrapper | `0` | `1` | `2` | `75` (lock or package manager) | `mdm_secret_failed` carries `secret set`'s code |
| Windows MDM wrapper | `0` | `1603` | `1639` | `1618` | PowerShell parameter errors and a 5.1 start: `1`, no document |
| `detect.sh` | `0` detected | `1` not detected | `2` | - | Formats `value` and `jamf` always exit `0` |
| `detect.ps1` | `0` detected (one stdout line) | `1` (reason on stderr) | - | - | |
| `Remediate-Detect.ps1` | `0` healthy or not installed | `1` | - | - | |
| Linux package scripts | postinstall always `0` | preremove `1` only when the lock stays busy for 10 minutes | - | - | |
| macOS pkg postinstall | `0` | The lifecycle's code (fails `installer`) | - | - | preinstall `1` on a Secure Client host or a refused downgrade |

## Standard-account rows

Run each row as `std1` and `std2` in their own live sessions after PACK-01.
The administrator captures baseline hashes and runs `status`, `verify` and
`policy verify` after each attempt. Use the protected paths in [Paths and
commands](#paths-and-commands); restore every disposable change. In Linux
standard sessions use `systemctl --no-ask-password`; in Windows use an
unelevated PowerShell. Record repair time against the one-minute reconcile
bound, or 5.5 minutes for foreign-hook cleanup. Calls during repair must
remain inspected or match a named residual.

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| A1 | Managed profile healthy; standard account | Try to stop, disable, delete, or reconfigure each DefenseClaw service using normal OS controls; try to terminate a managed service process. | Denied; services remain healthy, or privileged recovery restores an unexpected exit. | User error and exit code; CLI `status`, `verify`. |
| A2 | Install and state paths known | Try a harmless replace, rename, truncate, permission change, or link swap against installed binaries and protected install, config, state, log, and socket paths. | Denied; trusted bytes and ownership unchanged. | User result; CLI `verify`; before/after metadata or hash. |
| A3 | Admin config and policy applied | Try to edit managed config, rule pack, secret, manifest, ledger, descriptor, service definition, or vendor machine policy. | Denied; policy remains effective. | User result; CLI `verify` and `policy verify`; before/after hash. |
| A4 | Two enrolled accounts | Try to read protected secrets and the other account's scoped credentials or agent configuration. | Denied; no secret appears in evidence. | Redacted denial; CLI `secret status` and `verify`. |
| A5 | Managed descriptor present | Invoke documented per-user install, upgrade, rollback, or gateway start/restart route as a standard account. | Refused with a managed-host explanation; managed deployment stays healthy. | User message and exit code; CLI `status`, `verify`. |
| B1 | Admin can restart gateway; harmless listener observation prepared | During an admin CLI restart, a standard account attempts to hold the local API endpoint or hook socket. Run an agent marker call during the window. | Native managed hooks reject an untrusted listener or continue on a trusted socket. Record the separate plugin, telemetry, and availability limits of enterprise residual R7 rather than claiming they are protected by the hook transport. | Agent screen and side effect; CLI `status`, `verify`, `audit export`; listener observation records only counts or status. |
| B2 | Clean restart window | Try to pre-create the hook socket directory or socket object before gateway start. | Denied or ignored; gateway never trusts a user-owned path. | User result; CLI `status`, `verify`; owner/mode metadata. |
| D2 | Scoped test credential issued; no credential copied to evidence | Attempt a config change or reload with the account's scoped credential, and cross-account or cross-connector use. | Management request forbidden (`403`); a credential cannot change identity or scope. | Redacted status only; CLI `audit export`, `verify`. |
| D3 | Audit, event, and lifecycle logs exist | Try to alter or delete protected audit, event, and lifecycle records as a standard account. | Denied; records remain available and intact. | User error; CLI audit export and lifecycle/verify output; hash where applicable. |
| D4 | Enrolled account with a default home | Temporarily change only the account's own home or connector config location, then restore it. | Enforcement persists where a machine route applies; per-user repair is bounded or a precisely named residual is recorded; another account remains healthy. | Before/after CLI `status`, `verify`; marker call and audit; elapsed repair time. |

### Platform command sheet for A and B

Use these literal probes on one representative path of each type. Replace angle-bracket operands with the path from [Paths and commands](#paths-and-commands) or the account-owned disposable fixture. Record exit status immediately. For A2–A4 and D3, read only metadata or digests; never print a credential.

```bash
# Linux, standard account
systemctl --no-ask-password stop defenseclaw-gateway.service; echo "exit=$?"
systemctl --no-ask-password disable defenseclaw-hook-guardian.service; echo "exit=$?"
sh -c ': >> /etc/defenseclaw/config.yaml'; echo "exit=$?"
/opt/defenseclaw/bin/defenseclaw-gateway start; echo "exit=$?"
# Admin review
sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux verify --json
sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise policy verify --json
```

```bash
# macOS, standard account
launchctl bootout system/com.cisco.defenseclaw.gateway; echo "exit=$?"
sh -c ': >> /opt/cisco/defenseclaw/etc/config.yaml'; echo "exit=$?"
/opt/cisco/defenseclaw/bin/defenseclaw-gateway start; echo "exit=$?"
# Admin review
sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos verify --json
sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise policy verify --json
```

```powershell
# Windows, standard account
Stop-Service DefenseClawGateway; $?
sc.exe config DefenseClawGateway start= disabled; $LASTEXITCODE
$p = 'C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml'
try { [IO.File]::OpenWrite($p).Dispose(); 'OPENED' } catch { $_.Exception.GetType().Name }
& "C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe" enterprise windows status --profile standalone --json; $LASTEXITCODE
# Run verify and policy verify in the separate elevated PowerShell 7 session.
```

The admin hashes the managed config before and after these probes; its hash
must be identical. For B1/B2 use only a harmless local listener and a
test-owned socket path during an administrator-controlled service restart;
keep the listener from capturing payload bytes. For D2 use the issued scoped
credential from its normal hook path and record only HTTP status `403`, never
the credential. For D4 change one account-owned config root at a time and
restore it before the next row.

For B1 on Linux, the administrator first stops
`defenseclaw-gateway-api.socket` and `defenseclaw-gateway-hook.socket` on
the disposable snapshot. As std1 on Linux/macOS run the following listener;
it never accepts or reads a connection. The admin then restarts the gateway,
runs [REG-1-4-02](#gateway-and-hook-trust) and restores the socket units.
Windows uses the same listener in std1's PowerShell with
`[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,18970)`, `Start()`,
then `Stop()` after [REG-1-4-03](#gateway-and-hook-trust). A held port is an
availability residual; the C0b side effect and audit test enforcement.

```bash
python3 -c 'import socket,time; s=socket.socket(); s.bind(("127.0.0.1",18970)); s.listen(1); time.sleep(90); s.close()'
```

For B2, during the same admin-controlled stopped-socket window, std1 tries
`touch /run/defenseclaw-hook/dctest-squat` on Linux or
`touch /opt/cisco/defenseclaw/run/dctest-squat` on macOS, verifying that the
protected parent exists first; the attempt must be denied and the file
absent. Windows has no Unix hook socket (`N/A`). For D2 use the owner-only curl options file
described in [Rules for every row](#rules-for-every-row) against
`/config/patch`, then a second user's scoped route. For D4 run C3 and C3b
with only one account's environment changed.

For the remaining A variants, use a separate disposable snapshot for each
platform and stop at once if a protected mutation unexpectedly succeeds.
As std1 on Linux try `systemctl --no-ask-password mask
defenseclaw-gateway.service`, `systemctl --no-ask-password edit
defenseclaw-gateway.service`, and `kill -9 <gateway MainPID>`; on macOS try
`launchctl disable system/com.cisco.defenseclaw.gateway`, `launchctl kill
SIGKILL system/com.cisco.defenseclaw.gateway` and `launchctl kickstart -k
system/com.cisco.defenseclaw.gateway`; on Windows try `sc.exe delete
DefenseClawGateway` and `taskkill /F /PID <gateway service PID>`. For A2
check a binary's write access with `test -w` (Windows: the `OpenWrite` probe
above), then attempt a rename and a test-owned sibling link on the snapshot;
compare hashes and owners. For A3 repeat the non-mutating open against the
rule pack, `targets.yaml`, ledger, descriptor and service definition named in
[Paths and commands](#paths-and-commands). For A4 use `test -r` or
`Test-Path` on the other account's scoped token, never print it. For A5 run
the platform release installer, `defenseclaw upgrade`, `rollback` and the
full gateway path on the managed-host snapshot as in PU-04. The admin checks
each attempt against baseline hashes and restores the snapshot afterward.

## Multi-user isolation and enrollment

Keep `std1` and `std2` signed in with concurrent agent sessions. Create a
separate `~/dc-test-proj` per account with distinct `dctest-*` markers. Run
E1–E7, then sign `std2` out and repeat applicable checks, recording the
Windows deferred-repair residual. After each row the admin runs platform
`status --json`, `verify --json`, `enterprise policy verify --json` and
`audit export --since 30m --connector <connector>`. Filter audit by marker
and account, not output order. Include an admin-account agent session for E6;
use disposable test fixtures.

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| E1 | Both accounts have test config and project files | From `std1`, try read/modify/delete of `std2` and admin agent files, credentials, ledger or audit paths; include a harmless link from a shared folder. | Denied; no cross-account content or ownership change. | User error; CLI `verify`; test-file hashes. |
| E2 | Both agents have distinct harmless markers | Run one allowed call per account; attempt identity or scoped-credential crossover without recording a credential. | Gateway rejects crossover; tool audit attributes each call to its real account. | CLI `audit export` filtered by both markers and accounts. |
| E3 | `std2` keeps a marker-ready agent session | Let `std1` damage only its own disposable config/home/quota or interrupt its own hook; run `std2` allow and block calls. | `std2` enforcement and availability persist; one user's failure does not make whole-host health fail. | Both TUI captures; CLI `status`, `verify`, audit; timing. |
| E4 | Shared disposable project | Add a harmless unapproved rewriting hook as `std1`; start `std2`'s agent in that project. | Guard or vendor lock prevents a rewritten `std2` call, subject to documented connector residuals. | `std2` TUI and side effect; CLI audit/policy verification. |
| E5 | Enrollment manifest and ledger established | Try to change `std2`'s enrollment or reuse a prior identity/home through `std1`'s permissions. | Denied or deferred for administrator review; no `std2` authorization change. | CLI `status`, `verify`; manifest/ledger comparison without credentials. |
| E6 | Admin session available | Try to influence administrator lifecycle or agent behavior via user-writable files, search paths, or service environment. | Admin lifecycle reads trusted inputs; no privilege gain or policy weakening. | Admin CLI `status`, `verify`, `policy verify`; test-file hashes. |
| E7 | Both accounts have a repairable test registration | Trigger simultaneous repair of each account's own file. | Each file restored with its own account ownership and mode; no cross-write. | CLI `status`, `verify`; owner/mode and measured times. |

For E1, std1 checks access without printing contents:
`test -r /home/std2/.defenseclaw; echo $?` and
`ls -ld /home/std2/.defenseclaw` (macOS: `/Users/std2`). On Windows use
`icacls C:\Users\std2\.defenseclaw` and `Test-Path`; never `Get-Content` on
another account's credential. For E5, test write access on the manifest and
ledger paths from [Paths and commands](#paths-and-commands) without changing
their bytes, then compare admin hashes. For E6, put a harmless
`defenseclaw-gateway` name in std1's test `PATH`, inspect
`systemctl show -p Environment defenseclaw-gateway.service` and sudo
`secure_path` (Windows: compare the administrator `PSModulePath` and service
path), and require the admin's absolute CLI path to resolve to the protected
binary. For E7 both accounts run `chmod 000 ~/.defenseclaw` in their own
sessions, wait for repair, and record each restored owner/mode separately.

## Standard-user hardening checks

Run these checks as `std1` and `std2` in their own interactive sessions on each supported OS. Keep the admin account in a separate elevated session for managed lifecycle actions and DefenseClaw CLI review. Use harmless marker rules applied by the admin through the documented policy workflow. For every row, capture the standard user's observed result, the agent's interactive UI where a tool call is involved, and the admin's DefenseClaw CLI output. Record elapsed seconds for a repair, the exact client version and hook route, and `PASS`, `FAIL`, `N/A`, or a named residual. Restore every disposable change and finish with healthy `status` and `verify`. Never copy credentials or tool payloads into evidence.

The expected outcomes are **denied/refused**, **repaired within the documented cycle**, or **fail closed**. Per-user registration watching has a one-minute periodic reconcile; record the actual interval. Foreign-hook cleanup can take about 5.5 minutes, while its hook-time guard should block an affected call during that window. A standard user cannot be expected to repair or override an administrator-owned policy. Test clients that lack a vendor lock or supported hook contract against the residual notes below before calling a result a new defect.

### Windows

| ID | What a standard user attempts | Expected outcome | Confirm through the DefenseClaw CLI | Threat-model row |
|---|---|---|---|---|
| W-H1 — Disable DefenseClaw | Stop or reconfigure a DefenseClaw service; alter a protected binary, config, ledger, or deployment marker; start a per-user DefenseClaw deployment. | Service and file changes denied; per-user lifecycle refused. An unexpected service exit is recovered by the service manager. | `enterprise windows status` and `verify` remain healthy; `secret status` reveals no secret value; repeat after repair. | W-01, W-02, W-20, W-21, W-52 |
| W-H2 — Impersonate the gateway | Hold the local API endpoint during an admin-controlled gateway restart or present a user-owned hook endpoint. | The native managed hook rejects the wrong gateway identity and sends it no hook credential or tool content; its calls fail closed if the trusted gateway is unavailable. Plugin request races, endpoint availability, and telemetry have documented residuals. | The fail-closed marker side effect and `audit export` show no trusted allow decision. Status may omit the listener holder (#929). | W-25, W-28 |
| W-H3 — Disable hooks per connector | Alter the user's own hook registration; select a hook-off client option or alternate user config; run an older client; interrupt the user's hook process. | Managed Claude Code and Codex hooks stay active under supported clients. User-owned registration is repaired within one reconcile cycle; foreign or unsupported routes follow the named residuals below. | `enterprise policy verify` (Windows managed hosts refuse `--live`), plus `enterprise windows status`, `verify`, and connector-filtered `audit export`; compare the marker side effect with the agent UI. | W-09, W-26, W-27, W-49, W-55 |
| W-H4 — Weaken policy | Change managed mode or policy; add a user or project hook that rewrites a call; use a scoped credential to change protected configuration or another account's identity. | Protected changes denied; managed hook lock or foreign-hook guard blocks the call or repairs user-owned entries within its cycle; management and cross-scope requests forbidden. | `enterprise policy show`/`verify`, `enterprise windows verify`, and connector-filtered `audit export` show effective policy, attribution, and the guard decision. | W-04, W-14, W-49, W-50, W-51 |
| W-H5 — Tamper with audit | Modify or remove protected audit, event, or lifecycle records, or substitute another account's scoped identity. | Protected records denied; accepted tool records remain attributed to the authenticated account. | Export both accounts' distinct marker rows with `audit export`; run `enterprise windows events` and `verify`, comparing event/lifecycle presence without exposing record secrets. | W-02, W-14; event-log forging #928 (open) |

### Linux

| ID | What a standard user attempts | Expected outcome | Confirm through the DefenseClaw CLI | Threat-model row |
|---|---|---|---|---|
| L-H1 — Disable DefenseClaw | Stop or reconfigure a system unit; alter protected binaries, config, policy, ledger, or descriptor; start a competing per-user installation. | Unit and protected-file changes denied; per-user lifecycle refused; a service exit is restarted. | `enterprise linux status` and `verify` stay healthy; `enterprise secret status` shows status only. | L-01, L-02, L-21, L-24 |
| L-H2 — Impersonate the gateway | Hold the local API endpoint during an admin-controlled restart or pre-create a hook socket object. | Service manager retains the trusted hook socket; hooks verify its peer before sending. User-owned socket paths are denied or ignored. TCP availability and telemetry have documented residuals. | `enterprise linux status`/`verify` report socket and gateway health; marker outcome and `audit export` show a trusted decision or a closed failure. | L-05, L-06, L-08 |
| L-H3 — Disable hooks per connector | Change the user's own registration; choose a hook-off option or alternate config root; run an older client; interrupt a user-owned hook. | Machine-policy hooks remain active under supported clients; default user registration is repaired within one minute; route-specific exceptions below are residuals. | `enterprise policy verify --live --user std1 --connector codex --agent-binary <absolute path to codex>` (repeat for `claudecode`), `enterprise linux status`/`verify`, connector-filtered `audit export`, and marker side effect. | L-14, L-15, L-25, L-32, L-34 |
| L-H4 — Weaken policy | Change managed config or mode; add a rewriting user/project hook; attempt a cross-account or cross-connector scoped request. | Protected edits denied; vendor lock or foreign-hook guard blocks the call or removes the entry within its cycle; scoped request forbidden. | `enterprise policy show`/`verify`, `enterprise linux verify`, and `audit export` show the effective policy, block, and real account identity. | L-02, L-03, L-08, L-15, L-16 |
| L-H5 — Tamper with audit | Alter protected audit or lifecycle records, read another account's scoped credential, or attribute a request to that account. | Protected records and cross-account credential access denied; audit attribution remains bound to the real account. | `audit export` shows distinct marker rows for `std1` and `std2`; `enterprise linux verify` remains healthy. | L-02, L-07, L-08 |

### macOS

| ID | What a standard user attempts | Expected outcome | Confirm through the DefenseClaw CLI | Threat-model row |
|---|---|---|---|---|
| M-H1 — Disable DefenseClaw | Unload or reconfigure a system LaunchDaemon; alter a protected binary, config, policy, ledger, or descriptor; start a competing per-user deployment. | System-domain and protected-file changes denied; per-user lifecycle refused; a killed daemon is restarted. | `enterprise macos status` and `verify` remain healthy; `enterprise secret status` reveals no secret. | M-01, M-02, M-14 |
| M-H2 — Impersonate the gateway | Hold the local API endpoint during an admin-controlled restart or pre-create a hook socket object. | Hooks use the protected socket and verify its peer; user-owned socket paths are denied or ignored. TCP availability and telemetry have documented residuals. | `enterprise macos status`/`verify` report the listener state; the marker outcome and `audit export` show a trusted decision or closed failure. | M-05, M-06, M-07 |
| M-H3 — Disable hooks per connector | Change the user's own registration; choose a hook-off option or alternate config root; run an older client; interrupt a user-owned hook. | Managed Claude Code/Codex hooks remain active under supported clients; default per-user registration is repaired within one minute; named connector gaps remain residuals. | `enterprise policy verify --live --user std1 --connector codex --agent-binary <absolute path to codex>` (repeat for `claudecode`), `enterprise macos status`/`verify`, connector-filtered `audit export`, and marker side effect. | M-10, M-17, M-22, M-23, M-26 |
| M-H4 — Weaken policy | Change managed mode or policy; introduce a rewriting user/project hook; use a scoped credential across accounts. | Protected edits denied; vendor lock or foreign-hook guard blocks or repairs the user entry within its cycle; cross-account use forbidden. A higher-precedence administrator source is checked separately. | `enterprise policy show`/`verify`, `enterprise macos verify`, and `audit export` show effective coverage, guard result, and account identity. | M-02, M-03, M-07, M-10, M-11, M-12 |
| M-H5 — Tamper with audit | Alter protected audit or lifecycle records, read another account's credential, or assign a call to that account. | Protected records and cross-account reads denied; accepted rows retain the true account identity. | `audit export` shows distinct markers for `std1` and `std2`; `enterprise macos verify` remains healthy. | M-07 (credential read); no audit-tampering threat-model row |

### Documented residuals: record, do not file as new failures

- **User-owned connector routes (enterprise R1, R3, R4, R14, R24, R30; Linux L-33/L-34; macOS M-23/M-26):** a per-user agent can start with an alternate config root or vendor mode that never loads DefenseClaw's registration. The guardian repairs the default location, not an unobserved per-process location. OpenCode pure mode and a project-level OpenHands hooks file are specific examples. Such a session may show no DefenseClaw audit row while `status`/`verify` report the default target ready. Record the exact client and route. Application control or a vendor machine-policy route is needed for stronger coverage.
- **Hook process failures (enterprise R5, R6, R18; Linux L-32; macOS M-22):** the hook process belongs to the user. Some clients run a tool after a killed or stalled hook, including Claude Code, Codex, Hermes, Devin, and OpenHands under the documented conditions; Copilot has a timeout case. Record the observed client version, timeout, side effect, and missing or delayed pre-tool audit. Do not assert a universal fail-closed guarantee.
- **Old or copied clients (enterprise R15; Windows W-27; Linux L-25; macOS M-17):** a client below its supported hook contract can ignore both managed hooks and the Claude Code version-floor file. Discovery and `verify` may still report the enrolled default client as ready. Use application control for a required client/version floor; record this as the version-contract residual.
- **Gateway endpoint availability and telemetry (enterprise R7; Windows W-25; Linux L-05; macOS M-05):** a user holding the TCP endpoint can deny availability during a restart. Native telemetry exporters do not verify the listener, and certain Windows plugin request races are documented. Check that hook transport does not trust the listener; record the separate availability or telemetry residual without claiming no data can reach the holder.
- **Vendor and policy precedence (enterprise R2, R9, R13, R17, R22, R23, R25–R29; Windows W-51/W-57–W-61; Linux L-27–L-31; macOS M-18–M-21):** Claude Code `--bare` and `CLAUDE_CODE_SIMPLE` skip some prompt/session hooks while managed tool hooks remain; a higher-precedence administrator or cloud policy can shadow local files; signed-out Windows users may wait for an active session before per-user repair; several desktop, editor, ACP, and licensed surfaces are outside this release's live coverage. Test only the supported surface and state the exact residual or `N/A` reason.
- **Platform-specific residuals (enterprise R20/R31; Linux L-26; macOS M-24/M-25):** Linux private namespaces can hide machine policy if the host permits them; macOS permits limited idempotent on-demand job triggering and harmless hard links under the stated ownership checks. A verified account also has a finite request budget. Record these conditions without treating the documented behavior as a fresh hardening failure.

A result outside the exact conditions above is a finding. In particular, a supported managed-hook client executing the blocked marker with the ordinary configuration, an admin-owned policy changed by a standard user, a cross-account audit attribution, or a repair beyond its documented cycle needs a reproducible functional finding with the relevant CLI and interactive evidence.

## Connectors

Run one record per connector, OS, account and distinct hook route. A connector
without a usable license, sign-in, model or verified version is `NOT_RUN` with
the reason. On each applicable connector run C0a–C0c for both `std1` and
`std2`; run C0d for every route whose matrix cell says prompt block. Run
C1–C5 and C6 for each distinct route, at least once as `std1`, and C1 as
`std2` for per-user routes and every Windows connector. Repeat the core calls
for `std2` to prove attribution. A desktop surface reading the same hook file
can share the CLI result; a different surface needs its own record. Keep each
prompt literal; accept no model prose as evidence of a tool result.

### Route matrix

| Connector (`audit --connector`) | Linux | macOS | Windows | Tool / prompt / confirm contract |
| --- | --- | --- | --- | --- |
| Claude Code (`claudecode`) | Machine policy and lock | Same | Same | Tool and prompt block; native confirm |
| Codex (`codex`) | Machine policy and lock | Same | Same | Tool and prompt block; confirm alerts, then may run |
| Cursor (`cursor`) | Machine policy and guard | Same | Same, when enrolled | Tool and prompt block; confirm alerts; plan entitlement required |
| Copilot CLI (`copilot`) | Machine policy and guard | Same | Same | Tool block; native confirm |
| OpenCode (`opencode`) | Machine plugin and guard; per-user fallback | Same | Same plus per-user runtime | Tool block; confirm alerts |
| Amp (`amp`) | Per-user plugin and guard | Same | Same | Tool block; native confirm |
| Devin (`devin`) | Per-user hooks and guard | Same | Same | Tool and prompt block; confirm alerts |
| Antigravity (`antigravity`) | Per-user hook, no guard | Same | Same | Tool block; native confirm |
| Hermes (`hermes`) | Per-user hook and guard | Same | Per-user hook, no guard | Tool block; confirm cannot ask and blocks |
| OpenHands (`openhands`) | Per-user hook, no guard | Same | Unsupported | Tool and prompt block; confirm cannot ask and blocks |
| OmniGent (`omnigent`) | Per-user policy bridge, no guard | Same | Unsupported | Tool and prompt block; native confirm |
| Kiro (`kiro`) | Per-user global hook and CLI agent; ACP optional | Same | ACP route only | Tool block; v3 prompt veto unavailable (R22); confirm alerts |

`openclaw` and `zeptoclaw` require the separate guardrail proxy and are
refused here. `windsurf` is a retired id migrated to Devin; `geminicli` is
removed. Record their migration or refusal under CON-14 and CON-15.
Windows must refuse guardian rows for OpenHands, OmniGent and Kiro. Kiro ACP
is a separate route and needs its own UI and [ACP guard](https://cisco-ai-defense.github.io/defenseclaw/docs/acp-guard)
evidence if deployed.

### Marker rule pack

PACK-01 runs at the end of S1b, before any S2 marker check. As administrator,
copy `policies/guardrail/default` from the checkout at the recorded build
commit to a new administrator-owned `dctest` pack under the platform policy
directory in [Paths and commands](#paths-and-commands). Use `sudo install -d
-o root -g root -m 0755 /etc/defenseclaw/policies/guardrail/dctest/rules`
on Linux and the corresponding `/opt/cisco/defenseclaw/etc/...` path and
`root:wheel` group on macOS. On Windows create
`C:\ProgramData\Cisco\DefenseClaw\policies\guardrail\dctest\rules`
from the elevated prompt and protect it with the `$Stage` `icacls` rule.
| ID | Source on installed host | Destination |
| --- | --- | --- |
| PACK-01 Linux | `/opt/defenseclaw/share/policies/guardrail/default` (or the same directory in the recorded checkout) | `/etc/defenseclaw/policies/guardrail/dctest` |
| PACK-01 macOS | `/opt/cisco/defenseclaw/share/policies/guardrail/default` (or checkout) | `/opt/cisco/defenseclaw/etc/policies/guardrail/dctest` |
| PACK-01 Windows | `C:\Program Files\Cisco\DefenseClaw\share\policies\guardrail\default` (or checkout) | `C:\ProgramData\Cisco\DefenseClaw\policies\guardrail\dctest` |

Copy from the installed source, or the same directory in the recorded checkout
if the installed copy is absent:

```bash
sudo cp -a /opt/defenseclaw/share/policies/guardrail/default/. /etc/defenseclaw/policies/guardrail/dctest/  # Linux
sudo cp -a /opt/cisco/defenseclaw/share/policies/guardrail/default/. /opt/cisco/defenseclaw/etc/policies/guardrail/dctest/  # macOS
```

```powershell
Copy-Item 'C:\Program Files\Cisco\DefenseClaw\share\policies\guardrail\default\*' 'C:\ProgramData\Cisco\DefenseClaw\policies\guardrail\dctest' -Recurse
```

Files must be gateway-readable and neither files nor parents user-writable.
Add `rules/dctest.yaml`:

```yaml
version: 1
category: dctest-marker
rules:
  - id: TEST-MARKER-BLOCK
    tool_call_only: true
    pattern: 'dctest-block-marker'
    expression: >-
      f.commands.exists(c, 'dctest-block-marker' in c.argv)
    title: "Test marker command (block)"
    severity: CRITICAL
    confidence: 0.99
    tags: [test]
  - id: TEST-MARKER-ASK
    tool_call_only: true
    pattern: 'dctest-ask-marker'
    expression: >-
      f.commands.exists(c, 'dctest-ask-marker' in c.argv)
    title: "Test marker command (confirm)"
    severity: HIGH
    confidence: 0.99
    tags: [test]
  - id: TEST-PROMPT-MARKER
    pattern: 'dctest-prompt-marker'
    title: "Test marker prompt"
    severity: CRITICAL
    confidence: 0.99
    tags: [test]
```

Validate with `<G> rulepack validate --dir <absolute-pack-path>` (add `--json` for machine output). Put `guardrail.mode: action`, `guardrail.rule_pack_dir: <absolute-pack-path>`, and `guardrail.hilt: {enabled: true, min_severity: HIGH}` in the managed config. Apply through `enterprise linux ensure --from-package --config <absolute-config> --json`, `enterprise macos ensure --from-package --config <absolute-config> --json`, or Windows Setup `/ensure JSON=1 CONFIG=<absolute-config>`. On a payload install use `--payload <payload-dir>` in place of `--from-package`. Then run `enterprise policy show` and `enterprise policy verify --json`. A bare `pattern` can be detection-only for generic tool calls, so the block and ask rules also use parsed command facts. `in c.argv` matches one exact argument; quote the marker as its own argument in the prompt.

### Common interactive cases

Use a new `~/dc-test-proj` per account and one new absolute file per case. In Windows prompts replace the POSIX commands with `New-Item -ItemType File -Path "$env:USERPROFILE\dc-test-proj\dctest-allowed.txt"` and the corresponding block or ask filename; the marker remains a separate command argument where the agent supports shell arguments. For C0b and C0c on Windows, ask for `Write-Output dctest-block-marker | Out-File "$env:USERPROFILE\dc-test-proj\dctest-block.txt"` and the corresponding `dctest-ask-marker` / ask file: the marker is an exact command argument. For native approval and denial, use an ordinary `touch`/`New-Item` command that asks for permission, without the block marker. Before a blocked case ensure the target file is absent.

| ID | Preconditions | Steps typed into the agent's TUI | Expected result and evidence |
| --- | --- | --- | --- |
| C0a | Enrolled account; action pack active | `Run exactly this shell command: touch "$HOME/dc-test-proj/dctest-allowed.txt"` (Windows: `New-Item -ItemType File -Path "$env:USERPROFILE\dc-test-proj\dctest-allowed.txt"`) | File exists. `audit export --connector <connector> --since 30m` contains an allow tool row with the real account name and uid/SID |
| C0b | C0a; target absent | `Run exactly this shell command: touch "$HOME/dc-test-proj/dctest-block.txt" dctest-block-marker` | No file; a CRITICAL blocked pre-tool row; capture the visible DefenseClaw reason or the connector's documented notice limitation |
| C0c | Confirm enabled | `Run exactly this shell command: touch "$HOME/dc-test-proj/dctest-ask-yes.txt" dctest-ask-marker`; approve when offered. Repeat with `dctest-ask-no.txt` and deny | File and audit follow the approval contract in the route matrix. If DefenseClaw confirm falls back to alert, record that and separately exercise the vendor's native approve/deny dialog |
| C0d | Route matrix marks prompt block | Enter `dctest-prompt-marker` as a user prompt in a fresh TUI turn | Prompt blocked before a model turn, with a prompt audit row, unless a named residual applies. Kiro v3 reports a block but cannot veto the prompt (R22); other Kiro routes without a prompt hook are `N/A` |
| C1 | C0 passed; machine policy or own repairable registration | On Linux/macOS machine-policy routes, try a non-mutating open of the protected policy file and hash it before/after. On per-user routes, back up and edit or remove only the account's DefenseClaw registration. On Windows, remove only the user's `.defenseclaw\hooks\.hook-<connector>.token`. Run C0b immediately, then poll `status` and `verify` by mtime and SHA-256 | Machine policy edit denied with unchanged hash; per-user file or Windows token restored within the watcher/one-minute cycle. Interim call inspected or recorded under the exact residual |
| C2 | C0 passed | In a fresh interactive session, use the agent's normal hooks-off setting or launch flag from its procedure below, then run C0b | Machine-policy lock still inspects; a named per-user/vendor-mode residual is recorded rather than called a pass |
| C3 | C0 passed | In a new session set the agent's documented alternate config root or `HOME` for a disposable copy; run C0b; restore the environment | Machine policy still applies. Per-user bypasses follow R1/R3/R4/R22; record side effect and audit absence separately |
| C3b | C0 passed; fresh TUI | In the user's session set `DEFENSECLAW_FAIL_MODE=open`, `DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:1`, `DEFENSECLAW_GATEWAY_TOKEN=x`, `DEFENSECLAW_HOOK_SOCKET=$HOME/x.sock` and `DEFENSECLAW_HOME=$HOME/dc-copy` (Windows: `$env:` assignments), then start the agent and run C0b; unset all five | Managed hooks ignore these user overrides; the block marker remains absent and audit attributes the real account. On a per-user route that never loaded the hook, use the named alternate-root residual rather than claiming this proves a managed hook bypass |
| C4 | An older or copied client safely available | Record its `--version`, start it interactively, run C0a and C0b | Refused or inspected if it honors the contract. Otherwise record R15 and the version; don't claim an old-client pass |
| C5 | Test-owned hook process and temporary storage | During a live TUI call interrupt only that account's hook process, then in a second run constrain its test-owned temp folder; run C0b and restore. OmniGent has no hook process: record that half `N/A` | Record exact file, audit and delay. R5/R6/R18 describe vendor fail-open cases; all other accounts remain healthy |
| C6 | Guard-enabled connector; C0 passed | Add a harmless user or project hook in the documented vendor location that rewrites a disposable command, start the TUI in that project, and run C0b. Restore the fixture | Guard blocks at call time or user file is cleaned within about 5.5 minutes; project files stay in place but blocked. Audit and `policy show --user <account> --project <path>` and `policy verify --user <account>` name the source and allowlist key. Admin hooks retain original hashes |

Audit review (admin, use an output path that does not exist):

```bash
sudo install -d -m 0700 /root/dctest-evidence  # macOS: /var/root/dctest-evidence
sudo "$G" audit export --connector claudecode --since 30m --newest --limit 50 -o /root/dctest-evidence/dctest-audit.jsonl
sudo "$G" enterprise policy show --user std1 --project /home/std1/dc-test-proj --json
sudo "$G" enterprise policy verify --user std1 --json
```

```powershell
New-Item -ItemType Directory -Path C:\DcEvidence -Force | Out-Null
icacls C:\DcEvidence /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
& $Cli audit export --connector claudecode --since 30m --newest --limit 50 -o C:\DcEvidence\dctest-audit.jsonl
& $Cli enterprise policy show --user std1 --project C:\Users\std1\dc-test-proj --json
& $Cli enterprise policy verify --user std1 --json
```

Use a new output file for each export or delete the test-owned old one first. `--limit` without `--newest` keeps the oldest matching rows. Check `structured["defenseclaw.user.name"]`, `structured["user.id"]`, `structured["defenseclaw.guardrail.raw_action"]`, `structured["defenseclaw.guardrail.effective_action"]`, severity and event. Scan rows may still lack user fields (#921); connector-hook, inspect-tool and auth-failure rows should carry attribution. A blocked call normally has no post-tool audit, except that Hermes reports the blocked result in `post_tool_call`.

### Per-connector procedure

For each row, install the verified version listed under [Agent CLIs and model access](#agent-clis-and-model-access), sign in as the testing account, confirm `policy show --connector <name>`, then execute C0a–C6 as applicable. The following commands are typed in each user's own live terminal; `/exit` or equivalent closes that TUI. If the CLI version or authentication differs, record it and mark dependent calls `NOT_RUN` rather than inferring results. User edits are always to test-owned files and are restored after measurement.

| ID | Connector and exact launch | C1–C6 variants and expected result |
| --- | --- | --- |
| CON-01 | Claude Code: `cd ~/dc-test-proj && claude`; `/status` for version and managed policy; `/exit` to quit | C1: machine drop-in edits denied (Windows: own scoped token repaired). C2: user `disableAllHooks`, `claude --settings <file with disableAllHooks>`, `claude --bare`, `CLAUDE_CODE_SIMPLE=1 claude`; tool remains blocked; prompt exception R2. C3 and C3b: `CLAUDE_CONFIG_DIR=<disposable-copy> claude` remains blocked. C4: 2.1.153 may load hooks; 1.0.128/2.0.0/2.0.77 are R15. C5: killed hook can run (R18); full temp fails closed. C6: user/project Claude hook is ignored under `allowManagedHooksOnly`; with `managed_hooks_only: preserve` the guard denies it. C0c uses Claude's own permission dialog. Windows needs CLI-12 attestation after a real tool call |
| CON-02 | Codex: `cd ~/dc-test-proj && codex`; trust folder; `/quit` to close | C1: machine requirements denied (Windows: own token repaired). C2: `-c features.hooks=false`, `--disable hooks` or `hooks = false` in the existing `[features]` table still blocked; do not add a duplicate `[features]` table. C3 and C3b: `CODEX_HOME=<disposable-copy> codex` still blocked. C4: old builds may refuse to start. C5: killed/stalled hook can run (R18), full temp blocks. C6: user/project `.codex/hooks.json` ignored by lock. C0c confirm alerts; for actual approve/deny run `codex -s read-only -a on-request`, approve once and cancel once, checking files. On stock Ubuntu with user namespace restriction, use `codex --sandbox danger-full-access` in this disposable project so a sandbox failure does not masquerade as a hook result |
| CON-03 | Cursor Agent CLI: `cd ~/dc-test-proj && cursor-agent`; record Desktop or CLI version and entitlement; exit from the TUI | C1 machine policy denied. C2 no documented hook-off option: capture `cursor-agent --help`, mark `N/A` if none. C3 and C3b alternate `XDG_CONFIG_HOME`/`HOME` should still use machine policy. C4 copied current build remains inspected. C5 record vendor behavior. C6 user `~/.cursor/hooks.json` is neutralized with backup; project `.cursor/hooks.json` is blocked at call time. Without a usable agent plan, only config C1/C6 checks are possible (`NOT_RUN` for tool cases; R23) |
| CON-04 | Copilot CLI: `cd ~/dc-test-proj && copilot`; quit with `/exit` | C1 machine drop-in denied. C2 `disableAllHooks: true` in user settings, `COPILOT_ALLOW_ALL=true` or `copilot --allow-all-tools` does not disable policy hooks; confirm still asks. C3 and C3b `COPILOT_HOME=<disposable-copy> copilot` still denied. C4 old 1.0.15 with `--no-auto-update` is R15. C5 a stopped set of hooks may time out and run (R6); record each event. C6 user `~/.copilot/hooks/*.json` is blocked then neutralized; project `.github/hooks/*.json` remains blocked. Native confirm dialog is `Hook permission request` |
| CON-05 | OpenCode: `cd ~/dc-test-proj && opencode`; quit with `/exit` | C1 machine policy denied; per-user fallback plugin repaired. C2 an empty user `plugin` list, `OPENCODE_DISABLE_DEFAULT_PLUGINS=1`, or `OPENCODE_CONFIG_CONTENT='{"plugin":[]}'` remains blocked; `OPENCODE_TEST_MANAGED_CONFIG_DIR` is R4; `opencode --pure` or `OPENCODE_PURE=1 opencode` is R4. C3 and C3b alternate `OPENCODE_CONFIG`/`OPENCODE_CONFIG_DIR` still blocked unless it selects the documented pure bypass. C4 1.4.0 still loads policy where available. C5 plugin exceptions block, even after a stopped process resumes. C6 user plugin moved to backup; project `.opencode/plugins` blocked at call time. Confirm alerts; agent permission may be separate |
| CON-06 | Amp: `cd ~/dc-test-proj && amp`; exit from the TUI | C1 remove or edit `~/.config/amp/plugins/defenseclaw.ts`; restored within a minute, including appended bytes. C2 `amp plugins remove <plugin-path>` is repaired; `--settings-file <disposable-file>` still inspects. C3 and C3b alternate `XDG_CONFIG_HOME` or `HOME` can load no plugin (R1/R3). C4 copied client remains inspected. C5 plugin failure blocks. C6 user plugin is denied and removed; project `.amp/plugins/*.ts` cancels the turn at agent start. Native confirmation says `Allow shell_command?` |
| CON-07 | Devin CLI: `cd ~/dc-test-proj && devin`; exit from the TUI | C1 edited `~/.config/devin/config.json` hooks are repaired. C2 `devin --config <disposable-unhooked-config>` or Restricted Mode is R1. C3 and C3b `XDG_CONFIG_HOME=<disposable-copy> devin` is R1. C4 only pinned versions are covered. C5 killed hook can let the call run (R18). C6 user/project Devin hooks are blocked by the guard and user entries removed. Confirm alerts; no native DefenseClaw ask |
| CON-08 | Antigravity CLI: `cd ~/dc-test-proj && agy`; complete the user's own vendor consent screens; quit from the TUI | C1 edit/delete `~/.gemini/config/hooks.json` or own script; repaired. C2 capture `agy --help`; mark no hook-off flag `N/A`. C3 and C3b alternate `HOME` can skip the hook (R1). C4 older build often unavailable because it self-updates. C5 record process result. C6 foreign entry is not guarded or removed (R24); check that the DefenseClaw pre-tool hook still sees the final command. Native consent is the confirm surface |
| CON-09 | Hermes: `cd ~/dc-test-proj && hermes`; complete `hermes setup` once per account; quit from the TUI | C1 edit `~/.hermes/config.yaml`, its allowlist or `~/.defenseclaw/hooks/hermes-hook.sh`; repaired within a minute and re-rendered after upgrade. C2 `hermes --accept-hooks` still inspects; `hermes --safe-mode` skips hooks (R1); `--ignore-user-config` still inspects. C3 and C3b alternate `HERMES_HOME` is R1. C4 self-updating older version may be unavailable. C5 killed hook can run (R5/R18). C6 Linux/macOS foreign `pre_tool_call` entry is blocked and later removed; Windows has no guard (R24). Confirm without a native ask is blocked with a clear reason |
| CON-10 | OpenHands (Linux/macOS): `cd ~/dc-test-proj && openhands`; quit from the TUI | C1 edit `~/.openhands/hooks.json` or own script; repaired. C2 `openhands --always-approve` or `--yolo` still inspects. C3 and C3b alternate `HOME` may have no hooks (R1). C4 `uvx --from openhands==1.11.0 openhands` is R15. C5 killed/stalled hook can run after the user's native confirmation (R18). C6 project `.openhands/hooks.json` replaces global hooks (R30); user extra hooks are not guarded (R24). Windows `N/A` |
| CON-11 | OmniGent (Linux/macOS): start `omnigent server --config ~/.omnigent/config.yaml`; if the team has no documented interactive client command, mark tool-call cases `NOT_RUN` with that reason | C1 change the `policy_modules` entry or bridge, restart, then wait for repair. C2 `omnigent server` without its managed config can be R1. C3 and C3b `OMNIGENT_CONFIG`/`OMNIGENT_CONFIG_HOME` alternate root is R1. C4 0.14+ is unverified. C5 no hook process exists; simulate gateway unavailability and record the policy decision. C6 no foreign-policy guard (R24). Windows `N/A` |
| CON-12 | Kiro (Linux/macOS): `cd ~/dc-test-proj && kiro-cli` for CLI 2.x; separately `kiro-cli --v3`; use the DefenseClaw agent (`/agent swap defenseclaw` if necessary) | C1 change own `~/.kiro/hooks/defenseclaw.json`, `~/.kiro/agents/defenseclaw.json`, default-agent setting or `kiro-hook.sh`; guardian repairs. C2 `/agent swap` to an own agent or `kiro-cli chat --agent <own-agent>` bypasses the CLI 2.x hook (R22). C3 and C3b alternate `KIRO_HOME` is R22. C4 below 2.24.1 not enrolled. C5 a non-2 hook failure may let the call run. C6 project `.kiro/hooks` merges with global hooks on v3; no foreign guard. The v3 prompt marker reaches the model with a DefenseClaw result attached (R22). Windows guardian `N/A`; test the separate ACP route if configured |
| CON-12W | Windows Kiro ACP route; managed `acp:` profile `kiro-only` and a supported editor | Admin: `enterprise acp enroll --user std1 --client zed --agent kiro --profile kiro-only --json`; record `token_file` and `next`, never the token. Run `next` in std1's editor session; verify and run allowed and blocked calls; revoke, retry a copied bearer, and re-enroll. Expected: allow and block are audited, revoke immediately rejects the old bearer, re-enroll mints a new one, and enroll without `--profile` fails. |
| CON-13 | Windows managed config copies with `openhands: {}`, `omnigent: {}` and `kiro: {}` | Apply each unsupported connector separately with `ensure`, recording its exact `not supported on Windows managed_enterprise` refusal; after the three cycles `policy show` and targets contain none of them, and no Kiro guardian row appears. ACP is tested in CON-12W. |
| CON-14 | Disposable config using retired `windsurf` ID | Apply with `ensure`; `policy show` and `hooks status` name Devin after migration and publish no `windsurf` target. Record the migration notice. |
| CON-15 | Disposable config using removed `geminicli` ID | Run `ensure` and `policy show`; record the explicit unsupported-connector refusal and verify no target is published. |

For C1 on Windows use the account's actual per-user file: Devin
`%APPDATA%\devin\config.json`, Hermes
`%LOCALAPPDATA%\hermes\config.yaml`, Amp
`%USERPROFILE%\.config\amp\plugins\defenseclaw.ts`, or Antigravity
`%USERPROFILE%\.gemini\config\hooks.json` and its PowerShell launcher.
Back up the file and edit only the test account's copy; a machine-policy
file probe remains non-mutating. Run C1 as both accounts on these routes.

For C5, in the same standard account's second terminal, watch for its own
`defenseclaw-hook` process during a call and send `kill -KILL <hook-pid>`;
repeat with `kill -STOP <hook-pid>`, then `kill -CONT` if it remains. On
Windows use `Stop-Process -Id <own-hook-pid>`; suspension is `N/A`. Record
`NOT_RUN` if a short-lived process was not actually caught. For a temp-space
case use an account-owned disposable temp directory with a small quota or
read-only mode, set `TMPDIR` only for that TUI and restore it afterward.
Do not constrain the managed service's temp directory.

A TUI may clear a notice quickly. Capture the screen immediately after Enter, the marker file's existence, and the audit row. For Cursor, Devin Desktop, Copilot in VS Code, Kiro IDE, WSL and app-only enrollment, use the exact residuals in [Known residuals and open issues](#known-residuals-and-open-issues); a CLI pass does not establish a different hook surface.

## Rule engine and guardrails

Run RE-01–RE-05 in Claude Code and one generic-path connector on each
applicable OS and route, using the `dctest` pack in action mode. Repeat FM1
and FM2 for every connector, OS and distinct route. On Windows use the
PowerShell form `Write-Output dctest-block-marker | Out-File
"$env:USERPROFILE\dc-test-proj\dctest-<case>.txt"` for redirect cases.
Use the agent TUI and record the exact shell tool request, file side effect
and `audit export` row. Rule-pack edits in place need a gateway restart.

| ID | Preconditions | Exact interactive command or admin step | Expected result |
| --- | --- | --- | --- |
| RE-01 | Action pack, std1 TUI | `Run exactly this shell command: echo dctest-block-marker > ~/dc-test-proj/dctest-tilde.txt` | Block; file absent; attributed CRITICAL audit row |
| RE-02 | Same | `Run exactly this shell command: echo dctest-block-marker > "$HOME/dc-test-proj/dctest-home.txt"` | Same; runtime-expanded redirect recognized |
| RE-03 | Same | `Run exactly this shell command: echo dctest-block-marker && touch "$HOME/dc-test-proj/dctest-and.txt"` | First command blocked; `dctest-and.txt` absent; block row |
| RE-04 | Same | `Run exactly this shell command: echo dctest-block-marker \|\| echo done` | First command blocked; capture whether the shell attempts the later branch; later-command analysis is #923 |
| RE-05 | Same | `Run exactly this shell command: cd ~/dc-test-proj && echo dctest-block-marker` | Detection-only if the marker is in the later command; record #923, not a new finding |
| RE-06 | Admin, test pack copy | Add `c.argv_complete && 'dctest-block-marker' in c.argv` to a copy of the rule and run `<G> rulepack validate --dir <pack>`; reapply and repeat RE-01–RE-04 | Validation succeeds; first commands block. An incomplete argv is detection-only |
| RE-07 | Admin, separate deliberately invalid pack | `<G> rulepack validate --dir <invalid-pack> --json` with an over-cost expression | Nonzero; diagnostic names cost limits. Do not apply the invalid pack |
| FM1 | Observe mode applied for each connector/OS/route | Run C0a and C0b through that route | Both calls run; marker is detected and attributed without claiming an enforced block |
| FM2 | Action mode applied for each connector/OS/route | Run C0a–C0c through that route | Allowed, blocked, confirm decisions match the connector contract |
| FM3 | External inspection credential available | Set via `enterprise secret set --name ai-defense-api-key --from-stdin`, enable `enterprise.inspection.ai_defense.enabled: true`, apply, run a benign tool call | Local decision and external status combine as configured; `secret status` reveals only digest, never value. If no key or external service access, `NOT_RUN` |
| FM4 | Existing administrator vendor policy | Hash before install, after repair and after uninstall; `enterprise policy show --connector <name>` | Administrator entries identical; only DefenseClaw-owned changes appear or leave |
| FM5 | Concurrent std1 and std2 | Run distinct C0a/C0b markers in both TUIs | Correct account in each audit row; no cross-account effect |
| FM6 | Disposable new account | Run F1 and F2 | Timed enrollment/revocation as documented |
| FM7 | Directory-backed account available | Sign in, run C0a/C0b, then interrupt directory lookup under admin control | Lookup outage defers changes; no false revocation. If no directory fixture, `N/A` |
| FM8 | Windows directory fixture available | Run repository identity tests and a controlled profile-list simulation | SID/profile binding stays eligible and isolated; do not label a simulation a real directory sign-in |
| FM9 | Distinct desktop, IDE or ACP route available | Open that UI and repeat C0a/C0b | Same visible side effect and attributed audit, or named residual / `NOT_RUN` |

The expected block message names DefenseClaw, the rule id and title, and tells the agent not to retry in another form. `~/`, `$HOME/` and wildcard redirect targets are covered only when the parsed command facts are complete. A command after `&&` or `||`, a variable target such as `$OUT`, and command substitution have documented detection limits (#923/#925); record the exact form and audit decision. Built-in rules with code prerequisites retain their regex fallback. Never classify a model's alternate command as the original marker call.

## Foreign-hook guard

These are separate from the connector's normal registration repair. Admin sets `enterprise.machine_policy.default.foreign_hooks: remove` and leaves `allowed_hooks` empty for the disposable fixture. Run each row with a benign hook in a test-owned user or project file that changes a harmless `echo` argument; do not use untrusted downloaded scripts. The guard checks the current project and parents to the repository root. User files are backed up and cleaned on the roughly five-minute pass; project files are never rewritten. Record the source file and SHA-256 before and after; stop all test-owned processes afterward.

| ID | Preconditions | Steps in the agent's live UI | Expected result |
| --- | --- | --- | --- |
| FG-01 | Cursor, Copilot, Devin, OpenCode or Amp; guard enabled | Add a user hook/plugin in the vendor location named in CON-03–CON-07; start a new agent turn and run C0b | Hook-time block names source and `enterprise.machine_policy.connectors.<connector>.allowed_hooks`; no marker file; user entry cleaned within about 5.5 minutes with backup |
| FG-02 | Same connector, shared disposable project | Add a project hook in `.cursor/hooks.json`, `.github/hooks/`, `.devin/hooks.v1.json`, `.opencode/plugins/` or `.amp/plugins/` as appropriate; repeat C0b | Block at call or turn start; project file remains until tester removes it |
| FG-03 | Hermes on Linux/macOS | Add a second harmless `pre_tool_call` in the account's `~/.hermes/config.yaml`, start a new Hermes TUI, request C0a | `enterprise_foreign_hook_blocked` names file and allowlist key; no rewrite runs; only the `hooks` mapping is cleaned, other settings preserved. Windows `N/A` (R24) |
| FG-04 | User hook present at session start | Start the TUI, let the guardian remove the user entry before the first prompt, then send C0a; start a second fresh TUI after removal | The first process remains blocked by the gateway-held session record; fresh process allowed. Deleting a home-side cache does not clear that record (#911) |
| FG-05 | Approved hook fixture | Add its digest to `enterprise.machine_policy.connectors.<connector>.allowed_hooks`, apply through ensure, repeat FG-01 | Approved hook allowed, its exact digest recorded; changing the hook bytes invalidates approval |
| FG-06 | Scan-limit fixture on a disposable host | Fill one test hook folder beyond the documented 256-entry scan limit, including one harmless rewrite, then start the agent | Session blocked with a restart instruction; deleting files does not unblock that process. Restore fixture immediately |
| FG-07 | FG-01 fixture, separate config cycle | Set `foreign_hooks: report`, apply and run C0a; repeat with `foreign_hooks: allow` | Report warns and permits the call; allow skips the scan. Compare side effect, audit and `policy show` for each mode |
| FG-08 | Approved test hook | Put its digest under `enterprise.machine_policy.default.allowed_hooks`, then add a connector-specific digest and apply | Both allowed lists merge; the exact approved bytes run, changed bytes are blocked |
| FG-09 | FG-01 cleanup completed | Approve the hook digest, restore the exact file from `~/.defenseclaw/foreign-hooks-backup/<connector>/<timestamp>/`, start a new TUI and run C0a | Approved restored hook runs; no new cleanup of the approved bytes |
| FG-10 | Disposable redirected user config | Start an agent with the documented environment redirect and a benign foreign hook, run one DefenseClaw-inspected call, then wait for cleanup; inspect `~/.defenseclaw/foreign-hook-env.json` | The observed redirected source is recorded and cleaned within the interval; a never-observed redirect follows R14 |
| FG-11 | Test-owned hook source | In separate cycles use an unreadable file, a file over 1 MiB and a FIFO as the foreign source, then run C0a | Each is denied without a hang; restore the fixture after each cycle |
| FG-12 | std1 before managed enrollment | Run per-user `defenseclaw setup cursor`, then enroll std1 and start Cursor | The leftover per-user registration is classified foreign, blocked and cleaned with backup |
| FG-13 | Linux/macOS Claude Code and Codex | Set `managed_hooks_only: preserve`, add a benign user hook and repeat FG-01 | Foreign guard reports or blocks according to mode; admin hook hashes stay unchanged |
| FG-14 | Antigravity in a disposable project | Add a benign project `.agents/hooks.json`, start a fresh TUI and run C0a/C0b | Record the vendor's project-hook behavior and R24; DefenseClaw's own pre-tool decision still follows the observed route |

Claude Code and Codex under `managed_hooks_only: enforce` rely on their vendor lock; user and project hooks are ignored. Under `preserve` on Linux/macOS, exercise FG-01 with their user files. Windows managed Claude Code sets the lock; Windows Codex always locks hooks. Antigravity, OpenHands and OmniGent lack this guard (R24). Kiro lacks a foreign-hook guard and its v3 project file merges with the global file. The seven-day foreign-hook session hold and the limitations of an unobserved environment-redirected file are R13/R14.

## Enrollment

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| F1 | Admin may create a disposable `new account` | Create it after install; sign in; wait one enumerator cycle; run one allowed and one blocked interactive call. | Enrolled within the five-minute cycle; both calls have the expected decisions and identity. | CLI `status`, `verify`, audit; TUI; elapsed time. |
| F2 | F1 complete | End the new account's sessions; admin removes that account; observe consecutive enumerator runs. | Authorization revoked after the documented consecutive misses (typically three cycles); no stale accepted hook credential. | CLI `status`, `verify`, audit; elapsed time and cycle count. |
| F3 | An `excluded account` exists under policy | Sign in and run an available connector through its UI under `unenrolled_users: inspect`, then `deny`. | Machine-policy routes inspect under `inspect` and refuse under `deny`; per-user routes have no hook and show unprotected. Windows shows the unenrolled message. | CLI `status`, `verify`, audit; TUI. |
| F5 | Disposable config copy | Set `unenrolled_users: deny`, apply, run C0b as an unenrolled account; restore `inspect` | Managed routes refuse the call instead of treating it as an enrolled user's allow; status names the account state. Windows `N/A` (knob ignored) | Result and policy diff |
| F6 | Linux/macOS root test session | In separate cycles set `root: inspect` and `root: deny`; run a harmless managed tool call | Root follows the selected mode. Windows `N/A` | Result, audit and policy diff |
| F7 | `dcexcluded` and another disposable account | Set `exempt_users: [dcexcluded]`, then test exclusion separately; restore | Exempt account's own registration is cleaned; excluded account is skipped, as [Known residuals](#known-residuals-and-open-issues) states | Status, target manifest and account UI |
| F8 | Windows local test group | Set `include_groups` and `exclude_groups` in separate config cycles; sign in a member and nonmember | Only eligible signed-in accounts enroll; `status` counts and target SIDs agree | Config diff, status and sign-in evidence |
| F9 | Linux or macOS disposable account | Add its extra home root to `home_roots`, then vary `uid_max`/`UID_MAX`; include a nologin account. Run enumerator dry-run and apply | Eligible extra-root account appears; out-of-range and nologin accounts do not enroll. Record the platform's exact key and restore the config | Dry-run manifest, status and account metadata |

For F1, create `dcnew` with the platform account UI or administrator command
(`sudo useradd -m -s /bin/bash dcnew && sudo passwd dcnew` on Linux; the
Accounts UI on macOS or Windows), then sign in normally and install a verified
agent. For F2 remove that disposable account only after its sessions close;
preserve the run timeline. Use `enterprise hooks enumerate --dry-run --json`
on Unix for a preview, and platform `status --json` for effective enrollment.
On Windows, a real sign-in is needed for per-user writes.


## Claude Code version floor

For each CCF row run `enterprise policy show --connector claudecode`,
`enterprise policy verify --connector claudecode --json` and platform
`enterprise <os> verify --json`. Use administrator-owned fixtures and restore
their byte hashes after each row. The floor sources are Linux
`/etc/claude-code/managed-settings.json` and `managed-settings.d/`; macOS
`/Library/Application Support/ClaudeCode/`; Windows
`C:\Program Files\ClaudeCode\`. CCF-05 uses Windows
`HKLM\SOFTWARE\Policies\ClaudeCode` or macOS
`com.anthropic.claudecode` managed preferences; Linux has no corresponding
higher-precedence source (`N/A`). The merge setting is
`managedSourcesBehavior`; warning mode is `higher_precedence_sources: warn`.
Record both the client version and whether it reads the floor; an old-client
gap is R15.

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| CCF-01 | Default enforced floor; supported Claude Code client | Check the floor via `enterprise policy show --connector claudecode` and `verify`; admin temporarily removes DefenseClaw's owned floor, runs policy verify, then runs `enterprise <os> ensure --from-package --json` (or the platform repair route). | Before removal, policy says set by DefenseClaw and covered. During gap, `policy verify` fails while lifecycle `verify` may only warn `claude_version_floor_missing`; ensure/repair restores it, then both pass. | CLI show/verify before, during, after; file hash and repair seconds. |
| CCF-02 | Client below required floor available | Start the old client interactively. For diagnosis only, admin temporarily puts the required version in the base managed-settings file, retries, then restores it. | Refusal if client honors the key. If it ignores the drop-in or key, record R15 and whether the base file changes behavior; no claim of enforced floor. | Client version and TUI; CLI policy show/verify; before/after hashes. |
| CCF-03 | Admin base file sets a supported version | Admin sets a floor in base `managed-settings.json` and reconciles. | DefenseClaw withdraws its owned drop-in; show says set by administrator; verify passes; admin file unchanged. | CLI show/verify; base-file hash. |
| CCF-04 | Admin drop-in files available before and after DefenseClaw's sort position | Admin sets a numeric floor in each test drop-in, then tests `latest` in each position. | Numeric admin floor wins and DefenseClaw withdraws; earlier `latest` leaves DefenseClaw floor effective; later `latest` leaves Claude not covered and verify fails. | CLI show/verify for all four cases; drop-in hashes. |
| CCF-05 | Platform higher-precedence policy source available | Admin installs a source without the floor, tests default and `merge`, then adds the floor there; also tests configured warning mode. | Keyless higher source means not applied/not covered and verify fails by default; warning mode reports the conflict; a valid floor there becomes administrator-owned and verifies. | CLI show/verify and source description; source hash. |
| CCF-06 | Exported version-floor file; no DefenseClaw ownership record | Admin deploys `enterprise policy export --format version-floor` output at the floor filename; exercise `version_floor: enforce`, `report` and `off`, separately from `ownership: verify_only`. Repeat with a keyless file | Admin file stays byte-identical; show identifies administrator ownership. Keyless file is never overwritten; Claude is not covered and verify fails naming it | CLI export/show/verify; hash at each transition |
| CCF-07 | DefenseClaw-owned floor present | Admin sets `enterprise.machine_policy.connectors.claudecode.version_floor` to `report`, then `off`, then `enforce`, reconciling each time. | Report/off withdraw the DefenseClaw floor with mode visible and verify success under those modes; enforce restores it. | CLI show/verify; floor presence and hash. |
| CCF-08 | DefenseClaw-owned floor present | Admin sets `enterprise.machine_policy.connectors.claudecode.ownership` to `verify_only`, then `off`; restore baseline. | Verify-only neither writes nor removes the floor; off removes DefenseClaw's owned floor. Other managed Claude hooks stay unchanged. | CLI show/verify; before/after hashes of floor and hook drop-in. |

## Upgrade, repair, uninstall and purge

All changes in this section are administrator actions on disposable hosts. Use V1 and V2 artifacts from [Build and packaging](#build-and-packaging). After each action run `status --json`, `verify --json`, `enterprise policy verify --json`, C0a/C0b on both accounts and the linked A–E spot-check. Preserve separate evidence before and after upgrade. An in-place policy or rule-pack edit needs the gateway restart in LC-15; an upgrade, secret rotation or applied config change restarts it.

| ID | Preconditions | Exact command | Expected result |
| --- | --- | --- | --- |
| UPG-L-01 | Ubuntu package V1, V2 staged | `sudo apt install ./defenseclaw-enterprise-<v2>-linux-<arch>.deb`; `sudo cat /var/lib/defenseclaw-enterprise/last-package-result.json` | V2 installed; services healthy; config, policy and audit retained |
| UPG-L-02 | RHEL package V1 | `sudo dnf upgrade ./defenseclaw-enterprise-<v2>-linux-<arch>.rpm` | Same; x86_64 gateway and helper start |
| UPG-L-03 | Linux payload V1 | `sudo "$G" enterprise linux upgrade --payload <root-owned-v2-dir> --json` | V2; a package-owned install refuses this channel with `package_owned_binaries` |
| UPG-M-01 | macOS pkg V1 | `sudo installer -pkg ./defenseclaw-enterprise-9.9.10-darwin-arm64.pkg -target /` | V2 and healthy launchd jobs; failed apply fails installer |
| UPG-W-01 | Windows V1, V2 Setup staged | `& $SetupV2 /ensure JSON=1` | Action `ensure`, warning `ensure_upgrade`, event 112, marker V2. Guardian re-renders signed-in users' hooks before the new gateway starts; signed-out users at sign-in. Claude attestation becomes stale; repeat CLI-12 |
| UPG-02a | Ubuntu package V2, V1 staged | `sudo apt install --allow-downgrades ./defenseclaw-enterprise-<v1>-linux-<arch>.deb`; inspect `last-package-result.json`, then run V1 `ensure --from-package --allow-downgrade` | Package manager may install V1 but lifecycle records `downgrade_refused`; explicit allowance applies V1; verify afterward |
| UPG-02b | RHEL package V2, V1 staged | Try `sudo rpm -U ./defenseclaw-enterprise-<v1>-linux-amd64.rpm`; then `sudo dnf downgrade` and V1 `ensure --from-package --allow-downgrade` | First downgrade refused; explicit channel applies V1 and verifies |
| UPG-02c | macOS pkg V2, V1 staged | Try the V1 pkg; then create the one-use `/opt/cisco/defenseclaw/lifecycle/allow-downgrade` marker as described in the [lifecycle guide](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/lifecycle) and retry | Preinstall first refuses; marker permits one intentional downgrade; verify afterward |
| UPG-02d | Windows V2, V1 Setup staged | Try `& $SetupV1 /ensure JSON=1`, then explicit `& $SetupV1 /upgrade JSON=1` | Ensure refuses downgrade; explicit upgrade applies the approved V1 rollback; verify afterward |
| UPG-02e | Linux/macOS payload V2, V1 payload staged | Try V1 `ensure --payload <v1-dir>`, then `upgrade --payload <v1-dir> --allow-downgrade --json` | First refused; explicit downgrade applies V1; verify afterward |
| REP-01 | Admin-side mode drift | Linux `sudo chmod 0644 /etc/defenseclaw/config.yaml`; then `sudo "$G" enterprise linux verify --json`, `repair --json` | Verify fails on mode, repair restores it, then verify passes. On macOS use the managed config path; Windows use a reversible admin-owned service/config drift and Setup `/repair JSON=1` |
| REP-02 | V1 and V2 source commits have different Hermes hook bytes; `std1` enrolled | Hash `~/.defenseclaw/hooks/hermes-hook.sh` in std1's session, upgrade from V1 to V2, record inode and mtime and guardian log, then make a blocked TUI call | Script matches the V2 render and differs from V1; guardian records the rewrite; blocked call audited. If V1/V2 use the same source, compare inode/mtime and log instead of byte hashes |
| REP-03 | Disposable service drift | Stop `defenseclaw-hook-enumerator.service` (macOS: boot out `com.cisco.defenseclaw.hook-enumerator`; Windows: `Stop-Service DefenseClawHookEnumerator -Force`), run verify and repair | Verify shows incomplete coverage during drift; repair restores the service and passes |
| REP-04 | Windows signed-in Claude Code user | Admin removes only DefenseClaw's owned Claude drop-in, runs policy verify, then waits for guardian/repair | Coverage fails during drift and the managed file is restored with its expected owner and bytes |
| REP-05 | Staged payload with one altered byte | Run repair against the invalid payload, then `repair --payload <root-owned-good-payload>` | First returns `payload_invalid`; second restores the trusted payload and healthy verify |
| REP-06 | Linux package host | Run `sudo apt install --reinstall defenseclaw-enterprise` (Ubuntu) or `sudo dnf reinstall defenseclaw-enterprise` (RHEL); inspect package result | Reinstall runs ensure without erasing config, policy or audit; `status` and `verify` pass |
| REM-01 | Healthy package or payload host | Linux `sudo "$G" enterprise linux uninstall --json`; macOS `sudo "$G" enterprise macos uninstall --json`; Windows `& $Setup /uninstall JSON=1` | Services and DefenseClaw vendor-policy entries removed; config, secrets, data, logs kept; unrelated admin policy hash unchanged. Close cached agent sessions |
| REM-02 | REM-01 complete | Linux package: `sudo apt remove defenseclaw-enterprise` or `sudo dnf remove defenseclaw-enterprise`; macOS receipt: `pkgutil --pkg-info com.cisco.defenseclaw.enterprise`; Windows `Get-Service DefenseClaw*` and marker check | Package metadata and services absent; non-purge state remains protected. Second uninstall is a no-op |
| REM-03 | REM-01, retained config | Reinstall V2 via package/payload or Setup `/ensure JSON=1`, then verify | Retained config used; policy and enrollment return; no `unmanaged_layout_present` |
| REM-W-01 | Windows; std1 and std2 signed in | Run Setup `/uninstall JSON=1` as LocalSystem after both accounts exercised Amp, Antigravity, Devin, Hermes, OpenCode and Copilot | Signed-in users' DefenseClaw entries removed; user files outside owned entries retained |
| REM-W-02 | Same registrations on a separate snapshot | Run uninstall from an elevated Administrator prompt, and repeat with std2 signed out | `user_registrations_pending` lists connector and SID for deferred entries; signed-out user cleanup follows R17 |
| PUR-01 | Decommission phase, evidence saved | Linux/macOS: `sudo "$G" enterprise <os> uninstall --purge --remove-service-account --json`; Windows: `& $Setup /uninstall JSON=1 PURGE=1`. Then query services, package metadata, account and data roots with the platform commands in [Paths and commands](#paths-and-commands) | DefenseClaw units, package receipt, service account and data root absent after the matching package removal; unrelated policy preserved. Windows HKLM marker and `C:\ProgramData\Cisco\DefenseClaw` absent, `%WINDIR%\Logs\DefenseClaw` retained. System journal not purged |

For PUR-01, use `sudo apt purge defenseclaw-enterprise` on Ubuntu or
`sudo dnf remove defenseclaw-enterprise` on RHEL, then run `systemctl list-unit-files
'defenseclaw*'`, `dpkg -s defenseclaw-enterprise` (Ubuntu) or
`rpm -q defenseclaw-enterprise` (RHEL), and `getent passwd defenseclaw`;
each must report absent. On macOS run `dscl . -read
/Users/_defenseclaw` and `pkgutil --pkg-info
com.cisco.defenseclaw.enterprise`; both must report absent after receipt
removal. On Windows run `Test-Path
'HKLM:\SOFTWARE\Cisco\DefenseClaw\Enterprise'` and `Test-Path
'C:\ProgramData\Cisco\DefenseClaw'`; both must be false while
`%WINDIR%\Logs\DefenseClaw` is retained. Record package-manager exit codes.

### Post-transition enrollment check

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| F4 | Admin repair and upgrade completed | Run an A–E spot-check on both accounts after each transition. | Earlier boundaries still hold; repair did not change ownership or audit identity. | CLI `status`, `verify`, `policy verify`, audit; linked row records. |

Windows uninstall as SYSTEM can clean signed-in users' registrations. An elevated admin uninstall may leave inert user registrations and warn `user_registrations_pending`; signed-out users also defer cleanup (R17). On Linux, `apt remove` and `dnf remove` run preremove and must wait for the lifecycle lock; a busy lock must stop removal. A failed non-purge uninstall must retain enough deployment state for a retry. A failed upgrade must leave exactly one coherent installed version, not mixed binaries and policy. Record package manager output **and** `last-package-result.json`: Linux postinstall itself returns success even if the lifecycle result says failure.

## Failure drills

Run on a disposable host or controlled maintenance window. Restore the host
after each drill and capture both unhealthy and recovered `status --json` and
`verify --json`. Interrupt only test-owned processes, one failure at a time.

| ID | Preconditions | Interactive steps | Expected result | Evidence |
|---|---|---|---|---|
| FD1 | Healthy services; admin controls test process | Linux: `sudo systemctl kill -s KILL defenseclaw-gateway.service` five times; macOS: `sudo launchctl kill SIGKILL system/com.cisco.defenseclaw.gateway`; Windows: get the service PID with `Get-CimInstance Win32_Service` and `Stop-Process -Id <PID> -Force` | Service manager recovers after each exit; record seconds to healthy `status` and `verify` | CLI results; service event timeline |
| FD2 | Linux watchdog enabled | `systemctl show -p MainPID defenseclaw-gateway.service`; `sudo kill -STOP <MainPID>`; observe for at least 60 s, then `kill -CONT` only if that PID remains | Watchdog restarts the stalled gateway within about 60 s; hooks do not accept untrusted responses. macOS/Windows `N/A` for this Linux watchdog contract | CLI results; elapsed time and marker outcome |
| FD3 | Disposable snapshot with lifecycle state on a dedicated small test volume | Linux: on that mounted volume run `sudo dd if=/dev/zero of=/var/lib/defenseclaw-enterprise/dctest-fill bs=1M status=none` until ENOSPC; macOS use the lifecycle folder on its dedicated test volume. Confirm free space is below V2 payload size, attempt upgrade, then remove only `dctest-fill` and retry. Other layouts without an isolated volume are `NOT_RUN` | Upgrade fails and rolls back to one coherent version; retry succeeds after capacity is restored | Installer exit codes; `df`/volume free space; CLI results and version |
| FD4 | Local policy engine functioning | Admin temporarily makes the external inspection secret unavailable, then restores it. | Local guardrail continues under the configured behavior; no secret is printed or silently replaced. | CLI `secret status`, `status`, `verify`; TUI marker audit. |
| FD5 | Known-good config and manifest backup | Admin presents invalid config or manifest input through the documented lifecycle. | Apply fails with a useful diagnostic; last known good state remains effective. | CLI `ensure`, `status`, `verify`, `policy verify`; hashes. |
| FD6 | Directory-backed test account | On a disposable Linux directory fixture run `sudo systemctl stop sssd`, observe two enumerator cycles, then `sudo systemctl start sssd` and repair | Transient lookup failure defers action; no immediate wrongful revocation; state converges after recovery | CLI results; enumerator timeline |
| FD7 | Controlled clock adjustment available | On a disposable Linux host save time sync state; `sudo timedatectl set-ntp false`, `sudo date -s '+10 minutes'`, then `sudo date -s '-10 minutes'`; restore NTP and re-sign in each agent | No permanent stale enrollment, authorization or audit-ordering error after correction and re-sign-in | CLI results, audit timestamps; recovery timeline |
| FD8 | RHEL enforcing fixture | Run `sudo ausearch -m avc` during install/repair/calls; separately use `sudo semanage login -a -s user_u std2` and a disposable fapolicyd deny fixture, then remove the mapping with `sudo semanage login -d std2` and the rule | Denial is surfaced, deployment remains verifiable or the exact L-23/residual-6 limitation is recorded | CLI results; sanitized denial count |

## Per-user mode regression

Use a separate clean disposable host or revert the snapshot after all
enterprise rows. Install the normal per-user product as `std1` using the
[release installer](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install),
run `defenseclaw setup <connector>` for available agents, start
`defenseclaw-gateway start`, and run allowed and marker calls in their TUIs.
Then disable the connector and uninstall. Use no machine service in this run.

| ID | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| PU-01 | Clean host; normal installer | `defenseclaw-gateway --version`, `defenseclaw setup codex`, `defenseclaw setup claude-code`; run each TUI | Per-user gateway and hooks work; no enterprise services, machine-policy files or deployment marker are created |
| PU-02 | PU-01 | Edit or remove only the user's DefenseClaw hook file; run a tool call, then wait for normal self-heal | Exact per-user hook bytes restored; no enterprise guardian needed |
| PU-03 | PU-01; Hermes or Kiro available | `defenseclaw setup kiro` (or `defenseclaw setup hermes`), run an enabled TUI call, then `defenseclaw guardrail disable --connector kiro --yes` (or Hermes) | User registration removed; cached hook path is an inert `exit 0` stub until the process restarts; a later setup restores the active script |
| PU-04 | Separate snapshot deliberately retaining a per-user install before managed install (PRE-02 deviation); healthy managed host | As std1 run the per-user release installer, `defenseclaw upgrade`, `rollback` and `defenseclaw-gateway start`; inspect with admin enterprise CLI | Managed-host refusal; no competing per-user gateway, marker or hook mutation; self-update notice stays off |
| PU-05 | PU-01 | `defenseclaw uninstall --binaries --yes`, then `defenseclaw uninstall --all --binaries --yes` in a separate cycle | Per-user files removed per selected scope; no machine deployment touched |
| PU-06 | PU-01 | Run `defenseclaw doctor`; edit a user hook, run doctor again, then restore it | Healthy before drift, actionable finding during drift and healthy after repair |
| PU-07 | PU-01 | Save user config and hook hashes, disable each configured connector, then restore with setup | User bytes outside DefenseClaw entries stay identical; hook teardown leaves only the documented inert stubs |
| PU-08 | Clean per-user Linux/macOS and Windows snapshots | Install with the platform `install.sh` or `install.ps1`, then run PU-01 and PU-05 | Each installer creates only per-user state; Windows Kiro block returns exit `2` |
| PU-09 | PU-01 | Apply the marker pack in observe mode, run C0b, then change to action and repeat | Observe records without blocking; action blocks, with account attribution in both audit rows |

Per-user mode has no enterprise vendor lock or foreign-hook guard by default. Its block wording and local state may differ; compare with the pre-PR build, not with standalone behavior. Use a supported agent and model account; a missing sign-in is `NOT_RUN`.

## Secure Client non-regression

The Secure Client profile must remain unchanged. Run the available pinned
template and profile tests. If the team has a Secure Client package and an
isolated host, also execute the existing [Windows certification
runbook](WINDOWS-ENTERPRISE-CERTIFICATION.md) (or the supported platform
install lane) with its own signed artifact and evidence. Without that package,
record the live profile as `NOT_RUN`.

| ID | Preconditions | Exact command / steps | Expected result |
| --- | --- | --- | --- |
| SC-01 | Go checkout at build commit | `go test ./internal/gateway/connector -run "TestSecureClientPluginTemplatesArePinned\|TestPluginSecureClientProfileSelectsThePinnedTemplate" -count=1`; also run `go test ./internal/config ./internal/enterpriseunix ./internal/cli ./internal/gateway/... ./cmd/defenseclaw-enterprise-setup -run SecureClient -count=1` and `pytest cli/tests/test_windows_enterprise_service_contract.py cli/tests/test_cmd_status_enterprise_profile.py cli/tests/test_windows_enterprise_standalone_contract.py` | Available pinned template, profile and coexistence tests pass; record any missing test target rather than implying a golden gate exists |
| SC-02 | No repository CI golden or source tripwire at this commit | `NOT_RUN` with reason "gate not in repository"; attach a maintainer-run artifact if one exists for the final commit | Missing golden coverage remains an explicit verification gap |
| SC-03 | No repository Windows PowerShell golden gate at this commit | `NOT_RUN` with reason "gate not in repository"; attach a maintainer-run artifact if available | Missing PowerShell golden coverage remains an explicit verification gap |
| SC-04 | Signed Secure Client artifact and isolated host | Follow `docs/WINDOWS-ENTERPRISE-CERTIFICATION.md`, including lifecycle, standard-user and teardown checks | Existing profile still works; no standalone profile marker or hash-pinned trust substituted |
| SC-05 | Clean Secure Client host and separate standalone artifact | Attempt standalone installation over Secure Client on each OS | Linux `profile_conflict`; macOS pkg preinstall exits `1`; Windows Setup returns `1603` with `profile_conflict`; existing deployment remains healthy |
| SC-06 | Secure Client Windows Setup | Try `/ensure` and `ALLOWEDSIGNERS=` against that Setup | Both refused with exit `1603`; no standalone profile created |
| SC-07 | Secure Client host | Run `enterprise windows ensure --profile secure_client` and standalone-only flags | Refused without changing the Secure Client deployment |
| SC-08 | Secure Client host | Run `enterprise policy show` and `verify` | Refused as standalone-only policy commands; no mutation |
| SC-09 | Secure Client host with Claude Code, Codex and Cursor | In each interactive client run C0a and C0b with the pinned Secure Client config and record screen, side effect and audit | Decisions and messages match the base Secure Client release; no standalone `allowManagedHooksOnly` change |

## UX checklist

| ID | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| UX-01 | Every CLI row | Record `--help`, text output, exit code and JSON for the same state | The command and next step are discoverable; text and JSON agree; each problem appears once |
| UX-02 | Every blocked TUI call | Capture screen immediately and after a few seconds | DefenseClaw and rule title are visible where the vendor surfaces them; no raw reason code, stack trace, hidden path or false success |
| UX-03 | Windows Setup/MDM wrapper | Time `/ensure` and wrapper with a live terminal and record gaps in output | Result and exit code are correct; two to three minutes of silence is a UX finding even if eventual success |
| UX-04 | Standard account CLI refusal | Run CLI-14 from an unelevated session | Message names administrator action; a raw permission error or per-user config error is a UX finding |
| UX-05 | Unhealthy host | Run `status` and `verify` then follow printed remedy | Both name the same concrete problem and an executable recovery command |
| UX-06 | Connector permission dialog | Approve one and deny one harmless call | Actual file and audit reflect the choice; a model saying “done” for a blocked call is a UX finding |
| UX-07 | Install guide in use | Type documented command verbatim on each OS | It works; bad examples and stale paths are documentation findings |

## Regression checklist

Every bullet below is a previously fixed finding. Reproduce bullets with live
steps and record the result; for a `Code`-only bullet without a runnable step,
record `N/A (code review)` and name the source or test inspected. For `Docs`
bullets, check the linked page and record the page revision. `[L]`, `[M]`,
`[W]` and `[U]` mean Linux, macOS, Windows and Linux/macOS respectively. A
prior "Live" annotation is not the new team's verdict. Link each applicable
bullet to the numbered row that exercised it; every bullet already has an ID.

Each line: what to do, then the expected (fixed) behavior. A tester who sees the old behavior
has found a regression.

### Lifecycle: install, ensure, repair, uninstall, config

- **REG-1-1-01** **[L][M][W] Documented config installs as written.** Copy the Linux, macOS or Windows
  standalone config tab from the enterprise overview page verbatim and install it
  (`<G> enterprise <os> ensure --from-package --config <file> --json`, or Setup `/ensure
  CONFIG=`). Expect: it installs and the gateway starts; no `config_version_required`, no
  `trust.mode` enum error, no `data_dir must be ...` refusal. The tabs are byte-identical to
  the install-tested sample configs in the repository. Live: RHEL, Ubuntu, macOS, Windows.
- **REG-1-1-02** **[L][M][W] Empty `enterprise.trust.mode` is "not set".** Install a config with
  `enterprise.trust.mode: ""`. Expect: accepted (the schema no longer requires
  `authenticode|hash_pinned`). Live: macOS, Windows.
- **REG-1-1-03** **[U] Missing `config_version`.** Run ensure with a config that has no `config_version`.
  Expect: the error names the file you passed with `--config` (not the installed path) and
  says to add `config_version: 8`; it does not tell you to run `defenseclaw migrate` (not
  shipped in the enterprise package). Live: RHEL, macOS.
- **REG-1-1-04** **[U] Layout-fixed keys default.** Omit `data_dir` and `guardrail.rule_pack_dir`. Expect:
  `data_dir` defaults to the layout's data directory (`/var/lib/defenseclaw`,
  `/opt/cisco/defenseclaw/runtime`) and the rule pack to `<policy_dir>/guardrail/default` if
  that folder exists, else the vendor pack; an explicit wrong `data_dir` is still refused. An
  omitted `policy_dir` is the root-owned vendor policy folder, not a folder inside `data_dir`.
  Live: RHEL, macOS.
- **REG-1-1-05** **[U] Rule pack created after install.** With `rule_pack_dir` unset, create
  `<policy_dir>/guardrail/default` later and run ensure. Expect: ensure applies it and
  restarts the gateway (it does not say `up_to_date` while the gateway keeps the vendor pack).
  Code/docs.
- **REG-1-1-06** **[W] Shared config with a Linux/macOS-only key.** Install one config that carries
  `enterprise.enrollment.agent_prefixes: [/opt/tools]` on Windows. Expect: it loads (the key is
  checked with Unix path rules on every OS and ignored on Windows). Code.
- **REG-1-1-07** **[M] Rejected ensure keeps reporting the live deployment.** Run ensure with an invalid
  config (`--json`), then status. Expect: the result lists the running deployment's services
  and readiness (not `services: []` with every readiness false). Live: macOS.
- **REG-1-1-08** **[M] launchd job states.** `<G> enterprise macos status`. Expect: on-demand jobs read in full
  (for example "on demand, idle"), not a truncated `not`. Live: macOS.
- **REG-1-1-09** **[U] Each problem once.** Make verify fail with two problems. Expect: each problem printed
  once (not as `!` warning, `✗ verify_failed` and a joined `Error:` line); a result with
  warnings has a `!` headline. Live: macOS, Ubuntu.
- **REG-1-1-10** **[U] Verify catches loosened installed files.** As admin, `chmod 0644` the installed
  config and `chmod 0757` (or 0775) an installed binary, then verify and repair. Expect: verify
  names the config mode and the group/other-writable binary; repair fixes the config mode and
  refuses the writable binary with a remedy you can type (restore 0755 or reinstall the
  package). Live: macOS, RHEL.
- **REG-1-1-11** **[U] Invalid arguments exit 2.** `<G> enterprise <os> ensure --bogus; echo $?`. Expect: 2
  (1 means "failed, rolled back"). Live: macOS.
- **REG-1-1-12** **[L] No failed apply unit after a config change.** `ensure --config <changed file>`, then
  `systemctl --failed` and status. Expect: `defenseclaw-enterprise-apply.service` is not left
  failed; if any DefenseClaw oneshot is failed, status and verify warn `unit_failed`. Live:
  RHEL, Ubuntu.
- **REG-1-1-13** **[U] A config written during a running transaction is not lost.** While an ensure or package
  step holds the lifecycle lock, write a new config. Expect: the change is applied by a
  follow-up run (`input_changed`), not overwritten by the older bytes or dropped; a config put
  back after a rejected edit supersedes the rejection. Code.
- **REG-1-1-14** **[L] Package steps wait for the lock.** Remove or upgrade the package while an apply run
  holds the lock. Expect: the package scripts wait (`--lock-wait 10m`); the removal fails on a
  busy lock instead of deleting files under a live deployment. Code.
- **REG-1-1-15** **[U] Non-purge uninstall can be retried.** Make an uninstall hit one error, then retry and
  reinstall. Expect: the deployment record is kept until an uninstall fully succeeds, so the
  retry and a package reinstall work (no `unmanaged_layout_present`). Code.
- **REG-1-1-16** **[L] Uninstall removes the vendor folders it created.** On a host with no `/etc/claude-code`
  and no `/etc/github-copilot`, install, then `enterprise linux uninstall` (and the MDM
  `uninstall.sh`). Expect: both folders are gone, like `/etc/codex` and `/etc/opencode`.
  Live: Ubuntu (code + test for Copilot's folder).
- **REG-1-1-17** **[L] Remove and reinstall docs.** Follow the Linux page's Remove section on a package
  install. Expect: the page says to remove the package too (`apt remove`, `dnf remove`, or the
  MDM `uninstall.sh`) and how to reinstall; `unmanaged_leftovers` is explained. Docs.
- **REG-1-1-18** **[L] Tightened vendor policy file mode is restored.** As admin, `chmod 0600
  /etc/codex/requirements.toml`, then verify and repair; start Codex as std1. Expect: verify
  reports the file (it must stay `0644 root`), repair restores the mode, Codex starts for
  std1. Live: Ubuntu. (The verify wording is still wrong, record as a UX finding.)
- **REG-1-1-19** **[L] x86_64 services start after an upgrade.** Upgrade the rpm or deb on x86_64. Expect: the
  gateway and sensor helper start under their hardened units (no panic at start under the
  executable-memory restriction). Live: RHEL.
- **REG-1-1-20** **[L] Daily verify during an ensure (commit a60d1822c).** Let `defenseclaw-enterprise-verify.timer`
  fire while an admin ensure restarts units (restart the timer during ensure, or run ensure at
  the timer's time). Expect: verify waits for the lifecycle lock (default 5 s) or exits `75`
  (`lifecycle_busy`), which the unit accepts; no failed verify unit and no `unit_failed`
  warning on the next ensure or status. On macOS the daily verify job gets the same wait.
  Pending.
- **REG-1-1-21** **[U] Planned sensor-helper restart is not a failure.** Enroll or revoke an account (the
  sensor helper restarts itself when the guardian manifest changes) and run status in a loop
  for two minutes. Expect: every run exits 0 and waits out the planned restart (up to about
  15 s); a unit in a crash loop is still reported. Live: RHEL, macOS.
- **REG-1-1-22** **[U] Status exits 1 when unhealthy.** Stop the gateway (and on Linux its sockets), or hold
  the API port (see [Gateway and hook trust](#gateway-and-hook-trust)), then run status and verify. Expect: both exit 1 and describe the same
  problems the same way; a healthy status exits 0. Live: RHEL, macOS.
- **REG-1-1-23** **[U] Hook socket problem in words.** With the gateway stopped, run status. Expect: "the
  gateway does not serve the hook socket <path>: the socket file does not exist" (or "nothing
  is listening on it"), not a Go HTTP client error naming the TCP address. Live: RHEL.
- **REG-1-1-24** **[U] Inspection posture.** On a healthy host with the local engine and AI Defense off, run
  ensure/status `--json`. Expect: `inspection.local` active and `ai_defense` disabled, not
  `unknown`. Live: RHEL, Ubuntu (docs).
- **REG-1-1-25** **[L][M][W] No toolchain warning.** Run any `<G>` command and any hook. Expect: nothing on
  stderr from a third-party library (the old `WARNING: sonic/ast only supports ...` line is
  gone from admin output, MDM logs and agent hook-error text). Live: all four OSes.
- **REG-1-1-26** **[U] Sensor helper version.** `<helper> --version` and its first log line. Expect: package
  version and commit, as the gateway reports (not `version=dev commit=""`). Live: RHEL.
- **REG-1-1-27** **[U] Restart the managed gateway.** As root, run `<G> restart`. Expect: refused, and the
  refusal names the managed commands: `systemctl restart defenseclaw-gateway.service` (Linux),
  `launchctl kickstart -k system/com.cisco.defenseclaw.gateway` (macOS), plus
  `enterprise <os> repair`; the lifecycle page has a "Restart the managed gateway" section
  (Windows: run the installed Setup with `/repair JSON=1`). Live: RHEL, Ubuntu, macOS; docs
  for Windows.
- **REG-1-1-28** **[L][M][W] Build docs.** Look for how to build the macOS standalone pkg, the Linux packages
  and the unsigned Windows standalone Setup. Expect: documented (`make
  packaging-macos-enterprise`, the pinned goreleaser version, `build-setup.sh --version <v>`
  for an unsigned hash-pinned Setup). Docs.
- **REG-1-1-29** **[L][M][W] Busy exit codes per OS.** Docs say a run that finds another in progress exits
  `75` on Linux and macOS and `1618` on Windows; ensure's default lock wait is 5 s (up to 15
  min with `--lock-wait`), not "two minutes". Docs.
- **REG-1-1-30** **[L][M] Data directory mode.** Docs give the gateway data directory as `0700`, matching
  what verify enforces. Docs.

### Enrollment

- **REG-1-2-01** **[U] Connectors to enable are documented; no connectors is not "complete".** Install a
  config with no `guardrail.connectors`. Expect: the docs show which connectors to enable, and
  status says `security_complete: false` with `no_connectors_enabled`. Live: macOS. (ensure's
  own result still misses the warning, record as a UX finding.)
- **REG-1-2-02** **[U] New account.** Create a new account with a supported agent. Expect: enrolled within one
  enumerator cycle (about 5 min; seen 2 min 43 s to 3 min 42 s) with owner-only files.
  Live: RHEL, macOS. **[W]** Enrolled seconds after its first real sign-in (RDP or console).
- **REG-1-2-03** **[U] Kiro for accounts without `~/.kiro/hooks`.** Enable Kiro with `kiro-cli` installed
  machine-wide; include accounts that never ran Kiro. Expect: the guardian creates the missing
  folders as the user, owner-only (refusing links and foreign owners); no
  `guardian_target_failed` for those accounts; an install the contract refuses creates no
  folders. Live: macOS.
- **REG-1-2-04** **[U] OmniGent under the user's home.** Install OmniGent the usual way (`uv tool install`,
  interpreter under `~/.local/share/uv`) and enable it. Expect: admitted when the interpreter
  and every parent up to the home are owned by the user and not group/other-writable; a refusal
  names `enterprise.enrollment.agent_prefixes` or the `chmod` remedy in full (no internal
  environment variable, no truncation). Live: RHEL, macOS (for a verified OmniGent version).
- **REG-1-2-05** **[U] Discovery never runs files other accounts control.** Put an agent CLI in a shared
  prefix owned or writable by another account (for example a Linuxbrew prefix). Expect: it is
  not run; status reports the agent as unprotected with "(not run: ...)"; on macOS an
  admin-group-owned folder that others cannot write (`/Applications`, an administrator's
  Homebrew) is still probed. Live: macOS; code for Linux.
- **REG-1-2-06** **[U] Kiro below the floor.** Give an enrolled account a kiro-cli below 2.24.1. Expect: the
  row does not follow it; the installed version is reported unprotected; builds at or above
  2.24.1 are followed after a self-update. Code/live (macOS, RHEL at 2.24.1).
- **REG-1-2-07** **[U] Deleted account.** Delete an enrolled account (`userdel -r`; macOS `sysadminctl
  -deleteUser` or `dscl . -delete`). Expect: its rows show as pending, then the warning
  `guardian_target_account_removed`; `verify`, `detect.sh --require-healthy` and
  `security_complete` do not fail; rows are revoked at the third consecutive definitive miss
  (10 to 15 min; seen 13 min 52 s and 14 min 52 s); `enterprise <os> repair` removes them at
  once and lists `deleted_account_targets_removed`. If the local account database cannot be
  read, repair removes nothing and lists the accounts as kept with the reason. Live: RHEL,
  macOS, Ubuntu (warning).
- **REG-1-2-08** **[U] Account that returns with a new uid.** Recreate a deleted local account with the same
  name and a different uid. Expect: new rows for the new uid in the same cycle. Code.
- **REG-1-2-09** **[U] Excluded account shown as excluded.** `<G> enterprise policy show --user <excluded
  account>` (also with different letter case on macOS). Expect: an `enrollment:` line saying
  the account is excluded (or exempt, or root), matched on the resolved account name. Live:
  macOS.
- **REG-1-2-10** **[U] Per-account enrollment view.** As admin, `<G> enterprise hooks status [--json]`.
  Expect: enrollment per user and connector (text and a JSON `enrollment` array), without
  extra environment variables. Live: RHEL, macOS. (Windows has no such view yet, record as a UX finding.)
- **REG-1-2-11** **[U] Disabling a connector cleans its registration.** Enroll Kiro or Hermes, then apply a
  config without it (or exclude the user). Expect: within about a minute the guardian removes
  DefenseClaw's per-user registration as that user (hook files, default agent, the
  connector's credential) and puts back the user's previous settings; the agent then runs
  tools normally (no HTTP 403 from a leftover hook). A home that is not available is retried
  and reported as `guardian_cleanup_pending`. Re-enabling enrolls again at the next cycle.
  Live: RHEL, macOS.
- **REG-1-2-12** **[L][M] Documented enrollment timing.** The enrollment page states the three-miss rule and
  the 10 to 15 minute revocation window. Docs.
- **REG-1-2-13** **[L][M][W] Rollout table.** The rollout guide's user table matches the code: on Windows
  `include_users` is additive, `include_groups`/`exclude_groups` apply (local, AD, Entra by
  SID via session tokens and cached membership), `exempt_users` are still inspected; on Linux
  directory accounts above `UID_MAX` are enrolled unless `enrollment.uid_max` caps them. Docs.
- **REG-1-2-14** **[W] Account that ran an agent before enrollment.** Create a new account, start a
  machine-policy agent as that account before the enumerator enrolls it (runas), then as admin
  run status and repair; then sign in. Expect: status exits 0 with the warning
  `enrollment_pending_account_folder`; repair exits 0 and leaves services running with nothing
  pending; sign-in adopts the folder. Live: Windows.
- **REG-1-2-15** **[W] Not-yet-enrolled account message (prior build).** As a runas-only account that the
  enumerator has recorded but that never signed in, send a prompt in Claude Code and in Codex,
  before and after one enumerator cycle. Expect: both say the account is not enrolled yet and
  enrolls when it signs in (reason `enterprise_managed_enrollment_pending`), not "gateway
  unreachable" or "hook failed closed". Pending (Claude Code's first-cycle case live).
- **REG-1-2-16** **[W] Unenrolled or excluded account message.** As the excluded account, send a prompt in
  Claude Code and in Codex. Expect: "this account is not enrolled in DefenseClaw on this
  computer ..." with what to do, not a "gateway unreachable" text. Live: Windows (Claude Code);
  Codex in prior build, pending.
- **REG-1-2-17** **[W] Deleted account (prior builds).** Delete an enrolled account, then remove its profile.
  Expect: status warns `deleted_account_rows` for that account while the profile exists; after
  the profile is removed status stays exit 0 until the rows drop (about 2 min), and other
  accounts are unaffected. Live for the warning; host health after profile removal pending.
- **REG-1-2-18** **[W] Pending count.** `enterprise windows status --json` on a host where every enrolled
  account is signed in. Expect: `enrollment.pending` is 0 (it counts only targets waiting for a
  session, for example 2 for a runas-only account), not equal to `targets`. Pending.
- **REG-1-2-19** **[W] Status and verify agree on a user's agent.** After a SYSTEM install, run status and
  verify as an elevated admin and as LocalSystem. Expect: an agent path the admin cannot read
  is reported as unreadable with "run verify as LocalSystem" (not "missing" and not "run
  repair"); LocalSystem verify has no such error. Live: Windows.

### Multi-user isolation and host health

- **REG-1-3-01** **[U] One account's damage stays in that account.** As std1: replace
  `~/.config/amp/plugins` with a file, or `chmod 000 ~/.kiro`, or make a folder on the path a
  link. As admin: status, verify, `detect.sh --require-healthy`, reconcile. Expect: status and
  verify exit 0 with the per-account warning `guardian_target_user_path` naming the account,
  connector and path; `security_complete` stays true; MDM detection is healthy; std2 stays
  enforced (its marker call is blocked). Commit a60d1822c: reconcile also exits 0 for an own-path-only
  failure (Linux clears the oneshot's failed state); other failed targets are reported one
  plain `reconcile_failed` line per target, without the guardian command line or manifest
  path. Live: macOS, RHEL (reconcile wording pending).
- **REG-1-3-02** **[U] Own `~/.defenseclaw` mode is repaired.** As std1, `chmod 000 ~/.defenseclaw`. Expect:
  the guardian's worker (running as std1) restores 0700 and repairs std1's registrations
  within seconds; no admin action needed. Live: RHEL, macOS.
- **REG-1-3-03** **[U] A named pipe in place of a hook config.** As std1, replace `~/.openhands/hooks.json`
  with a FIFO and break `~/.hermes/config.yaml`. Expect: the worker does not hang; the warning
  names the file ("<path> is a named pipe, not a regular file") and the parse problem per
  connector, not "worker for uid N timed out". Code/live (RHEL).
- **REG-1-3-04** **[L][M] Hook flood fairness.** As std1, send a burst of inspect requests to the hook socket
  (for example thousands of requests, 10 to 40 in parallel) while std2 uses Claude Code.
  Expect: std2's hook latency rises only modestly (seen about 45 ms to about 170 ms on
  average) and std2's marker call is still blocked; std1 gets HTTP 429
  `enterprise_managed_rate_limited` or queues behind its own slots. Live: RHEL, macOS.
- **REG-1-3-05** **[U] Rejected and refused requests name the caller.** As std1, send a malformed hook
  request and a request that names std2 in the identity headers (hook socket, and TCP with
  std1's per-user credential). Expect: the request naming std2 is refused
  (`user_scoped_identity_mismatch`); the audit rows (`connector-hook` rejected,
  `inspect-tool`, `api-auth-failure`) carry std1's uid and name, the connector, the route and
  the reason. Live: RHEL, Ubuntu.
- **REG-1-3-06** **[U] Hook decisions name the account.** After std1's allowed, blocked and confirm calls,
  export the audit. Expect: `connector-hook`, `hook_decision` and tool rows carry
  `defenseclaw.user.name` and `user.id`. (Scan rows still do not, see #921.) Live: macOS.
- **REG-1-3-07** **[U] Home-relative rules match for every caller.** As std1, ask an agent to read a file under
  `~/.aws/` or `~/.kube/` by a `~` path. Expect: the built-in credential-path rules still
  flag it (the caller's home, or the bound account's home for a per-user credential, is
  used). Code.
- **REG-1-3-08** **[U] Gateway sessions store per user.** A user who starts many agent sessions in a week can
  still start new ones (clean records are evicted first; live blocked records never are).
  Code.

### Gateway and hook trust

- **REG-1-4-01** **[U] No loopback fleet connection.** On a managed standalone host, run a listener on
  `127.0.0.1:18789` as std1 that only records whether anything connects (print shape and
  status codes only), for several minutes; also read the gateway journal. Expect: no
  connection arrives; `<G> status` shows the fleet uplink disabled for the managed profile;
  the journal has no repeating "connect failed ... retry in 15s" lines. Live: Ubuntu, RHEL.
- **REG-1-4-02** **[L][M] API port held by another account.** As std1, hold `127.0.0.1:18970` while the admin
  restarts the gateway (Linux: stop the socket units first, since systemd otherwise keeps the
  port). Expect: status (exit 1) and verify name the holder: "the gateway API port
  127.0.0.1:18970 is held by pid N (uid U, user), not by the DefenseClaw gateway; stop that
  process, then run ... repair"; they say hooks are still served on the socket and the gateway
  keeps retrying the port; std1's listener receives no request (readiness is read over the
  peer-verified hook socket); repair fails once, rolled back, naming the holder once; after
  release the gateway takes the port back and repair is healthy. Live: RHEL, macOS.
- **REG-1-4-03** **[W] API port held during a restart.** As std1, hold `127.0.0.1:18970` (also a wildcard
  listener) while the admin runs `Restart-Service DefenseClawGateway`; release after a few
  minutes. Expect: hooks fail closed during the hold; the gateway rebinds about 1 s after
  release without another restart. Live: Windows. (Status naming the holder on Windows is
  #929.)
- **REG-1-4-04** **[U] Fail-closed text.** Stop the gateway (and its sockets) and send a prompt in Claude Code
  as std1. Expect: one line that starts with DefenseClaw, names the event and ends with the
  reason code in parentheses; no toolchain warning, and a prompt is not called a "tool".
  Live: RHEL, Ubuntu.
- **REG-1-4-05** **[U] Stop events do not loop.** With the hook socket unavailable, let Claude Code, Codex or
  Devin finish a turn. Expect: `Stop`, `SubagentStop`, `TeammateIdle` and session-end events
  get a neutral allow (logged as fail mode open), so the agent stops; prompt and tool events
  stay blocked. Code.
- **REG-1-4-06** **[U] Deleted or edited per-user hook script is restored.** As std1, delete
  `~/.defenseclaw/hooks/hermes-hook.sh` (or `openhands-hook.sh`, `_hardening.sh`), or edit it.
  Expect: the guardian re-renders it within the reconcile bound; verify reports the target as
  drifted until then. Live: Ubuntu (found), RHEL/macOS (fixed).
- **REG-1-4-07** **[U] Mode change reaches per-user hooks.** Install in observe mode, then switch
  `guardrail.mode` to action. Expect: within one guardian cycle every per-user hook runtime
  (`~/.defenseclaw/hooks/.hookcfg.*`) follows the new fail mode (OpenHands closed); verify
  reports a mismatch until then. Hermes stays open by its contract. Live: Ubuntu.
- **REG-1-4-08** **[U] Managed plugins are compared with their render.** As std1, append a line to
  `~/.config/amp/plugins/defenseclaw.ts` or `~/.config/opencode/plugins/defenseclaw.js` (also
  after editing the lock and receipt digests). Expect: the guardian restores the rendered
  plugin within seconds (seen 2 s and 14 s); verify reports drift until then. Live: RHEL,
  macOS.
- **REG-1-4-09** **[U] Hook scripts follow an upgrade (commit a60d1822c).** Upgrade the package on a host with enrolled
  accounts whose hook scripts changed between releases (for example Hermes). Expect: each
  enrolled account's scripts under `~/.defenseclaw/hooks` match the installed release shortly
  after the upgrade, with no connector disable/enable; `enterprise <os> repair` also
  re-renders; the agent's calls use the new script. Pending.
- **REG-1-4-10** **[W] Per-user plugins follow an upgrade (commit a60d1822c).** Upgrade Setup to a release whose Amp
  or OpenCode per-user plugin changed. Expect: signed-in users get the new plugin; signed-out
  users are re-rendered at their next sign-in and are not counted as failures, so the upgrade's
  readiness wait and other users' enrollment are not held up. Pending.
- **REG-1-4-11** **[W] State root keeps the gateway's access.** Run upgrade, repair (including a failed
  repair) and uninstall-retry. Expect: `C:\ProgramData\Cisco\DefenseClaw` keeps the gateway
  service's read ACE; if it is removed by hand, verify names `NT SERVICE\DefenseClawGateway`
  and says repair restores it, status shows `gateway_start_failed` once with the logged error
  and log path, and repair restores the saved DACL. Live: Windows (service naming pending).
- **REG-1-4-12** **[L][M] Hook transport.** Standalone Unix hooks and in-agent plugins use only the hook
  socket; a runtime descriptor without `hook_socket` fails closed (no TCP fallback);
  per-user credentials authenticate only their own connector route and account. Code; spot
  checks live.

### Rule engine

- **REG-1-5-01** **[L][M] Runtime-expanded redirect target.** In Claude Code (and one generic-path agent)
  run `echo dctest-block-marker > ~/dc-test-proj/dctest-redirect.txt`, `> "$HOME/dc-test-proj/dctest-expanded.txt"` and `> "$HOME/dc-test-proj/dctest-glob.txt"`. Expect:
  blocked, with both rule forms (plain and `argv_complete`); no file; one block CRITICAL audit
  row per call attributed to the account. A target named by another variable (`> $OUT`) or a
  command substitution stays detection-only by design. Live: RHEL, macOS.
- **REG-1-5-02** **[L][M] Same decision as a static target.** A rule that allows `sudo systemctl status
  <unit> > ~/dc-test-proj/dctest-tmp.txt` also allows it with `> ~/dc-test-proj/dctest-redirect.txt`. Code.
- **REG-1-5-03** **[L][M] First command of a list.** Run `echo dctest-block-marker && echo done`,
  `echo dctest-block-marker || true` and `echo dctest-block-marker; echo done`. Expect:
  blocked with both rule forms. `cd /tmp && echo dctest-block-marker` stays detection-only
  (a command after `&&` may not run; #923). Live: RHEL, macOS.
- **REG-1-5-04** **[L][M][W] Block wording tells the agent not to retry.** Trigger the block marker in each
  agent. Expect: "DefenseClaw blocked this action under your organization's policy (rule
  <ID>: <title>). Do not retry it in another form. Contact your administrator if you need it
  allowed." (per-user installs: "DefenseClaw policy blocked this action (rule <ID>)"); no
  `matched: <ID>:<redacted ...>` token; the agent stops instead of re-encoding the command.
  Live: RHEL, macOS (seven connectors); Windows to re-check (see [Connectors](#connectors)).
- **REG-1-5-05** **[U] Rule pack validation.** Validate a pack with an over-cost CEL expression using `<G>
  rulepack validate --dir <pack>` (listed in help). Expect: the refusal names the per-rule and
  catalog cost limits. The enterprise docs describe this validator, where a custom pack lives,
  `guardrail.rule_pack_dir`, ensure, and that in-place edits need a gateway restart. Live:
  macOS, RHEL. (The rule is still named by index, record as a UX finding.)

### Foreign-hook guard (standalone profile)

- **REG-1-6-01** **[U] Devin uses the administrator-owned hook.** Look at std1's Devin config. Expect: it runs
  `defenseclaw-hook hook --connector devin --enterprise-managed` (not a script in the home), fails
  closed, and a user or project `PreToolUse` entry that changes the tool input gets
  `enterprise_foreign_hook_blocked` naming the file and the allowlist key; the guardian removes
  the user-level entry within about five minutes. Live: RHEL (message), code.
- **REG-1-6-02** **[L][M] Hermes shell hooks are guarded.** As std1 add a second `pre_tool_call` entry to
  `~/.hermes/config.yaml` (a script that returns a modified command), start Hermes and ask for a
  benign echo. Expect: the call is blocked for that session with a message naming the file,
  the digest and `enterprise.machine_policy.connectors.hermes.allowed_hooks`; the rewritten
  command does not run; one gateway audit row per denial; with `foreign_hooks: remove` the
  guardian removes the entry (after a backup, rewriting only the hooks mapping) within about
  five minutes. The same applies to a `config.yaml` under `HERMES_MANAGED_DIR`; the
  `output_spill` and `outbound` settings sections are not treated as hooks. Live: RHEL, macOS.
- **REG-1-6-03** **[L][M] Hermes allowed calls work.** In a fresh Hermes session with no unapproved hook,
  run an allowed command. Expect: it runs (no "could not check the Hermes hooks of this
  account" fallback), also right after a package upgrade (commit a60d1822c re-render). When the check
  itself cannot decide, the message says why (exit status, no answer, unreadable answer) and
  the block is audited. Live: RHEL (after re-render), macOS; after-upgrade pending.
- **REG-1-6-04** **[L][M][W] Agent loaded a hook the guardian removed (commit a60d1822c).** Start an agent while an
  unapproved hook is present, let the guardian remove it before you send the first prompt, then
  prompt. Expect: calls from that agent process are still denied, naming the file; an agent
  process started after the removal is allowed; other accounts and connectors are not
  affected. A removal from a file several agents load (Claude Code's `~/.claude/settings.json`
  is also read by Cursor and Devin) holds each of them. Pending.
- **REG-1-6-05** **[L][M] Amp project plugin.** In a project with `.amp/plugins/<name>.ts` that modifies tool
  calls, start Amp and send a prompt. Expect: the turn is stopped at agent start; the thread
  keeps a message "DefenseClaw stopped this turn: ..." naming the file, the digest and the
  `allowed_hooks` key (not only a fading notice, no success check mark, no reason code); no
  tool call runs; audit block row. A plugin approved by digest proceeds. Live: RHEL, macOS
  (persistent message: code).
- **REG-1-6-06** **[U] OpenCode unapproved plugin.** Put a plugin in the project's `.opencode/plugins/`,
  start OpenCode, call a tool, remove the plugin, call again in the same process. Expect:
  both calls denied; the error and notice start with what DefenseClaw did (no
  `enterprise_foreign_hook_blocked:` prefix) and name the file and digest; each denied call has
  an attributed audit row. Live: RHEL, macOS.
- **REG-1-6-07** **[U] Copilot and Devin session block text.** Add a user-level hook, start the agent, send
  the first prompt. Expect: "When this agent session started, the user file <path> defined a
  hook ..." with the `allowed_hooks` key, as the per-call message does. Code/live (RHEL).
- **REG-1-6-08** **[U] Scan that hits a limit blocks the session.** Fill a user or project hook folder past
  the scan limit (more than 256 entries in one folder) with one rewriting hook among them.
  Expect: the session is blocked with a restart-the-agent reason; deleting the files later does
  not unblock that process. Code.
- **REG-1-6-09** **[U] Same-session start without process identity.** When the agent process cannot be named,
  a blocked record survives a SessionStart that reuses the session ID (compact, clear,
  resume); only a new session ID starts clean. Code.
- **REG-1-6-10** **[L][M][W] Session records are gateway state.** Delete `~/.defenseclaw/foreign-hook-sessions`
  (or anything in the home) during a blocked session. Expect: the block holds (records are in
  the gateway's protected data directory, keyed by uid or SID); a record that cannot be read or
  written denies the call; a block ends 7 days after it was recorded. Code; issue #911 closes
  with the PR.
- **REG-1-6-11** **[U] Symlinked approved program.** An approved hook that reaches an administrator-owned
  program through a symlink the user owns: re-pointing the link changes the digest. On macOS a
  root-owned file reached through a user-controlled folder (for example a hard link in a
  repository) is bound by content. Code/docs.
- **REG-1-6-12** **[W] Claude Code lock on Windows.** As std2, add a `PreToolUse` hook that returns modified
  input to `~\.claude\settings.json` and to `<project>\.claude\settings.json`, then ask Claude
  for a benign echo. Expect: neither hook runs (the drop-in sets `allowManagedHooksOnly` under
  the default `managed_hooks_only: enforce`); a later drop-in that turns the lock off is named
  by verify and policy verify. Live: Windows.

### Connectors

**Claude Code**
- **REG-1-7-01** **[U][W] Block and confirm text** as in [Rule engine](#rule-engine); Claude no longer tells the user to edit
  `~/.claude/settings.json`. Live: RHEL, Ubuntu, macOS; Windows to re-check.
- **REG-1-7-02** **[U] Version floor visible and restored.** As admin, delete
  `managed-settings.d/00-defenseclaw-version-floor.json`. Expect: status and verify warn
  `claude_version_floor_missing`; `enterprise policy show` names the command that restores it
  (ensure, reconcile or repair); ensure writes it back. Messages and docs say Claude Code
  reads `requiredMinimumVersion` only from 2.1.163, so the 2.1.154 floor stops no older build
  (#920). Live: RHEL, macOS.
- **REG-1-7-03** **[U] Admin floor wins.** Add `"requiredMinimumVersion"` to `managed-settings.json` (or a
  drop-in that sorts before DefenseClaw's). Expect: policy show/verify report the admin's value
  as the one in force and, under `ownership: merge`, as drift; the next lifecycle run
  withdraws DefenseClaw's floor drop-in. DefenseClaw's HKLM/reg/plist/Intune exports carry
  the floor when `version_floor: enforce`. Code.
- **REG-1-7-04** **[U] Ownership off.** Set `enterprise.machine_policy.connectors.claudecode.ownership: "off"`.
  Expect: DefenseClaw's drop-ins are removed; policy show lists "ownership off: machine policy
  not managed" with a note that sessions run without DefenseClaw's machine hooks (not
  "unsupported"); no per-user Claude Code hooks are written into any home; per-user
  registrations an earlier build wrote there (recorded as the guardian's own) are removed.
  Live: RHEL, macOS (removal of earlier leftovers: code).
- **REG-1-7-05** **[W] Managed-hooks lock** as in [Foreign-hook guard](#foreign-hook-guard-standalone-profile). Live: Windows.

**Codex**
- **REG-1-7-06** **[U] Machine policy file mode** as in [Lifecycle regression](#lifecycle-install-ensure-repair-uninstall-config). Live: Ubuntu.
- **REG-1-7-07** **[L][M][W] Block wording** stops the model from re-encoding a blocked command. Live: RHEL.
- **REG-1-7-08** **[W] Tool calls reach the gateway.** Allowed, marker-blocked and approve/deny calls behave
  and are audited for std1 and std2. Live: Windows.

**GitHub Copilot CLI**
- **REG-1-7-09** **[U] Foreign-hook denials are audited** (one attributed row per denied call, naming the
  file) and the first-prompt message is right (see [Foreign-hook guard](#foreign-hook-guard-standalone-profile)). Live: Ubuntu (found), RHEL/macOS.

**Cursor**
- **REG-1-7-10** **[W] Machine hooks file.** With Cursor enabled and at least one user enrolled for it,
  `C:\ProgramData\Cursor\hooks.json` is published; when no user is enrolled, status warns that
  Cursor is not protected and why, and policy verify names the absent file. The native Cursor
  Agent CLI is discovered. Live: Windows.
- **REG-1-7-11** **[U] No repair loop in action mode.** A Cursor row in action mode is not repaired on every
  cycle. Code.

**OpenCode**
- **REG-1-7-12** **[U][W] Visible block.** Run the block marker. Expect: the tool call fails with an error that
  names DefenseClaw and a notice appears (also on releases that show a failed tool with no
  text); the file does not exist; audit block row. Live: RHEL, Ubuntu, macOS, Windows.
- **REG-1-7-13** **[U] Confirm verdict notice.** Run the confirm marker. Expect: a warning notice "DefenseClaw
  flagged this action for review under your organization's policy (rule <ID>: <title>).
  OpenCode cannot ask you to confirm it here, so it runs; DefenseClaw recorded it." (no
  `matched: ...<redacted ...>`). Live: RHEL, macOS.
- **REG-1-7-14** **[U] Load-time check failure.** If the plugin's start-up foreign-plugin check fails, its
  blocks say to restart the agent once DefenseClaw is available. Code.
- **REG-1-7-15** **[W] Managed plugin loads for standard accounts.** As std1 and std2, run allowed, marker and
  approve/deny calls. Expect: the managed plugin under `C:\Program Files\Cisco\DefenseClaw\
  share\opencode\defenseclaw.js` runs the hook (block, audit row per account); a standard
  account's attribute change on it is rewritten on the guardian's next pass (residual 23,
  #930). Live: Windows.
- **REG-1-7-16** **[W] Planted `%ProgramData%\opencode\opencode.json`.** A file a standard account created
  there before install is moved aside before DefenseClaw publishes. Code.

**Amp**
- **REG-1-7-17** **[U] Appended plugin restored, project plugins stopped** (see [Gateway and hook trust](#gateway-and-hook-trust) and [Foreign-hook guard](#foreign-hook-guard-standalone-profile)). Live: RHEL, macOS.
- **REG-1-7-18** **[W] Moved config folder.** As std1, move `~\.config\amp` aside. Expect: the plugin is
  recreated within about 20 s (also while std2 is signed out). Live: Windows.
- **REG-1-7-19** **[W] `C:\ProgramData\ampcode` reserved.** As std1, try to create, change, re-ACL or rename
  it. Expect: refused; the folder is admin-owned, users read only (an empty admin-owned folder
  after uninstall is intended). Live: Windows.
- **REG-1-7-20** **[W] Token republish.** Reinstall or re-enroll Amp or OpenCode for a user whose token was
  hardened by an earlier reconcile. Expect: the guardian republishes the token; no Access
  Denied. Live: Windows.
- **REG-1-7-21** **[L][M][W] `async_shell_command`** is inspected like Amp's bash tool. Code.

**Devin**
- **REG-1-7-22** **[U] Administrator-owned hook** (see [Foreign-hook guard](#foreign-hook-guard-standalone-profile)). **[M] Config root moved** to `~/.config/devin`: an
  existing macOS Devin install from an earlier build upgrades without "managed backup target
  mismatch". Code.
- **REG-1-7-23** **[L][M][W] Contract pins documented.** Devin page says 3000.4.25 on every OS and 3000.11.3
  live-verified on Linux only. Docs.

**Antigravity**
- **REG-1-7-24** **[L][M][W] `run_command` matches command rules.** The marker in `run_command` is blocked
  (scheduling and UI arguments are dropped from the analyzed copy). Code/live (RHEL).

**Hermes**
- **REG-1-7-25** **[L][M] Foreign-hook guard and allowed calls** (see [Foreign-hook guard](#foreign-hook-guard-standalone-profile)). Live: RHEL, macOS.
- **REG-1-7-26** **[L][M] Confirm verdict in standalone.** Run the confirm marker in Hermes. Expect: blocked
  with a message that the organization's rule needs a confirmation Hermes cannot ask for (not a
  silent alert); per-user installs keep the alert. Code/live.
- **REG-1-7-27** **[L][M] Disabling keeps the user's file.** Disable Hermes. Expect: `config.yaml` keeps every
  byte outside the `hooks` mapping (comments, key order); all of DefenseClaw's allowlist
  approvals are removed and the user's own are kept; `hermes-hook.sh` stays as a stub that
  exits at once (a running Hermes keeps calling it until restart). Re-enabling renders the
  current script. Live: RHEL, macOS.
- **REG-1-7-28** **[W] Hermes enrolls next to other agents.** Both accounts with Hermes plus other agents,
  SYSTEM Setup `/ensure`. Expect: Hermes enrolled for both (no Access Denied on the data
  folder). Live: Windows.
- **REG-1-7-29** **[W] Large Hermes tree does not stall a fresh install.** A user with Hermes installed (a
  very large `%LOCALAPPDATA%\hermes` tree). Expect: a fresh install finishes in normal time
  (directory permissions are set without rewriting every descendant). Live: Windows.

**OpenHands**
- **REG-1-7-30** **[L][M][W] Terminal calls are inspected.** The block marker in OpenHands' terminal tool is
  blocked (PascalCase `PreToolUse` events are decoded). Code/live (Ubuntu, RHEL, macOS).
- **REG-1-7-31** **[U] Fail mode follows action mode, deleted script restored** (see [Gateway and hook trust](#gateway-and-hook-trust)). Live: Ubuntu.
- **REG-1-7-32** **[L][M] Confirm verdict in standalone** is blocked with the "needs a confirmation the agent
  cannot ask for" message (as Hermes). Code/live.

**Kiro**
- **REG-1-7-33** **[U] CLI 2.x tool hooks fire.** In `kiro-cli chat` (2.24.1), run an allowed command and the
  marker. Expect: `~/.kiro/agents/defenseclaw.json` uses matcher `*` (an agent with the old
  `.*` fails verification and is rewritten, also after an upgrade); `preToolUse` and
  `postToolUse` rows in the audit; the marker is blocked with DefenseClaw's text. Live: RHEL,
  macOS.
- **REG-1-7-34** **[U] Shell calls have complete facts** on 2.x (`__tool_use_purpose`) and `--v3` (null `cwd`,
  `description`, `timeout`): the marker is blocked, not detection-only. Live: RHEL, macOS.
- **REG-1-7-35** **[U] Disable restores the user's settings.** Disable Kiro. Expect: DefenseClaw's
  `~/.kiro/hooks/defenseclaw.json` and `~/.kiro/agents/defenseclaw.json` are removed,
  `chat.defaultAgent` goes back to the user's earlier value, and keys the user added since
  enrollment (for example `chat.enableAutoAgentUpgrade`) stay. Live: RHEL, macOS.
- **REG-1-7-36** **[U] Teardown finds a custom default agent.** A user whose `chat.defaultAgent` named their own
  agent before enrollment (or an earlier build hooked it): after upgrade and teardown no
  DefenseClaw entries remain in that agent, and a shared workspace copy is removed. Code.
- **REG-1-7-37** **[L][M][W] `defenseclaw doctor` (per-user)** passes a global Kiro install that has
  `~/.kiro/hooks/defenseclaw.json`. Code.
- **REG-1-7-38** **[W] (per-user) Kiro blocks on native Windows**: the hook accepts `--hook-surface` and the
  PowerShell bridge returns exit 2. Code. (The managed profile covers Kiro on Windows only
  through the ACP guard, R22.)


**OmniGent**
- **REG-1-7-39** **[U] Home-installed interpreter** (see [Enrollment](#enrollment)). **[L] Disabled connector shown disabled** in
  `<G> status` ("disabled, not enforced"). Live: RHEL.

- **REG-1-7-40** **[L][M][W] Kiro cached hook after disable.** On a per-user
  install run `defenseclaw setup kiro`, start Kiro, then disable Kiro without
  restarting the agent. Expect: `~/.defenseclaw/hooks/kiro-hook.sh` remains an
  owner-executable inert stub that exits `0`; it posts nothing to the gateway.
  Re-enable with setup and confirm the active hook is restored. On Linux and
  macOS repeat through managed teardown. Tested by PU-03 and the Kiro tombstone
  contract test.

### Status, admin CLI and messages

- **REG-1-8-01** **[L][M] Admin commands find the managed deployment.** As root (no extra environment):
  `<G> status`, `audit export`, `audit findings`, `enterprise hooks status|enumerate|verify`,
  `enterprise policy show|verify`. Expect: they read the managed config, data dir and manifest;
  `audit export` opens the service-owned audit store read-only (no "untrusted owner"); no
  "custom-providers overlay open error" line. Live: RHEL, Ubuntu, macOS.
- **REG-1-8-02** **[W] Admin audit and policy.** From an elevated prompt: `defenseclaw audit export
  --connector <c> -o <file>`, `enterprise policy show|verify`. Expect: they work on the managed
  deployment; `enterprise policy verify --live` is refused up front with the reason. Live:
  Windows.
- **REG-1-8-03** **[L][M][W] Recent audit rows.** `audit export --since 30m`, `--until`, and `--limit N
  --newest`. Expect: time filters work; `--newest` keeps the N most recent rows; output stays
  oldest first; help states the order. Live: RHEL, macOS.
- **REG-1-8-04** **[L][M] Audit review documented.** The enterprise pages name `journalctl -u <unit>` (Linux),
  the log folder (macOS) and the supported `audit export` command. Docs.
- **REG-1-8-05** **[L][M] Standard-account refusals.** As std1: `<G> stop`, bare `<G>`, `<G> start`,
  `DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise <G> start`, `<G> enterprise hooks status`,
  `<G> enterprise secret status`. Expect: each refuses with "this computer's DefenseClaw is
  managed by your organization (...)" and a non-zero exit, before any side effect (no
  `~/.defenseclaw/audit.db` created); the refusal names the absolute `<G>` path (sudo's
  `secure_path` and root's PATH do not include it); secret and hooks status say an
  administrator runs them. `defenseclaw uninstall` (per-user) on a managed host still removes a
  leftover per-user install. Live: RHEL, Ubuntu, macOS. (`enterprise <os> status` as a standard
  account is still wrong, record as a UX finding.)
- **REG-1-8-06** **[W] Standard-account `stop`.** As std1, run
  `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' stop;
  $LASTEXITCODE` and repeat from a deliberately retained per-user binary on a
  separate snapshot. Expect the managed-host refusal with a non-zero exit,
  never "command not recognized". To re-check on Windows.
- **REG-1-8-07** **[U] Disabled connector.** `<G> status` with a connector `enabled: false`. Expect: "Status:
  disabled, not enforced". Live: RHEL.
- **REG-1-8-08** **[U] A change reports the guardian's findings.** `ensure --config` that switches to action
  mode while an enrolled agent version has no verified contract. Expect: ensure's result carries
  the guardian's target findings after the change (for example `hook_contract_unverified`
  naming the connector, version and user), or `guardian_report_pending` when the guardian has
  not reported yet; not a bare "done". Guardian reasons keep their remedy text. Code/live
  (macOS).
- **REG-1-8-09** **[U] Machine-policy drift message** names the connector, the file and the repair command.
  Live: Ubuntu.
- **REG-1-8-10** **[U] `policy verify --user` order** is sorted by connector name. Live: Ubuntu.
- **REG-1-8-11** **[U] MDM wrapper result shows the package step.** Upgrade through the wrapper. Expect: the
  result carries `package_upgraded` (or `package_installed`) with the versions; `noop` is not
  the only signal. Live: macOS, RHEL.
- **REG-1-8-12** **[W] Status for a crash-looping gateway** names the start error, the log path and repair, once.
  Live (named); printed once: pending.
- **REG-1-8-13** **[L][M] CLI reference.** `policy verify --live` uses `--audit-db`; `policy export` lists
  `--format version-floor` for Claude Code. Docs.

### Windows Setup and MDM

- **REG-1-9-01** **[W] Republished manifest.** After the enumerator republishes `targets.yaml` (new user,
  agent update), run verify, repair and uninstall. Expect: verify passes and repair/uninstall use
  the current enrollment; a failed uninstall rolls back instead of leaving services stopped.
  Live.
- **REG-1-9-02** **[W] Rollback keeps the sensor helper.** Make a lifecycle action fail after the managed-hook
  teardown step. Expect: the rollback restarts the restored gateway with its sensor helper;
  the prior deployment runs again. Live.
- **REG-1-9-03** **[W] Uninstall of a running deployment.** `Setup /uninstall PURGE=1 JSON=1` on a healthy
  deployment. Expect: services, binaries, marker and ARP entry removed (the sensor helper is
  quiesced first; the ACP bridge and sensor helper binaries are retired); a retry after a
  committed uninstall finishes; the runtime-selector lock files in the Claude Code and Codex
  machine folders are removed. Live (selector locks: CI lane).
- **REG-1-9-04** **[W] MDM wrapper.** `pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 -SetupPath <exe>
  -Sha256 <pin> -ConfigPath <cfg>`. Expect: Setup gets `/ensure` and `JSON=1` as separate
  arguments and the wrapper prints Setup's result; a failure's next step names the admin's
  `-ConfigPath` (not the wrapper's temporary copy) and says it must run as LocalSystem. Live.
- **REG-1-9-05** **[W] First install with the default `data_dir`.** Fresh host, config without `data_dir`,
  Setup `/ensure`. Expect: installs. Live.
- **REG-1-9-06** **[W] Config the gateway cannot load.** Setup `/ensure` with a config the gateway would
  reject. Expect: exit 1639 before any change, naming the file, the location and the reason
  (the same check as `validate-service-config`). Live.
- **REG-1-9-07** **[W] No `rule_pack_dir`.** Expect: the gateway starts with the embedded packs. Live.
- **REG-1-9-08** **[W] Newer Setup recovers a pending transaction.** With a failed install pending, run a
  newer Setup `/ensure` as SYSTEM. Expect: it recovers the transaction with its own verified
  gateway and installs; rollback cleanup survives an enumerator republication. Live. The
  recovering run no longer exits 1603 with "add the target through a fresh Install": code, not
  retested.
- **REG-1-9-09** **[W] User moves `~\.defenseclaw` aside.** Expect: the token folder is recreated; the guardian
  re-publishes the user's targets; admin reconcile and SYSTEM `/ensure` converge; no host outage
  (services keep running). An enrolled, signed-in account that replaced its folder: repair and
  its rollback do not fail in the retire step (prior build, pending).
- **REG-1-9-10** **[W] Event-log entries.** As std1, write an entry under the `DefenseClaw Lifecycle`
  source and one under the Application log's `DefenseClaw Enterprise` source; as admin run
  `enterprise windows events` and `events --application`. Expect: the first write is refused
  (only SYSTEM and Administrators can write the `DefenseClaw` log, #928); the Application-log
  entry, which has no matching lifecycle record, is listed as not DefenseClaw (exit 1). Live.
- **REG-1-9-11** **[W] Exit-code docs.** Setup's own argument refusals (unknown property, relative or
  unexpanded `CONFIG=`, `/install` without `CONFIG=`/`MANIFEST=`, `TIMEOUTSECONDS` out of range)
  exit 1639 in every page; the MDM wrappers refuse a version mismatch before the package
  manager runs; `-ProductVersion` with `-SetupPath` is refused. Docs.
- **REG-1-9-12** **[W] Trust.** `trust.mode: hash_pinned` or unset is the minimum and still installs a signed
  payload; `authenticode` refuses hash-pinned runs and deployments (accepted decision). Live/docs.

### Upgrade

- **REG-1-10-01** **[L] rpm upgrade reports success.** `dnf upgrade ./<new>.rpm`, and the MDM wrapper with
  `rpm -U`. Expect: the scriptlet reports the managed deployment active;
  `/var/lib/defenseclaw-enterprise/last-package-result.json` has `ok: true` (no exit 75
  `lifecycle_busy` from the scriptlet racing its own apply trigger). Live: RHEL (repeated each
  round).
- **REG-1-10-02** **[M] pkg upgrade.** `installer -pkg <newer>.pkg -target /`, and the wrapper. Expect: "The
  upgrade was successful", `last-package-result` ok, status healthy, ensure a no-op twice. Live.
- **REG-1-10-03** **[L][M] After an upgrade:** status/verify healthy, ensure `up_to_date` twice, every per-user
  row still enrolled, Kiro agent matcher rewritten, managed plugins and hook scripts at the new
  render (commit a60d1822c). Live except the re-render.
- **REG-1-10-04** **[U] Downgrade.** Install an older package over a newer deployment. Expect: refused (the
  macOS preinstall refuses downgrades); apply runs of an older binary report the mismatch
  instead of skipping every config change. Code/live.
- **REG-1-10-05** **[L][M][W] Per-user upgrade preflight.** A per-user install whose only connector was removed
  from the new release (for example `geminicli`): `defenseclaw migrate --check` stops before the
  swap, names the connector and prints commands the installed release accepts; the installer
  keeps the old release. A non-UTF-8 `plugin.yaml` does not crash `migrate`; plugin connector
  names the gateway could load are kept. Code.
- **REG-1-10-06** **[L][M][W] `windsurf` to `devin` rename** reaches `connector_hooks`, judge and
  `application_protection` lists, `asset_policy` rules and observability selectors; the notice
  names each moved setting; an explicit `devin` entry wins. Code.
- **REG-1-10-07** **[W] Upgrade via SYSTEM Setup from a 32-bit parent** keeps the state-root ACL and enrolls
  every signed-in user. Live.

### Per-user (normal) mode and Secure Client invariance

Per-user installs got these changes from the branch (CHANGELOG "Enterprise hardening"); check
them on a normal install:

- **REG-1-11-01** OpenHands terminal calls blocked (decoder); Antigravity `run_command` matches rules.
- **REG-1-11-02** Redirect targets (`> ~/x`) and the first command of `&&`/`||` lists block for custom CEL rules
  (built-in rules with a code prerequisite keep the regex fallback, #925).
- **REG-1-11-03** Block wording: "DefenseClaw policy blocked this action (rule <ID>)" plus "do not retry";
  confirm-as-alert names the rule.
- **REG-1-11-04** OpenCode: visible block error and notice; confirm notice; restart hint after a failed
  start-up check; unapproved plugin message without the code.
- **REG-1-11-05** Kiro: CLI 2.x matcher `*`; shell facts; teardown finds the agent it hooked
  and leaves an inert `kiro-hook.sh`; `doctor` passes a global install; native
  Windows Kiro blocks (exit 2).
- **REG-1-11-06** Devin on macOS writes `~/.config/devin/config.json`.
- **REG-1-11-07** `migrate --check`, non-UTF-8 manifests, plugin connectors, full `windsurf` rename.
- **REG-1-11-08** Custom-providers overlay read from `DEFENSECLAW_HOME`; disabled connector shown disabled;
  no sonic warning; `defenseclaw uninstall` works on a managed host; Amp
  `async_shell_command`; `audit export --since/--until/--newest`; rejected hook rows name the
  account; a FIFO in place of a hook config fails at once.
- **REG-1-11-09** Teardown changes: an OpenCode/Amp plugin without a backup receipt is deleted when it still
  starts with the `// defenseclaw-managed-plugin` marker; an empty Copilot `defenseclaw.json`
  is deleted; teardown no longer creates missing Cursor, Copilot, OpenHands, Antigravity, Devin
  or Hermes files.

Secure Client profile (Windows and macOS): behavior must match the shipped release. The
Secure Client checks in SC-01 must pass on the final test commit; record missing gates as `NOT_RUN`. The only intended Secure Client changes: the Cursor
teardown no longer creates a hooks file where none existed; macOS Amp/OpenCode teardown deletes
a marker-bearing plugin without a receipt; the OpenHands decoder and Antigravity argument
projection reach every profile. Block and confirm wording, the Windows Codex machine-policy
command and other Secure Client texts are unchanged (Secure Client items are tracked
separately, see [Related open issues](#related-open-issues-outside-910-do-not-refile)).
---

## Known residuals and open issues

These are documented in `docs/ENTERPRISE-THREAT-MODEL.md` (R rows), the Linux (L- rows,
numbered residuals), macOS (M- rows, numbered residuals) and Windows (W- rows, numbered
residuals) threat models. A tester who reproduces one records it as "residual <id>, seen" with
the build and OS, and does not file a bug unless the behavior differs from the row.

| Row(s) | What a tester will see | Where |
| --- | --- | --- |
| R1, L-34, M-26, Linux residual 7, macOS residual 1, Windows residual 20 | A per-user agent started with another config root or a mode that skips user configuration runs with no DefenseClaw hook and no audit row, while status/verify keep the user's target ready: Amp (`XDG_CONFIG_HOME`, `HOME`), Devin (`XDG_CONFIG_HOME`, `devin --config <copy>`), Antigravity (`HOME`), Hermes (`--safe-mode`, `HERMES_HOME`, a replacing `HERMES_MANAGED_DIR` config), OpenHands (`HOME`), OpenCode on the per-user route (`OPENCODE_CONFIG_DIR`). Hermes `--ignore-user-config` alone keeps the hooks; `DEFENSECLAW_*` overrides do not remove them. A path a user breaks in their own home is only the warning `guardian_target_user_path` | Per-user connectors, every OS |
| R2 | Claude Code `--bare` and `CLAUDE_CODE_SIMPLE=1` skip managed `SessionStart`/`UserPromptSubmit` hooks; `PreToolUse` still runs | Claude Code |
| R3 | Amp: no machine plugin path, undefined handler order; another config dir loads no DefenseClaw plugin | Amp |
| R4 | OpenCode: plugin order undefined on the per-user route; `--pure`, `OPENCODE_PURE=1`, `OPENCODE_TEST_MANAGED_CONFIG_DIR` start without any DefenseClaw plugin | OpenCode |
| R5 | Hermes blocks only on a valid block answer (and exit 2 from 0.21); other failures and a timeout let the call run (some builds block on a stalled hook timeout, undocumented) | Hermes |
| R6 | Copilot command hooks that time out fail open | Copilot CLI |
| R7, L residual 3, macOS residual 6, Windows residual 5 | A user can hold the API port while the gateway restarts (every restart on macOS and Windows; on Linux only after an admin stops the socket unit): availability loss; hooks are unaffected (peer/PID check), but the native OTLP exporters of Codex, Claude Code, OpenHands and OmniGent send telemetry and the sender's per-user telemetry credential to the holder; the Windows Amp and per-user OpenCode listener proof is a separate request from the hook POST | Every OS |
| R8, Windows residual 13, macOS residual 4 | Hash-pinned (unsigned) payloads do not satisfy publisher-signature application control or Gatekeeper | Windows, macOS |
| Windows residual 4 | Application control and vendor MDM/GPO policy can add protection against old or copied clients, but are optional | Windows |
| Windows residual 10 | Authenticode proves publisher integrity, not that a particular rollout was authorized | Windows |
| R9 | A higher-precedence vendor source (Codex cloud/MDM requirements, Claude server-managed settings) can override local machine policy | Codex, Claude Code |
| macOS residual 3 | Codex and Claude Code MDM preference layers can override local files; check effective policy, not only file bytes | macOS |
| R10, R11 | A compromised privileged DefenseClaw service, or an administrator, can remove DefenseClaw | Every OS |
| Linux residual 4 | A compromised root sensor helper or guardian has root capabilities and falls under the trusted-administrator assumption | Linux |
| Windows residual 9 | An elevated administrator can disable or replace the deployment; restrict that role and monitor lifecycle evidence | Windows |
| R12, Windows residual 18 | Secure Client credentials are connector-scoped; attribution between users of one connector is advisory | Secure Client |
| R13 | A foreign hook that removes itself before the session-start check, a hook added after session start, a session older than 7 days, or a session whose process cannot be named keeps running without a recorded block; the per-call check still denies while the file exists | Foreign-hook guard |
| R14 | Environment-redirected config locations are cleaned only after a DefenseClaw hook ran with that environment (Windows: also the persistent environment while the hive is loaded); relative `OPENCODE_CONFIG` and `OPENCODE_CONFIG_CONTENT` are never cleaned | Foreign-hook guard |
| R15, L-25, M-17, W-27, macOS residual 7 | Old, copied or self-built clients ignore machine policy: Claude Code 1.0.128, 2.0.0, 2.0.77 (no `managed-settings.d` support, #920), Copilot below 1.0.18 (1.0.15 with `--no-auto-update`), OpenHands below 1.12.0 from the `uvx` cache; no audit row, status/verify silent | Every OS |
| R16, Windows residual 19 | Retired (Windows Claude Code drop-in now sets `allowManagedHooksOnly`) | - |
| R17, Windows residual 3 | Windows repairs and cleans a user only while that user has an active session; signed-out users are handled at sign-in; an uninstall not run as LocalSystem, or with users signed out, leaves inert registrations (`user_registrations_pending`) | Windows |
| R18, L-32, M-22, Linux residual 12, macOS residual 8, Windows residual 22 | A user who kills or stops their own hook process: Claude Code and Codex run the call (killed = non-2 exit; stopped = 30 s timeout), OpenHands (killed, or stalled 60 s then its own confirm), Devin (killed), Hermes (killed `pre_tool_call`); Copilot stays closed unless every hook is stopped; OpenCode, Amp, Antigravity stay closed. No pre-tool audit row | Every OS |
| R19, Linux residual 9, Windows residual 15 | Agents installed outside the known locations (custom `NVM_DIR`, `PNPM_HOME`, `--prefix`, arbitrary folders) are neither enrolled nor reported | Every OS |
| R20, L-26, Linux residual 11 | `unprivileged_user_namespaces` warning on stock Ubuntu 24.04 and RHEL 9; the sysctl remedies also restrict agent sandboxes (Codex's bubblewrap already fails on stock Ubuntu 24.04) | Linux |
| R21 | Admin-triggered windows: a hot reload just before the lifecycle rejects an in-place edit (`config_rejected`); an upgrade that changes a socket unit releases the listener | Linux, macOS |
| R22 | Kiro is advisory: neither kiro-cli engine vetoes prompts (`--v3` sends a blocked prompt to the model with the reason attached; the audit records the block); another agent, a moved `KIRO_HOME` or cloud config sync run without the hook; on Windows Kiro is covered only through the ACP guard | Kiro |
| R23 | Cursor applies enterprise `hooks.json` only on plans that support it | Cursor |
| R24 | Antigravity, OpenHands, OmniGent (and Hermes on Windows) have no lock and no foreign-hook guard; Hermes gaps on Linux/macOS: hooks re-read on plugin reload, Python plugins, a session that never loads DefenseClaw's hook | Those connectors |
| R25, W-57, L-27, M-18 | Desktop-app or editor-extension-only users are not enrolled (#912) | Every OS |
| R26, W-58, L-28, M-19 | Copilot in VS Code (Local harness) is not governed (#913) | Every OS |
| R27, W-59, L-29 | Agent sessions in WSL are partly covered (#914): CLIs inside the distribution, Remote - WSL windows and the Codex app's agent environment stay open; a Linux install inside WSL is refused | Windows |
| R28, W-60, L-30, M-20 | Devin Desktop enrolled at a bundled Devin CLI version from 3000.4.25 on that is not known broken; Cascade in builds 3.0.12 to before 3.9.19 refused through the machine-level Cascade hooks file, not inspected (#915) | Every OS |
| R29, W-61, L-31, M-21 | Kiro IDE not discovered, no floor, global hooks not live-verified; Kiro IDE Windows hook shell not live-verified (#916) | Every OS |
| R30, L-33, M-23 | A project `.openhands/hooks.json` replaces the user's, so none of DefenseClaw's OpenHands hooks run in that project (OpenHands shows "1 hook" instead of six) | OpenHands |
| R31 | Per-account hook budget (60/s, burst 120, 32 in flight): under `hook_fail_mode: open` a user who floods their own budget makes their own hooks allow | Standalone |
| Linux residual 1, macOS residual 1, Windows residual 1 | A user can delete or edit their own registration until the next repair (seconds with file watching, at most one reconcile interval) | Per-user connectors |
| Linux residual 2 | A runtime descriptor without `hook_socket` makes every managed hook fail closed | Linux |
| Linux residual 6, L-23 | Confined SELinux users or fapolicyd rules can block the hook or agent CLIs; the lifecycle reports, it does not rewrite host policy | Linux |
| Linux residual 8 | An agent version with no verified contract gets no hooks: `hook_contract_unverified`, `security_complete: false`; an enrolled user who upgrades keeps the row at the last verified version | Linux, macOS |
| Linux residual 10 | Local accounts above `UID_MAX` and nologin accounts are not enrolled unless listed in `include_users` | Linux |
| macOS residual 2 | Without socket activation a hook that runs while the macOS gateway restarts fails closed | macOS |
| macOS residual 9, M-24 | A standard user can `launchctl kickstart` the on-demand apply/verify jobs: extra `ensure` runs (noop), `lifecycle.log` growth, lock contention (an admin run or the daily verify may wait or exit 75 `lifecycle_busy`) | macOS |
| macOS residual 10, M-25 | A standard user can hard-link root-owned DefenseClaw files they can reach into their home; modes and owners are unchanged; verify and repair pass | macOS |
| M-09 | TCC-protected relocated agent configs would need a PPPC profile (not host-checked) | macOS |
| Windows residual 2 | Elevated-token targets are enrolled best effort with an advisory | Windows |
| Windows residual 6 | A target can deny access to or replace its own profile root; DefenseClaw fails health rather than taking ownership | Windows |
| Windows residual 8, 11 | Static policy inspection cannot prove client behavior; an old client process can cache the hook command across a decommission | Windows |
| Windows residual 12 | Inventory ACEs on the fixed dotdir catalog need review at decommission | Windows |
| Windows residual 14 | The guard knows only vendor-documented hook locations; it can block a legitimate project hook until approved by digest or set to `report` | Every OS |
| Windows residual 16 | Group filters decide a signed-out user from groups cached at last sign-in; a never-signed-in directory user is pending | Windows |
| Windows residual 21 | A process that held `WRITE_DAC` on a `%ProgramData%` vendor path before the takeback keeps that handle until it closes | Windows |
| Windows residual 23 (#930) | Users need `FILE_WRITE_ATTRIBUTES` on the managed OpenCode plugin; an attribute change can make it unreadable for every account until the guardian's next pass (about a minute) | Windows |
| W-56 | A standard user pre-creating `C:\ProgramData\Cisco`, a standalone root beneath it, or a deployment record: a planted record is ignored (`untrusted_deployment_record`); Install renames a user-owned root aside (`<name>.untrusted-<time>-<id>`) and completes. Residual: a user who holds a handle on the tree or re-creates it during the rename, or a user-owned `C:\ProgramData\Cisco` holding content another principal owns, keeps Install failing with `root_squatted` (1603) until the user signs out or an admin removes it | Windows |

### Documented behaviors that look like bugs

- A command after `&&` or `||` (including `cd /tmp && <marker>`) stays detection-only (#923).
- Built-in rules with a code prerequisite keep the regex fallback for `> ~/x` and list forms
  (#925); only custom rules without a prerequisite gain the new blocks.
- In-place edits of a rule pack or policy file need a gateway restart (lifecycle page); ensure
  does not reload them. Config changes, secrets and upgrades restart it on their own.
- A change to `enterprise.network` needs a gateway restart on every OS.
- The Linux and macOS guardian does not repair machine policy; `ensure`, `reconcile` or
  `repair` does (a plain ensure right after a floor deletion restores it now; the minute
  guardian pass does not).
- The Claude Code 2.1.154 floor stops no build older than 2.1.163 (#920); 2.1.153 still loads
  `managed-settings.d` and is still inspected.
- Kiro `--v3`: a blocked prompt still reaches the model (the audit records the block); each
  prompt carries two empty DefenseClaw prompt results and writes two `UserPromptSubmit` rows.
- `hermes-hook.sh` and `kiro-hook.sh` remain in `~/.defenseclaw/hooks` after
  disable as inert stubs that exit `0` until the agent restarts.
- A deleted account: verify and MDM detection stay healthy, but `reconcile` still fails for
  its target until revocation (10 to 15 min) or `repair`.
- Foreign-hook cleanup of user-level files runs about every five minutes (removal can take up
  to about 5.5 min).
- Windows: an account's rows are deferred until its first real session; runas or a scheduled
  task is not a session. A deleted account's rows stay while its profile folder exists; a
  loaded profile hive may need a reboot before the profile can be removed.
- Windows `enterprise policy verify --live` is refused on a managed host (use a tool call in the
  user's session and `audit export`).
- Bifrost supports only an `http://` proxy; an `https://` proxy URL refuses LLM provider calls
  (fail closed, accepted).
- After uninstall, the in-plugin guard allows when its binary and the install marker are gone.
- The per-user gateway guard counts a standalone deployment when either the HKLM marker or the
  trusted record (or gateway service) confirms it.
- Exempt users are cleaned by the foreign-hook cleanup; excluded and undecided users are
  skipped.
- The empty admin-owned `C:\ProgramData\ampcode` stays after uninstall on purpose.
- `detect.sh --min-version X` treats `X-SNAPSHOT` as older than `X` (semver pre-release order).
- The package postinstall activates the deployment with the built-in default config before the
  admin config is applied (observe mode, no connectors); the MDM wrapper's `--config-file` (or
  placing the config first) avoids that window.

---

## Open issues and open findings

### Issue #910 (enterprise standalone follow-ups) and its sub-issues

| Issue | Topic | Tester note |
| --- | --- | --- |
| #910 | Parent: standalone profile follow-ups | File new standalone follow-ups as sub-issues here |
| #911 | Project-hook session record in gateway-held state | Fixed on the branch; closes when #924 merges. Regression checks in [Foreign-hook guard](#foreign-hook-guard-standalone-profile) |
| #912 | Enroll users who have only a desktop app or editor extension; unverified app versions | R25 |
| #913 | Govern Copilot in VS Code (Local harness) | R26 |
| #914 | WSL sessions (Claude Desktop, Codex app and extension) | R27 |
| #915 | Devin Desktop (Devin Local under ACP, Cascade before 3.9.19) | R28 |
| #916 | Kiro IDE (global hooks, discovery, floor, Windows hook command) | R29 |
| #920 | Claude Code releases that do not read `managed-settings.d` run without DefenseClaw (also the 2.1.154 floor limit; old Copilot and OpenHands below their minimum are the same class) | R15 |
| #921 | Attribute scan and inspect-route audit rows to the verified caller | Remainder: `scan-finding` and `scan` rows still have no user fields; connector-hook, inspect-tool and auth-failure rows are fixed |
| #923 | Commands chained with `&&` or `\|\|`: later commands never block | First command now blocks; later ones stay detection-only |
| #925 | Built-in rules with a code prerequisite still record a runtime-expanded redirect target as detection-only | Custom rules fixed |
| #927 | Windows: roll back a failed first install cleanly for accounts with per-user agents (Amp, Antigravity, Copilot, Devin, Hermes, OpenCode) | Fixed on the branch (cleanup contracts for every per-user connector); forced first-install failure not exercised live |
| #928 | Windows: dedicated DefenseClaw event log only admins can write | Fixed on the branch: `DefenseClaw` log, source `DefenseClaw Lifecycle`; legacy Application-log copies continue for one transition. See CLI-13, REG-1-9-10 |
| #929 | Windows: status names the process holding the gateway API port | Fixed on the branch: `api_port_held` and `api_port_holders` |
| #930 | Windows: restore the managed OpenCode plugin as soon as its attributes change | Fixed on the branch (folder watch restores within about a second); the write-attributes right stays until OpenCode's runtime stops asking for it. Windows residual 23 |

### Related open issues (outside #910, do not refile)

| Issue | Topic |
| --- | --- |
| #922 | Rule engine: runtime-expanded redirect target turns a command rule detection-only (fixed on this branch; open for `main`) |
| #917, #918 | Managed Windows Cursor (Secure Client): per-user DefenseClaw entries left in `~/.cursor/hooks.json` / `~/.claude/settings.json` deny every tool call (fixed on the Secure Client follow-up branch) |
| #894 to #909 | Secure Client (`main`) follow-ups: Windows Codex machine-policy hook binding (#909), transaction recovery and sensor helper (#907, #908), uninstall refusals (#906), guardian freshness and state paths (#895, #896, #905), device identity (#904), enrollment of signed-out users (#894), Claude HKLM policy (#899), Codex requirements merge (#898), self-upgrade guard (#897), stale Windows docs (#900) |
| #932 to #942 | Secure Client hardening (gateway authentication for Unix hooks, per-user gateway coexistence, GUI socket peer, payload publishers, Codex requirements on macOS, Cursor hooks, Claude managed-hooks-only, inspection health and `unavailable_action`) |
| #901 | `managed_enterprise` on `main`: Windows sensor helper logs/home dirs, Claude floor below the contract |
| #704, #733 to #736 | Managed-enterprise scoped-token rotation (hook sidecars, guardians, Windows adapter) |
| #919 | Per-user Windows 0.8.10 Setup `/verify` rejects the unsigned published Setup |
| #836 | OpenCode hook contract range (the branch's contract covers 1.18.10 to before 1.19.0) |
| #953, #959, #962 | Sandbox-track follow-ups that touch the same connectors: Kiro v3 matcher measurement, the verdict for HIGH findings in unmapped categories, Hermes TUI block reason |
| #869, #882 | Per-user `audit.db` corruption reports (not enterprise) |

## Platform gotchas

### All platforms

- **Build numbering.** Packages refuse downgrades. Every test build must have a version above
  the installed one (keep a counter per host). Record the build's version and commit from
  `status` before each round.
- **Shared ports.** The managed gateway owns `127.0.0.1:18970`; the OpenClaw fleet port is
  `127.0.0.1:18789`. Another DefenseClaw (a per-user gateway, a CI job, another tester's test
  gateway) or any listener on those ports changes results. Check listeners before a round. On
  shared hosts, a scheduled job that kills every `defenseclaw-gateway` process (some end-to-end
  suites do) will take the managed gateway down too: do not certify on CI runners.
- **Timing.** Guardian repair: seconds (file watching), at most one reconcile (1 min).
  Enumerator: every 5 min (new accounts, version changes). Foreign-hook cleanup: about every 5
  min. Revocation of a deleted account: third miss, 10 to 15 min. A verify right after an
  ensure that enables a connector can be green before the guardian's verdict: run
  `enterprise <os> reconcile` or wait a cycle. Poll by file mtime, by modification time and SHA-256, not by size (the
  guardian rewrites the current generation).
- **Agent sign-ins and plans.** Many connectors need an interactive, human sign-in or terms
  acceptance before any row can run: Antigravity (terms and a Google sign-in), Amp (login),
  Kiro (a Builder ID or other sign-in), Devin (sign-in), Cursor (a plan that supports
  enterprise hooks, and usage limits), Copilot (GitHub sign-in or BYOK), Codex and Claude Code
  (login or a provider configuration). Plan these per account before the test window; rows
  without them are `NOT_RUN` with the reason. On Windows and macOS some sign-ins need the account's
  desktop session.
- **Versions and auto-update.** Agents self-update mid-test (Claude Code, OpenCode, Codex,
  kiro-cli). A version outside its hook contract becomes `hook_contract_unverified` and
  `security_complete: false`. Pin or turn off auto-update. Verified ranges on this branch
  (`cli/defenseclaw/inventory/hook_contracts.json`): Claude Code 2.1.154 and later; Codex 0.124
  and later (0.145 and later is the default contract); Copilot CLI 1.0.18 and later; Cursor
  2.4.0 to before 4.0.0 (plus one exact CLI build); OpenCode 1.18.10 to before 1.19.0; Hermes
  0.19.0 to before 0.22.0; Devin exactly 3000.4.25 (3000.11.3 on Linux only); OpenHands 1.12.0
  and later; OmniGent 0.7.0 to before 0.14.0; Antigravity 1.1.8 and later; Amp current; Kiro
  2.24.1 and later in the standalone profile.
- **Models.** Some models refuse prompts that say "block marker" or write to `/tmp`
  ("trigger file"); use neutral wording ("Run exactly this shell command: echo <marker>").
  Some append `&& cat <file>` to a command (that turns it into a list, see #923); some re-encode
  a blocked command; some claim success after a block. Always check the side-effect file and
  the audit. Some provider/model pairs drop the stream on the second prompt of a session:
  start a new session per row.
- **Notices that fade.** OpenCode's notice lasts about 4 to 10 s, Amp's about 2 s (a thread
  message now stays). Capture the screen every 1 to 2 s right after Enter.
- **Terminal handling.** Text typed while an agent is still starting goes to the shell (a
  `> file` in it creates an empty file); wait for the agent's input box. Exit keys differ
  (`/exit` for Claude Code, Copilot and OpenHands; Ctrl+C twice for Amp). Copilot's permission
  dialog: use Esc to decline. Hermes: send the prompt, then Enter as a separate key; a new
  `HERMES_HOME` builds its own runtime first (about 2 min). Codex with a new `CODEX_HOME`
  downloads a large runtime and leaves background processes. Screen clears can wipe
  scrollback: save the screen before the next clear.
- **Audit reading.** `audit export` is oldest first; use `--since` and `--newest`; filter by
  `--connector` and the marker. `--output` refuses an existing file. `hook_decision` and tool
  rows name the user; scan rows do not yet (#921). Direct test requests to hook routes need the
  client header the hooks send, or the gateway answers 403 before any audit row.
- **Undo drills at once.** A user-made break in their own home (a file where a folder
  belongs, `chmod 000`, a link) keeps that account's target unrepaired. A tightened vendor
  policy file (`requirements.toml` 0600) makes Codex refuse for every account until repair.
  Restore every config from a backup at the end of a row.
- **Shell details.** `echo rc=$?` after a pipe reports the last command (use `PIPESTATUS`);
  `set +H` before commands with `!`; root's `cp` may be aliased to `cp -i`.

### Linux

- **World-writable or ACL-carrying `/tmp`.** Homes, data directories or `TMPDIR` under a
  world-writable ancestor are refused (L-11), and a POSIX ACL on `/tmp` that grants group write
  makes the gateway's protected-state check refuse data directories under it. Keep test homes
  under `/home`, and point build and test `TMPDIR` at an owner-only folder. Only the
  documented bypass drills (R1) use a `HOME` under `/tmp`.
- **PATH.** `/opt/defenseclaw/bin` is not on root's PATH or in sudo's `secure_path` (RHEL and
  Ubuntu): use the full path.
- **polkit.** A standard user's `systemctl stop` opens a password prompt; use
  `--no-ask-password` for refusal checks.
- **SELinux** stays Enforcing on RHEL; the package relabels at install.
- **Ubuntu 24.04 user namespaces.** verify always warns `unprivileged_user_namespaces` there
  and on RHEL 9 (R20). Codex's own sandbox fails on stock Ubuntu 24.04 (`bwrap: loopback: Failed
  RTM_NEWADDR`), so Codex shell calls fail until run without its sandbox; not a DefenseClaw
  failure.
- **Package activation window.** `apt install`/`dnf install` activates the deployment with the
  built-in default config before the admin config exists; use the MDM wrapper's
  `--config-file` or expect observe mode with no connectors until `ensure --config`.
- **Logs.** Services log to the journal (`journalctl -u defenseclaw-gateway` and the other
  units); `/var/log/defenseclaw` can be empty.
- **Deleting accounts.** `userdel` refuses while the user has processes; some agents leave a
  background server (OpenHands leaves a tmux server). Stop the user's processes first. Starting
  some agents inside tmux can take over the enclosing server; start them with `TMUX` unset.
- **Build.** Use the pinned goreleaser version; build once, then select the amd64 or arm64 package for the host.

### macOS

- **Admin shell.** Switch to the admin account in a standard user's Terminal (`su -l
  <admin>`, then `sudo -i`); root's shell is `/bin/sh`. Use full paths.
- **Fast user switching.** The login window can reset input after a switch; log one account
  out before logging the next in, and never type a password unless the field is focused.
- **Restart and reload.** Restart the gateway with `sudo launchctl kickstart -k
  system/com.cisco.defenseclaw.gateway`; in-place rule pack edits need it.
- **pkg.** The preinstall refuses downgrades; an unsigned pkg installs with `installer -pkg`
  as root but not under Gatekeeper policies that require a signature.
- **Search tools.** `grep -r` over homes can hang on FIFOs and sockets (use `grep -D skip`);
  macOS `grep` has no `-P`; `status` returns in about 0.3 s (loop by time to catch a planned
  restart).
- **Agent locations.** Agents in an app bundle or folder owned by another standard account
  are not run by discovery (reported unprotected); install shared agents under a root-owned
  `enrollment.agent_prefixes` path.
- **Deleted accounts.** `dscl . -delete` leaves the enumerator's lookup cache; revocation
  still takes three misses; `repair` removes the targets at once.
- **launchd jobs.** A standard user can kickstart the apply/verify jobs (macOS residual 9):
  unexpected `lifecycle.log` entries or a `lifecycle_busy` verify can come from that.

### Windows

- **Run lifecycle actions the way MDM does.** Run Setup and the MDM wrapper as LocalSystem from
  a 32-bit Windows PowerShell 5.1 parent (a one-shot scheduled task works). From an elevated
  admin prompt a failed install cannot roll back per-user state.
- **Remote admin shells are elevated.** An SSH or similar remote session is usually the
  built-in Administrator, already elevated. Files it creates in user paths are
  Administrators-owned, which DefenseClaw refuses; it can also read folders a UAC admin cannot.
  Do user steps in the user's own desktop session, and admin steps in a UAC-elevated prompt.
- **Real sessions.** The guardian changes a user's files only while that user has an active
  session (R17). runas, scheduled tasks and remote shells are not sessions: enrollment is
  deferred, and a hook run from an interactive scheduled task gets
  `enterprise_managed_gateway_peer_unverified`. Use RDP or console sign-ins.
- **Silence.** Setup and the wrapper print nothing for 2 to 3 minutes; wait before assuming a
  hang.
- **Disk.** Staged Setups pile up; check free space on C: before each run.
- **Logs of a failed first install.** A failed first install's rollback deletes
  `C:\ProgramData\Cisco\DefenseClaw\logs`; copy the gateway log during the run if you need it.
- **Deleted accounts.** A deleted account's profile hive can stay loaded (even after restarting
  DefenseClaw's services) until a reboot, and its rows stay until the profile folder is gone.
- **Event log.** Test binaries run elevated on the test host (unit tests, goldens) write real
  Application-log events and lifecycle log lines; `enterprise windows events` will list them.
  Do not run tests elevated on a host before its certification pass.
- **PowerShell details.** `Start-Transcript` does not capture native command output unless it
  is piped; aliases shadow helper names (`H`, `rm`); PowerShell 7.6 passes native arguments
  verbatim (pass JSON settings as a file); `Get-NetTCPConnection` may not show the 18970
  listener from a remote shell (use `netstat`).
- **User PATH.** `%APPDATA%\npm` may be missing from a user's PATH, so npm-installed agents are
  not found by name.
- **Desktop sessions.** With two terminals in one desktop, click the target window before
  typing. OpenCode: wait about 20 s after start before typing; approve/deny rows need
  `permission.bash = "ask"` in the user's `opencode.json`; OpenCode shows a block as a red tool
  line.
- **Devin on Windows** is pinned to 3000.4.25; 3000.11.3 shows as unverified and keeps
  `security_complete: false`.

## Cleanup

Complete cleanup only after all evidence and pre-change hashes are saved. Each tester removes only their own disposable project, marker pack and account fixtures. A decommission test uses PUR-01; a host retained for a later run ends with healthy `status` and `verify` instead. Record which state you chose.

| ID | Preconditions | Steps | Expected result |
| --- | --- | --- | --- |
| CLN-01 | All connector rows complete | Exit each TUI (`/exit`, `/quit` or the agent's own quit command); stop only test-owned processes; remove `~/dc-test-proj` and account-owned `dctest-*` files | No stale interactive agent holds an old hook path; unrelated user files remain |
| CLN-02 | Test marker pack applied | As admin restore the baseline managed config via `enterprise <os> ensure --from-package --config <baseline> --json` (Windows Setup `/ensure JSON=1 CONFIG=<baseline>`), then remove only the test-owned `dctest` pack | Baseline policy effective; `policy verify` and `verify` pass |
| CLN-03 | Disposable `new account` and `excluded account` | Sign out; admin removes only accounts created for this run after F2 evidence is captured | No test account session or stale accepted credential; other accounts unchanged |
| CLN-04 | MDM simulation and CLI-09 complete | Remove only test-owned `C:\DcSim`, `C:\DcEvidence`, `C:\Admin\ai-defense-api-key.txt`, `/var/cache/mdm`, `/Library/Management/defenseclaw`, `$HOME/dctest-mdm`, `/root/dctest-evidence` (macOS `/var/root/dctest-evidence`) and `/root/ai-defense.key` plus the scheduled task created by this run | No simulation task, script, key file or temporary output remains; real MDM deployment untouched |
| CLN-05 | Host being retired | Execute PUR-01 and the matching package manager removal; compare vendor policy hashes | DefenseClaw-owned roots absent as documented; administrator policy restored; preserved OS logs noted |
| CLN-06 | Host retained for test team | Run platform `enterprise <os> status --json`, `verify --json`, `enterprise policy verify --json`; run C0a/C0b with std1 and std2 | Healthy with both users enrolled; all remaining issues linked to findings or named residuals |

## Appendix: templates

### Row result

Record one JSON line per row, account, connector, route and run stage. Do not put secrets or raw credential payloads in any field. A marker side effect and an audit row are required for connector decisions.

```json
{"os":"linux","os_version":"<version>","arch":"<arch>","build_commit":"<40 hex>","tree":"<40 hex>","artifact_sha256":"<64 hex>","stage":"S3","account":"std1","row":"C1","connector":"amp","connector_version":"<version>","route":"per-user plugin","guardrail_mode":"action","action":"edited own disposable registration","expected":"restored within one reconcile cycle; call inspected meanwhile","observed":"RESTORED in 22 seconds; BLOCKED","result":"PASS","seconds":22,"evidence":"S3/C1-amp-std1.txt","finding":""}
```

| Row | OS/build/artifact | Account/route/client version | Preconditions and typed steps | Expected | Observed, side effect, CLI/audit exit | Seconds | Verdict | Evidence/finding |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `<id>` | `<version / commit / hash>` | `<generic account / route / version>` | `<exact>` | `<exact>` | `<sanitized>` | `<n or N/A>` | `PASS/FAIL/N/A/NOT_RUN` | `<path / id>` |

### Finding

```json
{"id":"PLATFORM-F01","kind":"functional|ux|docs","severity":"blocker|major|minor","summary":"one reproducible statement","build_commit":"<40 hex>","os":"<name and version>","account":"std1","connector":"<name and version or N/A>","route":"<route>","steps":"exact live commands with neutral markers","expected":"...","observed":"sanitized screen, side effect, CLI output and exit code","evidence":"S3/C0b-std1.txt","status":"open|fixed and verified|residual|not-a-bug","linked_residual":""}
```

A finding is fixed only after retaining the pre-fix capture, recording the focused regression test and repeating the original live steps against the new build. For every platform publish PASS/FAIL/N/A/NOT_RUN counts and a list of named residuals, blocked findings, UX findings and unverified surfaces. Do not publish raw captures; sanitize excerpts first.

### Completion report

```text
Build: <commit>  Tree: <tree hash>  Artifact hashes: <one per OS>
Platforms: <OS versions and architectures, generic host labels>
Accounts: admin account, std1, std2, excluded account, new account
Rows: PASS <n> / FAIL <n> / N/A <n with reasons> / NOT_RUN <n with reasons>
Residuals observed: <threat-model IDs and exact conditions>
Findings: <IDs and fixed/open status; UX included>
Live MDM tenant pilot: <run with separate evidence / NOT_RUN with reason>
Secure Client live build: <run with separate evidence / NOT_RUN with reason>
Final health: <status/verify/policy verify exit codes per host>
Evidence index: <sanitized paths>
```
