# Management agent contract (management_contract 1)

A management agent is a vendor process that runs as root (Linux, macOS) or
LocalSystem (Windows) and manages DefenseClaw on a standalone enterprise
device, the way an MDM does. This file is its contract: the commands it runs,
the JSON they print, the exit codes, the locks and the rules for retries and
crashes. The MDM kits in `packaging/mdm` follow the same rules.

The agent starts the existing `defenseclaw-gateway` binary as a child process
with `--json`. Nothing new listens and no route is added to the running
gateway.

## 0. What the agent builds against

- **No server, no HTTP.** The gateway HTTP API (TCP and the hook socket), its
  token in `.env`, `/health`, `/policy/reload` and `/api/v1/admin/shutdown`
  are not part of this contract and must not be used. The managed gateway
  runs as an unprivileged service account, cannot write policy, and is
  restarted by an apply, so it is not a management endpoint.
- **Trust.** The operating system decides who may run the mutating commands
  (root, an elevated administrator, SYSTEM). Policy content is trusted only
  through the tenant signature, which the device checks against its installed
  trust anchors. A management agent is as trusted as an MDM agent:
  DefenseClaw guarantees signed policy and fail-closed enforcement for the
  agent sessions that loaded its hooks, not least privilege for the agent. An
  agent session already running when a bundle enables or changes its
  connector is not enforced until it restarts (4.3, sessions that need a
  restart).
- **No audit of trust anchor and credential changes.** DefenseClaw records
  bundle applies (receipts, the `config.bundle.receipt` audit event and
  OTel). It does not audit trust anchor installs (by the MDM kit, by Windows
  `ensure --trust-anchors` or by `bundle anchors install`) or
  `secret set` / `remove`. The agent reports those changes itself: the
  anchors install result carries `sha256`, `previous_sha256` and `key_ids`,
  and `secret status --json` carries `sha256_prefix`.

| Schema (this folder) | `$id` | Validates |
|---|---|---|
| `version.schema.json` | `.../enterprise/management/version-v1.json` | `--version-json` stdout |
| `bundle-verify.schema.json` | `.../enterprise/management/bundle-verify-v1.json` | `enterprise bundle verify --json` |
| `lifecycle-result.schema.json` | `.../enterprise/lifecycle-result-v2.json` | `bundle apply`, `<os> status`, `<os> ensure`, Linux and macOS `secret set` / `remove` |
| `bundle-refused.schema.json` | `.../enterprise/management/bundle-refused-v1.json` | `bundle apply` refused before the lifecycle ran; Windows `bundle status` `not_admin` |
| `bundle-status.schema.json` | `.../enterprise/management/bundle-status-v1.json` | `enterprise bundle status --json` |
| `secret-result.schema.json` | `.../enterprise/management/secret-result-v1.json` | `enterprise secret set` / `remove` / `status --json` |
| `anchors-install.schema.json` | `.../enterprise/management/anchors-install-v1.json` | `enterprise bundle anchors install --json` (Linux, macOS) |
| `bundle-receipt.schema.json` | `.../enterprise/management/bundle-receipt-v1.json` | the files `<etc>/bundles/receipt.json` and `<etc>/bundles/receipt-events/<receipt_id>.json` |
| `bundle-anchors.schema.json` | `.../enterprise/management/bundle-anchors-v1.json` | the trust anchor file the agent supplies (input) |

Every `$id` starts with `https://defenseclaw.cisco.com/schemas/enterprise/`.
The schemas are Draft 2020-12 and closed (`additionalProperties: false`), so
DefenseClaw's contract tests catch drift. The agent itself must **ignore
members it does not know**: a new optional member is added without a
`management_contract` bump; removing or changing a member, a command, a flag
or an exit code bumps it.

`exit-codes.md` lists the exit codes and the MDM wrapper codes;
`detection.md` covers inventory detection.

## 1. Binaries and paths

| | Linux | macOS | Windows |
|---|---|---|---|
| CLI | `/opt/defenseclaw/bin/defenseclaw-gateway` | `/opt/cisco/defenseclaw/bin/defenseclaw-gateway` | `<InstallRoot>\bin\defenseclaw-gateway.exe`; `InstallRoot` from `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise` (64-bit view), default `C:\Program Files\Cisco\DefenseClaw` |
| `<os>` command group | `linux` | `macos` | `windows` |
| `<etc>` | `/etc/defenseclaw` | `/opt/cisco/defenseclaw/etc` | `C:\ProgramData\Cisco\DefenseClaw\etc` |
| Trust anchors | `<etc>/trust/bundle-anchors.json` | same | same |
| Public receipts | `<etc>/bundles/receipt.json`, `<etc>/bundles/receipt-events/*.json` | same | same |
| Lifecycle state (root only) | `/var/lib/defenseclaw-enterprise` | `/opt/cisco/defenseclaw/lifecycle` | `C:\ProgramData\Cisco\DefenseClaw\install` |
| Locks | `<lifecycle>/lifecycle.lock` (flock) | same | `<lifecycle>\bundle.lock` (LockFileEx), then the installer's `lifecycle.lock` |

The sibling `defenseclaw` / `defenseclaw.exe` is the same Go CLI; both names
work.

Keep the bundle and anchor files the agent downloads in a folder that only
root or SYSTEM can write, and pass absolute paths. Never put a credential in
argv, an environment variable or a file the CLI reads: use stdin.

The anchors source is checked, not trusted. `bundle anchors install` (Linux,
macOS) and Windows `ensure --trust-anchors` refuse a file that is a link, or
whose file or any folder above it a non-root (non-administrator) account can
write (`anchor_insecure`, nothing written). So the folder must be root-only
from the start:

- Linux: `install -d -o 0 -g 0 -m 0700 /var/lib/<vendor>/trust`. macOS:
  `install -d -o 0 -g 0 -m 0700 "/Library/Application Support/<vendor>/trust"`.
  Every folder above it must be root-owned and not group or other writable,
  which `/var/lib` and `/Library/Application Support` are. On macOS `/var`
  and `/tmp` are links to `/private/...`, so a source under them is refused
  `anchor_insecure`; the `/var/lib/<vendor>` paths in the examples below are
  Linux paths.
- Windows: standard users can create subfolders of `C:\ProgramData`, so a
  user can pre-create the agent's folder and own it. Create the folder
  yourself, as SYSTEM, before the first download, with a protected DACL (no
  inherited entries; full control for SYSTEM and Administrators only), and
  refuse to use it if it already exists with another owner, an unprotected
  DACL or a write right for any other account. Compare SIDs, not names
  (account names are localized):

```powershell
$dir = 'C:\ProgramData\<Vendor>'
$sid = [System.Security.Principal.SecurityIdentifier]
$trusted = @('S-1-5-18', 'S-1-5-32-544')   # SYSTEM, Administrators
# Write data, append data, write attributes and extended attributes, delete,
# delete child, change permissions, take ownership, generic write, generic all.
$writeRights = 0x500D0156
$created = -not (Test-Path -LiteralPath $dir)
if ($created) {
  # Stops when the folder appeared since Test-Path (someone else created it).
  New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
} else {
  $acl = Get-Acl -LiteralPath $dir
  $writers = @($acl.GetAccessRules($true, $true, $sid) | Where-Object {
    $_.AccessControlType -eq 'Allow' -and ([int64]$_.FileSystemRights -band $writeRights) -and $_.IdentityReference.Value -notin $trusted })
  if ($acl.GetOwner($sid).Value -notin $trusted -or -not $acl.AreAccessRulesProtected -or $writers.Count) { throw "untrusted $dir" }
}
$sd = New-Object System.Security.AccessControl.DirectorySecurity
$sd.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $dir -AclObject $sd
# Until Set-Acl the new folder inherited C:\ProgramData's entries, which let
# users add files: a folder this script created must still be empty.
if ($created -and (Get-ChildItem -LiteralPath $dir -Force | Select-Object -First 1)) { throw "untrusted $dir" }
```

Otherwise an account that can write the download folder could swap the trust
anchors between download and install. The check then fails closed
(`anchor_insecure`), which blocks rotation until the folder is fixed.

## 2. General rules

### 2.1 Reading a result

1. Read stdout to EOF and the exit code. Never parse stderr or text output;
   always pass `--json`.
2. If stdout is exactly one JSON document, `ok` and `errors[].code` decide,
   and the exit code agrees (lifecycle result v2 also carries it as
   `exit_code`).
3. If stdout is empty or not one JSON document, classify by the exit code
   alone (section 2.3 lists when that happens).
4. `errors[].code` and `warnings[].code` are stable machine codes; `message`
   is for humans and may change. The bundle codes are in
   `internal/enterprisebundle/errors.go`, the Linux and macOS lifecycle codes
   in `internal/enterpriseunix/lifecycle.go`.

### 2.2 Exit codes and retry classes

| Exit | Linux / macOS | Windows | Class | Agent action |
|---|---|---|---|---|
| `0` | success or nothing to do | success | done | use the result |
| `75` | another lifecycle run holds the lock (`lifecycle_busy`), or a `bundle apply` whose gateway stopped reporting the bundle's policy before the receipt was confirmed (`not_confirmed` with `bundle.state` `applied`, section 4.3) | — | **retry** | back off (30 s, doubling, at most 10 min) and resubmit the same input |
| `1618` | — | `lifecycle_busy` (`bundle.lock` not free within `--lock-wait`, or the installer's `lifecycle.lock` not free within its fixed 30 s), or a verified bundle that did not finish applying (`bundle_apply_failed`, `bundle_policy_not_adopted`, `bundle_post_verify_failed`, `bundle_targets_refresh_failed`) | **retry** | as for 75 |
| `1` | failure, already rolled back; or a refusal | builds without `management_contract` only: a flag error on `enterprise secret` (section 2.3) | **final** | read `errors[].code`; do not retry until the bundle, anchors, credential or device changes |
| `1603` | — | failure, already rolled back; or a refusal | **final** | as for 1 |
| `2` | invalid arguments | — | **final, caller bug** | fix the call |
| `1639` | — | invalid arguments | **final, caller bug** | fix the call |
| `5` | — | `elevation_required`: not SYSTEM and not elevated | **final, deployment bug** | the agent is not running as LocalSystem |
| `3010` | — | reserved (success, reboot required); not returned today | done | treat as 0 |
| any other code, or killed by a signal | | | **unknown** | do not resubmit blindly; reconcile (section 5.1) |

A refusal is final even when the same bytes are resubmitted:
`version_not_newer`, `signature_invalid`, `key_unknown`, `secret_ref_missing`,
`digest_mismatch`, `capability_loss` and the rest repeat until the input
changes.

One 1603 is not final: Windows `secret set` / `remove` with `errors[0].code`
`restart_failed` changed the stored credential but did not restart the
gateway, which still runs with the old one. Resubmit the same call (it writes
and restarts again) even though `sha256_prefix` now matches (section 2.5).

One 1 is not final: Linux and macOS `secret set --from-stdin` with the
schema-1 failure document and `errors[0].code` `change_failed` stored nothing
because its value never arrived whole: the agent exited before it sent the
complete value, or no value ended within 60 s (the agent stopped sending
without closing stdin). Resubmit the same call once the agent runs again:
after its restart, or once a stopped agent continues (section 2.4). It is
not a busy retry, so no back-off: the call fails again only if the agent
stops again before it sends the value.

### 2.3 When stdout carries no JSON

These fail before a result document exists: stdout is empty, one line goes to
stderr, and the exit code is the only signal.

| Case | Exit |
|---|---|
| Unknown flag, malformed value or stray argument on a lifecycle verb | 2 / 1639 |
| `bundle apply` without `--bundle`; with both `--bundle` and `--inbox` (Linux, macOS); with `--inbox` (Windows) | 2 / 1639 |
| `--lock-wait` outside 0 to 15m: every Linux and macOS verb but `bundle anchors install` (which prints a JSON `invalid_arguments` document), and Windows `bundle apply` | 2 / 1639 |
| `bundle apply --delivery-id` empty, over 128 bytes, or with a byte outside `A-Z a-z 0-9 . _ : -` (2.6) | 2 / 1639 |
| `--version --json` (the flag is `--version-json`) | 2 |
| Windows `secret set` / `remove` / `status` on a build without `management_contract`: every failure (5, 1639, 1603), and `--lock-wait` on set or remove (an unknown flag there, exit 1) | 5 / 1639 / 1603 / 1 |

`bundle verify` and `bundle anchors install` print JSON for their own
argument errors (`errors[0].code` `invalid_arguments`, exit 2 / 1639);
`bundle apply` does not (the rows above). With
`management_contract` 1, `secret set`, `remove` and `status` print a JSON
document on every outcome on every OS (section 4.7): on Linux and macOS a
flag, argument, privilege, value or stdin read error prints the schema-1
failure document of `secret-result.schema.json` (exit 2 `invalid_arguments`,
or exit 1 `not_root`, `change_failed` or `state_invalid`).

### 2.4 Child process rules

- Start the CLI directly as the agent's own child: no shell, `systemd-run`,
  `nohup`, double fork or other wrapper that exits before the CLI does.
  Linux and macOS `secret set` refuse to store a credential when their parent
  changed while they read the value or waited for the lock (`errors[0].code`
  `change_failed`),
  and a wrapper that exits makes init the parent. Windows has no such rule.
- Run long commands on a worker thread. An apply blocks for its lock wait plus
  the transaction and the confirm step (usually under 2 minutes, plus up to
  15 minutes of lock wait). Do not kill a child on a timeout; stop waiting,
  then reconcile (section 5.1).
- The agent's own stop must not kill a running child. Keep the child in the
  agent's cgroup or process group and stop only the agent process: systemd
  `KillMode=process` on the agent's unit, launchd `AbandonProcessGroup=true`,
  and on Windows no job object with kill-on-close. Do not start children
  outside the agent's cgroup to get this (that needs a wrapper). When the
  agent stops, a running `bundle apply` finishes and writes its receipt; a
  Linux or macOS `secret set` still reading its value (the agent's end of the
  pipe closes early) or waiting for the lock sees its parent gone and refuses
  without storing (`change_failed`, exit 1, one JSON document), and the agent
  re-sends the
  credential after its restart (section 5.2). An agent that is stopped (for
  example `SIGSTOP`) or leaves stdin open without sending does not hold
  `secret set` forever: it gives up after 60 s with the same `change_failed`. A Windows `secret set` waiting
  for its locks stores the value after the agent stopped, and the agent does
  not see whether its restart worked: re-send it after the agent's restart
  (2.5). A killed child leaves an interrupted
  transaction; managed hooks fail closed until the next mutating run
  recovers it. Status shows it: once no run holds the lock, `enterprise <os>
  status` reports `transaction_pending: true`, and a bundle receipt the
  killed apply left unfinished adds the warning `bundle_pending` (4.4). Run
  4.6 ensure when status shows `transaction_pending: true` and no apply child
  of the agent's own is still running (5.1).
- One mutating call at a time per device is enough; the device serializes
  them anyway (section 6).

### 2.5 Secrets

Credentials go only through `enterprise secret set --name N --from-stdin`
(section 4.7). Bundles carry no secrets: a bundle lists `secret_refs`, and
apply refuses with `secret_ref_missing` until each named credential is
stored. Send the value as one line without surrounding whitespace and close
stdin, within 60 s of starting the command on Linux and macOS
(`change_failed` after that). Linux and macOS strip one trailing `\n` or `\r\n` and keep other
spaces; Windows trims all surrounding whitespace. On Linux and macOS a value
that ends without `\n` (`printf '%s'`) makes `secret set` wait up to 1 s to
tell an agent that exited while it sent the value from one that is done. At most 16 KiB. Names match
`^[a-z0-9][a-z0-9-]{0,62}$`.

Send a credential **only when it changed**. Every Windows `set` restarts the
gateway (managed hooks fail closed while it restarts), and there is no
identical-value no-op. Compare first with `enterprise secret status --json`
(no lock, read-only): `sha256_prefix` is the first 12 hex characters of the
SHA-256 of the stored value. Hash the value the way the device stores it: on
Windows with surrounding whitespace trimmed, on Linux and macOS without the
one trailing newline. Equal prefix: skip the call, unless the agent's last
call for that name did not end with exit 0. After a Windows `restart_failed`
(2.2), or an unknown outcome (a killed child, a `secret set` still waiting
when the agent stopped, 2.4), the value can be stored while the gateway runs
with the old one: resubmit even when the prefix matches.

### 2.6 `--reason` and `--delivery-id`

`--reason` is not recorded anywhere a caller can read: the result has no
reason field, and receipts carry `actor`, the OS account that ran the
apply (`os:uid:0:root` on Linux and macOS, `os:sid:S-1-5-18:<name>` for
LocalSystem on Windows), which is the same for MDM and agent alike. On Linux
and macOS some values switch modes: `path` takes a bundle from the inbox and
runs the path unit's logic, and `package` runs the package and tamper
handling. The agent passes `--reason management` or no `--reason`; `path`,
`package`, `secret` and `mdm` are reserved for DefenseClaw's own units,
packages and kits. Windows accepts the flag and ignores it, so one argv works
on every OS.

`--delivery-id <id>` (every OS) records an opaque id the caller chooses for
one delivery: 1 to 128 bytes of `A-Z`, `a-z`, `0-9`, `.`, `_`, `:` and `-`
(no space, no control character; a bad or empty value is an argument error,
section 2.3). It is written as `delivery_id` on the receipt and appears in
`receipt-events/<receipt_id>.json` and `receipt.json` (also in their
`last_refusal`), in the result `bundle` and `last_refusal` blocks, and in
`bundle status` (`current`, `last_good`, `last_receipt`, `bundle`,
`last_refusal`; `current` and `last_good` keep the id of the apply that
confirmed them after its receipt is pruned). Without the flag no
`delivery_id` member is written and every output is unchanged. Use an id
unique to the delivery, such as the agent's own delivery or job id.

There is no delivery channel field. The MDM kits and a management agent both
run `bundle apply --bundle` as root or SYSTEM, and nothing the apply can check
without trusting the caller tells them apart (`--reason`, the argv and the
parent process are all the caller's choice). `delivery_id` is caller-supplied
too: it names a delivery and does not prove who made it, since any root or
administrator caller can pass any id, including one the agent uses. The MDM
kits, Setup `BUNDLE=`, `enterprise windows ensure --bundle` and the inbox path
unit pass none. The agent's own list of receipt ids (section 4.3) stays the way
to tell its applies from MDM or administrator applies; `delivery_id` makes
matching a receipt to the agent's delivery direct.

## 3. Version probe and fallbacks

```
defenseclaw-gateway --version-json
```

Prints one line and exits 0, also on a managed device. Schema
`version.schema.json`, for example:

```json
{"schema_version":1,"name":"defenseclaw-gateway","version":"1.0.3","commit":"0123456789","built":"2026-10-30T18:00:00Z","management_contract":1}
```

There is no features list: a build that prints `management_contract: 1` has
everything in this file. A build without the member predates the contract;
use these fallbacks on it:

| Item | `management_contract` 1 | Member absent |
|---|---|---|
| `receipt_id` | apply and status results carry `bundle.receipt_id` | match the receipt by `bundle_id` and a `finished_at` after the apply started (section 4.9) |
| `--delivery-id` | `bundle apply --delivery-id` records `delivery_id` (2.6) | an unknown flag: exit 2 / 1639 with no JSON; leave it out and match by `receipt_id` or as above |
| Windows apply lock wait | Windows `bundle apply` waits up to `--lock-wait` for `bundle.lock` | the flag is accepted and ignored; a held `bundle.lock` returns 1618 at once, and the agent's backoff does the waiting |
| Windows secret locks and JSON | Windows `secret set` / `remove` take `--lock-wait`, `bundle.lock` then `lifecycle.lock`, and print a JSON document on every outcome | do **not** pass `--lock-wait` (exit 1); the set takes no lock and can collide with an apply's confirm step or an installer run; failures print no JSON |
| Linux and macOS secret failure JSON | `secret set` / `remove` / `status` print the schema-1 failure document for an argument, flag, privilege, value or stdin read error | those failures print one line on stderr and no JSON: classify them by the exit code (2 fix the call, 1 failed) |
| Anchors command (Linux, macOS) | `enterprise bundle anchors install` | install the file as the MDM kit does (section 4.8) |

On Windows the anchors call is the same on every build:
`enterprise windows ensure --profile standalone --trust-anchors F --json`
(section 4.8). There is no Windows anchors command.

If `--version-json` itself fails, the build is not supported by this
contract; do not manage the device.

## 4. Operations

Each operation gives the argv, privilege, preconditions, lock, idempotency,
stdout schema, exit codes, the codes to expect, and examples. The examples
assume these variables:

```sh
# Linux (root)
GW=/opt/defenseclaw/bin/defenseclaw-gateway;          OS=linux
# macOS (root)
GW=/opt/cisco/defenseclaw/bin/defenseclaw-gateway;    OS=macos
```

```powershell
# Windows (LocalSystem)
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
$root = [string]$hklm.OpenSubKey('SOFTWARE\Cisco\DefenseClaw\Enterprise').GetValue('InstallRoot')
$GW   = Join-Path $root 'bin\defenseclaw-gateway.exe'
```

Every command below refuses on a Secure Client computer
(`not_supported_secure_client`) and on a computer that is not a standalone
managed device (`not_managed`; the device test is the descriptor
`<etc>/managed-runtime.json`, and on Windows the trusted deployment record).
Every command below also assumes the deployment is already installed (Linux
and macOS `bundle apply` refuse `not_installed` without a deployment record;
Windows refuses `not_managed` unless the deployment was installed before the
run). Section 5.0 sets up a device that has no MDM.

### 4.1 Feature probe: `--version-json`

Section 3. No privilege, no lock, read-only. Schema `version.schema.json`.
Exit 0.

```sh
"$GW" --version-json
```
```powershell
& $GW --version-json
```

### 4.2 Check a bundle: `enterprise bundle verify`

- argv: `enterprise bundle verify --bundle <file.dcbundle> --json`. Do not
  pass `--anchors` on a device: the default is the installed anchor file,
  checked for root-only trust. `--platform` defaults to this OS.
- Privilege: any account can run it. Run it as root or SYSTEM so the floor
  includes the confirmed bundle and the credential check can read the store
  (otherwise it warns `floor_unchecked` and `secret_presence_unchecked`).
- Preconditions: none; it is the dry run of apply.
- Lock: none. Changes nothing (it stages into a private temporary folder).
- Idempotency: pure; repeat freely.
- stdout: `bundle-verify.schema.json`. `result` is `verified`,
  `already_applied` (the bytes are the confirmed bundle: apply would be a
  success no-op) or `refused`.
- Exit: 0 ok; 1 / 1603 refused (`errors[0].code`, for example
  `anchor_missing`, `key_unknown`, `key_revoked`, `key_expired`,
  `signature_invalid`, `tenant_mismatch`, `target_mismatch`,
  `version_not_newer`, `product_too_old`, `secret_ref_missing`,
  `digest_mismatch`, `config_invalid`); 2 / 1639 `invalid_arguments`.

```sh
"$GW" enterprise bundle verify --bundle /var/lib/<vendor>/inbox/v13.dcbundle --json
```
```powershell
& $GW enterprise bundle verify --bundle 'C:\ProgramData\<Vendor>\inbox\v13.dcbundle' --json
```

### 4.3 Apply a bundle: `enterprise bundle apply`

- argv: `enterprise bundle apply --bundle <file> --reason management
  --delivery-id <id> [--refuse-capability-loss] --lock-wait 10m --json`. Pass
  `--refuse-capability-loss` on every apply after the first bundle: it refuses
  a bundle that turns off a capability the device enforces now
  (`capability_loss`). Pass a `--delivery-id` unique to this delivery (2.6);
  it is optional. Never use `--inbox`.
- Privilege: root on Linux and macOS (`not_root`); an elevated administrator
  or SYSTEM on Windows (`not_admin`).
- Preconditions: a standalone managed device; trust anchors installed
  (`anchor_missing` otherwise); on Windows the deployment installed before
  this run (`not_managed`); every `secret_refs` credential stored (4.7).
- Lock: Linux and macOS take `lifecycle.lock` and wait `--lock-wait` (default
  5 s, at most 15 m). Windows takes `bundle.lock`, waiting up to
  `--lock-wait` (default: no wait, at most 15 m), then the installer's
  `lifecycle.lock`. On Windows
  `--lock-wait` covers **only** `bundle.lock`: a busy installer
  `lifecycle.lock` (a repair, an `ensure` without a bundle, a guardian repair;
  held for a fixed 30 s wait) still returns 1618 `lifecycle_busy`, whatever
  `--lock-wait` says, so retry with backoff. `--reason` is accepted and
  ignored on Windows (section 2.6).
- What happens: the file is copied into the root-only store and verified
  there (every check of 4.2), installed by the ensure transaction, confirmed
  against the running gateway's digest, and recorded in a receipt. A failure
  or an interruption keeps or puts back the last good bundle. A gateway
  restart or crash during the apply is handled by the child: the confirm step
  fails and the run rolls back (`not_confirmed` / `apply_failed`). On Linux
  and macOS the confirm step asks the gateway again just before the receipt
  is confirmed (waiting up to 20 s for a gateway its service manager starts
  again): a gateway that crashed or was killed after the transaction
  committed and does not report the bundle's digest in time is
  `not_confirmed` with exit 75, `bundle.state` `applied` and the last good
  bundle still current. Resubmit the same bundle (2.2): that run confirms it
  once the gateway reports its policy (the warning
  `bundle_confirmed_after_interrupt`, then the success test passes), or fails
  it and puts the last good bundle back. When another lifecycle run confirmed
  it first (the path-triggered `ensure` that the bundle's config write
  starts, or an MDM `ensure`), the resubmit is a repeat of the current bundle
  (`already_applied`) and still carries the warning: the confirmed receipt
  lists `bundle_confirmed_after_interrupt` in `warning_codes`. The warning
  is only about the submitted bundle; a different bundle submitted after a
  `not_confirmed` one does not carry it, even when that run confirms the
  earlier bundle (its receipt records it). Windows reads the gateway's policy
  when it confirms and fails a receipt it does not report (`not_confirmed`,
  rolled back).
  On Windows most bundles apply in the running gateway (a key the gateway
  reads only at start restarts the gateway alone). A bundle that turns Codex
  on or off runs the full lifecycle transaction instead (a repair with the
  bundle config), because only that transaction installs and removes
  Codex's machine policy: every DefenseClaw service restarts, managed hooks
  fail closed meanwhile (usually one to three minutes), and the receipt
  records `restart: true`.
- Idempotency: the same bytes as the confirmed bundle are a success no-op;
  the repeated delivery's receipt is discarded and no new public receipt is
  written. `noop_reason` is `already_applied` only when ensure also changed
  nothing else; a repeat that also repaired drift (a credential, a file
  mode, a stopped service) or installed other trust anchors (`--trust-anchors`,
  Setup `TRUSTANCHORS=`, the shell kit's `--trust-anchor-file`; a `changes`
  entry names the anchor file) has `noop: false` and no `noop_reason`. The
  success test below does not read `noop_reason`. A lower or equal version
  with other bytes is
  `version_not_newer` (final). A retry after 75 / 1618 is safe.
- stdout: `lifecycle-result.schema.json` (schema_version 2, `action:
  "ensure"`) with the `bundle` block (and `last_refusal` for a refusal before
  staging), or `bundle-refused.schema.json` (schema_version 1) when it refused
  before the lifecycle ran (Secure Client, not managed, Windows not
  elevated). Tell them apart by `schema_version`.
- **Success test**: `exit == 0 && ok && bundle.bundle_id == <submitted id> &&
  bundle.state == "confirmed"`. The submitted id is `bundle.bundle_id` of the
  4.2 result. A repeated delivery of the current bundle writes no receipt:
  its `bundle` block is the current confirmed bundle and its confirmed
  receipt, also when a newer delivery failed after staging, so the same test
  holds. `confirmed` means the submitted bundle is the device policy and the
  running gateway enforces its digest: the gateway reported that digest when
  the receipt was confirmed, so the result of the apply that confirmed it has
  `policy.applied` true. There is no confirmation without a running gateway:
  a gateway that is down (crashed, killed or stopped) never confirms a
  bundle. It does not mean that agent sessions
  already running enforce it: read `bundle.sessions_restart_required` next
  (sessions that need a restart, below).
- **Settings-only bundles do not confirm on builds without the fix**: on
  DefenseClaw 1.0.2 and earlier, and on 1.0.3 builds made before the fix, a
  bundle whose `config.yaml` names no file under the bundle's version
  directory (a settings-only bundle: the config names no path under the
  bundle's `policies/`, `discovery/` or `scanners/`) never passes the confirm
  step, although `bundle verify` (4.2) reports `digest_verified` true for the
  same file. The apply restarts the gateway, fails after about 40 to 50 s and
  rolls back: exit 1, final, with `errors[].code` and `bundle.error_code`
  `digest_mismatch`, `bundle.state` `failed`, the warning `rolled_back` and
  `bundle.current_version` still the last good bundle's. That bundle enforces
  again once the rollback has finished; while the apply runs, the gateway can
  already enforce the candidate's settings. Resubmitting the same file fails
  the same way. Seen on Linux; macOS and Windows compute the gateway digest
  with the same code. Stopgap: ship at least one file in the bundle and name
  it in `config.yaml`, for example a guardrail rule pack under
  `policies/guardrail/<pack>` named by `guardrail.custom_packs.<pack>.path`;
  such a bundle confirms. Remove this note once the agent's minimum
  DefenseClaw build contains the fix.
- **Sessions that need a restart**: an agent (Claude Code, Codex and the
  other connectors) reads its hooks when it starts. DefenseClaw does not stop
  or restart agent sessions, so a session that was already running when a
  bundle enabled or changed its connector keeps the hooks it loaded, or none:
  its tool calls are **not enforced** until it restarts, although the apply
  is `confirmed`. The live scan in `bundle.sessions_restart_required` (also in
  `bundle status`, 4.5) counts them. The apply result then warns
  `sessions_need_restart` (`sessions_scan_unknown` when the scan could not
  run) and reports `coverage_complete` and `security_complete` false;
  `bundle status` warns with the same codes. After
  any apply, and on any `bundle status`, whose `sessions_restart_required` has
  `count` above 0 or `state` `unknown`, the agent:
  - MUST report it upstream with the receipt as "enforcement pending for N
    sessions" (N is `count`; for `unknown`, "enforcement pending, session
    count unknown" with `reason`);
  - MUST NOT report the device as fully enforcing while the count is above 0
    or unknown;
  - MUST either ask the users to restart the listed agents or restart them
    itself in a maintenance window, then read `bundle status` (4.5) again
    until `count` is 0 with `state` `known`.

  Forward only `count` and the distinct `entries[].agent` values (connector
  names). `entries[].user` is the account name (a numeric id when the name
  cannot be resolved), which is personal data; `pid` and `started_at` are for
  local use. Do not forward them. `entries` lists at most 20 sessions, so the
  connector names can be incomplete when `count` is above 20. The integer
  `sessions_restart_required` of a receipt file (4.9) is the count at
  confirmation, not a live value.
- **The agent's own receipt id** (for its list, section 2.6):
  `bundle.receipt_id` when `bundle.bundle_id` is the submitted id and the
  apply was not a repeat of the current bundle (a confirmed or failed
  delivery); `last_refusal.receipt_id` when the apply was refused after the
  bundle was received (`last_refusal.bundle_id` is the submitted id, and the
  `bundle` block stays on the current bundle); none when it was refused before
  the bundle was received (no `receipt_id`) or was a repeat. A repeat returns
  the current confirmed receipt's id, which can be an MDM or administrator
  delivery's: do not add it to the list. A repeat has `noop_reason`
  `already_applied`, or a `bundle.confirmed_at` earlier than the time the
  agent started the apply.
- **Across an agent restart**: a running apply outlives the agent's stop
  (2.4), and the receipt it writes is still the agent's. So before it starts
  the child, the agent durably records the delivery: the `--delivery-id`, the
  submitted bundle id and the start time. After a restart, once 5.1 step 2
  ran, it settles each recorded delivery: the receipt whose `delivery_id` is
  the recorded id, in a `receipt-events/` file (4.9) or in the `bundle`,
  `last_receipt` or `last_refusal` block of `bundle status` (4.5), is its
  own: add its `receipt_id` to the list and forward it. No such receipt means
  the apply was refused before the bundle was received (it has no receipt),
  or its receipt file was not written (best effort, 4.9) and a newer receipt
  has replaced it in `bundle status`. The resubmit of 5.1 step 3 is a new
  delivery with a receipt of its own and does not recover the missing one
  (once a later bundle is confirmed, a resubmit of the recorded bundle is
  refused `version_not_newer`). The state keeps the `delivery_id` of the
  apply that confirmed a bundle (2.6): `current` or `last_good` of
  `bundle status` with the recorded id means that apply confirmed that
  bundle, so report it upstream as confirmed, without a receipt id. With
  neither, report the delivery's outcome as unknown. Then drop the record.
  On a build without `management_contract`
  (no `--delivery-id`, section 3), settle by the recorded bundle id and a
  `finished_at` after the recorded start time (4.9). Use ids unique to the
  agent: `delivery_id` is not authenticated (2.6).
- **`delivery_id`**: `bundle.delivery_id` (or `last_refusal.delivery_id`) is
  the `--delivery-id` of the delivery that block reports. It equals the id
  passed exactly when the block is this apply's receipt by the rules above. A
  repeat reports the confirmed receipt, so its `delivery_id` is that earlier
  delivery's (an MDM or administrator apply has none), not the one passed.
- Exit: 0; 1 / 1603 refused or failed (final): the bundle codes above plus
  `capability_loss`, `not_confirmed`, `apply_failed`, `interrupted`,
  `state_invalid`, `not_managed`, `not_root` / `not_admin`; 75 / 1618
  `lifecycle_busy` (Linux and macOS also `not_confirmed` with `bundle.state`
  `applied`; Windows also `bundle_apply_failed` and the codes in
  section 2.2: retry); 2 / 1639 invalid arguments (no JSON, section 2.3).

```sh
"$GW" enterprise bundle apply --bundle /var/lib/<vendor>/inbox/v13.dcbundle \
  --reason management --delivery-id acme-agent:d-000913 --refuse-capability-loss --lock-wait 10m --json
```
```powershell
# --lock-wait waits for bundle.lock only; retry a 1618 from a busy installer lock yourself.
& $GW enterprise bundle apply --bundle 'C:\ProgramData\<Vendor>\inbox\v13.dcbundle' `
  --reason management --delivery-id acme-agent:d-000913 --refuse-capability-loss --lock-wait 10m --json
```

### 4.4 Device state: `enterprise <os> status`

- argv: `enterprise linux status --json` or `enterprise macos status --json`
  (no `--lock-wait`); Windows `enterprise windows status --profile standalone
  --json`.
- Privilege: root or SYSTEM. On Linux and macOS a non-root caller gets
  `not_root` with the deployment fields left out; on Windows a non-elevated
  caller gets `elevation_required`, exit 5.
- Lock: Linux and macOS wait a fixed 5 s for another run, then report `ok:
  false`, `lifecycle_busy`, exit 75 (retry class). Windows status first
  settles a bundle receipt that a killed run left in state `applied`, under
  `bundle.lock`, and skips that step while an apply holds the lock, so Windows
  status can write; it is still idempotent.
- stdout: `lifecycle-result.schema.json` (`action: "status"`). Read
  `installed`, `installed_version`, `transaction_pending`,
  `policy.effective_digest` / `policy.gateway_reported_digest` /
  `policy.applied`, `bundle` (the last receipt that reached staging and the
  confirmed bundle), `last_refusal`, `inspection`, `readiness`, `services`,
  `coverage_complete` and `security_complete`. A pending transaction is
  `transaction_pending: true` with `errors[].code` `verify_failed`.
  A bundle receipt no run finished (state `received`, `verified`, `staged`
  or `applied`) while no run holds the lock is also `transaction_pending:
  true`, with the warning `bundle_pending` that names the receipt and its
  delivery id; `ok` can stay true, because the current or last good bundle
  keeps enforcing. Status only reads the store; 4.6 ensure settles the
  receipt (`failed` with `error_code` `interrupted` or `not_confirmed`, or
  `confirmed`). On Windows that is the plain `enterprise windows ensure
  --profile standalone --json` the warning names, with no `--bundle`. While a
  live apply holds the lock, Linux and macOS status is busy and Windows status
  does not count that run's receipt.
- Exit: 0; 1 / 1603; 75 (Linux, macOS busy); 5 (Windows, not elevated).

```sh
"$GW" enterprise "$OS" status --json
```
```powershell
& $GW enterprise windows status --profile standalone --json
```

### 4.5 Bundle state: `enterprise bundle status`

- argv: `enterprise bundle status --json`.
- Privilege: root on Linux and macOS (an unreadable store is `not_root`); an
  elevated administrator or SYSTEM on Windows (`not_admin` and the short
  document of `bundle-refused.schema.json`).
- Lock: none on Linux and macOS (the gateway digest comes from a read-only
  lifecycle status; if that is busy the result warns `gateway_unchecked`).
  Windows settles first, as in 4.4.
- stdout: `bundle-status.schema.json`: `current`, `last_good`, `floor`,
  `last_receipt` (the root-only receipt, with `transitions` and
  `error_message`), `last_refusal`, `bundle`, `gateway_digest`, `applied`.
  `current` and `last_good` carry the `delivery_id` of the apply that
  confirmed them, when it had one (2.6).
  `applied` is true when the running gateway enforces the current bundle's
  digest with no rejected reload. A refused status (`not_managed`,
  `not_root`, `state_invalid`) did not scan sessions and reports
  `sessions_restart_required` with state `unknown`. Warnings to act on:
  `bundle_failed`, `bundle_pending`, `anchor_missing`, `key_unknown` /
  `key_revoked` (the confirmed bundle's signer, as the bundle state records
  it, is no longer trusted; checked also after its receipt was pruned),
  `policy_reload_rejected`, `gateway_unchecked`, `sessions_need_restart` /
  `sessions_scan_unknown` (agent sessions not yet enforced: report and
  restart them as in 4.3, sessions that need a restart).
- Exit: 0; 1 / 1603.

```sh
"$GW" enterprise bundle status --json
```
```powershell
& $GW enterprise bundle status --json
```

### 4.6 Recover: `enterprise <os> ensure`

- argv: Linux and macOS `enterprise linux|macos ensure --reason management
  --lock-wait 10m --json`; Windows `enterprise windows ensure --profile
  standalone --json` (Windows ensure has no `--reason` and no `--lock-wait`).
  Never pass `--config` on a device in bundle mode (Windows refuses
  `bundle_required`).
- Use: after a killed child, an unknown exit, or `transaction_pending: true`.
  The run recovers an interrupted transaction first, settles bundle receipts,
  then converges; on a healthy device it is a no-op. Enforcement stays on the
  current or last good bundle, never open.
- Settled receipts: every receipt no run finished. `received`, `verified`
  and `staged` end `failed` with `error_code` `interrupted` (warning
  `bundle_interrupted`). An `applied` one whose config is installed is
  `confirmed` when the gateway enforces it (warning
  `bundle_confirmed_after_interrupt`), else `failed` (warning
  `bundle_unconfirmed`) and the run installs the last good bundle again. On
  Windows, when no bundle was confirmed before (a killed first bundle), there
  is no last good bundle to put back: the verified config of the unconfirmed
  bundle stays installed until a signed bundle is delivered and confirmed.
  After the run, status reports no `bundle_pending` for them. Windows settles under
  `bundle.lock` (try-lock): a live apply that holds it keeps its own receipt.
  When an install transaction is pending, Windows recovers it first and
  settles afterward; the warning `bundle_settle_deferred` means it is still
  pending, so run ensure again.
- Privilege: root or SYSTEM. Lock: Linux and macOS `lifecycle.lock` with
  `--lock-wait`; Windows the installer lock (1618), and `bundle.lock` (no
  wait, skipped when held) only while it settles receipts.
- Idempotency: converges; repeat freely. A recovered run may warn
  `recovered_interrupted_transaction`.
- stdout: `lifecycle-result.schema.json` (`action: "ensure"`). Exit: 0;
  1 / 1603; 75 / 1618; 2 / 1639.

```sh
"$GW" enterprise "$OS" ensure --reason management --lock-wait 10m --json
```
```powershell
& $GW enterprise windows ensure --profile standalone --json
```

### 4.7 Credentials: `enterprise secret set` / `remove` / `status`

- argv: `enterprise secret set --name <name> --from-stdin [--lock-wait 10m]
  --json`; `enterprise secret remove --name <name> [--lock-wait 10m] --json`;
  `enterprise secret status --json`. On Windows pass `--lock-wait` only to a
  `management_contract` 1 build.
- Privilege: root on Linux and macOS (checked first: `not_root`, exit 1); an elevated
  administrator or SYSTEM on Windows (exit 5 `elevation_required` on a
  managed computer; exit 1603 with the same code on a computer without the
  standalone deployment marker).
- Preconditions: Windows needs an installed deployment (`not_installed`, exit
  1603) and the installer's `lifecycle.lock` file (`state_invalid`, exit 1603,
  nothing written, when an install never created it). Linux and macOS store a credential before the first install and
  report `noop: true`, `noop_reason: "not_installed"`. Windows `remove`
  refuses while the installed config still references the credential
  (`credential_in_use`). A junction, mount point, symlink or file where the
  Windows secrets folder belongs makes `set`, `remove` and `status` refuse
  with `state_invalid`, exit 1603 (`<folder> is not a real directory`):
  nothing is read, written or deleted, and the target of a junction is never
  touched. Replace it with a real folder.
- Lock: Linux and macOS write and apply under one `lifecycle.lock` and wait
  `--lock-wait` (default 5 s). Windows takes the two locks in the order a
  bundle apply takes them: `bundle.lock` (waiting up to `--lock-wait`,
  default no wait), then the installer's
  `lifecycle.lock` (a fixed 30 s, as the installer waits). It writes and
  restarts the gateway while it holds both, so the restart cannot land inside
  an apply's confirm step, a repair, an `ensure` without a bundle or a
  guardian repair. Either lock not free in time: `lifecycle_busy`, 1618,
  nothing written; retry.
- Idempotency: on Linux and macOS an identical value is not rewritten and
  ensure runs anyway (usually a no-op). On Windows every set writes and
  restarts the running gateway (managed hooks fail closed while it restarts);
  there is no identical-value no-op, so send a credential only when `status`
  shows a different `sha256_prefix` (section 2.5). A Windows set or remove
  that changed the store and then failed to restart is `restart_failed`,
  exit 1603: resubmit it, which writes and restarts again, even though
  `sha256_prefix` already shows the new value (2.2).
- stdout: `secret-result.schema.json`, exactly one document with `--json`.
  Linux and macOS print lifecycle result v2 (`action: "ensure"`) once the
  lifecycle ran, and `{schema_version: 1, ok: false, action, name,
  gateway_restarted: false, errors[], exit_code}` for a failure before it:
  `invalid_arguments` (exit 2: a flag or argument error, an untrusted
  `--from-file`, an empty, multi-line or oversized value the agent sent in
  full, or stdin that cannot be read while the agent runs; the same call fails
  again), `not_root` (exit 1), `change_failed` (exit 1: the value never
  arrived whole. The agent that started `secret set` exited before it sent
  the complete value: its end of the pipe closed with nothing or part of the
  value written, or a process it started still holds the pipe. Or no value
  ended within 60 s: the agent stopped without closing stdin. Resubmit the
  same call once the agent runs again, section 2.2) or
  `state_invalid` (exit 1). Nothing is written in any of them. Windows prints `{schema_version, ok, action, name,
  gateway_restarted}` on success and `{schema_version, ok: false, action,
  name, gateway_restarted: false, errors[], exit_code}` on every failure,
  including elevation (5), argument and flag errors (1639), busy (1618) and
  the 1603 cases. `status` prints `{schema_version: 1, secrets: [{name,
  present, sha256_prefix, modified_at[, mode]}]}` on every OS. A Windows
  `status` failure prints the same failure document with `action: "status"`
  and no `name`: `elevation_required` (5 / 1603, as above),
  `invalid_arguments` (1639, a flag error) or `state_invalid` (1603, the
  store cannot be read or is not a real directory).
- Exit: 0; 1 (Linux and macOS failure: `change_failed`, `not_root`,
  `state_invalid`); 2 (Linux and macOS argument or value error,
  `invalid_arguments`); 75 busy; Windows 5 / 1603 / 1618 / 1639. Every one
  prints its JSON document.
- The value never appears in output, logs or audit; `status` shows only
  presence and a digest prefix. No audit event records a set or remove
  (section 0): the agent reports it.
- After pushing the Cisco AI Defense key, check that AI Defense accepts it.
  `sha256_prefix` proves only what is stored. Read `inspection.ai_defense`
  from `enterprise <os> status --json` (4.4); the Linux and macOS `set`
  result carries the same field:

  | Value | Meaning | Agent action |
  |---|---|---|
  | `ok` | AI Defense answered a request with the stored key | done |
  | `unknown` | No request answered since the key was stored or the gateway restarted. DefenseClaw does not probe AI Defense on its own: the value changes on the first prompt a hook sends for inspection | not a failure; read status again later (at most every 60 s) |
  | `unavailable:auth_failed` | AI Defense rejected the stored key: HTTP 401 or 403 on the last request (warning `ai_defense_unavailable`) | send the right key; the next answered request clears it |
  | `unavailable:credential_unavailable` | The credential the config names is missing or fails its trust check | store it under the name `enterprise.inspection.ai_defense.credential` gives |
  | `unavailable:unreachable`, `unavailable:proxy_auth_required`, `unavailable:proxy_config`, `unavailable:error`, `unavailable:not_initialized` | No answer (connection failure or timeout), the egress proxy wants credentials (HTTP 407) or is misconfigured, another failure such as HTTP 5xx, or no client was built | a network, proxy or service fault, not a key fault: do not rotate the key |
  | `unavailable:gateway_not_ready` | Windows: the gateway is not ready | recover the device (4.6) |
  | `disabled` | The config does not enable AI Defense | none |

  The code comes from the HTTP status alone; the value and the warning never
  carry the key or the response body. The local policy engine keeps deciding
  in every case. A Windows build without `management_contract` reports `ok`
  from gateway readiness alone, which does not prove the key.

The agent holds the value in its own memory and writes it to the child's
stdin; the examples stand that in with a variable of the agent process
(`key`, `$key`), never an environment variable, which the child would
inherit (2.5, section 1).

```sh
# The agent writes the value to the child's stdin and closes it; printf of an unexported variable stands in for that here.
printf '%s' "$key" | "$GW" enterprise secret set --name ai-defense-api-key --from-stdin --lock-wait 10m --json
```
```powershell
# The agent writes the value to the child's stdin and closes it; $key (a variable, not $env:) stands in for that here.
# On a build without management_contract, drop --lock-wait.
$key | & $GW enterprise secret set --name ai-defense-api-key --from-stdin --lock-wait 10m --json
```

### 4.8 Trust anchors

**One anchors owner per device.** Either MDM owns the trust anchors (the
shell kit's `--trust-anchor-file`, Windows Setup `TRUSTANCHORS=`) or the agent
does (the calls below), never both. The shell kit installs its anchor file
on every run and puts the previous one back after a failed apply: with
`bundle anchors install` under the lifecycle lock when the installed build
has `management_contract`, otherwise by writing the file itself without the
lock. Either way a kit run can undo an agent install at any time, and an MDM
re-delivery puts its own file back. That
fails closed (bundles signed by the agent's new key are refused
`key_unknown`; the current bundle keeps enforcing) but stops policy updates.
On a device where MDM owns the anchors, the agent applies only bundles signed
by keys MDM installed. An agent that runs the shell kit itself (section 5.0)
is still the one owner.

**Linux and macOS: `enterprise bundle anchors install`.**

- argv: `enterprise bundle anchors install --file <bundle-anchors.json>
  --lock-wait 10m --json`. Not registered on Windows.
- Input: `bundle-anchors.schema.json` (strict; anything else is
  `anchor_invalid`).
- Source trust: the command reads `--file` once, the way the device reads its
  own anchor file: `Lstat`, a regular file, the file and every folder above
  it root-owned, not group or other writable, without an ACL write entry and
  without links; open; the opened file must be the one checked; bounded read;
  strict decode. A source that fails is refused (`anchor_insecure`,
  `anchor_missing`, `anchor_invalid`) and nothing is written. The bytes it
  installs are exactly the bytes it validated in that one read. Keep the
  source in a root-only folder (section 1).
- Privilege: root (`not_root`). Lock: `lifecycle.lock`, waits `--lock-wait`.
- Behaviour: a file byte-identical to a trusted installed file is `result:
  "unchanged"` and writes nothing. Identical bytes in an installed file that
  fails its check (another owner, a loose mode) are rewritten and reported
  `replaced`, with `previous_sha256` equal to `sha256`. Otherwise the command writes
  `<etc>/trust/bundle-anchors.json` atomically (root:root 0644 in a root 0755
  folder), re-checks it, and puts the previous file back if that check fails.
  Warnings, checked against the new file: `key_unknown` (the confirmed
  bundle's signer is not in it), `key_revoked` (it is revoked there),
  `anchor_unreadable`. The current bundle keeps enforcing either way.
  There is no version or replay check on the anchor file itself (as with the
  MDM kit and Windows `--trust-anchors`): any valid root-owned file is
  installed, an older one included, so the agent tracks which anchor file
  it last installed. The confirmed bundle version floor still applies.
- stdout: `anchors-install.schema.json` (`sha256`, `previous_sha256` and
  `key_ids` for the agent's own report; no audit event records the change).
  Exit: 0; 1; 2; 75.

```sh
"$GW" enterprise bundle anchors install --file /var/lib/<vendor>/trust/bundle-anchors.json --lock-wait 10m --json
```

On a Linux or macOS build without `management_contract`, run the recipe the
MDM kit falls back to on such a build, as root. It does not check the source
folder; check it yourself first. It keeps the previous file in the agent's
own root-only folder, so a failed check can put it back:

```sh
# SRC is the agent's root-only folder (section 1).
case "$(uname -s)" in
  Darwin) ETC=/opt/cisco/defenseclaw/etc; SRC="/Library/Application Support/<vendor>/trust" ;;
  *) ETC=/etc/defenseclaw; SRC=/var/lib/<vendor>/trust ;;
esac
install -d -o 0 -g 0 -m 0755 "$ETC/trust"
rm -f "$SRC/bundle-anchors.previous.json"
if [ -f "$ETC/trust/bundle-anchors.json" ]; then
  cp -p "$ETC/trust/bundle-anchors.json" "$SRC/bundle-anchors.previous.json" || exit 1
fi
install -o 0 -g 0 -m 0644 "$SRC/bundle-anchors.json" "$ETC/trust/.bundle-anchors.json.new"
mv -f "$ETC/trust/.bundle-anchors.json.new" "$ETC/trust/bundle-anchors.json"
"$GW" enterprise bundle verify --bundle <bundle> --json
```

`bundle status` of such a build does not check the anchor file (1.0.2 does
not read it; later builds warn `anchor_unreadable` only while a bundle is
confirmed). 4.2 verify does: on a device it reads the installed anchor file
the way apply does, right after it reads the bundle. Pass a bundle file the
agent holds, such as the one it delivers next; a bundle verify cannot read
(`archive_invalid`) leaves the anchors unchecked. When the result has
`errors[].code` `anchor_insecure`, `anchor_invalid` or `anchor_missing`, put
the previous file back, or remove the new one when there was none:

```sh
if [ -f "$SRC/bundle-anchors.previous.json" ]; then
  install -o 0 -g 0 -m 0644 "$SRC/bundle-anchors.previous.json" "$ETC/trust/.bundle-anchors.json.new"
  mv -f "$ETC/trust/.bundle-anchors.json.new" "$ETC/trust/bundle-anchors.json"
else
  rm -f "$ETC/trust/bundle-anchors.json"
fi
```

**Windows: `enterprise windows ensure --profile standalone --trust-anchors F
[--bundle B] --json`** (every build). It takes `bundle.lock`, checks the source
(the file and every folder above it writable only by SYSTEM and
Administrators, no reparse points), installs the file with the administrator
ACL, re-checks it, and reports the change: other bytes than the installed
file make the run `noop: false` with a `changes` entry `installed trust
anchors in <path>` or `replaced the trust anchors in <path>`, also when the
bundle is the confirmed one (no `already_applied`); the same bytes leave the
run a no-op. With `--bundle B` the anchors are
staged and committed only when that bundle is confirmed, so a failed bundle
leaves the previous anchors. Do not combine it with `--config` (refused
`invalid_arguments`). stdout: `lifecycle-result.schema.json`; the warnings
`key_unknown` / `key_revoked` come from the bundle summary. Exit: 0; 1603;
1618; 1639; 5.

```powershell
& $GW enterprise windows ensure --profile standalone --trust-anchors 'C:\ProgramData\<Vendor>\trust\bundle-anchors.json' --json
```

**Key rotation without MDM**: install the new key active next to the old key
active; apply a bundle signed by the new key; install again with the old key
`retired` (or `revoked`; revoking while the confirmed bundle is still signed
by that key warns `key_revoked`). Each step leaves the current policy
enforcing.

### 4.9 Receipts for forwarding (files)

- Read `<etc>/bundles/receipt-events/*.json` (one immutable file per terminal
  receipt, mode 0644, refusals included). `<etc>/bundles/receipt.json` is a
  status summary, not a receipt log: the last finished receipt that reached
  staging (the first refusal only while there is none), with a later
  refusal named only in its `last_refusal` member. Forward refusals from
  `receipt-events/`. Schema `bundle-receipt.schema.json`. Any account can
  read them; no lock. Writing them is best effort, so the authoritative
  outcome of an apply is its stdout, and `bundle status` is authoritative for
  state.
- Refuse a link, a file over 16 KiB and a state other than `confirmed` /
  `failed`, as the gateway's own reader does.
- Deduplicate by `receipt_id`; every delivery has its own id (the first
  delivery of a bundle uses the bundle id, later deliveries `r-<ULID>`).
  Receipts whose id is not in the agent's own list (4.3) came from MDM or an
  administrator; settle the deliveries recorded before an agent restart
  first (4.3), so that the receipt of an apply that finished while the agent
  was stopped is not counted as theirs. On a build without
  `management_contract`, match on `bundle_id` with `finished_at` after the
  apply started.
- `delivery_id` is present when the apply had `--delivery-id` (2.6). The
  `config.bundle.receipt` audit event and OTel do not carry it; only these
  files, the command results and `bundle status` do.
- Remember the last forwarded id; nothing is acknowledged back.

```sh
ls -1 /etc/defenseclaw/bundles/receipt-events/        # macOS: /opt/cisco/defenseclaw/etc/bundles/receipt-events/
```
```powershell
Get-ChildItem 'C:\ProgramData\Cisco\DefenseClaw\etc\bundles\receipt-events' -Filter *.json
```

## 5. The agent loop

### 5.0 Set up a device that has no MDM

Every command in section 4 assumes an installed standalone deployment. An
agent that is the only manager of a new device sets it up first, in this
order. The order matters: until the first bundle is confirmed, and after a
first bundle that fails, the agents on the device run under the **base
config**, so the base config must already enforce what the bundle enforces.

**Base config rule**: the base config's `guardrail:` block equals the first
bundle's, apart from `custom_packs.<pack>.path` (the absolute folder of a pack
installed before the run); its `claude_code:`, `codex:`, `connector_hooks:`
and `application_protection:` blocks equal the bundle's or are absent from
both. No other key is compared. The MDM kits refuse a mismatch
(`mdm_base_config_mismatch`, `exit-codes.md`).

Linux and macOS (root):

1. Stage the base config: on Linux `install -d -o root -g root -m 0755
   /etc/defenseclaw` and `install -o root -g root -m 0640 base.yaml
   /etc/defenseclaw/config.yaml`; on macOS the same under
   `/opt/cisco/defenseclaw/etc` with group `wheel`.
2. Install the package: `dnf install ./defenseclaw-enterprise-<v>-linux-<arch>.rpm`
   (or `apt install ./...deb`); on macOS `installer -pkg
   defenseclaw-enterprise-<v>-darwin-arm64.pkg -target /`. The package's
   postinstall runs `ensure --from-package --reason package` (the agent never
   passes `--reason package` itself). Require `"ok": true` in
   `last-package-result.json` (in `/var/lib/defenseclaw-enterprise/` or
   `/opt/cisco/defenseclaw/lifecycle/`); then 4.4 `status` must report
   `installed: true`. Tarball installs: `enterprise <os> ensure --payload
   <root-only dir> --config <base.yaml> --reason management --json`.
3. Store every credential the first bundle's `secret_refs` names (4.7).
4. Keep a copy of the installed anchor file if there is one (a new device has
   none), then install the anchors (4.8).
5. 4.2 verify, then the first 4.3 apply **without** `--refuse-capability-loss`.
6. If that apply does not succeed (exit not 0, or the success test of 4.3
   fails), put the previous anchors back: 4.8 with the kept copy or, when
   there was none, `rm -f <etc>/trust/bundle-anchors.json` (one of the two
   file edits the contract allows, section 7). The base config keeps
   enforcing. Fix the bundle and start again at step 5.

Linux and macOS agents may instead run the MDM shell kit as root, which does
steps 2 to 6 in one call, including the base config check and the anchor
restore: `defenseclaw-enterprise.sh --source <pkg> --sha256 <hex>
--config-file <base.yaml> --secret-name <n> --secret-stdin
--trust-anchor-file <F> --bundle-file <B>` (`packaging/mdm/linux` and
`packaging/mdm/macos`). The agent stays the one anchors owner (4.8).

Windows (LocalSystem):

1. Create the agent's `C:\ProgramData\<Vendor>` folder with a protected DACL
   (section 1).
2. Install with the base config:
   `DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure JSON=1 CONFIG=<base.yaml>`.
   Then 4.4 `status` must report `installed: true`.
3. Store every credential the first bundle's `secret_refs` names (4.7;
   Windows refuses `not_installed` before step 2).
4. Install the anchors and the first bundle in one transaction:
   `enterprise windows ensure --profile standalone --trust-anchors F
   --bundle B --json` (4.8). The anchors are committed only when the bundle is
   confirmed, so a failed first bundle leaves the device without the new
   anchors and on the base config; there is nothing to put back. Do not pass
   `--config` here.

Later bundles go through 5.2.

### 5.1 Start-up and after any unknown outcome

1. Run `--version-json` and pick the paths of section 3 (`management_contract`
   present or absent).
2. Run `enterprise <os> status --json`. If `installed` is false, set the
   device up (5.0). If `transaction_pending` is true (an interrupted
   transaction, or the warning `bundle_pending` for a receipt a killed apply
   left), or the last apply the agent started has no terminal receipt
   (`bundle.state` not `confirmed` or `failed` for that bundle id), and no
   apply child of the agent's own is still running, run 4.6 ensure, then
   status again. Retry 75 /
   1618 with backoff. After an unknown outcome of `bundle anchors install`,
   run the same install again: `unchanged` with the same `sha256` means the
   file is in place.
3. Settle the deliveries the agent recorded before it stopped (4.3,
   across an agent restart). Only then resubmit the desired bundle; the same
   bytes give the no-op success or a fresh apply.

### 5.2 Deliver a bundle

1. Store every credential the bundle's `secret_refs` names (4.7), only when
   `sha256_prefix` differs or the last call for that name did not end with
   exit 0 (2.5).
2. If the anchors must change and the agent owns them (4.8), install them
   first.
3. Run 4.2 verify. `already_applied`: done. `refused`: report
   `errors[0].code` and stop (final).
4. Record the delivery (4.3, across an agent restart), then run 4.3 apply on
   a worker thread, with that new `--delivery-id` and
   `--refuse-capability-loss` (every apply after the first bundle). Apply the success test of 4.3 and the retry
   classes of section 2.2. Record the agent's own receipt id (4.3).
5. Forward the receipt (4.9). When `bundle.sessions_restart_required` has
   `count` above 0 or `state` `unknown`, report enforcement pending and get
   the sessions restarted (4.3, sessions that need a restart). Report anchor
   and credential changes yourself (section 0).

## 6. Locks

| Command | Linux / macOS | Windows |
|---|---|---|
| `bundle verify` | none | none |
| `bundle apply` | `lifecycle.lock`, `--lock-wait` | `bundle.lock` (`--lock-wait`; no wait on builds without `management_contract`), then the installer's `lifecycle.lock` (fixed 30 s, then 1618) |
| `<os> status` | `lifecycle.lock` probe, fixed 5 s, then 75 | `bundle.lock` try-lock for settling; skipped when held |
| `bundle status` | none (gateway digest from a read-only status) | as `<os> status` |
| `<os> ensure` | `lifecycle.lock`, `--lock-wait` | the installer's `lifecycle.lock` (fixed 30 s); with `--bundle` or `--trust-anchors`, `bundle.lock` first (no wait); without them, a `bundle.lock` try-lock while it settles unfinished receipts, skipped when held |
| `secret set` / `remove` | `lifecycle.lock`, `--lock-wait` | `bundle.lock` (`--lock-wait`), then `lifecycle.lock` (fixed 30 s); no lock on builds without `management_contract` |
| `bundle anchors install` | `lifecycle.lock`, `--lock-wait` | not registered |

On Windows, `--lock-wait` covers only `bundle.lock`. Repairs, `ensure`
without a bundle and guardian repairs are serialized by the installer's
`lifecycle.lock` (`Enter-DefenseClawLifecycleLock`,
`packaging/windows/DefenseClawEnterprise.psm1`, 30 s); a caller that finds it
busy past 30 s gets 1618.

MDM runs and the Linux bundle path unit
(`packaging/systemd/defenseclaw-enterprise-apply.{path,service}`) take the
same locks, so an MDM apply and an agent apply serialize: one of them waits or
gets 75 / 1618. The shell kit's anchor writes on a build without
`management_contract` are the exception (4.8, one anchors owner).

## 7. Not in the contract (version 1)

The gateway HTTP API (TCP and the hook socket), the token in `.env`,
`/health`, `/policy/reload`, `/api/v1/admin/shutdown`; the bundle inbox
(`--inbox`, `<etc>/bundles/inbox`); `--reason` values other than `management`
(2.6); editing any file under `<etc>` or the lifecycle folder, except the
4.8 fallback recipe and the 5.0 step 6 anchor removal; `--config` in bundle
mode; `enterprise bundle sign` (a control-plane tool, not a device call).
Per-user installs and Secure Client computers refuse every command.

## 8. Known limits

- Some failures print no JSON (section 2.3); the agent classifies them by the
  exit code.
- On DefenseClaw 1.0.2 and earlier, and on 1.0.3 builds made before the fix,
  a settings-only bundle (its `config.yaml` names no file under the bundle's
  version directory) never confirms: after about 40 to 50 s and a gateway
  restart the apply fails with `digest_mismatch` (exit 1 on Linux, final) and
  the last good bundle is put back. Ship and name one file in the bundle
  (4.3). Remove this note once the agent's minimum DefenseClaw build contains
  the fix.
- The credential value is normalised differently on Windows and on Linux and
  macOS (2.5), and Windows refuses a `secret set` before the deployment is
  installed while Linux and macOS store it (4.7).
- A busy Linux or macOS `status` is `ok: false`, `lifecycle_busy`, exit 75,
  after a fixed 5 s wait; it is not a device failure.
- A rejected AI Defense key shows only after the gateway has sent a request
  with it: until a hook sends a prompt for inspection, `inspection.ai_defense`
  stays `unknown` (4.7).
- Receipt files are written best effort (4.9); stdout and `bundle status` are
  authoritative.
- `delivery_id` is caller-supplied and not authenticated, and no receipt
  records the delivery channel (MDM, agent, administrator): the apply cannot
  tell them apart without trusting the caller (2.6).
- Trust anchor and credential changes are not audited by DefenseClaw
  (section 0).
- Windows `bundle apply` and `secret set` / `remove` default to no wait for
  `bundle.lock`; Linux and macOS wait 5 s. Pass `--lock-wait` on every OS.
- DefenseClaw does not stop or restart agent sessions. A session already
  running when a bundle enables or changes its connector is not enforced
  until it restarts, although the apply is `confirmed`;
  `sessions_restart_required` counts it and `coverage_complete` stays false.
  The agent reports enforcement pending and gets those sessions restarted
  (4.3).
- Windows standalone: rolling a device back to the published 1.0.2 Setup
  after an uninstall by the installed `defenseclaw.exe` (`enterprise windows
  uninstall`) of 1.0.2, or of a build without this fix, fails with
  `lifecycle_error`, exit 1603, "PowerShell is in NonInteractive mode. Read
  and Prompt functionality is not available.". That uninstall left the empty
  folders `lib\defenseclaw` and `lib` in the retired install folder
  `C:\Program Files\Cisco\DefenseClaw.retired-<32 hex>` together with its
  cleanup receipt, and the 1.0.2 cleanup cannot delete them. An uninstall by
  this version leaves nothing, and Setup of this version or later completes
  the old cleanup itself. Before running the 1.0.2 Setup on such a device,
  delete the two folders as LocalSystem; `Delete` refuses a folder that is
  not empty:

  ```powershell
  Get-ChildItem -LiteralPath 'C:\Program Files\Cisco' -Directory -Filter 'DefenseClaw.retired-*' |
      ForEach-Object {
          foreach ($leaf in 'lib\defenseclaw', 'lib') {
              $folder = Join-Path $_.FullName $leaf
              if (Test-Path -LiteralPath $folder -PathType Container) { [IO.Directory]::Delete($folder) }
          }
      }
  ```
