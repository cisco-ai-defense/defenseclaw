# Lifecycle exit codes

Every standalone lifecycle action exits with one of these codes, and so does
every wrapper and removal script in `packaging/mdm`. They also print one
lifecycle-result document (`lifecycle-result.schema.json`) whose `exit_code`
field matches the process exit code. The lifecycle prints the document when
it runs with `--json` (Linux, macOS, the installed Windows CLI) or `JSON=1`
(Setup); the kit's scripts always ask for it. The detection and Remediations
scripts print one line instead (see `detection.md`).

## Windows (MSI-compatible)

The codes match Windows Installer's codes so Intune and other MDMs classify
them with their default return-code tables.

| Code | Name | Meaning | MDM action |
| --- | --- | --- | --- |
| `0` | success | Installed, upgraded, repaired, removed, or nothing to do (`noop: true`). | Success |
| `1603` | `ERROR_INSTALL_FAILURE` | The action failed. Mutating actions have already rolled back to the previous deployment. | Failure; read `errors[].code` |
| `1618` | `ERROR_INSTALL_ALREADY_RUNNING` | Another lifecycle run holds the lock, or a signed policy bundle did not finish applying to the running deployment (`bundle_apply_failed`). | Retry later (Intune's default table retries 1618) |
| `1639` | `ERROR_INVALID_COMMAND_LINE` | Invalid arguments, for example a first install without a config. Retrying will not help. | Failure; fix the assignment |
| `5` | `ERROR_ACCESS_DENIED` | A standard account ran the installed CLI's `enterprise windows status` or `verify`, or `enterprise secret`, which need an elevated administrator or SYSTEM token (`elevation_required`). `enterprise secret` exits `5` only on a managed computer and `1603` with the same code on a computer without the standalone deployment marker. Setup and the wrappers report an unelevated token as `1603` instead. | Failure; run the command as SYSTEM |
| `3010` | `ERROR_SUCCESS_REBOOT_REQUIRED` | Reserved. The standalone lifecycle does not require reboots today. | Soft reboot |

Intune's default Win32 return codes are `0` Success, `1707` Success, `3010`
Soft reboot, `1641` Hard reboot and `1618` Retry. `1603` and `1639` report
as Failed, which is correct. You don't need to add any codes.

The standalone Setup can also refuse before the lifecycle starts:

- A malformed command line exits `1639`: an unknown property, a `CONFIG=`
  or `MANIFEST=` path that is missing, relative, padded,
  environment-expanded (contains `%`) or not on a local drive, `/install`
  without `CONFIG=` and `MANIFEST=`, or `TIMEOUTSECONDS` out of range.
- An unelevated token, and a `CONFIG=` or `MANIFEST=` file that exists but
  is a link, is not a regular file, or can be changed by a non-administrator,
  exit `1603`.

With `JSON=1`, Setup then prints a short document with `schema_version: 1`
and an `error` field; the wrappers keep Setup's exit code and turn the
document into a schema-version-2 document with the code
`mdm_lifecycle_no_result`. Setup stops reading arguments at the first
unknown one, so put `JSON=1` before the other properties. The Secure Client
Setup returns only `0` and `1603`, its argument errors included.

## Linux and macOS (sysexits-style)

| Code | Meaning | MDM action |
| --- | --- | --- |
| `0` | Success or nothing to do. | Success |
| `1` | The action failed (already rolled back), the config is invalid (`config_invalid`), or the wrapper refused an input. | Failure; read `errors[].code` |
| `2` | Invalid arguments. | Failure; fix the script settings |
| `75` | `EX_TEMPFAIL`: another lifecycle run or the package manager holds a lock, or a signed policy bundle whose gateway stopped reporting its policy before the receipt was confirmed (`not_confirmed`, receipt `applied`). | Retry later (set Intune's retry count or your MDM's retry policy) |

## Error codes

`errors[].code` is a stable machine code; `errors[].message` is for humans.
Codes that start with `mdm_` come from the wrapper scripts. They mean the
lifecycle did not run, so `installed: false` in that document means "not
evaluated". Run the `status` action to inspect the host.

| Code | Where | Exit (Windows / Unix) | Meaning |
| --- | --- | --- | --- |
| `mdm_invalid_arguments` | all | `1639` / `2` | A flag or setting is missing, malformed, contradictory or unknown. The Unix wrapper also refuses positional arguments. The Intune Windows launcher refuses a package pinning both config and bundle, or anchors without a bundle. |
| `mdm_not_root`, `mdm_not_elevated` | all | `1603` / `1` | Not running as root / SYSTEM / elevated administrator. |
| `mdm_wrong_platform` | unix | — / `2` | The Linux copy ran on macOS or the reverse. |
| `mdm_hash_mismatch` | all | `1603` / `1` | The staged source does not match the pinned SHA-256. |
| `mdm_signature_invalid`, `mdm_signer_not_allowed`, `mdm_signature_unsupported` | all | `1603` / `1` | Signature trust failed, the signer isn't allowed, or signing isn't supported for this source type. |
| `mdm_untrusted_input` | all | `1603` / `1` | A config, credential or keyring file can be changed by a non-administrator, or (`uninstall.sh`) the installed gateway is not root-owned. |
| `mdm_untrusted_install` | Windows | `1603` / — | `uninstall.ps1` only: the installed CLI or its folders are not administrator-only. `Invoke-DefenseClawEnterprise.ps1` reports the same condition as `mdm_lifecycle_launch_failed`. |
| `mdm_input_too_large` | all | `1639` / `2` | Config over 1 MiB, credential over 16 KiB, policy bundle over 4 MiB or trust anchors over 64 KiB (Intune launcher). |
| `mdm_payload_invalid`, `mdm_package_invalid`, `mdm_wrong_package`, `mdm_wrong_architecture` | unix | — / `1` | The archive or package is not a DefenseClaw enterprise artifact for this host. |
| `mdm_version_mismatch` | unix | — / `1` | The package is not the version set with `--product-version`. |
| `mdm_package_manager_busy` | unix | — / `75` | dpkg, rpm or installer held its lock. |
| `mdm_package_install_failed`, `mdm_package_remove_failed`, `mdm_package_manager_missing` | unix | — / `1` | The package manager failed or is absent. `rpm -U` also fails this way for an older rpm. |
| `mdm_package_result_empty` | macOS | — / `1` | The Installer failed and the package's postinstall left an empty result, with no lifecycle run holding the lock. When the lock is still held the wrapper reports `lifecycle_busy` and exits `75`. |
| `mdm_download_failed`, `mdm_download_unavailable` | unix | — / `1` | The HTTPS download failed, or there is no curl/wget. |
| `mdm_not_installed` | all | `1603` / `1` | A read-only action or source-less `ensure` found no installed deployment. |
| `mdm_lifecycle_no_result`, `mdm_lifecycle_launch_failed` | all | Setup's code or `1603` / the lifecycle's code or `1` | The lifecycle did not start or printed no result. |
| `mdm_secret_failed` | all | `1603` / `1`, `2` or `75` | Storing the credential failed. On Windows the deployment applied. On Linux and macOS the wrapper stores it before the config, so the config was not applied, and the exit code is the one `secret set` returned. |
| `mdm_staging_untrusted`, `mdm_package_incomplete` | all | `1603` / `1` | The private staging folder or the Intune content is not as expected, including a missing pinned bundle or anchors. |
| `mdm_base_config_mismatch` | unix | — / `2` | A config delivered with a signed bundle (the base config) does not match the bundle's. Its `guardrail:` block differs in more than `custom_packs.<pack>.path`, a pack path is not absolute, its `claude_code:`, `codex:`, `connector_hooks:` or `application_protection:` block differs from the bundle's (or only one of them has it), or the bundle's `config.yaml` does not match its manifest. No other key is compared. Nothing was installed. |
| `mdm_tar_missing` | unix | — / `1` | A base config came with a signed bundle and `tar`, which the comparison needs, is not installed. Nothing was installed. |
| `mdm_anchor_install_failed` | unix | — / `1`, `2` or `75` | The wrapper could not install the bundle trust anchor file (`--trust-anchor-file` or the inline anchors). When the installed gateway has `enterprise bundle anchors install` (`management_contract` 1), that command refused the file: the message names its code (`anchor_invalid`, `anchor_insecure`, `lifecycle_busy`, ...) and the exit code is the command's, `75` when the lifecycle lock stayed busy. With an older gateway the wrapper could not write the file, or its folder is not root-only. The bundle was not applied. |
| `mdm_staging_noexec` | unix | — / `1` | Linux: the payload's gateway cannot run from the staging folder (a `noexec` mount, named in the message). Use `--staging-dir` or a deb/rpm source. |
| `mdm_staging_full` | unix | — / `1` | The staging filesystem filled while extracting a payload archive. Choose a staging folder with more space and retry. |
| `mdm_cancelled` | unix | — / `1` | The MDM stopped the wrapper; it stopped the lifecycle child and reported failure. Inspect the deployment before retrying. |
| `unsupported_architecture`, `powershell_constrained_language`, `loader_environment_present`, `powershell7_untrusted` | Windows | `1603` / — | Host refusals of the PowerShell 7 wrapper. The lifecycle applies the same checks itself. |

Every other code (for example `config_invalid`, `lifecycle_busy`,
`rolled_back`, `profile_conflict`, `downgrade_refused`) comes from the
lifecycle itself, except `sandboxes_running`: the macOS package refused to
install while a sandbox daemon of DefenseClaw 1.0.3 or older runs a sandbox
(the Linux packages refuse the same way, with the reason on stderr). The
message names each user, sandbox and the command that user runs to end it;
install again once they are gone.

A signed policy bundle (`--bundle-file`, `-BundlePath`, Setup `BUNDLE=`) uses
the same exit codes. Its refusals (`signature_invalid`, `version_not_newer`,
`secret_ref_missing`, `not_confirmed` and the rest) exit `1603` / `1`;
`lifecycle_busy` exits `1618` / `75`. On Linux and macOS a bundle whose
config the transaction committed, but whose gateway stopped reporting its
policy (it crashed or was killed) before the receipt was confirmed, exits
`75` with `not_confirmed`: the receipt stays `applied`, the last good bundle
stays current, and the retry confirms it or puts the last good bundle back.
On Windows, a bundle that verified
but did not finish applying to the running deployment exits `1618` too:
`bundle_apply_failed`, after the error that names the cause (for example
`bundle_hot_apply_unavailable` with the verify detail, or
`bundle_policy_not_adopted`). Its receipt fails, the last good bundle or the
base config keeps enforcing, and the MDM's retry delivers it again. A cause
that a retry cannot get past exits `1603` instead, with the same
`bundle_apply_failed` after it: `fleet_setup_required` (the bundle turns
Fleet on or off, which needs signed Setup), `bundle_config_validation_failed`
and `bundle_install_options_changed` (the run also changes the install
options). A repeated delivery of the bundle in
force is a success (`already_applied`). The bundle codes are defined in
`internal/enterprisebundle/errors.go`; a public page that explains each one
ships with the sync service.

On Windows, `enterprise bundle status` and `apply` require an elevated
administrator or SYSTEM token. An unelevated token returns `not_admin` and
exits `1603` before reading the protected deployment record. The refused
status does not report bundle state that the caller could not read.

## Management agent commands

A management agent that runs the `enterprise` commands itself
(`management-agent.md`) gets the same codes:

- `enterprise bundle verify` and `apply`: `0`; `1` / `1603` for a refusal or
  a failed apply; `75` / `1618` for `lifecycle_busy`; `2` / `1639` for invalid
  arguments, with `errors[0].code` `invalid_arguments` in the JSON document.
  On Windows, `apply --lock-wait` waits only for `bundle.lock`; a busy
  installer `lifecycle.lock` (a repair, `ensure` without a bundle, a guardian
  repair) still exits `1618` after its fixed 30 s.
- `enterprise bundle anchors install` (Linux and macOS): `0`; `1` refused
  (`anchor_insecure`, `anchor_invalid`, `anchor_missing`,
  `anchor_restore_failed`, `not_root`, `not_managed`); `2` invalid arguments;
  `75` busy. Windows installs anchors with `enterprise windows ensure
  --trust-anchors`, which exits like `ensure`.
- `enterprise secret set` and `remove`: Linux and macOS `0`, `1`, `2` and
  `75`, as above; with `--json` every failure prints one JSON document (a
  failure before the lifecycle ran: `invalid_arguments` `2`, `not_root`,
  `change_failed` or `state_invalid` `1`). A `change_failed` before the
  lifecycle ran means the agent exited or stopped before it sent the whole
  value on stdin (or sent nothing for 60 s): nothing was stored, and the agent
  resubmits the same call once it runs again. An empty, multi-line or
  oversized value it sent in full is `invalid_arguments` `2`. Windows `0`; `5` not elevated on a managed computer
  (`1603` with the same `elevation_required` code on a computer without the
  standalone deployment marker); `1603` not installed,
  `credential_in_use`, `change_failed`, `restart_failed` or `state_invalid`
  (a junction, mount point, symlink or file where the secrets folder belongs:
  nothing was read, written or deleted); `1618` when
  `bundle.lock` is not free within `--lock-wait` or the installer's
  `lifecycle.lock` within 30 s (nothing was written); `1639` invalid
  arguments, unknown flags included. Builds that do not report
  `management_contract` in `--version-json` exit `1` for a flag error on
  Windows and print no JSON for failures.
- `enterprise secret status`: Linux and macOS as above. Windows `0`; `5` /
  `1603` `elevation_required` as for `set`; `1603` `state_invalid` when the
  store cannot be read or is not a real directory; `1639` invalid arguments. With `--json` and
  `management_contract` 1 every Windows failure prints the failure document
  of `secret-result.schema.json` with `action: "status"`.

## Retries, downgrades and rollback

Retry only `1618` and `75`. Every other failure repeats until you change the
artifact, the config or the host. Two exceptions are for a management agent:
Windows `secret set` / `remove` with `restart_failed` (`1603`), and Linux and
macOS `secret set` with a `change_failed` before the lifecycle ran (`1`, the
agent stopped before it sent the value); resubmit the same call
(`management-agent.md` section 2.2).

Windows `ensure` refuses an artifact older than the installed version
(`downgrade_refused`, `1603`), and `rpm -U` refuses an older rpm, so an MDM
that re-offers an old version never downgrades a host by accident. To go back
a version on purpose, follow the rollback procedure in the enterprise
documentation
(<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/lifecycle/#roll-back>);
`detection.md` explains how the inventory markers follow it.
