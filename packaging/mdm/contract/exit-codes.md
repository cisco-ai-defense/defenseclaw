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
| `1618` | `ERROR_INSTALL_ALREADY_RUNNING` | Another lifecycle run holds the lock. | Retry later (Intune's default table retries 1618) |
| `1639` | `ERROR_INVALID_COMMAND_LINE` | Invalid arguments, for example a first install without a config. Retrying will not help. | Failure; fix the assignment |
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
| `75` | `EX_TEMPFAIL`: another lifecycle run or the package manager holds a lock. | Retry later (set Intune's retry count or your MDM's retry policy) |

## Error codes

`errors[].code` is a stable machine code; `errors[].message` is for humans.
Codes that start with `mdm_` come from the wrapper scripts. They mean the
lifecycle did not run, so `installed: false` in that document means "not
evaluated". Run the `status` action to inspect the host.

| Code | Where | Exit (Windows / Unix) | Meaning |
| --- | --- | --- | --- |
| `mdm_invalid_arguments` | all | `1639` / `2` | A flag or setting is missing, malformed, contradictory or unknown. The Unix wrapper also refuses positional arguments. |
| `mdm_not_root`, `mdm_not_elevated` | all | `1603` / `1` | Not running as root / SYSTEM / elevated administrator. |
| `mdm_wrong_platform` | unix | — / `2` | The Linux copy ran on macOS or the reverse. |
| `mdm_hash_mismatch` | all | `1603` / `1` | The staged source does not match the pinned SHA-256. |
| `mdm_signature_invalid`, `mdm_signer_not_allowed`, `mdm_signature_unsupported` | all | `1603` / `1` | Signature trust failed, the signer isn't allowed, or signing isn't supported for this source type. |
| `mdm_untrusted_input` | all | `1603` / `1` | A config, credential or keyring file can be changed by a non-administrator, or (`uninstall.sh`) the installed gateway is not root-owned. |
| `mdm_untrusted_install` | Windows | `1603` / — | `uninstall.ps1` only: the installed CLI or its folders are not administrator-only. `Invoke-DefenseClawEnterprise.ps1` reports the same condition as `mdm_lifecycle_launch_failed`. |
| `mdm_input_too_large` | all | `1639` / `2` | Config over 1 MiB or credential over 16 KiB. |
| `mdm_payload_invalid`, `mdm_package_invalid`, `mdm_wrong_package`, `mdm_wrong_architecture` | unix | — / `1` | The archive or package is not a DefenseClaw enterprise artifact for this host. |
| `mdm_version_mismatch` | unix | — / `1` | The package is not the version set with `--product-version`. |
| `mdm_package_manager_busy` | unix | — / `75` | dpkg, rpm or installer held its lock. |
| `mdm_package_install_failed`, `mdm_package_remove_failed`, `mdm_package_manager_missing` | unix | — / `1` | The package manager failed or is absent. `rpm -U` also fails this way for an older rpm. |
| `mdm_download_failed`, `mdm_download_unavailable` | unix | — / `1` | The HTTPS download failed, or there is no curl/wget. |
| `mdm_not_installed` | all | `1603` / `1` | A read-only action or source-less `ensure` found no installed deployment. |
| `mdm_lifecycle_no_result`, `mdm_lifecycle_launch_failed` | all | Setup's code or `1603` / the lifecycle's code or `1` | The lifecycle did not start or printed no result. |
| `mdm_secret_failed` | all | `1603` / `1`, `2` or `75` | Storing the credential failed. On Windows the deployment applied. On Linux and macOS the wrapper stores it before the config, so the config was not applied, and the exit code is the one `secret set` returned. |
| `mdm_staging_untrusted`, `mdm_package_incomplete` | all | `1603` / `1` | The private staging folder or the Intune content is not as expected. |
| `mdm_staging_noexec` | unix | — / `1` | Linux: the payload's gateway cannot run from the staging folder (a `noexec` mount, named in the message). Use `--staging-dir` or a deb/rpm source. |
| `unsupported_architecture`, `powershell_constrained_language`, `loader_environment_present`, `powershell7_untrusted` | Windows | `1603` / — | Host refusals of the PowerShell 7 wrapper. The lifecycle applies the same checks itself. |

Every other code (for example `config_invalid`, `lifecycle_busy`,
`rolled_back`, `profile_conflict`, `downgrade_refused`) comes from the
lifecycle itself.

## Retries, downgrades and rollback

Retry only `1618` and `75`. Every other failure repeats until you change the
artifact, the config or the host.

Windows `ensure` refuses an artifact older than the installed version
(`downgrade_refused`, `1603`), and `rpm -U` refuses an older rpm, so an MDM
that re-offers an old version never downgrades a host by accident. To go back
a version on purpose, follow the rollback procedure in the enterprise
documentation
(<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/lifecycle/#roll-back>);
`detection.md` explains how the inventory markers follow it.
