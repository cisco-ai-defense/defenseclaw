# DefenseClaw managed enterprise: MDM deployment kit

This kit deploys the **standalone** managed-enterprise profile on Windows,
Linux and macOS with any MDM, configuration-management tool or administrator
shell. You don't need Cisco Secure Client. Secure Client deployments keep using
their own installer and are not affected by anything here.

The standalone profile installs DefenseClaw as protected system services. A
standard user cannot stop them, reconfigure them or remove the managed hooks.
Every lifecycle action is a transaction that rolls back on failure. `ensure`
installs, upgrades or repairs as needed, and does nothing when the host
already matches, so an MDM can run it on every check-in.

The user documentation, including the generic MDM contract and step-by-step
recipes, is published at
<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/>. What goes
in the config, including which agents to protect, is in
<https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/configuration/>.

## What is here

| Path | Use |
| --- | --- |
| `contract/lifecycle-result.schema.json` | The JSON document every lifecycle action, wrapper and removal script prints (schema version 2). |
| `contract/exit-codes.md` | Exit codes per OS, what they mean, and which ones an MDM should retry. |
| `contract/detection.md` | How to tell an MDM that DefenseClaw is installed, current and healthy. |
| `windows/Invoke-DefenseClawEnterprise.ps1` | Generic Windows wrapper (PowerShell 7.4 or later). Verifies and runs `DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure`. |
| `windows/detect.ps1`, `windows/uninstall.ps1` | Windows detection and removal. These run in Windows PowerShell 5.1 (32- or 64-bit) and PowerShell 7. |
| `linux/*.sh`, `macos/*.sh` | Generic wrapper (`defenseclaw-enterprise.sh`), `detect.sh` and `uninstall.sh`. The Linux and macOS copies differ only in the line `DC_SCRIPT_OS`. |
| `intune/` | Microsoft Intune guide for Windows (Win32 app and Remediations), macOS (shell script, or PKG app) and Linux (platform script). |
| `signing/` | Signing channels, and `authenticode-sign.sh` for release signing or re-signing with your own certificate. |

## Quick start

1. **Get a release and pin it.** Download the release's `checksums.txt` and
   `checksums.txt.bundle` with the artifact, verify them with cosign, and
   check the artifact:

   ```sh
   cosign verify-blob --bundle checksums.txt.bundle \
     --certificate-identity "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
   sha256sum --check --ignore-missing checksums.txt
   ```

   Then read the SHA-256 of the artifact you deploy from `checksums.txt`:

   | OS | Artifact |
   | --- | --- |
   | Windows x64 | `DefenseClawSetup-Enterprise-Standalone-x64.exe` |
   | Linux | `defenseclaw-enterprise-<version>-linux-<arch>.deb` / `.rpm`, or the `defenseclaw-enterprise-<version>-linux-<arch>.tar.gz` payload |
   | macOS (Apple silicon, 13.0 or later) | `defenseclaw-enterprise-<version>-darwin-arm64.pkg`, or the payload archive |

   That SHA-256 is the pin for hash-pinned trust, the default. See
   `signing/README.md` for signature-based trust instead.
2. **Write the administrator config.** It needs `config_version: 8`,
   `deployment_mode: managed_enterprise` and `enterprise.profile:
   standalone`, and it chooses the agents to protect. Start from the
   per-OS minimal config in
   <https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/#a-minimal-config>,
   which installs as written on Linux and macOS. On Linux and macOS a
   host installed without a config gets a default that protects no agents;
   on Windows the first install refuses to run without one (`1639`). Never put
   credentials in it: the standalone profile rejects an inline
   `cisco_ai_defense.api_key`.
3. **Run the wrapper as SYSTEM or root** from your MDM. Stage the config
   (and any credential file) in a folder that only administrators can
   change: the wrappers refuse a file when the file or any folder above it
   can be renamed, deleted or re-permissioned by another account. On
   Windows client editions a folder created directly under `C:\` inherits
   "Authenticated Users: Modify" (Windows Server does not add that entry,
   but the same commands work there), so remove the inheritance first:

   ```powershell
   # Windows (PowerShell 7)
   New-Item -ItemType Directory C:\Staging
   icacls C:\Staging /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
   pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 `
     -SetupPath C:\Staging\DefenseClawSetup-Enterprise-Standalone-x64.exe -Sha256 <pin> `
     -ConfigPath C:\Staging\config.yaml
   ```

   `-ProductVersion` pins the version the installed CLI converges to when
   you run the wrapper without `-SetupPath`; a staged Setup is pinned to one
   release by its `-Sha256`, and the wrapper refuses `-ProductVersion`
   together with `-SetupPath`.

   ```sh
   # Linux (deb, rpm or payload) and macOS (pkg or payload)
   sudo ./defenseclaw-enterprise.sh --source /var/cache/mdm/defenseclaw-enterprise-1.4.0-linux-amd64.deb \
     --sha256 <pin> --config-file /etc/mdm/defenseclaw/config.yaml
   ```

   Script-only MDMs that cannot pass arguments set the same values in the
   settings block at the top of `defenseclaw-enterprise.sh`.
4. **Deliver the optional Cisco AI Defense key** (or an observability
   credential) on standard input or from an administrator-only file, never as
   an argument or in a script body. On Linux and macOS the wrapper stores it
   before it applies the config, so a config that references the credential
   deploys in the same run:

   ```sh
   sudo ./defenseclaw-enterprise.sh --source <package> --sha256 <pin> \
     --config-file /etc/mdm/defenseclaw/config.yaml \
     --secret-name ai-defense-api-key --secret-file /secure/key
   ```

5. **Detect** with `detect.ps1` / `detect.sh`, or the registry and package
   rules in `contract/detection.md`. **Remove** with `uninstall.ps1` /
   `uninstall.sh`.

## What the wrappers guarantee

- **Verify, then install.** The wrapper copies the source into a fresh
  directory that only SYSTEM/Administrators or root can use, and verifies
  the copy. The copy it verified is the copy that gets installed, so
  changing the original afterwards has no effect.
- **No secrets in argv, logs or MDM script bodies.** Config and credentials
  come from standard input, or from files that other accounts cannot write.
  The wrapper deletes its staging copy of a credential after use (on Windows
  it overwrites it first). It leaves your source file alone: delete it
  yourself.
- **No trust in the caller's environment.**
  - Unix scripts set their own `PATH` and locale, and work under `env -i`
    with no TTY.
  - Windows scripts read Program Files and the enterprise marker through
    the protected 64-bit registry view, even from a 32-bit host.
  - The PowerShell 7 wrapper refuses:
    - an untrusted or emulated engine;
    - Constrained Language Mode;
    - .NET loader-injection variables.
- **One result document on stdout.** Every wrapper and removal-script run
  prints exactly one lifecycle-result document
  (`contract/lifecycle-result.schema.json`), including failures the wrapper
  detects itself. Those failures use error codes that start with `mdm_`. The
  detection and Remediations scripts print one line instead.
- **Idempotent.** `ensure` does nothing when the host already matches.
  `uninstall` succeeds on a host that has nothing installed.

## Validation status

`cli/tests/test_mdm_kit.py` checks the kit on every change: the scripts are
ASCII, the Linux and macOS copies and the shared Windows helpers stay
identical, the Unix scripts parse and pin their environment, credentials never
reach a command line, wrapper failures are schema-conformant result
documents, the Intune-facing Windows scripts stay Windows PowerShell 5.1
compatible, and the release workflow signs artifacts only when its signing
secrets exist.

No recipe has been run in a live Intune tenant or any other live MDM service
against this release. The recipes are templates that follow each vendor's
documentation and are checked by simulating the MDM's execution context (root
under `env -i` with no TTY; SYSTEM from 32- and 64-bit Windows PowerShell). Run
a pilot group first.
