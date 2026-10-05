# Intune on macOS: shell script (recommended) or PKG app

The macOS enterprise package (`defenseclaw-enterprise-<version>-darwin-arm64.pkg`,
package identifier `com.cisco.defenseclaw.enterprise`) installs command-line
binaries under `/opt/cisco/defenseclaw/bin` and no `.app` bundle. It installs
only on Apple silicon Macs running macOS 13.0 or later.

Intune's unmanaged PKG app type reports success using the app bundle IDs
listed under **Included apps**, so it cannot detect this package reliably.
Use the shell-script route, which detects through the lifecycle itself.

## Route A (recommended): one root shell script

1. Host the pkg on an HTTPS location your Macs can reach, for example an
   Azure blob container or your artifact server.
2. Edit a copy of `packaging/mdm/macos/defenseclaw-enterprise.sh`. In the
   settings block, set:
   - `DC_SOURCE_URL`;
   - `DC_SOURCE_SHA256`, from the cosign-verified `checksums.txt`;
   - optionally `DC_PRODUCT_VERSION`. The wrapper refuses a deb, rpm or pkg
     of another version with `mdm_version_mismatch` before the package
     manager runs, so nothing is installed; the lifecycle refuses a payload
     archive of another version before applying it;
   - for Developer ID trust, also `DC_TRUST_MODE=signed` and
     `DC_ALLOWED_TEAM_IDS="<team id>"`.

   Paste the administrator config between the `DEFENSECLAW_CONFIG` markers
   in `dc_inline_config`. On macOS its `data_dir` must be
   `/opt/cisco/defenseclaw/runtime`. Never put credentials there.
3. In the Intune admin center, go to **Devices > By platform > macOS > Manage
   devices > Scripts > Add**:

   | Setting | Value |
   | --- | --- |
   | Run script as signed-in user | **No** (root) |
   | Hide script notifications on devices | Yes |
   | Script frequency | Every 1 day. `ensure` does nothing when the host already matches, but with `DC_SOURCE_URL` set each run downloads the pkg first. |
   | Max number of times to retry if script fails | 3 (exit `75` means busy and succeeds on a later run) |

   The file must stay under 1 MB. The wrapper itself is about 30 KB. Intune
   stops a script after 60 minutes.
4. For inventory, add a custom attribute (**Devices > By platform > macOS >
   Organize devices > Custom attributes for macOS**), data type **String**,
   script `packaging/mdm/macos/detect.sh` with its settings block set to
   `DC_FORMAT="value"`. It reports the installed version or `not-installed`;
   set `DC_MIN_VERSION` to also report `outdated`, and `DC_REQUIRE_HEALTHY=1`
   to also report `unhealthy`. `detect.sh` must run as root.

Intune does not run macOS scripts through a proxy. If the download needs
one, set `DC_HTTPS_PROXY` in the settings block. Only the download uses it.

To change the config, edit it in the script and save; the next run validates
and applies it. To upgrade, update `DC_SOURCE_URL`, `DC_SOURCE_SHA256` and
`DC_PRODUCT_VERSION`.

## Route B: unmanaged PKG app

**macOS app (PKG)** with the pkg itself works for installation. The pkg's
own postinstall runs `enterprise macos ensure --from-package`, and a failure
fails the install. That run uses the config already installed at
`/opt/cisco/defenseclaw/etc/config.yaml`, or the built-in default, which
protects no agents. Detection relies on **Included apps**, however, and this
package has no app bundle, so Intune may report the install as unsuccessful
even when it worked. If you choose this route:

- Keep the pkg at **Ignore app version: No**.
- Deliver the config with the Route A script, with `DC_SOURCE_URL` empty.
  That configures the installed deployment (and exits with
  `mdm_not_installed` until the pkg is installed).
- Track health with the custom attribute above.
- Keep the pre-install script under 15,360 characters. Intune does not
  report post-install script failures.

## The Cisco AI Defense key

Intune scripts are not secret storage. Deliver the key once, after
DefenseClaw is installed, through an administrator channel:

```sh
sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise secret set --name ai-defense-api-key --from-file /secure/key
```

Or use `defenseclaw-enterprise.sh --secret-name ai-defense-api-key
--secret-file <root-only file>` from tooling that can drop root-only files,
then delete the file.

## Privacy prompts (TCC)

The guardian writes per-user hook registrations under each user's home
dot-directories (`~/.claude`, `~/.codex`, `~/.cursor` and similar). These
aren't TCC-protected, so no PPPC profile is needed.

If your organization relocates agent configuration into protected folders
(Desktop, Documents, iCloud Drive), deploy a PPPC profile. It grants
**SystemPolicyAllFiles** to `/opt/cisco/defenseclaw/bin/defenseclaw-gateway`,
identified by its code requirement (`codesign -dr -` prints it). This works
only for a Developer ID-signed release; an unsigned release's requirement is a
hash that changes with every release.

## Removal

Remove the Macs from the install script's assignment, then run
`packaging/mdm/macos/uninstall.sh` as a root shell script (once). Use
`DC_PURGE=1` to also remove the config, credentials and state. The lifecycle
removes the binaries and forgets the pkg receipt itself.
