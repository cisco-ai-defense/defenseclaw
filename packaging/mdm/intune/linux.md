# Intune on Linux: platform script

Intune manages **Ubuntu** and **Red Hat Enterprise Linux** devices enrolled
with the Microsoft Intune app (see Microsoft's list of supported Linux
releases). It deploys **Bash platform scripts** (`.sh` files) but no Linux
app packages. So a root platform script downloads, verifies, installs and
configures DefenseClaw.

## Script

1. Host `defenseclaw-enterprise-<version>-linux-<arch>.deb` (Ubuntu) or
   `.rpm` (RHEL) on HTTPS. Instead, you can host the architecture's
   `.tar.gz` payload, which works on both.
2. Edit a copy of `packaging/mdm/linux/defenseclaw-enterprise.sh`. In the
   settings block, set:
   - `DC_SOURCE_URL` and `DC_SOURCE_SHA256` (from the cosign-verified
     `checksums.txt`);
   - optionally `DC_PRODUCT_VERSION`. The wrapper refuses a deb, rpm or pkg
     of another version with `mdm_version_mismatch` before the package
     manager runs, so nothing is installed; the lifecycle refuses a payload
     archive of another version before applying it;
   - for GPG trust, when the release ships signatures, also
     `DC_TRUST_MODE=signed`, `DC_GPG_KEYRING` (a root-owned keyring you
     deploy separately; convert `defenseclaw-enterprise-release-key.asc`
     with `gpg --dearmor`, because `gpgv` reads only binary keyrings) and
     `DC_SIGNATURE_URL` (the artifact's `.asc`).

   Paste the administrator config between the `DEFENSECLAW_CONFIG` markers.
   On Linux its `data_dir` must be `/var/lib/defenseclaw`. Never put
   credentials there.

   Ubuntu and RHEL need different package files. Create one script per
   distribution and target each at a device group filtered by OS, or use
   the payload archive for both.
3. In the Intune admin center, go to **Devices > Manage devices > Scripts and
   remediations > Platform scripts > Add > Linux**:

   | Setting | Value |
   | --- | --- |
   | Execution context | **Root**. The first run can prompt the user for consent. |
   | Execution frequency | Daily. `ensure` does nothing when the host already matches, but with `DC_SOURCE_URL` set each run downloads the artifact first. |
   | Execution retries | 3. Exit `75` means dpkg, rpm or the lifecycle was busy. |
   | Execution script | the edited `defenseclaw-enterprise.sh` |

To change the config, edit it in the script and save; the next run validates
and applies it. To upgrade, update `DC_SOURCE_URL`, `DC_SOURCE_SHA256` and
`DC_PRODUCT_VERSION`.

## Health, inventory and removal

- Health: the install script's run status already fails whenever `ensure`
  fails. For a separate signal, assign a copy of
  `packaging/mdm/linux/detect.sh` with `DC_REQUIRE_HEALTHY=1` (and
  optionally `DC_MIN_VERSION`) as a second root platform script, with no
  retries. In the default `exit` format it exits 0 only when DefenseClaw is
  installed, new enough and passes `verify`, so its run status reports
  health.
- Custom compliance cannot run `detect.sh`: Microsoft runs Linux discovery
  scripts in the signed-in user's context, and the deployment's status is
  readable only by root.
- Inventory on the device: `dpkg-query -W defenseclaw-enterprise` or
  `rpm -q defenseclaw-enterprise` for the package channel.
- Removal: remove the devices from the install script's assignment, then
  assign `packaging/mdm/linux/uninstall.sh` as a root platform script. It
  removes the deployment and the deb/rpm; use `DC_PURGE=1` to also remove
  config, credentials and state. It is a no-op on a host with nothing
  installed.

## The Cisco AI Defense key

Microsoft states that custom scripts and settings must not carry sensitive
information, so do not embed the key in the script. Deliver it once, after
DefenseClaw is installed, through an administrator channel, such as SSH,
configuration management or a secrets agent:

```sh
sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise secret set --name ai-defense-api-key --from-file /secure/key
```

## Notes

- Hosts must run systemd 239 or later. On a host without systemd the
  package installs but reports that the deployment is inactive.
- SELinux: after installing files, the lifecycle runs `restorecon` on
  `/opt/defenseclaw` and `/etc/defenseclaw` so they get their default
  contexts.
- The wrapper writes `/var/log/defenseclaw-enterprise-mdm.log` (root,
  0600).
