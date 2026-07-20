# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import plistlib
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_systemd_enterprise_unit_pins_hardening_contract():
    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging" / "systemd" / "defenseclaw-gateway.service"
    text = unit.read_text(encoding="utf-8")

    required = {
        "User=defenseclaw",
        "Group=defenseclaw",
        "Environment=DEFENSECLAW_HOME=/var/lib/defenseclaw",
        "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
        "Environment=DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise",
        "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian",
        "StateDirectoryMode=0750",
        "RuntimeDirectoryMode=0750",
        "LogsDirectoryMode=0750",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw",
        "ReadWritePaths=/var/lib/defenseclaw /var/log/defenseclaw /run/defenseclaw",
        "CapabilityBoundingSet=",
        "RestrictNamespaces=true",
        "RestrictSUIDSGID=true",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        "NoNewPrivileges=true",
        "MemoryDenyWriteExecute=true",
    }
    missing = sorted(line for line in required if line not in text)
    assert not missing
    assert text.splitlines().count("NoNewPrivileges=true") == 1
    assert "NoNewPrivileges=false" not in text.splitlines()


def test_systemd_hook_guardian_is_oneshot_and_keeps_gateway_config_read_only():
    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging" / "systemd" / "defenseclaw-hook-guardian@.service"
    text = unit.read_text(encoding="utf-8")

    required = {
        "Type=oneshot",
        "User=root",
        "Group=root",
        "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment",
        "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
        "Environment=DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise",
        "EnvironmentFile=-/etc/defenseclaw/hook-guardian/%i.env",
        "ExecStart=/opt/defenseclaw/bin/defenseclaw-gateway enterprise hooks install --user %i",
        "UMask=0077",
        "ProtectSystem=strict",
        "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw",
        "ReadWritePaths=/home -/var/home /var/lib/defenseclaw /var/lib/defenseclaw-hook-guardian",
        "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID",
        "RestrictNamespaces=true",
        "RestrictSUIDSGID=true",
        "NoNewPrivileges=false",
    }
    missing = sorted(line for line in required if line not in text)
    assert not missing
    assert text.splitlines().count("NoNewPrivileges=false") == 1
    assert "NoNewPrivileges=true" not in text.splitlines()


def test_systemd_hook_guardian_reconcile_timer_and_manifest_contract():
    root = Path(__file__).resolve().parents[2]
    service = root / "packaging" / "systemd" / "defenseclaw-hook-guardian.service"
    watch = root / "packaging" / "systemd" / "defenseclaw-hook-guardian-watch.service"
    timer = root / "packaging" / "systemd" / "defenseclaw-hook-guardian.timer"
    tmpfiles = root / "packaging" / "systemd" / "defenseclaw.conf"
    sample = root / "packaging" / "systemd" / "hook-guardian-targets.example.yaml"

    service_text = service.read_text(encoding="utf-8")
    watch_text = watch.read_text(encoding="utf-8")
    timer_text = timer.read_text(encoding="utf-8")
    tmpfiles_text = tmpfiles.read_text(encoding="utf-8")
    sample_text = sample.read_text(encoding="utf-8")

    assert "enterprise hooks reconcile --manifest /etc/defenseclaw/hook-guardian/targets.yaml" in service_text
    assert "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment" in service_text
    assert "UMask=0077" in service_text
    assert "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw" in service_text
    assert "ReadWritePaths=/home -/var/home /var/lib/defenseclaw /var/lib/defenseclaw-hook-guardian" in service_text
    assert "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian" in service_text
    assert "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID" in service_text
    assert "NoNewPrivileges=false" in service_text
    assert service_text.splitlines().count("NoNewPrivileges=false") == 1
    assert "NoNewPrivileges=true" not in service_text.splitlines()
    assert "enterprise hooks watch --manifest /etc/defenseclaw/hook-guardian/targets.yaml --interval 1m" in watch_text
    assert "Restart=always" in watch_text
    assert "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw" in watch_text
    assert "ReadWritePaths=/home -/var/home /var/lib/defenseclaw /var/lib/defenseclaw-hook-guardian" in watch_text
    assert "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian" in watch_text
    assert "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID" in watch_text
    assert "NoNewPrivileges=false" in watch_text
    assert watch_text.splitlines().count("NoNewPrivileges=false") == 1
    assert "NoNewPrivileges=true" not in watch_text.splitlines()
    assert "OnUnitActiveSec=5min" in timer_text
    assert "Persistent=true" in timer_text
    assert "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment" in timer_text
    assert "d /etc/defenseclaw/hook-guardian 0750 root defenseclaw -" in tmpfiles_text
    assert "d /var/lib/defenseclaw-hook-guardian 0750 root defenseclaw -" in tmpfiles_text
    assert "version: 1" in sample_text
    assert "connector: codex" in sample_text


def test_launchd_gateway_plist_uses_managed_paths():
    # DefenseClaw installs under /opt/cisco/secureclient/defenseclaw/.
    # The plist name and every path inside it follows that layout, and
    # the daemon runs as root (no UserName/GroupName keys — the managed
    # cloud auth provider requires root for its credential store).
    root = Path(__file__).resolve().parents[2]
    plist_path = root / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.plist"

    with plist_path.open("rb") as fh:
        payload = plistlib.load(fh)

    assert payload["Label"] == "com.cisco.secureclient.defenseclaw"
    assert payload["ProgramArguments"] == ["/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway"]
    assert "UserName" not in payload, "daemon runs as root; UserName must be absent"
    assert "GroupName" not in payload, "daemon runs as root; GroupName must be absent"
    assert payload["WorkingDirectory"] == "/opt/cisco/secureclient/defenseclaw"
    assert payload["EnvironmentVariables"]["DEFENSECLAW_HOME"] == "/opt/cisco/secureclient/defenseclaw"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_CONFIG"]
        == "/opt/cisco/secureclient/defenseclaw/etc/config.yaml"
    )
    assert payload["EnvironmentVariables"]["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
        == "/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
    )
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["Umask"] == 0o77
    assert payload["StandardOutPath"] == "/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.log"
    assert payload["StandardErrorPath"] == "/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.err.log"


def test_launchd_hook_guardian_is_separate_privileged_job():
    root = Path(__file__).resolve().parents[2]
    plist_path = root / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.hook-guardian.plist"

    with plist_path.open("rb") as fh:
        payload = plistlib.load(fh)

    assert payload["Label"] == "com.cisco.secureclient.defenseclaw.hook-guardian"
    assert "UserName" not in payload
    # Guardian runs the long-running `enterprise hooks watch` command, not
    # the one-shot `reconcile` — fsnotify-driven auto-heal (~1 s) with a
    # 60 s periodic backstop, restart-managed via KeepAlive rather than
    # StartInterval. See internal/cli/enterprise_hooks.go runEnterpriseHooksWatch
    # for the loop's design (settle window + Stat-based rename-tail detection).
    assert payload["ProgramArguments"][1:4] == ["enterprise", "hooks", "watch"]
    # --interval 60s is the periodic backstop for tamper vectors the fsnotify
    # path intentionally cannot catch (SharedWriter Write/Chmod on native
    # agent configs, shared-across-connector generic scripts). Any drift in
    # this value should be a deliberate policy change, not an accidental edit.
    assert "--interval" in payload["ProgramArguments"]
    assert "60s" in payload["ProgramArguments"]
    assert payload["EnvironmentVariables"]["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
        == "/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
    )
    # Long-running watch mode is kept alive by KeepAlive, NOT StartInterval.
    # StartInterval would pointlessly relaunch the process every N seconds
    # (and possibly spawn duplicates); KeepAlive relaunches only on exit.
    assert "StartInterval" not in payload
    assert payload.get("KeepAlive") is True


def test_release_archives_ship_enterprise_packaging_assets():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    archive_files = config["archives"][0]["files"]

    assert "packaging/**/*" in archive_files
    assert "LICENSE*" in archive_files
    assert "README*" in archive_files


def test_launchd_enterprise_installer_enforces_managed_config_trust_boundary():
    installer = ROOT / "packaging" / "launchd" / "install-enterprise.sh"

    assert installer.is_file()
    assert installer.stat().st_mode & stat.S_IXUSR
    subprocess.run(["bash", "-n", str(installer)], check=True)
    help_result = subprocess.run(
        [str(installer), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--config" in help_result.stdout
    assert "root:wheel" in help_result.stdout
    assert "0640" in help_result.stdout
    assert "No dedicated service user or group" in help_result.stdout

    text = installer.read_text(encoding="utf-8")
    required = {
        'CONFIG_DEST="/opt/cisco/secureclient/defenseclaw/etc/config.yaml"',
        'install_file_atomic "$CONFIG_SOURCE" "$CONFIG_DEST" root wheel 0640',
        'install_file_atomic "$MANIFEST_SOURCE" "$MANIFEST_DEST" root wheel 0640',
        'create_directory_no_replace "$BINARY_ROOT" root wheel 0755',
        'create_directory_no_replace "$BIN_DIR" root wheel 0755',
        'create_directory_no_replace "$ETC_DIR" root wheel 0755',
        'create_directory_no_replace "$RUNTIME_DIR" root wheel 0750',
        'create_directory_no_replace "$GUARDIAN_DIR" root wheel 0750',
        'create_directory_no_replace "$AUTH_DIR" root wheel 0750',
        'create_directory_no_replace "$LOG_DIR" root wheel 0750',
        'for parent in /opt /opt/cisco /opt/cisco/secureclient "$LOG_VENDOR_DIR" "$LOG_PRODUCT_DIR"; do',
        'assert_path_metadata "$CONFIG_DEST" file 0 "$WHEEL_GID" 640',
        'assert_path_metadata "$MANIFEST_DEST" file 0 "$WHEEL_GID" 640',
        'assert_path_metadata "$ETC_DIR" dir 0 "$WHEEL_GID" 755',
        'assert_path_metadata "$RUNTIME_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$GUARDIAN_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$AUTH_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$LOG_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_existing_secure_dir_or_absent "$RUNTIME_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_VENDOR_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_PRODUCT_DIR"',
        "assert_trusted_system_dir /opt",
        "assert_trusted_system_dir /opt/cisco",
        "assert_trusted_system_dir /opt/cisco/secureclient",
        'refuse_symlink "$CONFIG_DEST"',
        "assert_no_write_acl()",
        'assert_no_write_acl "$path"',
        "write-capable macOS ACL is not trusted",
        'EnvironmentVariables',
        'DEFENSECLAW_DEPLOYMENT_MODE',
    }
    missing = sorted(value for value in required if value not in text)
    assert not missing
    directory_creation = 'create_directory_no_replace "$BINARY_ROOT" root wheel 0755'
    for ancestor in ("/opt", "/opt/cisco", "/opt/cisco/secureclient"):
        assert text.index(directory_creation) < text.index(f"assert_trusted_system_dir {ancestor}")
    stale_service_identity_contract = {
        "SERVICE_USER",
        "SERVICE_GROUP",
        "SERVICE_UID",
        "SERVICE_GID",
        "assert_existing_acl_safe_dir_or_absent",
    }
    present = sorted(value for value in stale_service_identity_contract if value in text)
    assert not present

    assert "existing DefenseClaw installation detected at" in text
    assert "no changes were made. This installer is fresh-install-only" in text
    assert "remain on the current version" in text
    assert 'local_users="$(/usr/bin/dscl . -list /Users 2>/dev/null)"' in text
    assert '/usr/bin/dscl . -read "/Users/${local_user}" NFSHomeDirectory' in text
    assert '"${local_home}/.defenseclaw"' in text
    assert '"${local_home}/.local/bin/defenseclaw"' in text
    assert '"${local_home}/.local/bin/defenseclaw-gateway"' in text
    assert "BINARY_ROOT=/opt/cisco/secureclient/defenseclaw" in text
    assert "LOG_DIR=/Library/Logs/Cisco/SecureClient/DefenseClaw" in text
    assert "LEGACY_GATEWAY_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.gateway.plist" in text
    assert "LEGACY_GUARDIAN_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist" in text
    assert "com.defenseclaw.gateway" in text
    assert "com.defenseclaw.hook-guardian" in text
    guard_offset = text.index("existing DefenseClaw installation detected at")
    user_scan_offset = text.index('local_users="$(/usr/bin/dscl . -list /Users 2>/dev/null)"')
    assert guard_offset < text.index(directory_creation)
    assert guard_offset < text.index('ROLLBACK_DIR="$(/usr/bin/mktemp -d')
    assert user_scan_offset < text.index('assert_trusted_file_source "$CONFIG_SOURCE"')
    atomic_install = text[
        text.index("install_file_atomic() {") : text.index("plist_pins_managed_mode() {")
    ]
    assert '/bin/mv -f -- "$temporary" "$destination"' not in atomic_install
    assert '/bin/ln -- "$temporary" "$destination"' in atomic_install
    assert "appeared concurrently and was preserved" in text
    assert guard_offset < text.index("ROLLBACK_ARMED=true")
    assert guard_offset < text.index('stop_job_if_loaded "$GUARDIAN_LABEL"')
    assert '/bin/launchctl enable "system/${GATEWAY_LABEL}"' in text
    assert '/bin/launchctl kickstart -k "system/${GATEWAY_LABEL}"' in text
    assert "system/com.defenseclaw.gateway" not in text
    assert "system/com.defenseclaw.hook-guardian" not in text

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "macos-enterprise-packaging:" in workflow
    assert "./scripts/test-macos-enterprise-packaging.sh" in workflow

    smoke = (ROOT / "scripts" / "test-macos-enterprise-packaging.sh").read_text(encoding="utf-8")
    assert "everyone allow add_file,add_subdirectory,delete_child" in smoke
    assert "fresh-install-only enterprise package accepted a write-capable existing root" in smoke
    assert "managed_root=\"/opt/cisco/secureclient/defenseclaw\"" in smoke
    assert "config_dest=\"${managed_root}/etc/config.yaml\"" in smoke
    assert "log_dir=/Library/Logs/Cisco/SecureClient/DefenseClaw" in smoke
    assert "assert_no_defenseclaw_identity()" in smoke
    assert smoke.count("assert_no_defenseclaw_identity \"") == 5
    assert "dscl . -create" not in smoke
    assert 'legacy_managed_root="/Library/Application Support/DefenseClaw"' in smoke
    assert "legacy_binary_root=/Library/DefenseClaw" in smoke
    assert "fresh-install-only enterprise package overwrote an existing deployment" in smoke
    assert "enterprise package ignored a per-user DefenseClaw installation" in smoke
    assert "per-user refusal did not name the dscl-resolved home marker" in smoke
    assert "per-user refusal mutated managed destination" in smoke
    assert "existing-install refusal modified managed config" in smoke
    assert "enterprise package repaired/overwrote existing damaged metadata" in smoke
    assert 'trusted_fixture="/Library/DefenseClawPackagingSmoke.$$"' in smoke


def test_launchd_enterprise_installer_matches_cisco_plist_layout():
    installer = ROOT / "packaging" / "launchd" / "install-enterprise.sh"
    text = installer.read_text(encoding="utf-8")

    gateway_plist = ROOT / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.plist"
    guardian_plist = (
        ROOT / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.hook-guardian.plist"
    )
    with gateway_plist.open("rb") as fh:
        gateway = plistlib.load(fh)
    with guardian_plist.open("rb") as fh:
        guardian = plistlib.load(fh)

    home = gateway["EnvironmentVariables"]["DEFENSECLAW_HOME"]
    config = gateway["EnvironmentVariables"]["DEFENSECLAW_CONFIG"]
    auth_dir = gateway["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
    # The manifest path follows the --manifest flag; explicit lookup instead
    # of positional indexing (ProgramArguments[-1] used to be the manifest
    # under `hooks reconcile --manifest <path>`, but the current watch-mode
    # args add `--interval 60s` after the manifest, making index -1 wrong).
    guardian_args = guardian["ProgramArguments"]
    manifest_flag = guardian_args.index("--manifest")
    manifest = guardian_args[manifest_flag + 1]

    assert f"BINARY_ROOT={home}" in text
    assert f'CONFIG_DEST="{config}"' in text
    assert f'MANIFEST_DEST="{manifest}"' in text
    assert f'AUTH_DIR="{auth_dir}"' in text
    assert f'GATEWAY_LABEL={gateway["Label"]}' in text
    assert f'GUARDIAN_LABEL={guardian["Label"]}' in text
    assert '"system/${GATEWAY_LABEL}"' in text
    assert '"system/${GUARDIAN_LABEL}"' in text
    assert "snapshot_file()" in text
    assert "restore_snapshots()" in text
    assert "rebootstrap_previously_loaded_job()" in text
    assert "rollback_install()" in text
    assert "GATEWAY_WAS_LOADED=true" in text
    assert "GUARDIAN_WAS_LOADED=true" in text
    assert 'snapshot_file "$destination"' in text
    assert text.index("ROLLBACK_ARMED=true") < text.index('stop_job_if_loaded "$GUARDIAN_LABEL"')
    assert 'stop_job_if_loaded "$GATEWAY_LABEL"' in text
    assert 'stop_job_if_loaded "$GUARDIAN_LABEL"' in text
    assert "ROLLBACK_ARMED=false" in text
    assert "system/com.defenseclaw." not in text

    deployment_docs = (
        ROOT / "docs-site" / "content" / "docs" / "setup" / "enterprise-deployment.mdx"
    ).read_text(encoding="utf-8")
    documented_contract = {
        "There is no dedicated `defenseclaw` service user on macOS.",
        "| `/opt/cisco/secureclient/defenseclaw/etc` | `root:wheel` | `0755` |",
        "| `/opt/cisco/secureclient/defenseclaw/etc/config.yaml` | `root:wheel` | `0640` |",
        "| `/opt/cisco/secureclient/defenseclaw/runtime` | `root:wheel` | `0750` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian` | `root:wheel` | `0750` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml` | `root:wheel` | `0640` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian-state` | `root:wheel` | `0750` |",
        "| `/Library/Logs/Cisco/SecureClient/DefenseClaw` | `root:wheel` | `0750` |",
        "A failure after jobs are stopped restores the previous binary, config, manifest, and plists",
    }
    missing_contract = sorted(value for value in documented_contract if value not in deployment_docs)
    assert not missing_contract
