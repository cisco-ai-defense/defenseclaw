# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


SYSTEMD = ROOT / "packaging" / "systemd"
STANDALONE_ENV = {
    "Environment=DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise",
    "Environment=DEFENSECLAW_ENTERPRISE_PROFILE=standalone",
    "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
    "Environment=DEFENSECLAW_HOME=/var/lib/defenseclaw",
    "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian",
}


def _unit(name: str) -> list[str]:
    return (SYSTEMD / name).read_text(encoding="utf-8").splitlines()


def test_systemd_gateway_unit_pins_the_hardening_contract():
    lines = _unit("defenseclaw-gateway.service")
    required = STANDALONE_ENV | {
        "Type=notify",
        "NotifyAccess=main",
        "Sockets=defenseclaw-gateway-api.socket defenseclaw-gateway-hook.socket",
        "User=defenseclaw",
        "Group=defenseclaw",
        "Restart=always",
        "StartLimitIntervalSec=0",
        "WatchdogSec=60s",
        "PrivateUsers=no",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "SystemCallFilter=@system-service",
        "ReadWritePaths=/var/lib/defenseclaw /var/log/defenseclaw /run/defenseclaw -/run/defenseclaw-hook",
    }
    missing = sorted(line for line in required if line not in lines)
    assert not missing
    assert "DynamicUser=yes" not in lines


def test_systemd_sockets_and_the_sensor_helper_socket_directory():
    api = _unit("defenseclaw-gateway-api.socket")
    hook = _unit("defenseclaw-gateway-hook.socket")
    assert "ListenStream=127.0.0.1:18970" in api and "FileDescriptorName=api" in api
    for line in (
        "ListenStream=/run/defenseclaw-hook/hook.sock",
        "FileDescriptorName=hook",
        "SocketUser=defenseclaw",
        "SocketMode=0666",
        "DirectoryMode=0755",
    ):
        assert line in hook
    # A stop of the gateway must not take the listeners with it.
    assert not any(line.startswith("PartOf=") for line in api + hook)
    helper = _unit("defenseclaw-sensor-helper.service")
    assert "RuntimeDirectory=defenseclaw-sensor" in helper
    assert "ReadWritePaths=/run" not in helper
    # Plane C's fanotify watch: fanotify_* are in @privileged, not @system-service.
    assert "SystemCallFilter=fanotify_init fanotify_mark" in helper
    assert "Before=defenseclaw-gateway.service" in helper


def _unit_values(lines: list[str], key: str) -> set[str]:
    values: set[str] = set()
    for line in lines:
        if line.startswith(key + "="):
            values.update(line.split("=", 1)[1].split())
    return values


def test_systemd_root_hook_units_keep_setid_capabilities_under_a_syscall_filter():
    # systemd 255 (Ubuntu 24.04) drops CAP_SETUID from a service that names
    # User= and sets SystemCallFilter= unless the capability is also ambient.
    # The hook guardian, its reconcile run and the enumerator then refuse to
    # start their per-user workers, the package's postinstall ensure fails
    # verify and rolls back, and the deb never installs. The CI deb install
    # lane (scripts/test-enterprise-unix-install.sh) runs this on the real
    # systemd; this pins the unit contract.
    checked = set()
    for unit in sorted(SYSTEMD.glob("*.service")):
        lines = _unit(unit.name)
        needed = _unit_values(lines, "CapabilityBoundingSet") & {"CAP_SETUID", "CAP_SETGID"}
        if not needed or not _unit_values(lines, "User") or not _unit_values(lines, "SystemCallFilter"):
            continue
        assert needed <= _unit_values(lines, "AmbientCapabilities"), unit.name
        checked.add(unit.name)
    assert checked == {
        "defenseclaw-hook-enumerator.service",
        "defenseclaw-hook-guardian-reconcile.service",
        "defenseclaw-hook-guardian.service",
    }
    for name in checked:
        # Ambient capabilities never widen the bounding set.
        lines = _unit(name)
        assert _unit_values(lines, "AmbientCapabilities") == {"CAP_SETGID", "CAP_SETUID"}, name
        assert _unit_values(lines, "AmbientCapabilities") <= _unit_values(lines, "CapabilityBoundingSet"), name
        assert "User=root" in lines and "NoNewPrivileges=true" in lines, name


def test_systemd_enumerator_can_publish_refused_surfaces():
    # The enumerator writes refused-surfaces.json into the guardian data dir;
    # under ProtectSystem=strict that dir must be writable or every cycle
    # fails with EROFS and the gateway never sees the refusals (GAP-1441).
    lines = _unit("defenseclaw-hook-enumerator.service")
    assert "ProtectSystem=strict" in lines
    assert "/var/lib/defenseclaw-hook-guardian" in _unit_values(lines, "ReadWritePaths")
    assert "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian" in lines
    # The file is chowned root:defenseclaw so the gateway can read it; without
    # CAP_CHOWN the chown fails and every hook call is refused 503 (GAP-1760).
    assert "CAP_CHOWN" in _unit_values(lines, "CapabilityBoundingSet")


def test_launchd_standalone_daemons():
    directory = ROOT / "packaging" / "launchd-standalone"
    labels = sorted(p.stem for p in directory.glob("*.plist"))
    assert labels == [
        "com.cisco.defenseclaw.apply",
        "com.cisco.defenseclaw.gateway",
        "com.cisco.defenseclaw.hook-enumerator",
        "com.cisco.defenseclaw.hook-guardian",
        "com.cisco.defenseclaw.sensor-helper",
        "com.cisco.defenseclaw.verify",
    ]
    for label in labels:
        with (directory / f"{label}.plist").open("rb") as fh:
            payload = plistlib.load(fh)
        assert payload["Label"] == label
        assert payload["ProgramArguments"][0].startswith("/opt/cisco/defenseclaw/bin/")
        assert "secureclient" not in json.dumps(payload).lower()
    with (directory / "com.cisco.defenseclaw.gateway.plist").open("rb") as fh:
        gateway = plistlib.load(fh)
    assert gateway["UserName"] == "_defenseclaw" and gateway["GroupName"] == "_defenseclaw"
    env = gateway["EnvironmentVariables"]
    assert env["DEFENSECLAW_ENTERPRISE_PROFILE"] == "standalone"
    assert env["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert env["DEFENSECLAW_UNIX_SERVICE_ACCOUNT"] == "_defenseclaw"
    assert env["DEFENSECLAW_CONFIG"] == "/opt/cisco/defenseclaw/etc/config.yaml"
    for root_job in ("com.cisco.defenseclaw.hook-guardian", "com.cisco.defenseclaw.hook-enumerator", "com.cisco.defenseclaw.sensor-helper"):
        with (directory / f"{root_job}.plist").open("rb") as fh:
            assert "UserName" not in plistlib.load(fh)


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
    args = payload["ProgramArguments"]
    assert "--interval" in args, "guardian must pass --interval flag"
    interval_idx = args.index("--interval")
    # The value must immediately follow the flag, otherwise the CLI
    # will misparse the argv (a lone "60s" later in the vector would
    # bind to a different flag or be ignored).
    assert interval_idx + 1 < len(args), "--interval has no value argument"
    assert args[interval_idx + 1] == "60s", (
        f"guardian --interval value must be 60s, got {args[interval_idx + 1]!r}"
    )
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


def test_enterprise_rpm_owns_its_doc_directory():
    # An rpm erase removes only the directories the package lists; without
    # the entry /usr/share/doc/defenseclaw-enterprise stays behind, empty.
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    owned = {c["dst"] for c in nfpm["contents"] if c.get("type") == "dir"}
    assert "/usr/share/doc/defenseclaw-enterprise" in owned


def test_release_archives_ship_enterprise_packaging_assets():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    for archive in config["archives"]:
        archive_files = archive["files"]
        assert "packaging/**/*" in archive_files
        assert "LICENSE*" in archive_files
        assert "NOTICE" in archive_files
        assert "THIRD_PARTY_LICENSES.txt" in archive_files
        assert "README*" in archive_files


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize("argument", ["upgrade", "1", "deconfigure", "failed-upgrade"])
def test_linux_enterprise_preremove_leaves_upgrades_to_the_new_postinstall(tmp_path: Path, argument: str):
    # The script must exit before it touches the lifecycle on an upgrade;
    # a stub gateway on PATH would never be reached (it uses an absolute path).
    completed = subprocess.run(
        ["sh", str(ROOT / "packaging/linux/preremove.sh"), argument],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""


def test_third_party_license_text_and_platform_packaging_contracts():
    third_party = (ROOT / "THIRD_PARTY_LICENSES.txt").read_text(encoding="utf-8")
    section_separator = "=" * 78
    heading, first_section, _ = third_party.partition(f"{section_separator}\n")
    assert first_section
    assert "not an exhaustive inventory" in " ".join(heading.split())

    def exact_section(title: str) -> str:
        marker = f"{section_separator}\n{title}\n{section_separator}\n\n"
        assert third_party.count(marker) == 1
        remainder = third_party.partition(marker)[2]
        body, next_section, _ = remainder.partition(f"\n{section_separator}\n")
        return body if next_section else remainder

    section_digests = {
        "mvdan.cc/sh/v3 v3.13.1 (BSD-3-Clause)": (
            "ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c"
        ),
        "github.com/google/cel-go v0.30.0 (LICENSE)": (
            "4cdb9af102dfbb0ca03d87d6f650a505df098646a4080f4665b389ad9c6caa02"
        ),
        "github.com/antlr4-go/antlr/v4 v4.13.1 (LICENSE)": (
            "683fcd416d83b64781e229a3c2a598462fbf55c5c9fea54be244766b22c033cf"
        ),
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 (LICENSE)": (
            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
        ),
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 (PATENTS)": (
            "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"
        ),
        "github.com/NVIDIA/OpenShell/sdk/go v0.0.0-20260926030648-4ce767fc0cad (LICENSE)": (
            "c4be3acebe12527d7de689933d98329b4065f8c50cd929d0365584eafe6c20dd"
        ),
    }
    for title, digest in section_digests.items():
        assert digest in heading
        assert hashlib.sha256(exact_section(title).encode()).hexdigest() == digest

    provenance_urls = (
        "https://github.com/mvdan/sh/blob/v3.13.1/LICENSE",
        "https://github.com/google/cel-go/blob/v0.30.0/LICENSE",
        "https://github.com/antlr4-go/antlr/blob/v4.13.1/LICENSE",
        "https://github.com/golang/exp/blob/"
        "054e65f0b394d1bf387a254295588fb7e5bd0516/LICENSE",
        "https://github.com/golang/exp/blob/"
        "054e65f0b394d1bf387a254295588fb7e5bd0516/PATENTS",
        "https://github.com/NVIDIA/OpenShell/blob/v0.1.1/LICENSE",
    )
    for provenance_url in provenance_urls:
        assert provenance_url in heading
    assert "cel.dev/expr v0.25.2 is Apache-2.0-only" in heading

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    go_sum = (ROOT / "go.sum").read_text(encoding="utf-8")
    go_mod_requirements = (
        "\tgithub.com/google/cel-go v0.30.0\n",
        "\tmvdan.cc/sh/v3 v3.13.1\n",
        "\tcel.dev/expr v0.25.2 // indirect\n",
        "\tgithub.com/NVIDIA/OpenShell/sdk/go v0.0.0-20260926030648-4ce767fc0cad\n",
        "\tgithub.com/antlr4-go/antlr/v4 v4.13.1 // indirect\n",
        "\tgolang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect\n",
    )
    for requirement in go_mod_requirements:
        assert requirement in go_mod

    go_module_sums = (
        "cel.dev/expr v0.25.2 h1:K6j46C81hXtZQfuX60cVWQFBJahKSE2gfRbNuvr5bFs=",
        "github.com/antlr4-go/antlr/v4 v4.13.1 "
        "h1:SqQKkuVZ+zWkMMNkjy5FZe5mr5WURWnlpmOuzYWrPrQ=",
        "github.com/google/cel-go v0.30.0 "
        "h1:ll54AkzKunWkBn9wSoiUXbFZXYZTkdJGNXTBXUoolGo=",
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 "
        "h1:nDVHiLt8aIbd/VzvPWN6kSOPE7+F/fNFDSXLVYkE/Iw=",
        "mvdan.cc/sh/v3 v3.13.1 "
        "h1:DP3TfgZhDkT7lerUdnp6PTGKyxxzz6T+cOlY/xEvfWk=",
    )
    for module_sum in go_module_sums:
        assert f"{module_sum}\n" in go_sum

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    notice_words = " ".join(notice.split())
    assert "GoReleaser archive Syft SBOM sidecars" in notice
    assert "Windows Setup merged SPDX 2.3 SBOM" in notice
    assert "not an exhaustive dependency inventory" in notice_words
    notice_dependencies = (
        "CEL-Go (github.com/google/cel-go) — Apache-2.0 with BSD-3-Clause component",
        "CEL expression protobufs (cel.dev/expr) — Apache-2.0",
        "ANTLR4 Go runtime (github.com/antlr4-go/antlr/v4) — BSD-3-Clause",
        "Go experimental packages (golang.org/x/exp) — BSD-3-Clause",
    )
    for dependency in notice_dependencies:
        assert dependency in notice
    manifest_paths = (
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/openclaw.plugin.json",
        "extensions/defenseclaw/package-lock.json",
        "docs-site/package.json",
        "docs-site/package-lock.json",
    )
    for manifest_path in manifest_paths:
        assert (ROOT / manifest_path).is_file()
        assert manifest_path in notice
        assert manifest_path in heading
    assert "the runtime archive carries them as root package.json" in notice_words
    assert "is not placed in that runtime archive" in notice_words
    assert "not a DefenseClaw runtime artifact" in notice_words

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f"include {name}" in manifest

    bundle_builder = (ROOT / "scripts/build-macos-bundle.sh").read_text(encoding="utf-8")
    windows_builder = (ROOT / "scripts/windows-native-ci.ps1").read_text(encoding="utf-8-sig")
    windows_installer = (ROOT / "scripts/build-windows-installer.ps1").read_text(
        encoding="utf-8-sig"
    )
    windows_gateway_license_staging = """\
    foreach ($file in @('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.txt')) {
        foreach ($targetRoot in @($gatewayVerificationStage, $stage)) {
            Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) -Destination $targetRoot -Force
        }
    }"""
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f'cp {name} ' in bundle_builder
    assert windows_gateway_license_staging in windows_builder
    assert (
        "foreach ($file in @('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', "
        "'THIRD_PARTY_LICENSES.txt', 'MANIFEST.in'))"
    ) in windows_builder
    assert (
        "Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) "
        "-Destination $packageStage -Force"
    ) in windows_builder
    assert (
        """\
        '--source', $stage,
        '--output', $gatewayArchive,"""
        in windows_builder
    )
    assert (
        """\
        '--source', $gatewayVerificationStage,
        '--output', $gatewayArchiveVerification,"""
        in windows_builder
    )
    assert "gateway ZIP must contain exactly one root $file file" in windows_builder
    assert "gateway ZIP $file differs from the canonical source file" in windows_builder
    assert "Expand-Archive -LiteralPath $gatewayZip -DestinationPath $gatewayPayloadDir" in (
        windows_installer
    )
    assert "Write-ZipFromDirectory $gatewayPayloadDir $embeddedGatewayZip" in windows_installer


@pytest.mark.skipif(os.name == "nt", reason="launchd installer POSIX ownership and executable-bit contract")
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

    # Idempotent-reinstall contract: the installer no longer refuses on
    # existing markers. It logs a reconcile message, unloads any current-
    # generation launchd labels, and relocates legacy paths under LOG_DIR.
    # Per-user ~/.defenseclaw is informational only — the hook-guardian
    # daemon owns per-user reconciliation, so the installer must not
    # abort or delete on those markers.
    assert "reconciling existing DefenseClaw installation in place" in text
    assert "idempotent reinstall" in text
    assert "fresh managed_enterprise install" in text
    assert "will be reconciled by hook-guardian" in text
    assert "moved legacy path aside" in text
    # Old refusal strings must NOT be present — they were the exact
    # symptoms the reinstall rework fixes.
    assert "no changes were made. This installer is fresh-install-only" not in text
    assert "remain on the current version" not in text
    assert '/usr/bin/dscl . -list /Users' in text
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
    # Reconcile happens before any mutation: bootout / rebootstrap the
    # current-gen labels and relocate legacy paths before the ROLLBACK
    # snapshot arms so an interrupted reinstall rolls back cleanly.
    reconcile_offset = text.index("reconciling existing DefenseClaw installation in place")
    assert reconcile_offset < text.index('ROLLBACK_DIR="$(/usr/bin/mktemp -d')
    assert reconcile_offset < text.index('assert_trusted_file_source "$CONFIG_SOURCE"')
    # Pre-mutation logs-chain trust check MUST run before the early
    # mkdir/mv relocation block. Without this a symlinked /Library/Logs
    # ancestor or an ACL-writable LOG_DIR ancestor could let the
    # `mkdir -p` + `mv` steps below relocate legacy config / audit
    # material into an attacker-controlled target before the later
    # validation (line ~582) has a chance to fire. Mirrors the
    # `_assert_trusted_logs_chain_or_die` gate in packaging/macos/install.sh.
    logs_chain_gate = text.index("Ancestor trust check: before ANY mkdir/chown/chmod on the")
    early_mkdir_landing = text.index("Ensure LOG_DIR exists early so the legacy relocation below")
    legacy_relocation = text.index("moved legacy path aside")
    assert logs_chain_gate < early_mkdir_landing
    assert logs_chain_gate < legacy_relocation
    # The gate must call the primitive assertions against every
    # /Library/Logs/... ancestor, not just LOG_DIR itself.
    gate_block = text[logs_chain_gate:early_mkdir_landing]
    assert 'assert_trusted_system_dir /Library' in gate_block
    assert 'assert_existing_secure_dir_or_absent /Library/Logs' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_VENDOR_DIR"' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_PRODUCT_DIR"' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_DIR"' in gate_block
    # install_file_atomic uses mv -f (rename(2), atomic replace) so an
    # existing regular destination is overwritten cleanly on reinstall.
    # ln (hardlink) would fail with EEXIST on the second run.
    atomic_install = text[
        text.index("install_file_atomic() {") : text.index("plist_pins_managed_mode() {")
    ]
    assert '/bin/mv -f -- "$temporary" "$destination"' in atomic_install
    assert '/bin/ln -- "$temporary" "$destination"' not in atomic_install
    assert '/bin/launchctl enable "system/${GATEWAY_LABEL}"' in text
    assert '/bin/launchctl kickstart -k "system/${GATEWAY_LABEL}"' in text
    # Legacy launchd labels are unloaded (via bootout) so their stale
    # plists don't keep spawn-and-crashing; the current-gen labels are
    # ALSO booted out before rebootstrap during a reinstall.
    assert '/bin/launchctl bootout "system/${_legacy_label}"' in text

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "macos-enterprise-packaging:" in workflow
    assert "./scripts/test-macos-enterprise-packaging.sh" in workflow

    smoke = (ROOT / "scripts" / "test-macos-enterprise-packaging.sh").read_text(encoding="utf-8")
    # Smoke test asserts the reinstall contract end-to-end.
    assert "managed_root=\"/opt/cisco/secureclient/defenseclaw\"" in smoke
    assert "config_dest=\"${managed_root}/etc/config.yaml\"" in smoke
    assert "log_dir=/Library/Logs/Cisco/SecureClient/DefenseClaw" in smoke
    assert "assert_no_defenseclaw_identity()" in smoke
    assert 'legacy_managed_root="/Library/Application Support/DefenseClaw"' in smoke
    assert "legacy_binary_root=/Library/DefenseClaw" in smoke
    # Reinstall-contract-specific expectations:
    assert "Reinstall reconciles machine-wide state" in smoke
    assert "idempotent reinstall failed" in smoke
    assert "reinstall did not restore config to freshly-rendered content" in smoke
    assert "reinstall did not emit legacy-relocation log line" in smoke
    assert "reconciling existing DefenseClaw installation in place" in smoke
    # Untrusted config source is still refused (trust contract unchanged
    # by the reinstall rework):
    assert "installer accepted writable config source (source-trust contract broken)" in smoke
    assert "untrusted source refusal did not identify managed config trust" in smoke
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
        ROOT / "docs-site" / "content" / "docs" / "enterprise" / "secure-client.mdx"
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


# ---- scriptlets and the MDM wrapper under concurrent lifecycle runs

LINUX = ROOT / "packaging" / "linux"
APPLY_PATH = "defenseclaw-enterprise-apply.path"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def _write_stub(bin_dir: Path, name: str, body: str) -> None:
    stub = bin_dir / name
    stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    stub.chmod(0o755)


def _rooted(text: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        assert old in text, old
        text = text.replace(old, new)
    return text


class _Host:
    """A temporary host: stub tools on PATH, a stub gateway and a call log."""

    def __init__(
        self,
        tmp_path: Path,
        gateway_rc: int = 0,
        apply_path_active: bool = False,
        gateway_out: str = '{"schema_version":2,"ok":true}',
    ):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.log = tmp_path / "calls.log"
        self.gateway = tmp_path / "defenseclaw-gateway"
        self.state = tmp_path / "state"
        self.run_systemd = tmp_path / "run-systemd-system"
        self.run_systemd.mkdir()
        self.active = tmp_path / "apply-path-active"
        if apply_path_active:
            self.active.write_text("", encoding="utf-8")
        _write_stub(self.bin, "systemctl", f"""echo "systemctl $*" >>'{self.log}'
case "$1" in
    is-active) [ -e '{self.active}' ] ;;
    stop) rm -f '{self.active}' ;;
    start) : >'{self.active}' ;;
esac""")
        for tool in ("systemd-sysusers", "systemd-tmpfiles"):
            _write_stub(self.bin, tool, f"""echo "{tool} $*" >>'{self.log}'""")
        _write_stub(self.tmp, "defenseclaw-gateway", f"""echo "gateway $*" >>'{self.log}'
cat <<'JSON'
{gateway_out}
JSON
exit {gateway_rc}""")

    def run(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        path = self.tmp / "script.sh"
        path.write_text(script, encoding="utf-8")
        env = {"PATH": f"{self.bin}:/usr/bin:/bin"}
        return subprocess.run(["sh", str(path), *args], env=env, capture_output=True, text=True, timeout=60)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


def _linux_scriptlet(host: _Host, name: str) -> str:
    return _rooted(
        (LINUX / name).read_text(encoding="utf-8"),
        {
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "/run/systemd/system": str(host.run_systemd),
        },
    )


# The postinstall's own systemd-tmpfiles and daemon-reload started
# the config-apply path unit, whose ensure won the lifecycle lock and did the
# upgrade, while the scriptlet's ensure (default 5 s wait) exited 75 and every
# upgrade reported "the lifecycle reported a problem".
def test_linux_postinstall_holds_the_apply_trigger_and_waits_for_the_lock(tmp_path: Path) -> None:
    host = _Host(tmp_path, gateway_rc=0, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0, result.stderr
    assert "the managed deployment is active" in result.stdout
    calls = host.calls()
    ensure = next(i for i, call in enumerate(calls) if call.startswith("gateway "))
    assert calls[ensure] == "gateway enterprise linux ensure --from-package --reason package --json --lock-wait 10m"
    stop = calls.index(f"systemctl stop {APPLY_PATH}")
    for tool in ("systemd-sysusers", "systemd-tmpfiles", "systemctl daemon-reload"):
        index = next(i for i, call in enumerate(calls) if call.startswith(tool))
        assert stop < index < ensure, (tool, calls)
    assert calls.index(f"systemctl start {APPLY_PATH}") > ensure, calls


@pytest.mark.parametrize(("rc", "message"), [(75, "held the lock for 10 minutes"), (1, "the lifecycle reported a problem")])
def test_linux_postinstall_reports_a_lifecycle_problem_and_restores_the_trigger(tmp_path: Path, rc: int, message: str) -> None:
    host = _Host(tmp_path, gateway_rc=rc, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0  # a package install never fails on the lifecycle
    assert message in result.stderr
    assert host.calls()[-1] == f"systemctl start {APPLY_PATH}"


# GAP-1744: dnf printed only "run verify"; the cause (a missing protected
# credential) was only in last-package-result.json.
# `ensure --json` writes indented JSON (Go SetIndent), so the
# cause must be found in the multi-line form too, not only a compact line.
# GAP-0176: a refused config leaves the previous deployment running, but the
# scriptlet said "no deployment is active".
@pytest.mark.parametrize(("indent", "running"), [(None, ""), (2, ""), (2, "1.0.46-SNAPSHOT-84d98d524")])
def test_linux_postinstall_names_the_lifecycle_error_and_the_finish_step(tmp_path: Path, indent: int | None, running: str) -> None:
    document = {
        "schema_version": 2,
        "ok": False,
        "action": "ensure",
        **({"installed": True, "installed_version": running} if running else {}),
        "errors": [
            {
                "code": "config_invalid",
                "message": 'protected credential "galileo-api-key" is not stored; '
                "store it with `enterprise secret set --name galileo-api-key`",
            }
        ],
        "warnings": [{"code": "unmanaged_leftovers", "message": "not the cause"}],
    }
    separators = (",", ":") if indent is None else None
    result_line = json.dumps(document, indent=indent, separators=separators)
    host = _Host(tmp_path, gateway_rc=1, gateway_out=result_line)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0
    assert (
        'config_invalid: protected credential "galileo-api-key" is not stored; store it with '
        "`enterprise secret set --name galileo-api-key`"
    ) in result.stderr
    if running:
        assert f"installed but not applied; the previous deployment ({running}) keeps running unchanged" in result.stderr
        assert "no deployment is active" not in result.stderr
        assert f"apply this package with: sudo {host.gateway} enterprise linux ensure --from-package" in result.stderr
    else:
        assert f"finish the install with: sudo {host.gateway} enterprise linux ensure --from-package" in result.stderr



# GAP-0268: MDM writes config.yaml and then installs the package. The config
# write started the apply unit, whose ensure ran the old binary while the
# package replaced the files under it; it rolled back and marked the config
# rejected, and the package ensure kept the previous config and said only
# "active". The preinstall now holds the trigger and waits for that run, the
# postinstall puts the trigger back, and a rejected config.yaml is named.
def test_linux_preinstall_holds_the_apply_trigger_until_the_postinstall(tmp_path: Path) -> None:
    rejected = {"code": "config_rejected", "message": "config.yaml was rejected; the last applied config is running"}
    host = _Host(tmp_path, apply_path_active=True, gateway_out=json.dumps({"schema_version": 2, "ok": True, "warnings": [rejected]}))
    held = tmp_path / "apply-path.held"
    host.state.mkdir()
    (host.state / "lifecycle.lock").write_text("", encoding="utf-8")
    _write_stub(host.bin, "flock", f"echo \"flock $*\" >>'{host.log}'")
    rooting = {
        "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
        "/run/systemd/system": str(host.run_systemd),
        "/run/defenseclaw-enterprise-apply-path.held": str(held),
    }
    pre = host.run(_rooted((LINUX / "preinstall.sh").read_text(encoding="utf-8"), rooting), "2")
    assert pre.returncode == 0, pre.stderr
    assert host.calls() == [
        f"systemctl is-active --quiet {APPLY_PATH}",
        f"systemctl stop {APPLY_PATH}",
        f"flock -w 600 {host.state}/lifecycle.lock true",
    ]
    assert held.exists()
    post = host.run(_linux_scriptlet(host, "postinstall.sh").replace("/run/defenseclaw-enterprise-apply-path.held", str(held)), "configure")
    assert post.returncode == 0, post.stderr
    calls = host.calls()
    ensure = next(i for i, call in enumerate(calls) if call.startswith("gateway "))
    assert calls.index(f"systemctl start {APPLY_PATH}") > ensure, calls
    assert not held.exists()
    assert f"config.yaml was not applied: {rejected['message']}" in post.stderr


# GAP-0392: a package older than the administrator config replaced every
# file and then failed its ensure, leaving new binaries next to the old
# deployment. The preinstall refuses it before anything changes, and its
# limit is the gateway MaxSupportedConfigVersion.
def test_linux_preinstall_refuses_a_config_newer_than_the_package(tmp_path: Path) -> None:
    script = (LINUX / "preinstall.sh").read_text(encoding="utf-8")
    limit = re.search(r"^max_config_version=(\d+)$", script, re.M)
    go_config = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "internal" / "config").glob("*.go"))
    go_limit = re.search(r"const MaxSupportedConfigVersion = (\w+)", go_config)
    if go_limit and not go_limit.group(1).isdigit():
        go_limit = re.search(rf"const {go_limit.group(1)} = (\d+)", go_config)
    assert limit and go_limit and limit.group(1) == go_limit.group(1)
    host = _Host(tmp_path, apply_path_active=True)
    config = tmp_path / "config.yaml"
    config.write_text(f"config_version: {int(limit.group(1)) + 1}\nguardrail: {{}}\n", encoding="utf-8")
    rooting = {
        "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
        "/run/systemd/system": str(host.run_systemd),
        "config=/etc/defenseclaw/config.yaml": f"config={config}",
    }
    result = host.run(_rooted(script, rooting), "2")
    assert result.returncode == 1
    assert "Nothing was changed" in result.stderr
    assert host.calls() == []


# Preremove ran uninstall with the 5 s default and exited 0
# on busy (75), so dpkg/rpm deleted the binaries and units while machine
# policy, per-user hooks and the running gateway still named them.
@pytest.mark.parametrize(("rc", "exit_code"), [(0, 0), (1, 0), (75, 1)])
def test_linux_preremove_waits_for_the_lock_and_refuses_the_removal_when_busy(tmp_path: Path, rc: int, exit_code: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "remove")
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    assert host.calls() == ["gateway enterprise linux uninstall --json --lock-wait 10m"]
    if rc == 75:
        assert "nothing was removed" in result.stderr
    elif rc:
        assert "uninstall reported a problem" in result.stderr


# After preremove refuses a removal (busy lock), dpkg runs "postinst
# abort-remove": the postinstall must not wait on the same lock again.
# "abort-upgrade" follows a failed upgrade step the same way.
@pytest.mark.parametrize("argument", ["abort-remove", "abort-upgrade"])
def test_linux_postinstall_does_nothing_after_a_refused_removal(tmp_path: Path, argument: str) -> None:
    host = _Host(tmp_path, gateway_rc=75, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), argument)
    assert result.returncode == 0, result.stderr
    assert host.calls() == []


# GAP-0112: an older deb replaced the binaries before its own scripts could
# refuse it, and the older release cannot read the config_version 9 config, so
# the services crash-looped. dpkg falls back to the incoming package's prerm
# when the installed one fails, so an apt Pre-Install-Pkgs hook refuses the
# downgrade before dpkg runs, unless the rollback marker exists.
@pytest.mark.parametrize(
    ("line", "marker", "exit_code"),
    [
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb < 1.0.47~SNAPSHOT-aaa f.deb", False, 0),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.46~SNAPSHOT-aaa f.deb", False, 0),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > - **REMOVE**", False, 0),
        ("other-package 1.0.46 > 1.0.45 f.deb", False, 0),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.45~SNAPSHOT-aaa f.deb", False, 1),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.45~SNAPSHOT-aaa f.deb", True, 0),
    ],
)
def test_linux_apt_hook_refuses_a_deb_downgrade_unless_the_marker_exists(
    tmp_path: Path, line: str, marker: bool, exit_code: int
) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    _write_stub(
        host.bin,
        "dpkg",
        '[ "$1" = --compare-versions ] && [ "$3" = lt ] && [ "$2" != "$4" ] && '
        '[ "$(printf \'%s\\n%s\\n\' "$2" "$4" | sort -V | head -n 1)" = "$2" ]',
    )
    allow = host.state / "allow-downgrade"
    if marker:
        allow.write_text("", encoding="utf-8")
    script = _rooted(
        (LINUX / "apt-downgrade-guard.sh").read_text(encoding="utf-8"),
        {"state=/var/lib/defenseclaw-enterprise": f"state={host.state}"},
    )
    path = tmp_path / "guard.sh"
    path.write_text(script, encoding="utf-8")
    protocol = f"VERSION 2\nAPT::Architecture=amd64\n\n{line}\n"
    result = subprocess.run(
        ["sh", str(path)],
        input=protocol,
        env={"PATH": f"{host.bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    assert not allow.exists() or exit_code == 1
    if exit_code:
        assert "refusing to downgrade to 1.0.45~SNAPSHOT-aaa" in result.stderr
        assert f"sudo touch {allow}" in result.stderr


def test_enterprise_deb_ships_the_apt_downgrade_hook_and_rpm_does_not() -> None:
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    hook = {c["dst"]: c for c in nfpm["contents"] if c.get("packager") == "deb"}
    script = "/usr/lib/defenseclaw-enterprise/apt-downgrade-guard"
    assert set(hook) == {script, "/etc/apt/apt.conf.d/50defenseclaw-enterprise"}
    assert hook[script]["file_info"]["mode"] == 0o755
    assert hook["/etc/apt/apt.conf.d/50defenseclaw-enterprise"].get("type") != "config"  # removed with the package
    apt_config = (ROOT / hook["/etc/apt/apt.conf.d/50defenseclaw-enterprise"]["src"]).read_text(encoding="utf-8")
    assert f'DPkg::Pre-Install-Pkgs {{ "{script}"; }};' in apt_config
    assert f'DPkg::Tools::Options::{script}::Version "2";' in apt_config


def _macos_pkg_postinstall(host: _Host) -> str:
    builder = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    match = re.search(r"cat >\"\$SCRIPTS/postinstall\" <<'EOF'\n(.*?)\nEOF\n", builder, re.DOTALL)
    assert match, "the pkg postinstall heredoc was not found"
    return _rooted(
        match.group(1) + "\n",
        {
            "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/opt/cisco/defenseclaw/lifecycle": f"state={host.state}",
        },
    )


@pytest.mark.parametrize("rc", [0, 75])
def test_macos_pkg_postinstall_waits_for_the_lock(tmp_path: Path, rc: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_macos_pkg_postinstall(host))
    assert result.returncode == rc
    assert host.calls() == ["gateway enterprise macos ensure --from-package --reason package --json --lock-wait 10m"]


MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"


def _macos_pkg_preinstall(host: _Host, version: str) -> str:
    builder = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    match = re.search(r"cat >\"\$SCRIPTS/preinstall\" <<'EOF'\n(.*?)\nEOF\n", builder, re.DOTALL)
    assert match, "the pkg preinstall heredoc was not found"
    _write_stub(host.bin, "stat", "echo 0")  # the record and marker are root-owned
    return _rooted(
        match.group(1) + "\n",
        {
            "state=/opt/cisco/defenseclaw/lifecycle": f"state={host.state}",
            "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "@DC_PKG_VERSION@": version,
        },
    )


# GAP-1199: a refused downgrade showed only the Installer's generic error,
# and last-package-result.json still held the previous success. The
# refusal now rewrites the result with downgrade_refused and the next step.
@pytest.mark.parametrize("version", ["1.0.0", "1.0.2"])
def test_macos_pkg_preinstall_records_a_refused_downgrade(tmp_path: Path, version: str) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    result_path = host.state / "last-package-result.json"
    result_path.write_text('{"ok":true}', encoding="utf-8")
    (host.state / "deployment.json").write_text('{"product_version": "1.0.1"}', encoding="utf-8")
    result = host.run(_macos_pkg_preinstall(host, version))
    if version == "1.0.2":
        assert result.returncode == 0, result.stderr
        assert result_path.read_text(encoding="utf-8") == '{"ok":true}'
        return
    assert result.returncode == 1
    assert str(result_path) in result.stderr
    document = json.loads(result_path.read_text(encoding="utf-8"))
    assert document["ok"] is False and document["installed_version"] == "1.0.1"
    assert document["errors"][0]["code"] == "downgrade_refused"
    assert "allow-downgrade" in document["errors"][0]["message"]
    assert result_path.stat().st_mode & 0o077 == 0
    try:
        import jsonschema
    except ImportError:
        return
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert not sorted(validator.iter_errors(document), key=str)


def _validate_lifecycle_result(document: dict) -> None:
    try:
        import jsonschema
    except ImportError:
        return
    validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert not sorted(validator.iter_errors(document), key=str)


# GAP-1428: the refusal wrote a fixed document saying every service was down
# and inspection unknown, while the installed version kept running healthy.
# The result now carries the running deployment's status, as the installed
# gateway prints it (indented JSON), plus the refusal.
@pytest.mark.parametrize("standing_errors", [[], [{"code": "verify_failed", "message": "a target drifted"}]])
def test_macos_pkg_preinstall_refusal_keeps_the_running_deployment_facts(tmp_path: Path, standing_errors: list) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    (host.state / "deployment.json").write_text('{"product_version": "1.0.6"}', encoding="utf-8")
    service = {"name": "com.cisco.defenseclaw.gateway", "kind": "gateway", "state": "running", "pid": 42, "required": True}
    status = {
        "schema_version": 2, "ok": not standing_errors, "action": "status", "noop": False, "profile": "standalone",
        "platform": "darwin", "product_version": "1.0.6", "installed_version": "1.0.6", "installed": True,
        "transaction_pending": False, "services": [service],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "active", "ai_defense": "disabled"}, "machine_policy": {},
        "enrollment": {"targets": 2, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True, "security_complete": True, "errors": standing_errors,
        "exit_code": 1 if standing_errors else 0,
    }
    (tmp_path / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    _write_stub(host.tmp, "defenseclaw-gateway", f"""echo "gateway $*" >>'{host.log}'
cat '{tmp_path / "status.json"}'""")
    result = host.run(_macos_pkg_preinstall(host, "1.0.5"))
    assert result.returncode == 1
    assert host.calls() == ["gateway enterprise macos status --json"]
    document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
    assert document["ok"] is False and document["action"] == "ensure" and document["exit_code"] == 1
    assert document["product_version"] == "1.0.5" and document["installed_version"] == "1.0.6"
    assert document["readiness"] == status["readiness"] and document["services"] == [service]
    assert document["inspection"]["local"] == "active"
    assert [e["code"] for e in document["errors"]] == ["downgrade_refused"] + [e["code"] for e in standing_errors]
    _validate_lifecycle_result(document)


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found"
    return match.group(0)


# Each stub answers the queries dc_install_package makes; DC_TEST_INSTALLED is
# the version already installed (empty: not installed).
_PACKAGE_STUBS = {
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in --print-architecture) echo amd64 ;; esac""",
    "dpkg-query": """[ -n "$DC_TEST_INSTALLED" ] || exit 1
printf 'install ok installed %s' "$DC_TEST_INSTALLED\"""",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    -q)
        if [ -z "$DC_TEST_INSTALLED" ]; then echo "package defenseclaw-enterprise is not installed"; exit 1; fi
        [ "$2" != --qf ] || printf '%s' "$DC_TEST_INSTALLED"
        ;;
esac""",
    "pkgutil": """case "$1" in
    --expand) mkdir -p "$3" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="%s" onConclusion="none">x.pkg</pkg-ref>\\n' "$DC_TEST_VERSION" >"$3/Distribution" ;;
    --pkg-info) [ -n "$DC_TEST_INSTALLED" ] || exit 1; echo "version: $DC_TEST_INSTALLED" ;;
    *) exit 1 ;;
esac""",
    "installer": ":",
}


def _noop_ensure_result(platform: str, version: str, warnings: bool) -> dict:
    # The field order and indentation of the Go lifecycle result encoder.
    document = {
        "schema_version": 2, "ok": True, "action": "ensure", "noop": True, "noop_reason": "up_to_date",
        "profile": "standalone", "platform": platform, "product_version": version, "installed_version": version,
        "installed": True, "transaction_pending": False,
        "services": [{"name": "com.cisco.defenseclaw.gateway", "kind": "gateway", "state": "running", "required": True}],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "unknown", "ai_defense": "unknown"}, "machine_policy": {},
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True, "security_complete": True, "errors": [],
    }
    if warnings:
        document["warnings"] = [{"code": "verify_failed", "message": 'a "quoted" \\ message'}]
    document["exit_code"] = 0
    return document


# The wrapper's one result document reported the no-op ensure that
# followed the package step ("action": "ensure", "noop": true) after the
# package's postinstall had upgraded 0.8.11 to 0.8.12.
@pytest.mark.parametrize(
    ("source", "installed", "version", "action", "code", "text"),
    [
        ("defenseclaw-enterprise.pkg", "0.8.11", "0.8.12", "upgrade", "package_upgraded", "from 0.8.11 to 0.8.12"),
        ("defenseclaw-enterprise.pkg", "", "0.8.12", "install", "package_installed", "package 0.8.12"),
        ("defenseclaw-enterprise.deb", "1.4.0", "1.5.0", "upgrade", "package_upgraded", "from 1.4.0 to 1.5.0"),
        ("defenseclaw-enterprise.rpm", "1.4.0-1", "1.5.0-1", "upgrade", "package_upgraded", "from 1.4.0 to 1.5.0"),
        ("defenseclaw-enterprise.rpm", "", "1.5.0-1", "install", "package_installed", "package 1.5.0"),
        ("defenseclaw-enterprise.deb", "1.5.0", "1.5.0", None, None, None),
    ],
)
@pytest.mark.parametrize("warnings", [False, True])
def test_unix_wrapper_result_reports_the_package_step(
    tmp_path: Path, source: str, installed: str, version: str, action: str | None, code: str | None, text: str | None, warnings: bool
) -> None:
    import json

    os_dir = "macos" if source.endswith(".pkg") else "linux"
    wrapper = (MDM / os_dir / "defenseclaw-enterprise.sh").read_text(encoding="utf-8")
    functions = "\n".join(
        _shell_function(wrapper, name)
        for name in ("dc_json_escape", "dc_busy_output", "dc_require_product_version", "dc_package_release_version",
                     "dc_package_step", "dc_annotate_package_step", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in _PACKAGE_STUBS.items():
        _write_stub(bin_dir, name, body)
    platform = "darwin" if os_dir == "macos" else "linux"
    release = version.split("-")[0] if source.endswith(".rpm") else version
    result = tmp_path / "result.json"
    result.write_text(json.dumps(_noop_ensure_result(platform, release, warnings), indent=2) + "\n", encoding="utf-8")
    script = f"""
DC_SCRIPT_OS={platform}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}' DC_RESULT='{result}'
DC_PACKAGE_ACTION='' DC_PACKAGE_PREVIOUS='' DC_PACKAGE_VERSION=''
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
{functions}
dc_install_package
dc_annotate_package_step
cat "$DC_RESULT"
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": version, "DC_TEST_INSTALLED": installed}
    for shell in ("sh", "bash"):
        completed = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        assert completed.returncode == 0, (shell, completed.stdout, completed.stderr)
        document = json.loads(completed.stdout)
        if action is None:
            assert document == _noop_ensure_result(platform, release, warnings), shell
            continue
        assert document["action"] == action and document["noop"] is False and "noop_reason" not in document, (shell, document)
        notes = [w for w in document.get("warnings", []) if w["code"] == code]
        assert len(notes) == 1 and text in notes[0]["message"], (shell, document.get("warnings"))
        if warnings:
            assert {"code": "verify_failed", "message": 'a "quoted" \\ message'} in document["warnings"]
        try:
            import jsonschema
        except ImportError:
            continue
        validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        assert not sorted(validator.iter_errors(document), key=str), shell


# The removal script wrote its result into /var/lib/defenseclaw-enterprise
# after the uninstall had removed it, so a clean package removal left that
# folder behind. Only a removal that reports a problem keeps its result.
@pytest.mark.parametrize("rc", [0, 1])
def test_linux_preremove_keeps_its_result_only_when_the_uninstall_failed(tmp_path: Path, rc: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_linux_scriptlet(host, "preremove.sh").replace("${TMPDIR:-/tmp}", str(tmp_path)), "remove")
    assert result.returncode == 0, result.stderr
    assert list(tmp_path.glob("defenseclaw-preremove.*")) == []
    if rc:
        assert (host.state / "last-package-result.json").is_file()
    else:
        assert not host.state.exists()


# GAP-1254, GAP-1258: the wrapper applied the config before it stored
# --secret-name, so a config that references the credential never applied,
# and the store then failed busy against the apply its own config change
# started. It now stores the credential first and both steps wait.
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("secret_rc", [0, 75])
def test_unix_wrapper_stores_the_credential_before_it_applies_the_config(tmp_path: Path, os_dir: str, secret_rc: int) -> None:
    wrapper = (MDM / os_dir / "defenseclaw-enterprise.sh").read_text(encoding="utf-8")
    functions = "\n".join(_shell_function(wrapper, name) for name in ("dc_run_lifecycle", "dc_main"))
    log = tmp_path / "calls.log"
    gateway = tmp_path / "defenseclaw-gateway"
    gateway.write_text(f"""#!/bin/sh
echo "$*" >>'{log}'
case "$2" in secret) cat >/dev/null; echo secret-busy >&2; exit {secret_rc} ;; esac
echo '{{"ok":true}}'
""", encoding="utf-8")
    gateway.chmod(0o755)
    (tmp_path / "config.yaml").write_text("x: 1\n", encoding="utf-8")
    (tmp_path / "key").write_text("value\n", encoding="utf-8")
    group = "macos" if os_dir == "macos" else "linux"
    script = f"""
DC_SCRIPT_OS={"darwin" if os_dir == "macos" else "linux"}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_MAX_CONFIG_BYTES=4096 DC_MAX_SECRET_BYTES=4096
dc_parse_args() {{ DC_ACTION=ensure DC_CONFIG_STDIN=0 DC_CONFIG_FILE='{tmp_path}/config.yaml' DC_SECRET_NAME=k DC_SECRET_STDIN=0 DC_SECRET_FILE='{tmp_path}/key' DC_SOURCE='' DC_SOURCE_URL='' DC_PRODUCT_VERSION=''; }}
dc_platform() {{ echo "$DC_SCRIPT_OS"; }}
dc_layout() {{ DC_GATEWAY='{gateway}' DC_OS_GROUP={group}; }}
dc_validate_args() {{ :; }}
id() {{ echo 0; }}
mktemp() {{ command mktemp -d '{tmp_path}/stage.XXXXXX'; }}
dc_cleanup() {{ :; }}
dc_stat_uid() {{ echo 0; }}
dc_log() {{ :; }}
dc_trusted_path() {{ :; }}
dc_stage_file() {{ cp "$1" "$2"; }}
dc_annotate_package_step() {{ :; }}
dc_emit_result() {{ cat "$DC_RESULT"; }}
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
{functions}
dc_main
"""
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60)
    calls = log.read_text(encoding="utf-8").splitlines()
    assert result.returncode == secret_rc, result.stdout + result.stderr
    assert calls[0] == "enterprise secret set --name k --from-stdin --lock-wait 10m --json"
    if secret_rc:
        assert calls == calls[:1], calls
        assert "FAIL mdm_secret_failed" in result.stdout and "config was not applied" in result.stdout
        return
    assert len(calls) == 2 and re.fullmatch(
        rf"enterprise {group} ensure --reason mdm --lock-wait 10m --config=.*/stage\.\w+/config\.yaml --json", calls[1]
    ), calls



# GAP-2331: the pkg postinstall logged only "did not apply (exit 1); see
# last-package-result.json"; install.log must name the first error and the
# finish step, as the Linux postinstall does (GAP-1744).
def test_macos_pkg_postinstall_names_the_lifecycle_error_and_the_finish_step(tmp_path: Path) -> None:
    document = {
        "schema_version": 2,
        "ok": False,
        "errors": [{"code": "config_invalid", "message": 'config guardrail.rule_pack_dir "/x/cert-s3" does not exist'}],
    }
    host = _Host(tmp_path, gateway_rc=1, gateway_out=json.dumps(document, indent=2))
    result = host.run(_macos_pkg_postinstall(host))
    assert result.returncode == 1
    assert 'DefenseClaw: config_invalid: config guardrail.rule_pack_dir "/x/cert-s3" does not exist' in result.stderr
    # GAP-2359: a failed install records no pkg receipt and ensure adds
    # none, so the finish step is to install the pkg again.
    assert "fix that, then install the package again" in result.stderr
    assert "records the pkg receipt" in result.stderr
    assert f"sudo {host.gateway} enterprise macos ensure --from-package also finishes the install, but records no pkg receipt" in result.stderr
