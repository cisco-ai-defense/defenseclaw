# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
import plistlib
import stat
import subprocess
from pathlib import Path

import pytest
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


def test_release_archives_ship_enterprise_packaging_assets():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    for archive in config["archives"]:
        archive_files = archive["files"]
        assert "packaging/**/*" in archive_files
        assert "LICENSE*" in archive_files
        assert "NOTICE" in archive_files
        assert "THIRD_PARTY_LICENSES.txt" in archive_files
        assert "README*" in archive_files


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
        "golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 (LICENSE)": (
            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
        ),
        "golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 (PATENTS)": (
            "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"
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
        "9b4947da3948bdd8d6ae728bc4ba72b93f61e841/LICENSE",
        "https://github.com/golang/exp/blob/"
        "9b4947da3948bdd8d6ae728bc4ba72b93f61e841/PATENTS",
    )
    for provenance_url in provenance_urls:
        assert provenance_url in heading
    assert "cel.dev/expr v0.25.1 is Apache-2.0-only" in heading

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    go_sum = (ROOT / "go.sum").read_text(encoding="utf-8")
    go_mod_requirements = (
        "\tgithub.com/google/cel-go v0.30.0\n",
        "\tmvdan.cc/sh/v3 v3.13.1\n",
        "\tcel.dev/expr v0.25.1 // indirect\n",
        "\tgithub.com/antlr4-go/antlr/v4 v4.13.1 // indirect\n",
        "\tgolang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect\n",
    )
    for requirement in go_mod_requirements:
        assert requirement in go_mod

    go_module_sums = (
        "cel.dev/expr v0.25.1 h1:1KrZg61W6TWSxuNZ37Xy49ps13NUovb66QLprthtwi4=",
        "github.com/antlr4-go/antlr/v4 v4.13.1 "
        "h1:SqQKkuVZ+zWkMMNkjy5FZe5mr5WURWnlpmOuzYWrPrQ=",
        "github.com/google/cel-go v0.30.0 "
        "h1:ll54AkzKunWkBn9wSoiUXbFZXYZTkdJGNXTBXUoolGo=",
        "golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 "
        "h1:kx6Ds3MlpiUHKj7syVnbp57++8WpuKPcR5yjLBjvLEA=",
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

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    dist_plugin = makefile[
        makefile.index("\ndist-plugin:") : makefile.index("\ndist-sandbox:")
    ]
    assert "package.json openclaw.plugin.json dist/" in dist_plugin
    assert "package-lock.json" not in dist_plugin

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f"include {name}" in manifest

    bundle_builder = (ROOT / "scripts/build-macos-bundle.sh").read_text(encoding="utf-8")
    app_builder = (ROOT / "scripts/build-macos-app-release.sh").read_text(encoding="utf-8")
    app_verifier = (ROOT / "scripts/verify-macos-app-release.sh").read_text(encoding="utf-8")
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
        assert f'cp "${{ROOT}}/{name}" ' in app_builder
    assert windows_gateway_license_staging in windows_builder
    assert (
        "foreach ($file in @('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', "
        "'THIRD_PARTY_LICENSES.txt', 'MANIFEST.in'))"
    ) in windows_builder
    assert (
        "Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) "
        "-Destination $packageStage -Force"
    ) in windows_builder
    assert 'cmp -s "${ROOT}/${relative}" "${PAYLOAD}/${relative}"' in app_verifier
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
