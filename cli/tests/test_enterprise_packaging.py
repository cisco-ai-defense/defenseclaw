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
import sys
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


# The per-user archives install.sh and install.ps1 extract. Their Fleet-on
# install copies bin/edge-connector/tools/policy_compiler.py and fails
# without it, so these two must carry it (the 1.0.3 Release install gate
# failed when they did not).
PER_USER_ARCHIVES = {"default", "windows-amd64"}
FLEET_COMPILER = "edge-connector/tools/policy_compiler.py"


def test_managed_package_recipes_exclude_fleet_compiler():
    release = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    archive_ids = {archive["id"] for archive in release["archives"]}
    assert PER_USER_ARCHIVES <= archive_ids
    for archive in release["archives"]:
        files = archive.get("files", [])
        if archive["id"] in PER_USER_ARCHIVES:
            assert FLEET_COMPILER in files, archive["id"]
            continue
        assert not any("policy_compiler.py" in entry for entry in files), archive["id"]
    for package in release["nfpms"]:
        assert not any("policy_compiler.py" in entry.get("src", "") or
                       "policy_compiler.py" in entry.get("dst", "")
                       for entry in package.get("contents", [])), package["id"]
    mac_recipe = (ROOT / "scripts/build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    windows_recipe = (ROOT / "packaging/windows/standalone/build-setup.sh").read_text(encoding="utf-8")
    windows_layout = (ROOT / "packaging/windows/DefenseClawEnterprise.psm1").read_text(encoding="utf-8")
    assert "BUNDLED_COMPILER" not in mac_recipe
    assert 'install -m 0644 "$compiler_src"' not in mac_recipe
    assert "policy_compiler.py" not in windows_recipe
    # The layout still names where a 1.0.2 install put the compiler, so a
    # Fleet-on host can keep it (GAP-0274), but no lifecycle creates that tree.
    layout_directories = windows_layout[windows_layout.index("function New-DefenseClawLayoutDirectories {") :]
    layout_directories = layout_directories[: layout_directories.index("\nfunction ")]
    assert "Compiler" not in layout_directories


def test_windows_standalone_retires_the_empty_compiler_tree():
    # GAP-0270: 1.0.2 Setup created lib\defenseclaw for the Fleet compiler.
    # The Fleet-off retire and every uninstall install-tree check use the same
    # empty-only helper. A recorded compiler a Fleet-on host keeps (GAP-0274)
    # is accepted only through its hash-checked helper.
    module = (ROOT / "packaging/windows/DefenseClawEnterprise.psm1").read_text(encoding="utf-8")
    retire = module[module.index("if ($StandaloneFleetStateKnown -and -not $StandaloneFleetEnabled) {") :]
    assert retire.splitlines()[1].strip() == "Remove-DefenseClawRetiredStandaloneCompiler -Layout $Layout"
    helper = module[module.index("function Get-DefenseClawEmptyRetiredCompilerDirectories {") :]
    helper = helper[: helper.index("\n}\n")]
    assert "ReparsePoint" in helper and "-notin $empty" in helper
    for function in ("Assert-DefenseClawManagedInstallTree", "Remove-DefenseClawCommittedEmptyInstallRoot"):
        body = module[module.index(f"function {function} {{") :]
        body = body[: body.index("\nfunction ")]
        assert "Get-DefenseClawEmptyRetiredCompilerDirectories -InstallRoot $Layout.InstallRoot" in body, function
        assert "-Name CompilerPath" not in body, function
    walk = module[module.index("function Assert-DefenseClawManagedInstallTree {") :]
    walk = walk[: walk.index("\nfunction ")]
    assert "Get-DefenseClawRecordedStandaloneCompilerPath -Layout $Layout" in walk


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
    # The socket's directory holds no regular file of the helper: systemd
    # chowns it back from the gateway's group at the next start and fails on
    # one (GAP-0031); the pause and the policy copies have their own.
    assert _unit_values(helper, "RuntimeDirectory") == {"defenseclaw-sensor", "defenseclaw-sensor-tetragon"}
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


def test_tmpfiles_touches_no_path_the_apply_trigger_watches():
    # rpm runs systemd-tmpfiles on the package entry at the end of every
    # transaction; it relabels each existing directory it lists, and a
    # watched one started an unrequested apply run after every upgrade, which
    # applied a rolled-back upgrade anyway (GAP-0984).
    watched = {line.split("=", 1)[1] for line in _unit("defenseclaw-enterprise-apply.path") if line.startswith("PathChanged=")}
    listed = {line.split()[1] for line in _unit("defenseclaw.conf") if line and not line.startswith("#")}
    assert "/etc/defenseclaw/policies" in watched
    assert not watched & listed
    assert "d /etc/defenseclaw/bundles 0755 root root -" in _unit("defenseclaw.conf")


def test_windows_bundle_acl_contract_keeps_public_receipt_separate():
    module = (ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1").read_text(encoding="utf-8")
    # The path classifier lives in its own function next to the contract; both
    # together decide the descriptor of every path in the bundle store.
    classifier = module[module.index("function Get-DefenseClawBundlePathKind {"):module.index("function Invoke-DefenseClawBundleAclContract {")]
    contract = classifier + module[module.index("function Invoke-DefenseClawBundleAclContract {"):module.index("function Set-DefenseClawManagedAcls {")]
    assert "Kind = 'BundleDirectory'" in contract
    assert "'BundleReceipt'" in contract
    assert "'BundleVersionFile'" in contract
    assert "'AdminFile'" in contract
    assert "'bundle-state.json'" in contract and "'receipts'" in contract
    assert "if ($IsDirectory) { return 'AdminDirectory' }" in contract and "return 'AdminFile'" in contract
    assert "Get-DefenseClawBundlePathKind -RelativePath $relative" in contract
    assert "Assert-DefenseClawCanonicalPathAcl" in contract
    assert "Set-DefenseClawPathAcl" in contract


def test_systemd_guardian_can_flush_the_sssd_caches():
    # When SSSD is online again after an outage the guardian runs
    # sss_cache -E, which opens SSSD's databases read-write and invalidates its
    # memory cache. Under ProtectSystem=strict both directories must be
    # writable, or the flush exits 5 (GAP-0208). Nothing broader is opened.
    lines = _unit("defenseclaw-hook-guardian.service")
    assert "ProtectSystem=strict" in lines
    writable = _unit_values(lines, "ReadWritePaths")
    assert {"-/var/lib/sss/db", "-/var/lib/sss/mc"} <= writable
    assert not writable & {"/var", "-/var", "/var/lib", "-/var/lib", "/var/lib/sss", "-/var/lib/sss"}
    # Only the watching guardian flushes; the one-shot reconcile and the
    # enumerator never write SSSD's caches.
    for name in ("defenseclaw-hook-guardian-reconcile.service", "defenseclaw-hook-enumerator.service"):
        assert not any("/var/lib/sss" in path for path in _unit_values(_unit(name), "ReadWritePaths")), name


def test_systemd_enumerator_can_publish_refused_surfaces():
    # The enumerator writes refused-surfaces.json into the guardian data dir;
    # under ProtectSystem=strict that dir must be writable or every cycle
    # fails with EROFS and the gateway never sees the refusals (GAP-1441).
    lines = _unit("defenseclaw-hook-enumerator.service")
    assert "ProtectSystem=strict" in lines
    assert "/var/lib/defenseclaw-hook-guardian" in _unit_values(lines, "ReadWritePaths")
    # It revokes the ACP enrollments of deleted accounts (GAP-0697).
    assert "-/var/lib/defenseclaw/acp" in _unit_values(lines, "ReadWritePaths")
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


# GAP-0108: nfpm copies the builder's file mode for an entry without
# file_info, so a checkout made under umask 0002 shipped every systemd unit
# 0664 and the first install rolled back (verify refuses group-writable
# units). Every entry the package installs pins its owner and mode.
_NFPM_DIR_MODE, _NFPM_FILE_MODE = 0o755, 0o644
_NFPM_EXECUTABLES = {"/usr/lib/defenseclaw-enterprise/apt-downgrade-guard"}


def _enterprise_nfpm_contents() -> list[dict]:
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    return nfpm["contents"]


def test_enterprise_package_pins_owner_and_mode_of_every_entry() -> None:
    contents = _enterprise_nfpm_contents()
    checked, problems = 0, []
    for entry in contents:
        if entry.get("type") == "symlink":
            continue
        checked += 1
        info = entry.get("file_info") or {}
        if entry.get("type") == "dir" or entry["dst"] in _NFPM_EXECUTABLES:
            want = _NFPM_DIR_MODE
        else:
            want = _NFPM_FILE_MODE
        if info.get("mode") != want or info.get("owner") != "root" or info.get("group") != "root":
            problems.append(f"{entry['dst']}: file_info {info!r}, want mode {want:04o} owner root group root")
    assert not problems, "\n".join(problems)
    assert checked >= 20, f"only {checked} package entries were checked"


def test_enterprise_package_ships_every_systemd_unit_at_0644() -> None:
    units = {
        p.relative_to(ROOT).as_posix()
        for pattern in ("*.service", "*.socket", "*.timer", "*.path")
        for p in [*SYSTEMD.glob(pattern), *(SYSTEMD / "user").glob(pattern)]
    }
    shipped = {c["src"]: c for c in _enterprise_nfpm_contents() if "src" in c}
    assert len(units) >= 14 and units <= set(shipped), sorted(units - set(shipped))
    for src in sorted(units):
        assert shipped[src]["file_info"]["mode"] == 0o644, src
        assert shipped[src]["dst"].startswith(("/usr/lib/systemd/system/", "/usr/lib/systemd/user/")), src


def test_enterprise_rpm_owns_its_doc_directory():
    # An rpm erase removes only the directories the package lists; without
    # the entry /usr/share/doc/defenseclaw-enterprise stays behind, empty.
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    owned = {c["dst"] for c in nfpm["contents"] if c.get("type") == "dir"}
    assert "/usr/share/doc/defenseclaw-enterprise" in owned


# GAP-0763: fapolicyd refused the OpenCode plugin the lifecycle wrote (no
# package owned it) to OpenCode, which then ran tool calls without DefenseClaw
# while status stayed green. The package ships the plugin's exact bytes where
# the managed OpenCode config names it, so package-database trust covers it.
def test_enterprise_package_ships_the_managed_opencode_plugin():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    shipped = {c["dst"]: c for c in nfpm["contents"] if "src" in c}
    plugin = shipped.get("/opt/defenseclaw/share/opencode/index.js")
    assert plugin is not None and plugin["src"] == "internal/enterprisepolicy/opencode_managed_plugin.js"
    assert plugin.get("file_info", {}).get("mode") == 0o644


# GAP-0108: the archives take each file's mode from the checkout. The
# before hook drops the group and other write bits of every archived tree,
# so a builder under umask 0002 archives the modes CI's umask 0022 gives,
# and the binaries are root-owned 0755 (a root `tar -x` keeps the owner, and
# `enterprise <os> install --payload` refuses binaries another uid owns).
_ARCHIVE_MODE_HOOK = "chmod -R go-w packaging edge-connector LICENSE NOTICE THIRD_PARTY_LICENSES.txt README.md CHANGELOG.md"


def test_release_archives_do_not_take_the_builders_modes() -> None:
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    assert _ARCHIVE_MODE_HOOK in config["before"]["hooks"]
    covered = set(_ARCHIVE_MODE_HOOK.split()[3:])
    for archive in config["archives"]:
        assert archive.get("builds_info") == {"mode": 0o755, "owner": "root", "group": "root"}, archive["id"]
        for pattern in archive["files"]:
            matched = {p.relative_to(ROOT).parts[0] for p in ROOT.glob(pattern)}
            assert matched and matched <= covered, (archive["id"], pattern, sorted(matched - covered))
    assert "\numask 022\n" in (ROOT / "scripts" / "build-release-assets.sh").read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
def test_archive_mode_hook_gives_umask_0002_checkouts_the_ci_modes(tmp_path: Path) -> None:
    files = {
        "packaging/systemd/defenseclaw-gateway.service": 0o664,
        "packaging/systemd/user/defenseclaw-sandbox.socket": 0o664,
        "packaging/linux/postinstall.sh": 0o775,
        "edge-connector/tools/policy_compiler.py": 0o664,
        "LICENSE": 0o664,
        "NOTICE": 0o664,
        "THIRD_PARTY_LICENSES.txt": 0o664,
        "README.md": 0o664,
        "CHANGELOG.md": 0o664,
    }
    for name, mode in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
        path.chmod(mode)
    for directory in (tmp_path / "packaging").rglob("*"):
        if directory.is_dir():
            directory.chmod(0o775)
    completed = subprocess.run(
        ["sh", "-c", _ARCHIVE_MODE_HOOK], cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert completed.returncode == 0, completed.stderr
    for name, mode in files.items():
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == mode & ~0o022, name
    for directory in (tmp_path / "packaging").rglob("*"):
        if directory.is_dir():
            assert stat.S_IMODE(directory.stat().st_mode) == 0o755, directory


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
# The package scripts look for this text in the installed gateway to know it
# has the release floor check (internal/cli/enterprise_bundle_floor.go).
_FLOOR_SOURCE = (ROOT / "internal" / "cli" / "enterprise_bundle_floor.go").read_text(encoding="utf-8")
_FLOOR_MATCH = re.search(r'^const floorCheckMarker = "([^"]+)"$', _FLOOR_SOURCE, re.MULTILINE)
assert _FLOOR_MATCH, "floorCheckMarker not found"
FLOOR_CHECK_MARKER = _FLOOR_MATCH.group(1)
APPLY_PATH = "defenseclaw-enterprise-apply.path"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def _write_stub(bin_dir: Path, name: str, body: str) -> None:
    stub = bin_dir / name
    stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    stub.chmod(0o755)


def _stat_stub(host: "_Host", entries: dict[Path | str, str] | None = None) -> None:
    """stat for the package scripts: `stat -c|-f FORMAT PATH` prints FORMAT with
    %u, %a and %Lp taken from PATH's entry ("uid mode", "uid" alone, or "" for a
    path stat cannot read). Every other path is root's, writable by root only.
    A path is matched as written and with its folder resolved, as the trust
    check walks it."""
    keys: dict[str, str] = {}
    for path, entry in (entries or {}).items():
        path = Path(path)
        keys[str(path)] = entry
        keys[str(path.parent.resolve() / path.name)] = entry
    cases = "".join(f"    '{path}') e='{entry}' ;;\n" for path, entry in keys.items())
    _write_stub(
        host.bin,
        "stat",
        f"""for p; do :; done
case $p in
{cases}    *) e='0 755' ;;
esac
[ -n "$e" ] || {{ echo "stat: cannot statx '$p'" >&2; exit 1; }}
uid=${{e%% *}} mode=${{e#"$uid"}} mode=${{mode# }}
printf '%s\\n' "$2" | sed -e "s/%u/$uid/g" -e "s/%Lp/$mode/g" -e "s/%a/$mode/g"
""",
    )


def _ls_stub(host: "_Host", allows_write: tuple[Path | str, ...] = ()) -> None:
    """ls for the macOS pkg preinstall: `ls -lde PATH` lists a deny entry (which
    does not let anyone write), or an entry that lets another account write
    for a path in allows_write; any other use is the real ls."""
    paths = {str(Path(p)) for p in allows_write} | {str(Path(p).parent.resolve() / Path(p).name) for p in allows_write}
    cases = "".join(f"        '{path}') echo ' 1: user:other allow add_file,add_subdirectory,delete_child' ;;\n" for path in sorted(paths))
    _write_stub(
        host.bin,
        "ls",
        f"""if [ "$1" = -lde ]; then
    echo "drwxr-xr-x  2 root  wheel  64 Oct 21 12:00 $2"
    echo ' 0: group:everyone deny delete'
    case $2 in
{cases}    esac
    exit 0
fi
exec /bin/ls "$@"
""",
    )


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
        floor_check: bool = False,
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
        _write_stub(self.bin, "systemd-run", f"""echo "systemd-run $*" >>'{self.log}'""")
        for tool in ("systemd-sysusers", "systemd-tmpfiles", "sync"):
            _write_stub(self.bin, tool, f"""echo "{tool} $*" >>'{self.log}'""")
        # A gateway from 1.0.4 on carries the floor check marker; the default
        # stub is an older gateway, which the package scripts do not ask.
        carries = f"# {FLOOR_CHECK_MARKER}\n" if floor_check else ""
        _write_stub(self.tmp, "defenseclaw-gateway", f"""{carries}echo "gateway $*" >>'{self.log}'
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
    text = (LINUX / name).read_text(encoding="utf-8")
    # The preremove walks the user managers' runtime directories; a test
    # never reaches the real /run/user.
    if "user_runtime=/run/user" in text:
        text = text.replace("user_runtime=/run/user", f"user_runtime={host.tmp / 'run-user'}")
    return _rooted(
        text,
        {
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "/run/systemd/system": str(host.run_systemd),
        },
    )


def test_linux_postinstall_preserves_last_result_when_output_storage_is_full(tmp_path: Path) -> None:
    host = _Host(tmp_path, apply_path_active=True)
    host.state.mkdir()
    previous = b'{"schema_version":2,"ok":true,"installed_version":"1.0.3"}\n'
    result_path = host.state / "last-package-result.json"
    result_path.write_bytes(previous)
    # The log's open fails as on ENOSPC, after the old stdout redirect had
    # already truncated the last good result. No lifecycle process ran.
    (host.state / "last-package-result.log").mkdir()
    _write_stub(host.bin, "mktemp", "echo 'mktemp: No space left on device' >&2; exit 1")
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "2")
    assert result.returncode == 0  # the package transaction still completes
    assert result_path.read_bytes() == previous
    assert not any(call.startswith("gateway ") for call in host.calls())
    assert "no deployment is active" not in result.stderr
    assert "not applied" in result.stderr
    assert "disk" in result.stderr.lower() or "space" in result.stderr.lower()
    assert "enterprise linux ensure --from-package" in result.stderr
    assert "systemctl start defenseclaw-enterprise-apply.path" in host.calls()


def test_linux_postinstall_preserves_last_result_when_atomic_publish_fails(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    result_path = host.state / "last-package-result.json"
    previous = b'{"schema_version":2,"ok":true,"installed_version":"1.0.3"}\n'
    result_path.write_bytes(previous)
    _write_stub(host.bin, "mv", "echo 'mv: No space left on device' >&2; exit 1")
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "2")
    assert result.returncode == 0
    assert result_path.read_bytes() == previous
    assert "current package result could not be saved" in result.stderr
    assert "enterprise linux ensure --from-package" in result.stderr
    assert not list(host.state.glob(".last-package-result.*"))


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
    assert calls[ensure] == "gateway enterprise linux ensure --from-package --reason package --json --lock-wait 8m"
    stop = calls.index(f"systemctl stop {APPLY_PATH}")
    # GAP-0467: the unpacked payload is flushed before anything uses it.
    assert calls.index("sync ") < next(i for i, call in enumerate(calls) if call.startswith("systemd-sysusers")), calls
    for tool in ("systemd-sysusers", "systemd-tmpfiles", "systemctl daemon-reload"):
        index = next(i for i, call in enumerate(calls) if call.startswith(tool))
        assert stop < index < ensure, (tool, calls)
    assert calls.index(f"systemctl start {APPLY_PATH}") > ensure, calls


@pytest.mark.parametrize(("rc", "message"), [(75, "held the lock for 8 minutes"), (1, "the lifecycle reported a problem")])
def test_linux_postinstall_reports_a_lifecycle_problem_and_restores_the_trigger(tmp_path: Path, rc: int, message: str) -> None:
    host = _Host(tmp_path, gateway_rc=rc, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0  # a package install never fails on the lifecycle
    assert message in result.stderr
    calls = host.calls()
    assert f"systemctl start {APPLY_PATH}" in calls
    assert calls.index(f"systemctl start {APPLY_PATH}") < calls.index(
        "systemctl stop defenseclaw-enterprise-apply-recovery.timer"
    )


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
        assert "deployment state could not be confirmed" in result.stderr
        assert "no deployment is active" not in result.stderr
        assert f"finish the install with: sudo {host.gateway} enterprise linux ensure --from-package" in result.stderr



# GAP-0662: a package ensure that failed on a full disk named only the failed
# step (the services not active); the disk_full entry after it is shown too.
def test_linux_postinstall_names_a_full_disk_after_the_failed_step(tmp_path: Path) -> None:
    document = {
        "schema_version": 2,
        "ok": False,
        "action": "ensure",
        "installed": True,
        "installed_version": "1.0.2",
        "errors": [
            {"code": "verify_failed", "message": "defenseclaw-hook-guardian.service is not active"},
            {
                "code": "disk_full",
                "message": "the filesystem holding /var/lib/defenseclaw has 456 KiB free of 64.0 MiB: "
                "free space on it and run ensure again",
            },
        ],
        "warnings": [{"code": "rolled_back", "message": "the previous deployment was restored"}],
    }
    host = _Host(tmp_path, gateway_rc=1, gateway_out=json.dumps(document, indent=2))
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0
    assert "verify_failed: defenseclaw-hook-guardian.service is not active" in result.stderr
    assert "disk_full: the filesystem holding /var/lib/defenseclaw has 456 KiB free of 64.0 MiB" in result.stderr
    assert result.stderr.index("verify_failed:") < result.stderr.index("disk_full:")


def test_linux_postinstall_names_no_full_disk_without_one(tmp_path: Path) -> None:
    document = {"schema_version": 2, "ok": False, "errors": [{"code": "verify_failed", "message": "not active"}]}
    host = _Host(tmp_path, gateway_rc=1, gateway_out=json.dumps(document, indent=2))
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert "disk_full" not in result.stderr

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
    calls = host.calls()
    assert calls[0] == f"systemctl is-active --quiet {APPLY_PATH}"
    assert calls[1] == "systemctl stop defenseclaw-enterprise-apply-recovery.timer"
    assert calls[2].startswith(
        "systemd-run --quiet --unit=defenseclaw-enterprise-apply-recovery --on-active=30m "
    )
    assert calls[3:] == [
        f"systemctl stop {APPLY_PATH}",
        f"flock -w 480 {host.state}/lifecycle.lock true",
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


# GAP-1115: dnf downgrade replaced every binary before the postinstall ensure
# refused the downgrade, which left the older binaries under the newer
# deployment (verify_failed, a failed apply unit). The stamped preinstall now
# refuses an older package before anything changes, unless the root-owned
# rollback marker exists; the postinstall then applies it with
# --allow-downgrade and deletes the marker.
def test_linux_preinstall_refuses_a_downgrade_without_the_rollback_marker(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    (host.state / "deployment.json").write_text('{\n  "product_version": "1.0.7101-SNAPSHOT-37ba9cdbb"\n}\n', encoding="utf-8")
    _stat_stub(host)  # the record and the marker are root-owned
    rooting = {
        "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
        "/run/systemd/system": str(host.run_systemd),
        "/run/defenseclaw-enterprise-apply-path.held": str(tmp_path / "held"),
    }
    script = _rooted((LINUX / "preinstall.sh").read_text(encoding="utf-8"), rooting)
    older, deployed = "1.0.7100-SNAPSHOT-37ba9cdbb", "1.0.7101-SNAPSHOT-37ba9cdbb"
    refused = host.run(script.replace("@DC_PKG_VERSION@", older), "2")
    assert refused.returncode == 1
    assert "Nothing was changed" in refused.stderr and "--allow-downgrade" in refused.stderr
    assert host.calls() == []
    assert host.run(script.replace("@DC_PKG_VERSION@", deployed), "2").returncode == 0
    marker = host.state / "allow-downgrade"
    marker.write_text("", encoding="utf-8")
    assert host.run(script.replace("@DC_PKG_VERSION@", older), "2").returncode == 0
    post = host.run(_linux_scriptlet(host, "postinstall.sh").replace("/run/defenseclaw-enterprise-apply-path.held", str(tmp_path / "held")), "2")
    assert post.returncode == 0, post.stderr
    assert "gateway enterprise linux ensure --from-package --allow-downgrade --reason package" in "\n".join(host.calls())
    assert not marker.exists()


# A device that takes signed policy bundles refuses a package below the
# release its confirmed bundle requires, even with the rollback marker: the
# installed gateway's floor check exits 3. Only exit 0 leaves the install to
# the downgrade rules above; any other result leaves the floor unchecked and
# refuses too. An older gateway (no floor check marker) is not asked.
@pytest.mark.parametrize(
    ("rc", "floor_check", "refused"),
    [(3, True, True), (1, True, True), (2, True, True), (0, True, False), (3, False, False), (1, False, False)],
)
def test_linux_preinstall_refuses_a_package_below_the_bundle_release_floor(
    tmp_path: Path, rc: int, floor_check: bool, refused: bool
) -> None:
    host = _Host(tmp_path, gateway_rc=rc, floor_check=floor_check)
    host.state.mkdir()
    (host.state / "deployment.json").write_text('{\n  "product_version": "1.0.6"\n}\n', encoding="utf-8")
    (host.state / "allow-downgrade").write_text("", encoding="utf-8")
    _stat_stub(host)
    rooting = {
        "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
        "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
        "/run/systemd/system": str(host.run_systemd),
        "/run/defenseclaw-enterprise-apply-path.held": str(tmp_path / "held"),
    }
    script = _rooted((LINUX / "preinstall.sh").read_text(encoding="utf-8"), rooting)
    result = host.run(script.replace("@DC_PKG_VERSION@", "1.0.5"), "2")
    assert ("gateway enterprise bundle floor-check --product-version 1.0.5" in host.calls()) == floor_check
    assert (result.returncode == 1) == refused, (result.stdout, result.stderr)
    if refused:
        assert "Nothing was changed" in result.stderr
        assert len([c for c in host.calls() if not c.startswith("gateway ")]) == 0


# Preremove ran uninstall with the 5 s default and exited 0
# on busy (75), so dpkg/rpm deleted the binaries and units while machine
# policy, per-user hooks and the running gateway still named them.
@pytest.mark.parametrize(("rc", "exit_code"), [(0, 0), (1, 0), (75, 1)])
def test_linux_preremove_waits_for_the_lock_and_refuses_the_removal_when_busy(tmp_path: Path, rc: int, exit_code: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "remove")
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    assert [c for c in host.calls() if c.startswith("gateway ")] == ["gateway enterprise linux uninstall --json --lock-wait 8m"]
    if rc == 75:
        assert "nothing was removed" in result.stderr
        # A refused removal keeps the package, so its units keep running.
        assert not [c for c in host.calls() if c.startswith("systemctl ")]
    elif rc:
        assert "uninstall reported a problem" in result.stderr


# GAP-0112: the preremove's uninstall waited on the lock of a concurrent MDM
# purge, which removed the deployment and the lock with it. That uninstall
# now reports a not_installed no-op and exits 0 (it exited busy 75, and the
# preremove aborted the rpm or deb removal after the purge had removed
# everything): the removal goes on, stops the package units and keeps no
# result.
@pytest.mark.parametrize("argument", ["remove", "0"])
def test_linux_preremove_goes_on_when_a_concurrent_purge_removed_the_deployment(tmp_path: Path, argument: str) -> None:
    noop = {
        "schema_version": 2,
        "action": "uninstall",
        "ok": True,
        "exit_code": 0,
        "noop": True,
        "noop_reason": "not_installed",
        "warnings": [
            {
                "code": "not_installed",
                "message": "DefenseClaw enterprise was uninstalled by the lifecycle run this uninstall waited for; nothing was left to remove",
            }
        ],
    }
    host = _Host(tmp_path, gateway_rc=0, gateway_out=json.dumps(noop))
    result = host.run(_linux_scriptlet(host, "preremove.sh").replace("${TMPDIR:-/tmp}", str(tmp_path)), argument)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "nothing was removed" not in result.stderr
    assert "reported a problem" not in result.stderr
    assert not host.state.exists()
    assert list(tmp_path.glob("defenseclaw-preremove.*")) == []
    calls = host.calls()
    assert calls[0] == "gateway enterprise linux uninstall --json --lock-wait 8m"
    assert any(call.startswith("systemctl stop ") for call in calls), calls


# The preremove aborts the package removal only on a busy lock (75), a
# refused hook-removal precheck and an uninstall that stopped before removing
# the binaries (uninstall_incomplete, GAP-1519); every other uninstall
# outcome, the not_installed no-op above included, lets the removal go on.
def test_linux_preremove_aborts_only_on_busy_a_refused_precheck_or_an_incomplete_uninstall() -> None:
    text = (LINUX / "preremove.sh").read_text(encoding="utf-8")
    aborts = [line.strip() for line in text.splitlines() if re.match(r"\s*exit [1-9]", line)]
    assert aborts == ["exit 1", "exit 1", "exit 1"], aborts  # busy, precheck, incomplete
    assert 'if [ "$status" = 75 ]; then' in text
    assert 'if [ "$precheck_refused" = 1 ]; then' in text
    assert 'if [ "$incomplete" = 1 ]; then' in text


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
    ("line", "marker", "backup", "exit_code"),
    [
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb < 1.0.47~SNAPSHOT-aaa f.deb", False, False, 0),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb = 1.0.46~SNAPSHOT-bbb f.deb", False, False, 0),
        ("defenseclaw-enterprise 1.0.46~rc.1 < 1.0.46 f.deb", False, False, 0),
        # A prerelease is older than its release, as the lifecycle orders them.
        ("defenseclaw-enterprise 1.0.46 > 1.0.46~SNAPSHOT-aaa f.deb", False, False, 1),
        ("defenseclaw-enterprise 1.0.46~rc.2 > 1.0.46~rc.1 f.deb", False, False, 1),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.46~SNAPSHOT-aaa f.deb", False, False, 1),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > - **REMOVE**", False, False, 0),
        ("other-package 1.0.46 > 1.0.45 f.deb", False, False, 0),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.45~SNAPSHOT-aaa f.deb", False, False, 1),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.45~SNAPSHOT-aaa f.deb", False, True, 1),
        ("defenseclaw-enterprise 1.0.46~SNAPSHOT-bbb > 1.0.45~SNAPSHOT-aaa f.deb", True, False, 0),
        # The product versions decide, not apt's direction: a higher epoch
        # makes an older release an apt upgrade, and a lower one the reverse.
        ("defenseclaw-enterprise 1.0.46 < 1:1.0.45 f.deb", False, False, 1),
        ("defenseclaw-enterprise 1.0.46 < 1:1.0.45 f.deb", True, False, 0),
        ("defenseclaw-enterprise 1:1.0.46 < 2:1.0.45~rc.1 f.deb", False, False, 1),
        ("defenseclaw-enterprise 1:1.0.45 > 1.0.46 f.deb", False, False, 0),
        ("defenseclaw-enterprise 1.0.46 = 1.0.46 **CONFIGURE**", False, False, 0),
        ("defenseclaw-enterprise - < 1.0.45 f.deb", False, False, 0),
    ],
)
def test_linux_apt_hook_refuses_a_deb_downgrade_unless_the_marker_exists(
    tmp_path: Path, line: str, marker: bool, backup: bool, exit_code: int
) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    allow = host.state / "allow-downgrade"
    if marker:
        allow.write_text("", encoding="utf-8")
    config = tmp_path / "config.yaml"
    previous_config = tmp_path / "config.yaml.v8.bak"
    config.write_text("config_version: 8\n", encoding="utf-8")
    if backup:
        previous_config.write_text("config_version: 8\n", encoding="utf-8")
    script = _rooted(
        (LINUX / "apt-downgrade-guard.sh").read_text(encoding="utf-8"),
        {
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "previous_config=/etc/defenseclaw/config.yaml.v8.bak": f"previous_config={previous_config}",
            "config=/etc/defenseclaw/config.yaml": f"config={config}",
        },
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
    assert allow.exists() == marker  # left for the older package's preinstall and postinstall (GAP-1115)
    if exit_code:
        assert f"refusing to downgrade to {line.split()[3]}" in result.stderr
        assert f"sudo touch {allow}" in result.stderr
        assert "postinstall applies it" in result.stderr
        assert f"--config {previous_config if backup else config}" in result.stderr


# The rollback marker does not lift the release floor of the confirmed signed
# bundle: the hook asks the installed gateway with the full product version
# (a prerelease of the floor release is below it) and refuses on its exit 3.
@pytest.mark.parametrize(
    ("line", "version", "rc", "exit_code"),
    [
        ("defenseclaw-enterprise 1.0.4 > 1.0.4~SNAPSHOT-aaa f.deb", "1.0.4-SNAPSHOT-aaa", 3, 1),
        ("defenseclaw-enterprise 1.0.6 > 1.0.4~SNAPSHOT-aaa f.deb", "1.0.4-SNAPSHOT-aaa", 3, 1),
        ("defenseclaw-enterprise 1.0.6 > 1:1.0.5 f.deb", "1.0.5", 3, 1),
        # Only exit 0 passes: any other result leaves the floor unchecked.
        ("defenseclaw-enterprise 1.0.6 > 1.0.5 f.deb", "1.0.5", 1, 1),
        ("defenseclaw-enterprise 1.0.6 > 1.0.5 f.deb", "1.0.5", 2, 1),
        ("defenseclaw-enterprise 1.0.6 > 1.0.5 f.deb", "1.0.5", 0, 0),
        # Whatever apt's direction (a higher epoch makes 1.0.5 an apt
        # upgrade), and for every install action, as the preinstall checks.
        ("defenseclaw-enterprise 1.0.6 < 1:1.0.5 f.deb", "1.0.5", 3, 1),
        ("defenseclaw-enterprise 1.0.6 < 1:1.0.5 f.deb", "1.0.5", 0, 0),
        ("defenseclaw-enterprise 1.0.4 < 1.0.6 f.deb", "1.0.6", 3, 1),
        ("defenseclaw-enterprise 1.0.4 < 1.0.6 f.deb", "1.0.6", 0, 0),
        ("defenseclaw-enterprise 1.0.6 = 1.0.6 f.deb", "1.0.6", 3, 1),
        ("defenseclaw-enterprise - < 1.0.5 f.deb", "1.0.5", 3, 1),
    ],
)
def test_linux_apt_hook_refuses_a_downgrade_below_the_bundle_release_floor(
    tmp_path: Path, line: str, version: str, rc: int, exit_code: int
) -> None:
    host = _Host(tmp_path, gateway_rc=rc, floor_check=True)
    host.state.mkdir()
    (host.state / "allow-downgrade").write_text("", encoding="utf-8")
    _stat_stub(host)  # the gateway is root-owned and only root can write it
    script = _rooted(
        (LINUX / "apt-downgrade-guard.sh").read_text(encoding="utf-8"),
        {
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
        },
    )
    path = tmp_path / "guard.sh"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run(
        ["sh", str(path)],
        input=f"VERSION 2\nAPT::Architecture=amd64\n\n{line}\n",
        env={"PATH": f"{host.bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    assert host.calls() == [f"gateway enterprise bundle floor-check --product-version {version}"]
    if exit_code:
        assert "Nothing was changed" in result.stderr


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
    # The installed programs the postinstall gives new files before ensure.
    prefix = host.tmp / "prefix"
    (prefix / "bin").mkdir(parents=True)
    for name in ("defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper"):
        _write_stub(prefix / "bin", name, "exit 0")
    return _rooted(
        match.group(1) + "\n",
        {
            "prefix=/opt/cisco/defenseclaw": f"prefix={prefix}",
            "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/opt/cisco/defenseclaw/lifecycle": f"state={host.state}",
        },
    )


@pytest.mark.parametrize("rc", [0, 75])
def test_macos_pkg_postinstall_waits_for_the_lock(tmp_path: Path, rc: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_macos_pkg_postinstall(host))
    assert result.returncode == rc
    assert host.calls() == ["gateway enterprise macos ensure --from-package --reason package --json --lock-wait 8m"]


MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"


def _macos_pkg_preinstall(host: _Host, version: str) -> str:
    builder = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    match = re.search(r"cat >\"\$SCRIPTS/preinstall\" <<'EOF'\n(.*?)\nEOF\n", builder, re.DOTALL)
    assert match, "the pkg preinstall heredoc was not found"
    _stat_stub(host)  # the record, the marker and the gateway are root's
    _ls_stub(host)
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


# The pkg preinstall checks the confirmed signed bundle's release floor
# before the Installer replaces any file: with the rollback marker, and on a
# reinstall after uninstall --keep-state (no deployment record). Only the
# installed gateway's exit 0 passes: exit 3 refuses, and so does any other
# result, which leaves the floor unchecked.
@pytest.mark.parametrize(
    ("rc", "record", "marker", "refused"),
    [(3, True, True, True), (3, False, False, True), (1, True, True, True), (2, False, False, True), (0, False, False, False)],
)
def test_macos_pkg_preinstall_refuses_below_the_bundle_release_floor(
    tmp_path: Path, rc: int, record: bool, marker: bool, refused: bool
) -> None:
    host = _Host(tmp_path, gateway_rc=rc, floor_check=True)
    host.state.mkdir()
    if record:
        (host.state / "deployment.json").write_text('{"product_version": "1.0.6"}', encoding="utf-8")
    if marker:
        (host.state / "allow-downgrade").write_text("", encoding="utf-8")
    result = host.run(_macos_pkg_preinstall(host, "1.0.5"))
    assert host.calls()[0] == "gateway enterprise bundle floor-check --product-version 1.0.5"
    result_path = host.state / "last-package-result.json"
    assert (result.returncode == 1) == refused, (result.stdout, result.stderr)
    if not refused:
        assert not result_path.exists()
        return
    assert "Nothing was changed" in result.stderr
    document = json.loads(result_path.read_text(encoding="utf-8"))
    assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
    assert document["installed"] is record and document["installed_version"] == ("1.0.6" if record else "")
    _validate_lifecycle_result(document)


# After uninstall --keep-state (or an uninstall that failed after removing the
# binaries) the installed gateway is gone, but the trust anchors and the
# confirmed bundle stay. Each package script then asks the root-only copy of
# the gateway that uninstall kept in the lifecycle folder (floor-check/), before
# any file is replaced. A copy that is not root-owned, or a floor-check folder
# that is a symlink, is not run, and it does not count as no copy either: the
# floor is unchecked, so the install is refused.
def _floor_checker_case(tmp_path: Path, kind: str, rc: int, checker: str) -> tuple[_Host, subprocess.CompletedProcess[str]]:
    host = _Host(tmp_path)
    host.gateway.unlink()  # removed with the deployment's binaries
    host.state.mkdir()
    kept = host.state / "floor-check"
    target = kept
    if checker == "symlink":
        target = tmp_path / "elsewhere"
        kept.symlink_to(target)
    target.mkdir()
    _write_stub(target, "defenseclaw-gateway", f"""echo "checker $*" >>'{host.log}'
exit {rc}""")
    entries = {target / "defenseclaw-gateway": "501 755"} if checker == "not-root" else None
    return host, _run_floor_script(host, kind, entries)


def _run_floor_script(
    host: _Host, kind: str, entries: dict[Path | str, str] | None = None, acl_writable: tuple[Path, ...] = ()
) -> subprocess.CompletedProcess[str]:
    """Run the macOS pkg preinstall, the Linux preinstall or the apt hook for 1.0.5."""
    tmp_path = host.tmp
    if kind == "macos":
        script = _macos_pkg_preinstall(host, "1.0.5")  # writes its own stat and ls stubs
        _stat_stub(host, entries)
        _ls_stub(host, acl_writable)
        return host.run(script)
    _stat_stub(host, entries)
    if kind == "linux":
        rooting = {
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "/run/systemd/system": str(host.run_systemd),
            "/run/defenseclaw-enterprise-apply-path.held": str(tmp_path / "held"),
        }
        script = _rooted((LINUX / "preinstall.sh").read_text(encoding="utf-8"), rooting)
        return host.run(script.replace("@DC_PKG_VERSION@", "1.0.5"), "1")
    # The apt hook of a package whose binaries are gone; the rollback marker
    # leaves only the floor to decide.
    (host.state / "allow-downgrade").write_text("", encoding="utf-8")
    script = _rooted(
        (LINUX / "apt-downgrade-guard.sh").read_text(encoding="utf-8"),
        {
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
        },
    )
    path = tmp_path / "guard.sh"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        ["sh", str(path)],
        input="VERSION 2\nAPT::Architecture=amd64\n\ndefenseclaw-enterprise 1.0.6 > 1.0.5 f.deb\n",
        env={"PATH": f"{host.bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize(
    ("rc", "checker", "asked", "refused"),
    [
        (3, "root", True, True),
        (0, "root", True, False),
        (1, "root", True, True),
        (0, "not-root", False, True),
        (0, "symlink", False, True),
    ],
)
def test_package_scripts_ask_the_kept_floor_checker_when_the_gateway_is_gone(
    tmp_path: Path, kind: str, rc: int, checker: str, asked: bool, refused: bool
) -> None:
    host, result = _floor_checker_case(tmp_path, kind, rc, checker)
    floor_calls = [c for c in host.calls() if "floor-check" in c]
    assert floor_calls == (["checker enterprise bundle floor-check --product-version 1.0.5"] if asked else []), host.calls()
    assert (result.returncode == 1) == refused, (result.stdout, result.stderr)
    if not refused:
        return
    assert "Nothing was changed" in result.stderr
    # Refused before any file changed: no other tool ran.
    assert [c for c in host.calls() if not c.startswith("checker ")] == []
    if not asked:
        assert "could not be checked" in result.stderr and "floor-check/defenseclaw-gateway" in result.stderr, result.stderr
    if kind == "macos":
        document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
        assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
        assert document["installed"] is False
        _validate_lifecycle_result(document)


def _floor_checker_stub(path: Path, log: Path, failure: str, marker: bool) -> None:
    """A floor checker that cannot complete its check, the way it fails on a host."""
    shebang = "#!/nonexistent/loader\n" if failure == "loader-missing" else "#!/bin/sh\n"
    body = f"# {FLOOR_CHECK_MARKER}\n" if marker else ""
    body += f"""echo "run $*" >>'{log}'\n"""
    body += {"killed": "kill -KILL $$\n", "crashed": "exit 2\n", "usage": "exit 1\n"}.get(failure, "exit 0\n")
    path.write_text(shebang + body, encoding="utf-8")
    # Application control, or a lost mode bit, refuses the execution: 126.
    path.chmod(0o644 if failure == "denied" else 0o755)


# The whole class of a floor checker that is there but cannot complete its
# check (fapolicyd denies the execution, the checker is killed, crashes, has
# no loader, or answers with another error): before, only exit 3 refused, so
# the package replaced the files below the floor. Each package script now
# refuses before any file changes, for the installed 1.0.4+ gateway (it
# carries the floor check marker) and for the copy uninstall kept (always a
# 1.0.4+ gateway).
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("where", ["installed", "kept"])
@pytest.mark.parametrize("failure", ["denied", "killed", "crashed", "usage", "loader-missing"])
def test_package_scripts_refuse_when_the_floor_checker_cannot_complete(
    tmp_path: Path, kind: str, where: str, failure: str
) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    if where == "installed":
        _floor_checker_stub(host.gateway, host.log, failure, marker=True)
    else:
        host.gateway.unlink()
        (host.state / "floor-check").mkdir()
        _floor_checker_stub(host.state / "floor-check" / "defenseclaw-gateway", host.log, failure, marker=False)
    result = _run_floor_script(host, kind)
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "could not be checked" in result.stderr and "exited " in result.stderr, result.stderr
    assert "Nothing was changed" in result.stderr
    # Refused before any file changed: no tool other than the checker ran.
    assert [c for c in host.calls() if not c.startswith("run ")] == [], host.calls()
    if kind == "macos":
        document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
        assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
        assert "could not be checked" in document["errors"][0]["message"]
        _validate_lifecycle_result(document)


# An upgrade from 0.8.10 or 1.0.0-1.0.3 goes on: that gateway has no floor
# check (no marker in its binary), so it is not run even when it cannot run
# or fails; the copy a 1.0.4+ uninstall kept still answers when present.
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("failure", ["denied", "usage"])
@pytest.mark.parametrize("kept_rc", [None, 0, 3])
def test_package_scripts_do_not_ask_a_gateway_without_the_floor_check(
    tmp_path: Path, kind: str, failure: str, kept_rc: int | None
) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    _floor_checker_stub(host.gateway, host.log, failure, marker=False)
    if kept_rc is not None:
        (host.state / "floor-check").mkdir()
        _write_stub(host.state / "floor-check", "defenseclaw-gateway", f"""echo "checker $*" >>'{host.log}'
exit {kept_rc}""")
    result = _run_floor_script(host, kind)
    assert not [c for c in host.calls() if c.startswith("run enterprise bundle floor-check")], host.calls()
    asked = [c for c in host.calls() if c.startswith("checker ")]
    assert asked == ([] if kept_rc is None else ["checker enterprise bundle floor-check --product-version 1.0.5"])
    assert (result.returncode == 1) == (kept_rc == 3), (result.stdout, result.stderr)


# Only a gateway that was read and has no floor check marker is an older one,
# which is not asked. Before, a gateway that could not be inspected counted
# as one: its marker could not be read (no read permission, a read error, a
# dangling symlink), or it carries the marker but is not a root-owned file
# (another owner, a symlink, or an owner stat could not read). With no kept
# copy each package script then let the transaction through with no floor
# decision. It now refuses before any file changes, without running that
# gateway; a root-owned kept copy still answers for it, and an older gateway
# whose owner cannot be read is still not asked (the 0.8.10 and
# 1.0.0-1.0.3 upgrades).
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize(
    "failure",
    ["unreadable", "read-error", "dangling-symlink", "symlink", "not-root", "owner-unreadable", "older-owner-unreadable"],
)
@pytest.mark.parametrize("kept_rc", [None, 0, 3])
def test_package_scripts_refuse_when_the_installed_gateway_cannot_be_inspected(
    tmp_path: Path, kind: str, failure: str, kept_rc: int | None
) -> None:
    if failure == "unreadable" and os.geteuid() == 0:
        pytest.skip("root reads a file without read permission")
    host = _Host(tmp_path)
    host.state.mkdir()
    gateway = str(host.gateway)
    _floor_checker_stub(host.gateway, host.log, "ok", marker=failure != "older-owner-unreadable")
    if failure in ("symlink", "dangling-symlink"):
        target = tmp_path / "real-gateway"
        host.gateway.rename(target)
        if failure == "dangling-symlink":
            target.unlink()
        host.gateway.symlink_to(target)
    elif failure == "unreadable":
        host.gateway.chmod(0o311)
    elif failure == "read-error":
        # grep reports an I/O error (exit 2) for the gateway, as on a bad disk.
        real = subprocess.run(["sh", "-c", "command -v grep"], capture_output=True, text=True, check=True).stdout.strip()
        _write_stub(
            host.bin,
            "grep",
            f"""for a in "$@"; do [ "$a" = '{gateway}' ] && {{ echo "grep: $a: Input/output error" >&2; exit 2; }}; done
exec '{real}' "$@"
""",
        )
    if kept_rc is not None:
        (host.state / "floor-check").mkdir()
        _write_stub(host.state / "floor-check", "defenseclaw-gateway", f"""echo "checker $*" >>'{host.log}'
exit {kept_rc}""")
    owner = {"not-root": "501", "owner-unreadable": "", "older-owner-unreadable": ""}.get(failure)
    # The gateway's owner: stat prints another uid, or fails with no output.
    entries = None if owner is None else {gateway: f"{owner} 755" if owner else ""}
    result = _run_floor_script(host, kind, entries)
    calls = host.calls()
    # That gateway is not asked for the floor, and one that is not a
    # root-owned file is not run as root at all (not for a status either).
    assert not [c for c in calls if c.startswith("run enterprise bundle floor-check")], calls
    if failure in ("symlink", "dangling-symlink", "not-root", "owner-unreadable"):
        assert not [c for c in calls if c.startswith("run ")], calls
    asked = [c for c in calls if c.startswith("checker ")]
    assert asked == ([] if kept_rc is None else ["checker enterprise bundle floor-check --product-version 1.0.5"])
    older = failure == "older-owner-unreadable"
    refused = kept_rc == 3 or (kept_rc is None and not older)
    assert (result.returncode == 1) == refused, (result.stdout, result.stderr)
    if not refused:
        return
    assert "Nothing was changed" in result.stderr
    if kept_rc is None:
        assert "could not be checked" in result.stderr and gateway in result.stderr, result.stderr
    if kind == "macos":
        document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
        assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
        _validate_lifecycle_result(document)


_WRITABLE_CHECKER_CASES = [
    "file-group-writable",
    "file-other-writable",
    "file-mode-unreadable",
    "folder-writable",
    "folder-group-writable",
    "folder-not-root",
    "folder-unreadable",
    "ancestor-writable",
    "root-folder-writable",
    "symlinked-folder-writable",
    "acl-allows-write",
]


def _writable_checker_host(tmp_path: Path, where: str, how: str) -> tuple[_Host, dict[Path | str, str], tuple[Path, ...]]:
    """A floor checker (the installed 1.0.4+ gateway, or the copy uninstall
    kept) that exits 0 if run, which another account can change as `how` says."""
    host = _Host(tmp_path)
    host.state.mkdir()
    if how == "symlinked-folder-writable":
        # The checker's folder is reached through a symlink; the folder it
        # resolves to is the one another account can write.
        real = tmp_path / "real"
        real.mkdir()
        if where == "installed":
            host.gateway.unlink()
            (tmp_path / "link").symlink_to(real)
            host.gateway = tmp_path / "link" / "defenseclaw-gateway"
        else:
            host.state.rmdir()
            host.state.symlink_to(real)
    if where == "installed":
        checker = host.gateway
        _floor_checker_stub(checker, host.log, "ok", marker=True)
    else:
        host.gateway.unlink()
        (host.state / "floor-check").mkdir()
        checker = host.state / "floor-check" / "defenseclaw-gateway"
        _floor_checker_stub(checker, host.log, "ok", marker=False)
    folder = checker.parent
    entries: dict[Path | str, str] = {
        "file-group-writable": {checker: "0 775"},
        "file-other-writable": {checker: "0 757"},
        "file-mode-unreadable": {checker: "0"},
        "folder-writable": {folder: "0 777"},
        "folder-group-writable": {folder: "0 775"},
        "folder-not-root": {folder: "501 755"},
        "folder-unreadable": {folder: ""},
        "ancestor-writable": {tmp_path: "0 1777"},
        "root-folder-writable": {"/": "0 777"},
        "symlinked-folder-writable": {tmp_path / "real": "0 777"},
        "acl-allows-write": {},
    }[how]
    acl = (folder,) if how == "acl-allows-write" else ()
    return host, entries, acl


# The package scripts run the floor checker as root. Before, they asked only
# that it be a root-owned file, so an account that could write the file or a
# folder above it could replace a root-owned checker's code and keep the
# marker, and the Linux preinstall, the apt hook and the macOS pkg preinstall
# ran it as root. Each now runs a checker only when it and every folder above
# it, as resolved, belong to root and no other account can write them (and,
# on macOS, no access control entry lets one); otherwise the floor is
# unchecked and the install is refused, without running it (the macOS refusal
# does not ask it for a status either).
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("where", ["installed", "kept"])
@pytest.mark.parametrize("how", _WRITABLE_CHECKER_CASES)
def test_package_scripts_never_run_a_floor_checker_another_account_can_write(
    tmp_path: Path, kind: str, where: str, how: str
) -> None:
    if how == "acl-allows-write" and kind != "macos":
        pytest.skip("a Linux ACL that grants write shows in the group bits (folder-group-writable)")
    host, entries, acl = _writable_checker_host(tmp_path, where, how)
    result = _run_floor_script(host, kind, entries, acl)
    assert not [c for c in host.calls() if c.startswith("run ")], host.calls()
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "could not be checked" in result.stderr and "only root can" in result.stderr, result.stderr
    assert "Nothing was changed" in result.stderr
    assert host.calls() == [], host.calls()
    if kind == "macos":
        document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
        assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
        _validate_lifecycle_result(document)


# A root-only kept copy still answers for an installed gateway that another
# account can write (that gateway is not run), and the same checker runs when
# only root can change it.
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("kept_rc", [0, 3])
def test_package_scripts_ask_a_root_only_kept_copy_for_a_writable_gateway(tmp_path: Path, kind: str, kept_rc: int) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    _floor_checker_stub(host.gateway, host.log, "ok", marker=True)
    (host.state / "floor-check").mkdir()
    _write_stub(host.state / "floor-check", "defenseclaw-gateway", f"""echo "checker $*" >>'{host.log}'
exit {kept_rc}""")
    result = _run_floor_script(host, kind, {host.gateway: "0 777"})
    assert not [c for c in host.calls() if c.startswith("run ")], host.calls()
    assert [c for c in host.calls() if c.startswith("checker ")] == ["checker enterprise bundle floor-check --product-version 1.0.5"]
    assert (result.returncode == 1) == (kept_rc == 3), (result.stdout, result.stderr)
    (tmp_path / "trusted").mkdir()
    trusted_host = _Host(tmp_path / "trusted")
    trusted_host.state.mkdir()
    _floor_checker_stub(trusted_host.gateway, trusted_host.log, "ok", marker=True)
    ok = _run_floor_script(trusted_host, kind)
    assert ok.returncode == 0, (ok.stdout, ok.stderr)
    assert [c for c in trusted_host.calls() if c.startswith("run ")] == ["run enterprise bundle floor-check --product-version 1.0.5"]


# The floor checker reached through a symlink. Before, the trust check walked
# only the folders the path resolves to, and the package scripts then ran the
# path as written: a symlink in a folder another account can write, a symlink
# that account owns, or a symlink whose target passes through such a folder
# (none of them on the resolved path) was accepted, and that account could
# swap the symlink between the check and the run as root. Each script now
# looks the path up one entry at a time, as the kernel does, refuses unless
# every folder an entry is found in and every symlink on the way belongs to
# root and no other account can change it (on macOS, by mode or access
# control entry), refuses a symlink it cannot read, and runs the file the
# path resolves to.
_SYMLINK_CHECKER_REFUSED = [
    "link-folder-writable",
    "link-folder-group-writable",
    "link-folder-not-root",
    "link-folder-unreadable",
    "relative-link-folder-writable",
    "link-not-root",
    "link-owner-unreadable",
    "nested-link-folder-writable",
    "nested-link-not-root",
    "link-unreadable",
    "link-folder-acl-allows-write",
    "link-acl-allows-change",
]
_SYMLINK_CHECKER_TRUSTED = ["absolute", "relative", "nested", "dot-dot"]


def _symlinked_checker_host(
    tmp_path: Path, where: str, how: str
) -> tuple[_Host, Path, dict[Path | str, str], tuple[Path, ...]]:
    """A floor checker that exits 0, in tmp/real, reached through the symlink
    tmp/swap/link (the installed gateway tmp/swap/link/defenseclaw-gateway, or
    the kept copy under the lifecycle folder tmp/swap/link/state). Returns the
    host, the checker's real path, the stat entries and the ACL-writable paths
    for `how`."""
    host = _Host(tmp_path)
    host.gateway.unlink()
    real = tmp_path / "real"
    real.mkdir()
    swap = tmp_path / "swap"
    swap.mkdir()
    link = swap / "link"
    hop = tmp_path / "hop"
    if how.startswith("nested") or how == "dot-dot":
        # link -> tmp/hop/inner -> tmp/real: hop holds the second symlink and
        # is on neither the written nor the resolved path of the checker.
        hop.mkdir()
        (hop / "inner").symlink_to("../real" if how == "dot-dot" else real)
        link.symlink_to(hop / "inner" if how != "dot-dot" else "../hop/./inner")
    elif how.startswith("relative"):
        link.symlink_to("../real")
    else:
        link.symlink_to(real)
    if where == "installed":
        host.state.mkdir()
        host.gateway = link / "defenseclaw-gateway"
        checker = real / "defenseclaw-gateway"
        marker = True
    else:
        (real / "state" / "floor-check").mkdir(parents=True)
        host.state = link / "state"
        checker = real / "state" / "floor-check" / "defenseclaw-gateway"
        marker = False
    body = f"# {FLOOR_CHECK_MARKER}\n" if marker else ""
    checker.write_text(f"""#!/bin/sh\n{body}echo "run $0 $*" >>'{host.log}'\nexit 0\n""", encoding="utf-8")
    checker.chmod(0o755)
    entries: dict[Path | str, str] = {
        "link-folder-writable": {swap: "0 777"},
        "link-folder-group-writable": {swap: "0 775"},
        "link-folder-not-root": {swap: "501 755"},
        "link-folder-unreadable": {swap: ""},
        "relative-link-folder-writable": {swap: "0 777"},
        "link-not-root": {link: "501"},
        "link-owner-unreadable": {link: ""},
        "nested-link-folder-writable": {hop: "0 1777"},
        "nested-link-not-root": {hop / "inner": "501"},
    }.get(how, {})
    acl = {"link-folder-acl-allows-write": (swap,), "link-acl-allows-change": (link,)}.get(how, ())
    if how == "link-unreadable":
        real_readlink = subprocess.run(
            ["sh", "-c", "command -v readlink"], capture_output=True, text=True, check=True
        ).stdout.strip()
        _write_stub(
            host.bin,
            "readlink",
            f"""for a in "$@"; do [ "$a" = '{link}' ] && {{ echo "readlink: $a: Input/output error" >&2; exit 1; }}; done
exec '{real_readlink}' "$@"
""",
        )
    return host, checker, entries, acl


@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("where", ["installed", "kept"])
@pytest.mark.parametrize("how", _SYMLINK_CHECKER_REFUSED)
def test_package_scripts_never_run_a_floor_checker_behind_a_replaceable_symlink(
    tmp_path: Path, kind: str, where: str, how: str
) -> None:
    if how in ("link-folder-acl-allows-write", "link-acl-allows-change") and kind != "macos":
        pytest.skip("a Linux ACL that grants write shows in the group bits (link-folder-group-writable)")
    host, _checker, entries, acl = _symlinked_checker_host(tmp_path, where, how)
    result = _run_floor_script(host, kind, entries, acl)
    assert host.calls() == [], host.calls()
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert "could not be checked" in result.stderr and "only root can" in result.stderr, result.stderr
    assert "Nothing was changed" in result.stderr
    if kind == "macos":
        document = json.loads((host.state / "last-package-result.json").read_text(encoding="utf-8"))
        assert [e["code"] for e in document["errors"]] == ["product_floor_refused"]
        _validate_lifecycle_result(document)


# A checker reached through symlinks only root can change (an /opt or a
# lifecycle folder moved to another volume) still answers, and it is run by
# the path it resolves to, so a symlink changed after the check cannot
# redirect the run.
@pytest.mark.parametrize("kind", ["macos", "linux", "apt"])
@pytest.mark.parametrize("where", ["installed", "kept"])
@pytest.mark.parametrize("how", _SYMLINK_CHECKER_TRUSTED)
def test_package_scripts_run_a_root_only_symlinked_floor_checker_by_its_resolved_path(
    tmp_path: Path, kind: str, where: str, how: str
) -> None:
    host, checker, entries, acl = _symlinked_checker_host(tmp_path, where, how)
    result = _run_floor_script(host, kind, entries, acl)
    assert result.returncode == 0, (result.stdout, result.stderr)
    runs = [c for c in host.calls() if c.startswith("run ")]
    assert runs == [f"run {checker.resolve()} enterprise bundle floor-check --product-version 1.0.5"], host.calls()


def test_package_scripts_look_for_the_gateway_floor_check_marker() -> None:
    builder = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    for text in (
        (LINUX / "preinstall.sh").read_text(encoding="utf-8"),
        (LINUX / "apt-downgrade-guard.sh").read_text(encoding="utf-8"),
        builder,
    ):
        assert f"floor_check_marker={FLOOR_CHECK_MARKER}\n" in text
        assert 'grep -qaF "$floor_check_marker" "$gateway"' in text
    assert "floorCheckMarkerAnnotation: floorCheckMarker" in _FLOOR_SOURCE


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found"
    return match.group(0)


# Each stub answers the queries dc_install_package makes; DC_TEST_INSTALLED is
# the version already installed (empty: not installed).
_PACKAGE_STUBS = {
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in
    --print-architecture) echo amd64 ;;
    --compare-versions)
        [ "$3" = lt ] && [ "$2" != "$4" ] && [ "$(printf '%s\\n%s\\n' "$2" "$4" | sort -V | head -n 1)" = "$2" ]
        exit $?
        ;;
esac""",
    "dpkg-query": """[ -n "$DC_TEST_INSTALLED" ] || exit 1
printf 'install ok installed %s' "$DC_TEST_INSTALLED\"""",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *ARCH*) echo x86_64 ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    --eval) echo x86_64 ;;
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


# The package removal deleted the vendor policies after a preremove
# uninstall that failed (machine policy not removed, say) and so kept the
# deployment record, the config and the registrations that name them. They
# leave with the package only once the uninstall removed the deployment.
@pytest.mark.parametrize("deployment_kept", [False, True])
def test_linux_postremove_keeps_the_vendor_policies_while_the_deployment_stays(tmp_path: Path, deployment_kept: bool) -> None:
    host = _Host(tmp_path)
    opt = tmp_path / "opt"
    pack = opt / "share" / "policies" / "rule-packs" / "default"
    pack.mkdir(parents=True)
    (pack / "pack.yaml").write_text("name: default\n", encoding="utf-8")
    host.state.mkdir()
    if deployment_kept:
        (host.state / "deployment.json").write_text("{}\n", encoding="utf-8")
    script = _rooted(
        (LINUX / "postremove.sh").read_text(encoding="utf-8"),
        {
            "lifecycle=/var/lib/defenseclaw-enterprise": f"lifecycle={host.state}",
            "/opt/defenseclaw": str(opt),
            "/etc/tmpfiles.d/defenseclaw.conf": str(tmp_path / "tmpfiles-defenseclaw.conf"),
            "/run/systemd/system": str(host.run_systemd),
        },
    )
    result = host.run(script, "remove")
    assert result.returncode == 0, result.stderr
    assert (pack / "pack.yaml").is_file() is deployment_kept


# GAP-0112: the package removal deleted the unit files of units that were
# still running. Under hook traffic the gateway's API socket stayed
# "not-found active (listening)" after the MDM purge. The preremove now stops
# and disables every unit the package ships, after the lifecycle uninstall
# and only on a removal.
def _package_system_units() -> set[str]:
    return {
        Path(c["dst"]).name
        for c in _enterprise_nfpm_contents()
        if c.get("dst", "").startswith("/usr/lib/systemd/system/") and c.get("type") != "dir"
    }


def _preremove_units(name: str) -> list[str]:
    text = (LINUX / "preremove.sh").read_text(encoding="utf-8")
    match = re.search(rf'^{name}="([^"]*)"', text, re.M)
    assert match, f"{name} is not set in preremove.sh"
    return match.group(1).split()


def test_enterprise_package_scripts_are_the_linux_scriptlets() -> None:
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    assert nfpm["scripts"]["preremove"] == "packaging/linux/preremove.sh"
    assert nfpm["scripts"]["postremove"] == "packaging/linux/postremove.sh"


def test_linux_preremove_names_every_unit_the_package_ships() -> None:
    shipped = _package_system_units()
    assert len(shipped) >= 11 and {"defenseclaw-gateway-api.socket", "defenseclaw-gateway-hook.socket"} <= shipped
    assert set(_preremove_units("package_units")) == shipped


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize("argument", ["remove", "0"])
@pytest.mark.parametrize("gateway", [True, False])
def test_linux_preremove_stops_and_disables_every_package_unit_on_removal(tmp_path: Path, argument: str, gateway: bool) -> None:
    host = _Host(tmp_path)
    if not gateway:
        host.gateway.unlink()
    result = host.run(_linux_scriptlet(host, "preremove.sh"), argument)
    assert result.returncode == 0, result.stderr
    calls = host.calls()
    units = _preremove_units("package_units")
    stops = [c.split()[2:] for c in calls if c.startswith("systemctl stop ")]
    # One request for all of them, after the lifecycle uninstall.
    assert stops == [[*units, "defenseclaw-enterprise-apply-recovery.timer"]], calls
    assert [c.split()[2:] for c in calls if c.startswith("systemctl disable ")] == [units]
    if gateway:
        assert calls.index("gateway enterprise linux uninstall --json --lock-wait 8m") < calls.index(
            "systemctl stop " + " ".join(stops[0])
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize("arguments", [("upgrade", "9.9.10"), ("1",), ("deconfigure",), ("failed-upgrade", "9.9.8")])
def test_linux_preremove_leaves_the_units_alone_on_an_upgrade(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    host = _Host(tmp_path, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "preremove.sh"), *arguments)
    assert result.returncode == 0, result.stderr
    assert not [c for c in host.calls() if c.startswith(("systemctl stop", "systemctl disable", "gateway "))]


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
def test_linux_preremove_stops_again_while_a_unit_still_runs(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    log = host.log
    _write_stub(host.bin, "systemctl", f"""echo "systemctl $*" >>'{log}'
case "$1" in
    is-active) [ "$3" = defenseclaw-gateway-api.socket ] ;;
esac""")
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "0")
    assert result.returncode == 0, result.stderr
    assert len([c for c in host.calls() if c.startswith("systemctl stop ")]) == 3
    assert "could not stop defenseclaw-gateway-api.socket" in result.stderr


def _postremove(host: _Host, tmp_path: Path) -> str:
    _write_stub(host.bin, "flock", f"echo \"flock $*\" >>'{host.log}'\nshift 3\nexec \"$@\"")
    return _rooted(
        (LINUX / "postremove.sh").read_text(encoding="utf-8"),
        {
            "lifecycle=/var/lib/defenseclaw-enterprise": f"lifecycle={host.state}",
            "/etc/defenseclaw": str(tmp_path / "etc-defenseclaw"),
            "/var/lib/defenseclaw ": str(tmp_path / "var-lib-defenseclaw") + " ",
            "/var/lib/defenseclaw-hook-guardian": str(tmp_path / "guardian"),
            "/var/log/defenseclaw": str(tmp_path / "log"),
            "/opt/defenseclaw": str(tmp_path / "opt"),
            "/etc/tmpfiles.d/defenseclaw.conf": str(tmp_path / "tmpfiles-defenseclaw.conf"),
            "/run/systemd/system": str(host.run_systemd),
        },
    )


# GAP-0112: the purge left root-only /var/lib/defenseclaw-enterprise with its
# lifecycle.lock. A removal drops the lock, under its own flock, and the
# directory once nothing else is in it; an upgrade keeps both.
@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize(("argument", "gone"), [("remove", True), ("0", True), ("purge", True), ("1", False), ("upgrade", False)])
def test_linux_postremove_removes_the_lone_lifecycle_lock(tmp_path: Path, argument: str, gone: bool) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    lock = host.state / "lifecycle.lock"
    lock.write_text("", encoding="utf-8")
    result = host.run(_postremove(host, tmp_path), argument)
    assert result.returncode == 0, result.stderr
    assert host.state.exists() is not gone
    if gone:
        assert f"flock -w 10 {lock} rm -f {lock}" in host.calls()
        assert "systemctl reset-failed defenseclaw-*" in host.calls()
    else:
        assert lock.is_file()
        assert "systemctl reset-failed defenseclaw-*" not in host.calls()


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
def test_linux_postremove_keeps_the_lock_with_a_kept_result(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    host.state.mkdir()
    (host.state / "lifecycle.lock").write_text("", encoding="utf-8")
    (host.state / "last-package-result.json").write_text("{}\n", encoding="utf-8")
    result = host.run(_postremove(host, tmp_path), "remove")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in host.state.iterdir()) == ["last-package-result.json", "lifecycle.lock"]
    # A deb purge removes the kept result too, and then the lock.
    result = host.run(_postremove(host, tmp_path), "purge")
    assert result.returncode == 0, result.stderr
    assert not host.state.exists()


# GAP-0706: the Fleet compiler ships under share/fleet, so a Fleet-off
# package removal left share/fleet, share and the install root behind.
def test_linux_postremove_drops_the_empty_install_tree(tmp_path: Path) -> None:
    host = _Host(tmp_path)
    opt = tmp_path / "opt"
    for sub in ("share/fleet", "share/opencode", "bin"):
        (opt / sub).mkdir(parents=True)
    result = host.run(_postremove(host, tmp_path), "remove")
    assert result.returncode == 0, result.stderr
    assert not opt.exists()


# GAP-1254, GAP-1258: the wrapper applied the config before it stored
# --secret-name, so a config that references the credential never applied,
# and the store then failed busy against the apply its own config change
# started. It now stores the credential first and both steps wait.
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("secret_rc", [0, 75])
def test_unix_wrapper_stores_the_credential_before_it_applies_the_config(tmp_path: Path, os_dir: str, secret_rc: int) -> None:
    wrapper = (MDM / os_dir / "defenseclaw-enterprise.sh").read_text(encoding="utf-8")
    functions = "\n".join(
        _shell_function(wrapper, name)
        for name in ("dc_run_lifecycle", "dc_run_lifecycle_retry", "dc_secret_json_error", "dc_store_secret", "dc_main")
    )
    log = tmp_path / "calls.log"
    gateway = tmp_path / "defenseclaw-gateway"
    gateway.write_text(f"""#!/bin/sh
echo "$*" >>'{log}'
case "$2" in secret) cat >/dev/null; echo secret-busy >&2; exit {secret_rc} ;; esac
echo '{{"ok":true}}'
""", encoding="utf-8")
    gateway.chmod(0o755)
    # This test isolates credential ordering from binary integrity checks.
    for sibling in ("defenseclaw-hook", "defenseclaw-sensor-helper"):
        (tmp_path / sibling).write_text("#!/bin/sh\n", encoding="utf-8")
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
dc_binaries_damaged() {{ return 1; }}
id() {{ echo 0; }}
mktemp() {{ command mktemp -d '{tmp_path}/stage.XXXXXX'; }}
dc_cleanup() {{ :; }}
dc_stage_parent() {{ DC_STAGE_PARENT='{tmp_path}'; }}
dc_sweep_stages() {{ :; }}
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


# #1210: the package removal deleted the sandbox user units while an
# account's socket still listened, and the daemon it started failed 203/EXEC
# on the deleted binary in a loop. The preremove stops the user units in the
# user manager of every account that runs one, as that account, after the
# system units, and drops the socket's global enable link.
def _package_user_units() -> set[str]:
    return {
        Path(c["dst"]).name
        for c in _enterprise_nfpm_contents()
        if c.get("dst", "").startswith("/usr/lib/systemd/user/") and c.get("type") != "dir"
    }


def test_linux_preremove_names_every_user_unit_the_package_ships() -> None:
    assert set(_preremove_units("user_units")) == _package_user_units() == {
        "defenseclaw-sandbox.socket",
        "defenseclaw-sandbox.service",
        "defenseclaw-openshell-gateway.service",
    }


def _user_manager(host: _Host, uid: int) -> Path:
    """A runtime directory with the user manager's private socket."""
    import socket

    runtime = host.tmp / "run-user" / str(uid)
    (runtime / "systemd").mkdir(parents=True)
    cwd = os.getcwd()
    os.chdir(runtime / "systemd")
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind("private")
        sock.close()
    finally:
        os.chdir(cwd)
    return runtime


# What the account's user manager answers, as `case` branches of a runuser or
# setpriv stub: is-active exits 3 when no unit is active, with each unit's
# state; a manager that does not answer exits 1 with no state.
_USER_MANAGER_ANSWERS = {
    # Every unit stopped (a failed daemon is not running either).
    "stopped": "*is-active*) printf 'inactive\\ninactive\\nfailed\\n'; exit 3 ;;",
    # A unit keeps running after every stop.
    "still_active": "*is-active*) printf 'active\\ninactive\\ninactive\\n'; exit 0 ;;",
    # The socket is still deactivating: exit 3, but not established stopped.
    "deactivating": "*is-active*) printf 'deactivating\\ninactive\\ninactive\\n'; exit 3 ;;",
    # Neither stop nor is-active reaches the manager.
    "no_answer": "*) echo 'Failed to connect to bus' >&2; exit 1 ;;",
    # The account signed out during the stop: its manager exited.
    "signed_out": "*' stop '*) rm -f \"$XDG_RUNTIME_DIR/systemd/private\"; exit 1 ;; *) exit 1 ;;",
}


@pytest.mark.skipif(not sys.platform.startswith("linux") or os.getuid() == 0, reason="GNU stat and a non-root runtime directory owner")
@pytest.mark.parametrize("answer", sorted(_USER_MANAGER_ANSWERS))
def test_linux_preremove_stops_the_sandbox_user_units_in_every_user_manager(tmp_path: Path, answer: str) -> None:
    host = _Host(tmp_path)
    uid = os.getuid()
    runtime = _user_manager(host, uid)
    # Not a user manager: a directory someone else's uid names, a name that
    # is no uid, and a runtime directory without the private socket.
    _user_manager(host, uid + 1)
    (host.tmp / "run-user" / "abc" / "systemd").mkdir(parents=True)
    (host.tmp / "run-user" / str(uid + 2)).mkdir()
    _write_stub(host.bin, "getent", f"""[ "$2" = {uid} ] && echo "sample-user:x:{uid}:{uid}::/home/sample-user:/bin/sh" """)
    # The stub runs the env the script passes, so the manager's runtime
    # directory is known to it.
    _write_stub(host.bin, "runuser", f"""echo "runuser $*" >>'{host.log}'
while [ "$1" != env ]; do shift; done
shift
export "$1"
case "$*" in {_USER_MANAGER_ANSWERS[answer]} esac""")
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "remove")
    stopped = answer in ("stopped", "signed_out")
    calls = host.calls()
    env = f"env XDG_RUNTIME_DIR={runtime} DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"
    units = " ".join(_preremove_units("user_units"))
    stop = f"runuser -u sample-user -- {env} systemctl --user stop {units}"
    stops = [c for c in calls if c.startswith("runuser ") and " stop " in c]
    # A unit that keeps running, or a manager that does not say, is stopped
    # three times; then the removal fails and the package keeps its files.
    assert stops == [stop] * (1 if stopped else 3), calls
    system_stop = next(c for c in calls if c.startswith("systemctl stop "))
    assert calls.index(system_stop) < calls.index(stop) < calls.index("systemctl --global disable defenseclaw-sandbox.socket")
    if stopped:
        assert result.returncode == 0, result.stderr
        assert "sandbox user units" not in result.stderr
    else:
        assert result.returncode == 1
        assert "could not stop, or confirm stopped, the sandbox user units of sample-user; package files were kept" in result.stderr


# An account lookup that does not answer (a directory service outage) does
# not skip a live user manager: its units stop as the uid and gid that own
# its runtime directory, and a manager that then does not answer keeps the
# package.
@pytest.mark.skipif(not sys.platform.startswith("linux") or os.getuid() == 0, reason="GNU stat and a non-root runtime directory owner")
@pytest.mark.parametrize("answer", ["stopped", "no_answer"])
def test_linux_preremove_stops_the_user_units_of_an_account_the_lookup_does_not_name(tmp_path: Path, answer: str) -> None:
    host = _Host(tmp_path)
    uid, gid = os.getuid(), os.getgid()
    runtime = _user_manager(host, uid)
    _write_stub(host.bin, "getent", "exit 2")
    _write_stub(host.bin, "runuser", f"""echo "runuser $*" >>'{host.log}'; exit 1""")
    _write_stub(host.bin, "setpriv", f"""echo "setpriv $*" >>'{host.log}'
case "$*" in {_USER_MANAGER_ANSWERS[answer]} esac""")
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "remove")
    calls = host.calls()
    units = " ".join(_preremove_units("user_units"))
    stop = (
        f"setpriv --reuid={uid} --regid={gid} --clear-groups env XDG_RUNTIME_DIR={runtime} "
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus systemctl --user stop {units}"
    )
    assert not [c for c in calls if c.startswith("runuser ")], calls
    if answer == "stopped":
        assert result.returncode == 0, result.stderr
        assert [c for c in calls if c.startswith("setpriv ") and " stop " in c] == [stop], calls
    else:
        assert result.returncode == 1
        assert [c for c in calls if c.startswith("setpriv ") and " stop " in c] == [stop] * 3, calls
        assert f"the sandbox user units of uid {uid}; package files were kept" in result.stderr
    assert "systemctl --global disable defenseclaw-sandbox.socket" in calls


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize("arguments", [("upgrade", "9.9.10"), ("1",)])
def test_linux_preremove_leaves_the_user_units_alone_on_an_upgrade(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    host = _Host(tmp_path)
    _write_stub(host.bin, "runuser", f"""echo "runuser $*" >>'{host.log}'""")
    result = host.run(_linux_scriptlet(host, "preremove.sh"), *arguments)
    assert result.returncode == 0, result.stderr
    assert not [c for c in host.calls() if c.startswith(("runuser", "systemctl --global"))]
