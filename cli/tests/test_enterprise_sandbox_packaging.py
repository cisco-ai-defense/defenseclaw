# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Packaging of the standard user's sandbox launcher and the user units.

The enterprise packages install `/usr/bin/defenseclaw` (Linux) or
`/usr/local/bin/defenseclaw` (macOS) as a root-owned link to the gateway,
the user units (Linux) or launch agents (macOS) of the per-user sandbox
daemon, and, on Linux, `/etc/defenseclaw/openshell/`. The Go side of the
launcher is covered by internal/cli/launcher_test.go; the install lane
(scripts/test-enterprise-unix-install.sh) checks a real install.
"""

import os
import plistlib
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SYSTEMD = ROOT / "packaging" / "systemd"
# The per-user units and launch agents live in subdirectories so the
# //go:embed globs of the system units and LaunchDaemons (assets.go) never pick
# them up: the lifecycle installs those, and the packages ship these.
SYSTEMD_USER = SYSTEMD / "user"
LAUNCHD = ROOT / "packaging" / "launchd-standalone"
LAUNCHD_AGENTS = LAUNCHD / "agents"
BUILDER = ROOT / "scripts" / "build-macos-enterprise-pkg.sh"

USER_UNITS = (
    "defenseclaw-sandbox.socket",
    "defenseclaw-sandbox.service",
    "defenseclaw-openshell-gateway.service",
)
LAUNCH_AGENTS = (
    "com.cisco.defenseclaw.sandbox",
    "com.cisco.defenseclaw.openshell-gateway",
)


def test_user_unit_and_launch_agent_sources_exist():
    # No skip: a source that is missing (or moved) must fail here, not only
    # in the release build.
    for name in USER_UNITS:
        assert (SYSTEMD_USER / name).is_file(), f"packaging/systemd/user/{name}"
    for label in LAUNCH_AGENTS:
        assert (LAUNCHD_AGENTS / f"{label}.plist").is_file(), f"packaging/launchd-standalone/agents/{label}.plist"


def _nfpm() -> dict:
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (nfpm,) = [n for n in config["nfpms"] if n["id"] == "defenseclaw-enterprise"]
    return nfpm


def _contents() -> dict:
    return {c["dst"]: c for c in _nfpm()["contents"]}


def test_enterprise_package_links_the_launcher_to_the_gateway():
    link = _contents().get("/usr/bin/defenseclaw")
    assert link is not None, "the package must install /usr/bin/defenseclaw"
    assert link["type"] == "symlink"
    assert link["src"] == "/opt/defenseclaw/bin/defenseclaw-gateway"
    # The link points where the package installs the gateway.
    assert _nfpm()["bindir"] == "/opt/defenseclaw/bin"


def test_enterprise_package_ships_the_user_units_where_systemd_loads_user_units():
    contents = _contents()
    for name in USER_UNITS:
        entry = contents.get(f"/usr/lib/systemd/user/{name}")
        assert entry is not None, name
        assert entry["src"] == f"packaging/systemd/user/{name}"
        assert (ROOT / entry["src"]).is_file(), f"{entry['src']} is missing (it ships with the daemon lane)"
        # Not also a system unit: a system manager would start the daemon as root.
        assert f"/usr/lib/systemd/system/{name}" not in contents


def test_enterprise_package_owns_the_openshell_config_directory():
    entry = _contents().get("/etc/defenseclaw/openshell")
    assert entry is not None
    assert entry["type"] == "dir"
    # The rendered gateway.toml holds no secret and every account's OpenShell
    # gateway reads it.
    assert entry["file_info"]["mode"] == 0o755
    assert entry["file_info"].get("owner", "root") == "root"
    assert entry["file_info"].get("group", "root") == "root"


def test_user_units_run_the_packaged_gateway():
    service = (SYSTEMD_USER / "defenseclaw-sandbox.service").read_text(encoding="utf-8")
    assert "ExecStart=/opt/defenseclaw/bin/defenseclaw-gateway sandbox-daemon" in service
    # A user unit runs as the user that started it; User= is a system-unit key.
    for name in USER_UNITS:
        assert "\nUser=" not in (SYSTEMD_USER / name).read_text(encoding="utf-8"), name
    socket = (SYSTEMD_USER / "defenseclaw-sandbox.socket").read_text(encoding="utf-8")
    assert "ListenStream=%t/defenseclaw/sandbox.sock" in socket
    assert "SocketMode=0600" in socket


@pytest.mark.parametrize("label", LAUNCH_AGENTS)
def test_launch_agents_are_per_user_jobs_of_the_packaged_gateway(label: str):
    plist = plistlib.loads((LAUNCHD_AGENTS / f"{label}.plist").read_bytes())
    assert plist["Label"] == label
    # A launch agent runs as the account that loads it; naming a user would
    # run it as someone else.
    assert "UserName" not in plist and "GroupName" not in plist
    assert plist["ProgramArguments"][0] == "/opt/cisco/defenseclaw/bin/defenseclaw-gateway"
    assert {"Aqua", "Background"} <= set(
        [plist["LimitLoadToSessionType"]]
        if isinstance(plist["LimitLoadToSessionType"], str)
        else plist["LimitLoadToSessionType"]
    )


# ---- the macOS package builder, run with stub Apple tools -------------------


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)


def _build_fixture(
    tmp_path: Path,
    agents: tuple[str, ...] = LAUNCH_AGENTS,
    compiler_kind: str = "regular",
):
    """A copy of the builder in a fixture repo, with stubs for the Apple tools.

    The stub pkgbuild copies the payload root it is given (symlinks kept) so
    the test reads the tree the installer would lay down.
    """
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(BUILDER, repo / "scripts" / BUILDER.name)
    launchd = repo / "packaging" / "launchd-standalone" / "agents"
    launchd.mkdir(parents=True)
    for label in agents:
        (launchd / f"{label}.plist").write_bytes(plistlib.dumps({"Label": label}))
    payload = tmp_path / "payload"
    payload.mkdir()
    for name in ("defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper"):
        (payload / name).write_text("#!/bin/sh\n", encoding="utf-8")
        (payload / name).chmod(0o755)
    compiler = payload / "edge-connector" / "tools" / "policy_compiler.py"
    compiler.parent.mkdir(parents=True)
    if compiler_kind == "regular":
        shutil.copyfile(ROOT / "edge-connector" / "tools" / "policy_compiler.py", compiler)
    elif compiler_kind == "symlink":
        compiler.symlink_to(payload / "defenseclaw-gateway")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    captured = tmp_path / "captured-root"
    captured_scripts = tmp_path / "captured-scripts"
    _stub(bin_dir, "uname", "echo Darwin")
    pkgbuild = (
        'while [ "$#" -gt 0 ]; do\n'
        '    case "$1" in --root) root=$2; shift 2 ;; --scripts) scripts=$2; shift 2 ;; *) last=$1; shift ;; esac\n'
        "done\n"
        f"cp -R -P \"$root\" '{captured}'\n"
        f"cp -R -P \"$scripts\" '{captured_scripts}'\n"
        ': >"$last"'
    )
    _stub(bin_dir, "pkgbuild", pkgbuild)
    _stub(bin_dir, "productbuild", 'for last; do :; done; : >"$last"')
    _stub(bin_dir, "shasum", "echo 0000")
    return repo, payload, bin_dir, captured


def _run_builder(
    tmp_path: Path,
    umask: str = "022",
    agents: tuple[str, ...] = LAUNCH_AGENTS,
    compiler_kind: str = "regular",
):
    repo, payload, bin_dir, captured = _build_fixture(tmp_path, agents, compiler_kind)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "TMPDIR": str(tmp_path)}
    result = subprocess.run(
        [
            "sh",
            "-c",
            f'umask {umask}; exec bash "$@"',
            "sh",
            str(repo / "scripts" / BUILDER.name),
            "--version",
            "1.2.3",
            "--payload",
            str(payload),
            "--dist-dir",
            str(tmp_path / "dist"),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result, captured


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
@pytest.mark.parametrize("umask", ["022", "077"])
def test_macos_pkg_payload_carries_the_launcher_and_the_launch_agents(tmp_path: Path, umask: str):
    result, root = _run_builder(tmp_path, umask)
    assert result.returncode == 0, result.stderr

    launcher = root / "usr" / "local" / "bin" / "defenseclaw"
    assert launcher.is_symlink()
    assert os.readlink(launcher) == "/opt/cisco/defenseclaw/bin/defenseclaw-gateway"

    for label in LAUNCH_AGENTS:
        agent = root / "Library" / "LaunchAgents" / f"{label}.plist"
        assert agent.is_file() and not agent.is_symlink(), label
        assert _mode(agent) == 0o644, label
        assert plistlib.loads(agent.read_bytes())["Label"] == label

    # launchd and every account must be able to reach what the payload lays
    # down, whatever umask the builder has.
    for directory in (
        root / "usr" / "local" / "bin",
        root / "Library" / "LaunchAgents",
        root / "opt" / "cisco" / "defenseclaw" / "bin",
    ):
        assert _mode(directory) & 0o755 == 0o755, directory
    assert _mode(root / "opt" / "cisco" / "defenseclaw" / "bin" / "defenseclaw-gateway") == 0o755
    compiler = root / "opt" / "cisco" / "defenseclaw" / "lib" / "defenseclaw" / "policy_compiler.py"
    assert compiler.read_bytes() == (ROOT / "edge-connector" / "tools" / "policy_compiler.py").read_bytes()
    assert _mode(compiler) == 0o644
    assert _mode(compiler.parent) == 0o755


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
@pytest.mark.parametrize("compiler_kind", ["missing", "symlink"])
def test_macos_pkg_rejects_missing_or_symlink_compiler(tmp_path: Path, compiler_kind: str):
    result, _ = _run_builder(tmp_path, compiler_kind=compiler_kind)
    assert result.returncode == 1
    assert "payload lacks a regular policy compiler" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_postinstall_runs_lifecycle_ensure(tmp_path: Path):
    result, _ = _run_builder(tmp_path)
    assert result.returncode == 0, result.stderr
    postinstall = tmp_path / "captured-scripts" / "postinstall"
    assert _mode(postinstall) == 0o755
    body = postinstall.read_text(encoding="utf-8")
    assert 'enterprise macos ensure --from-package' in body
    assert '--reason package --json' in body


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_build_stops_when_a_launch_agent_is_missing(tmp_path: Path):
    result, _ = _run_builder(tmp_path, agents=LAUNCH_AGENTS[:1])
    assert result.returncode == 1
    assert "com.cisco.defenseclaw.openshell-gateway.plist" in result.stderr
