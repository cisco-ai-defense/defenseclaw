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

import hashlib
import os
import plistlib
import shlex
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
PACKAGE_CHECK = ROOT / "scripts" / "test-managed-package-no-fleet-compiler.sh"
E2FSPROGS_TOOLS = ("mke2fs", "debugfs", "e2fsck")
E2FSPROGS_LICENSES = ("NOTICE", "e2fsprogs-1.47.4.tar.xz", "README.txt")

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
    shutil.copy(PACKAGE_CHECK, repo / "scripts" / PACKAGE_CHECK.name)
    e2fs_builder = repo / "scripts" / "build-macos-e2fsprogs.sh"
    e2fs_builder.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'install -d -m 0755 "$1/sbin" "$1/licenses"\n'
        + "".join(f'install -m 0755 /dev/null "$1/sbin/{name}"\n' for name in E2FSPROGS_TOOLS)
        + "".join(f'install -m 0644 /dev/null "$1/licenses/{name}"\n' for name in E2FSPROGS_LICENSES),
        encoding="utf-8",
    )
    e2fs_builder.chmod(0o755)
    launchd = repo / "packaging" / "launchd-standalone" / "agents"
    launchd.mkdir(parents=True)
    for label in agents:
        shutil.copyfile(LAUNCHD_AGENTS / f"{label}.plist", launchd / f"{label}.plist")
    payload = tmp_path / "payload"
    payload.mkdir()
    for name in ("defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper", "defenseclaw-acp"):
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
    _stub(bin_dir, "pkgutil", f'mkdir -p "$3"; cp -R -P "{captured}/." "$3/"')
    codesign_calls = tmp_path / "codesign-calls"
    codesign_calls.mkdir()
    _stub(
        bin_dir,
        "codesign",
        'for target; do :; done\n'
        f'printf "%s\\n" "$@" > {shlex.quote(str(codesign_calls))}/"$(basename "$target")"\n'
        'printf "signed fixture\\n" >> "$target"',
    )
    return repo, payload, bin_dir, captured


def _run_builder(
    tmp_path: Path,
    umask: str = "022",
    agents: tuple[str, ...] = LAUNCH_AGENTS,
    compiler_kind: str = "regular",
    sign_identity: str | None = None,
):
    repo, payload, bin_dir, captured = _build_fixture(tmp_path, agents, compiler_kind)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "TMPDIR": str(tmp_path)}
    if sign_identity is not None:
        env["MACOS_APP_SIGN_IDENTITY"] = sign_identity
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

    gateway = root / "opt" / "cisco" / "defenseclaw" / "bin" / "defenseclaw-gateway"
    digest = hashlib.sha256(gateway.read_bytes()).hexdigest()
    # Each label carries the gateway's tag (GAP-0206), as the lifecycle
    # names it (openshell.LaunchAgentLabel); no bare-label plist is shipped.
    assert sorted(p.name for p in (root / "Library" / "LaunchAgents").iterdir()) == sorted(
        f"{label}.{digest[:12]}.plist" for label in LAUNCH_AGENTS
    )
    for label in LAUNCH_AGENTS:
        agent = root / "Library" / "LaunchAgents" / f"{label}.{digest[:12]}.plist"
        assert agent.is_file() and not agent.is_symlink(), label
        assert _mode(agent) == 0o644, label
        launchd = plistlib.loads(agent.read_bytes())
        assert launchd["Label"] == f"{label}.{digest[:12]}"
        program = f"/opt/cisco/defenseclaw/bin/launch-agents/{digest}/defenseclaw-gateway"
        assert launchd["ProgramArguments"][0] == program
        agent_binary = root / program.lstrip("/")
        assert agent_binary.read_bytes() == gateway.read_bytes()
        assert _mode(agent_binary) == 0o755

    # launchd and every account must be able to reach what the payload lays
    # down, whatever umask the builder has.
    for directory in (
        root / "usr" / "local" / "bin",
        root / "Library" / "LaunchAgents",
        root / "opt" / "cisco" / "defenseclaw" / "bin",
    ):
        assert _mode(directory) & 0o755 == 0o755, directory
    assert _mode(root / "opt" / "cisco" / "defenseclaw" / "bin" / "defenseclaw-gateway") == 0o755
    assert not list(root.rglob("policy_compiler.py"))
    assert not (root / "opt" / "cisco" / "defenseclaw" / "share" / "fleet").exists()

    e2fs = root / "opt" / "cisco" / "defenseclaw" / "share" / "e2fsprogs"
    for name in E2FSPROGS_TOOLS:
        tool = e2fs / "sbin" / name
        assert tool.is_file() and not tool.is_symlink(), name
        assert _mode(tool) == 0o755, name
    for name in E2FSPROGS_LICENSES:
        license_file = e2fs / "licenses" / name
        assert license_file.is_file() and not license_file.is_symlink(), name
        assert _mode(license_file) == 0o644, name
    assert _mode(e2fs / "sbin") == 0o755
    assert _mode(e2fs / "licenses") == 0o755


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_signs_all_executables_with_hardened_runtime(tmp_path: Path):
    result, root = _run_builder(tmp_path, sign_identity="fixture-developer-id")
    assert result.returncode == 0, result.stderr

    install_root = root / "opt" / "cisco" / "defenseclaw"
    executable_dirs = (install_root / "bin", install_root / "share" / "e2fsprogs" / "sbin")
    executables = {path.name: path for directory in executable_dirs for path in directory.iterdir() if path.is_file()}
    assert set(executables) == {
        "defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper", "defenseclaw-acp",
        *E2FSPROGS_TOOLS,
    }
    calls = tmp_path / "codesign-calls"
    assert {path.name for path in calls.iterdir()} == set(executables)
    for name, executable in executables.items():
        args = (calls / name).read_text(encoding="utf-8").splitlines()
        assert args[:-1] == [
            "--force", "--timestamp", "--options", "runtime", "--sign", "fixture-developer-id",
            "--identifier", f"com.cisco.defenseclaw.{name}",
        ]
        assert args[-1].endswith("/" + executable.relative_to(root).as_posix())
    gateway = install_root / "bin" / "defenseclaw-gateway"
    digest = hashlib.sha256(gateway.read_bytes()).hexdigest()
    agent_binary = install_root / "bin" / "launch-agents" / digest / "defenseclaw-gateway"
    assert agent_binary.read_bytes() == gateway.read_bytes()
    assert gateway.read_bytes().endswith(b"signed fixture\n")


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
@pytest.mark.parametrize("compiler_kind", ["missing", "symlink"])
def test_macos_pkg_omits_optional_compiler_regardless_of_source(tmp_path: Path, compiler_kind: str):
    result, root = _run_builder(tmp_path, compiler_kind=compiler_kind)
    assert result.returncode == 0, result.stderr
    assert not list(root.rglob("policy_compiler.py"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_postinstall_runs_lifecycle_ensure(tmp_path: Path):
    result, _ = _run_builder(tmp_path)
    assert result.returncode == 0, result.stderr
    postinstall = tmp_path / "captured-scripts" / "postinstall"
    assert _mode(postinstall) == 0o755
    body = postinstall.read_text(encoding="utf-8")
    assert 'enterprise macos ensure --from-package' in body
    assert '--reason package --json' in body


def _postinstall_refresh(tmp_path: Path) -> tuple[str, Path]:
    """The generated postinstall and its program-refresh functions as a file."""
    result, _ = _run_builder(tmp_path / "build")
    assert result.returncode == 0, result.stderr
    body = (tmp_path / "build" / "captured-scripts" / "postinstall").read_text(encoding="utf-8")
    start = body.index("refresh_program() {")
    end = body.index("\n}\n", body.index("refresh_programs() {")) + 3
    functions = tmp_path / "refresh.sh"
    functions.write_text(body[start:end], encoding="utf-8")
    return body, functions


def _refresh_programs(functions: Path, prefix: Path, path: str = "/usr/bin:/bin"):
    return subprocess.run(
        ["sh", "-c", '. "$1"; refresh_programs "$2"', "sh", str(functions), str(prefix)],
        env={"PATH": path},
        capture_output=True,
        text=True,
        timeout=30,
    )


def _installed_programs(prefix: Path, optional: bool = True) -> list[Path]:
    names = ["defenseclaw-gateway", "defenseclaw-hook", "defenseclaw-sensor-helper"]
    if optional:
        names.append("defenseclaw-acp")
    programs = [prefix / "bin" / name for name in names]
    if optional:
        programs.append(prefix / "bin" / "launch-agents" / ("0" * 64) / "defenseclaw-gateway")
        programs += [prefix / "share" / "e2fsprogs" / "sbin" / name for name in E2FSPROGS_TOOLS]
    for program in programs:
        program.parent.mkdir(parents=True, exist_ok=True)
        program.write_bytes(b"signed " + program.name.encode() + b"\n")
        program.chmod(0o755)
    return programs


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_postinstall_gives_every_program_a_new_file_before_ensure(tmp_path: Path):
    # GAP-0049: a program rewritten in place keeps the code signature macOS
    # checked before, so its LaunchAgent start is killed for code signing.
    body, functions = _postinstall_refresh(tmp_path)
    lines = body.splitlines()
    refresh = lines.index('if ! refresh_programs "$prefix"; then')
    ensure = next(i for i, line in enumerate(lines) if "enterprise macos ensure --from-package" in line)
    assert refresh < ensure
    assert lines[refresh + 1].strip() == "exit 1"

    prefix = tmp_path / "opt" / "cisco" / "defenseclaw"
    programs = _installed_programs(prefix)
    other = prefix / "share" / "fleet" / "policy_compiler.py"
    other.parent.mkdir(parents=True)
    other.write_text("compiler\n", encoding="utf-8")
    notice = prefix / "share" / "e2fsprogs" / "licenses" / "NOTICE"
    notice.parent.mkdir(parents=True)
    notice.write_text("notice\n", encoding="utf-8")
    kept = {path: path.stat().st_ino for path in (other, notice)}
    for run in range(2):  # a reinstall of the same version gives new files again
        before = {program: program.stat().st_ino for program in programs}
        result = _refresh_programs(functions, prefix)
        assert result.returncode == 0, result.stderr
        for program in programs:
            assert program.stat().st_ino != before[program], (run, program)
            assert program.read_bytes() == b"signed " + program.name.encode() + b"\n"
            assert _mode(program) == 0o755
    assert {path: path.stat().st_ino for path in kept} == kept
    assert not [path for path in prefix.rglob(".*.pkg.*")]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_postinstall_refresh_skips_absent_optional_programs(tmp_path: Path):
    _, functions = _postinstall_refresh(tmp_path)
    prefix = tmp_path / "opt" / "cisco" / "defenseclaw"
    programs = _installed_programs(prefix, optional=False)
    before = {program: program.stat().st_ino for program in programs}
    result = _refresh_programs(functions, prefix)
    assert result.returncode == 0, result.stderr
    assert all(program.stat().st_ino != before[program] for program in programs)
    assert not (prefix / "bin" / "defenseclaw-acp").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
@pytest.mark.parametrize("problem", ["symlink", "missing", "rename"])
def test_macos_pkg_postinstall_refresh_fails_closed(tmp_path: Path, problem: str):
    _, functions = _postinstall_refresh(tmp_path)
    prefix = tmp_path / "opt" / "cisco" / "defenseclaw"
    programs = _installed_programs(prefix)
    gateway, hook = programs[0], programs[1]
    path = "/usr/bin:/bin"
    if problem == "symlink":
        target = tmp_path / "elsewhere"
        target.write_bytes(b"other program\n")
        gateway.unlink()
        gateway.symlink_to(target)
    elif problem == "missing":
        hook.unlink()
    else:
        fake = tmp_path / "fakebin"
        fake.mkdir()
        _stub(fake, "mv", "exit 1")
        path = f"{fake}:{path}"
    inode = gateway.lstat().st_ino
    result = _refresh_programs(functions, prefix, path)
    assert result.returncode != 0
    assert "reinstall the package" in result.stderr
    if problem != "missing":  # the gateway comes first; a later required program is missing
        assert gateway.lstat().st_ino == inode
    if problem == "symlink":
        assert gateway.is_symlink()
    else:
        assert gateway.read_bytes() == b"signed defenseclaw-gateway\n"
    assert not [path for path in prefix.rglob(".*.pkg.*")]


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell contract")
def test_macos_pkg_build_stops_when_a_launch_agent_is_missing(tmp_path: Path):
    result, _ = _run_builder(tmp_path, agents=LAUNCH_AGENTS[:1])
    assert result.returncode == 1
    assert "com.cisco.defenseclaw.openshell-gateway.plist" in result.stderr
