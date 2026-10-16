import os
import re
import subprocess
from pathlib import Path

KIT = Path(__file__).parent
INSTALLER = KIT / "install-sssd-okta.sh"


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


def test_identical_sssd_config_repairs_unsafe_mode(tmp_path: Path) -> None:
    config = tmp_path / "sssd.conf"
    rendered = tmp_path / "rendered.conf"
    config.write_text("# managed fixture\n", encoding="ascii")
    rendered.write_bytes(config.read_bytes())
    config.chmod(0o644)
    calls = tmp_path / "calls"
    for name, body in {
        "chown": 'echo "chown $*" >>"$CALL_LOG"',
        "chmod": 'echo "chmod $*" >>"$CALL_LOG"; /bin/chmod "$@"',
        "stat": 'echo "stat $*" >>"$CALL_LOG"; /usr/bin/stat "$@"',
        "systemctl": 'echo "systemctl $*" >>"$CALL_LOG"',
        "sshd": 'echo "sshd $*" >>"$CALL_LOG"',
    }.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="ascii")
        path.chmod(0o755)
    source = INSTALLER.read_text(encoding="utf-8")
    script = (
        f"set -euo pipefail\nCONF='{config}'\nDRY_RUN=0\nCHANGED=0\nCONF_CHANGED=0\n"
        "log() { :; }\nfail() { exit \"$1\"; }\n"
        + function(source, "install_conf") + f"\ninstall_conf '{rendered}'\n"
    )
    result = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(calls)},
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert config.stat().st_mode & 0o777 == 0o600
    assert "chown root:root" in calls.read_text()


def test_failed_sshd_reload_is_retried_on_unchanged_rerun(tmp_path: Path) -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    names = ["sshd_step"]
    if "sshd_reload_with_marker()" in source:
        names.append("sshd_reload_with_marker")
    functions = "\n".join(function(source, name) for name in names)
    calls = tmp_path / "reload-calls"
    work = tmp_path / "work"
    work.mkdir()
    dropin = tmp_path / "45-okta-ldap.conf"
    marker = Path(str(dropin) + ".reload-pending")
    for name, body in {
        "install": 'if [ "$1" = -d ]; then mkdir -p "${@: -1}"; else /bin/cp "$7" "$8"; fi',
        "sshd": 'echo "sshd $*" >>"$CALL_LOG"; exit 0',
        "systemctl": 'echo "systemctl $*" >>"$CALL_LOG"; [ "$RELOAD_FAIL" != 1 ]',
    }.items():
        path = tmp_path / name
        path.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="ascii")
        path.chmod(0o755)
    script = (
        f"set -euo pipefail\nWORK='{work}'\nSSHD_DROPIN='{dropin}'\n"
        "MARKER='Managed by DefenseClaw packaging/identity/okta'\n"
        "ALLOW_GROUP=dc-r102-users\nNO_SSHD=0\nDRY_RUN=0\nCHANGED=0\n"
        "log() { :; }\nfail() { echo \"$*\" >&2; exit \"$1\"; }\n"
        + functions + "\nsshd_step\n"
    )

    def run(fail: bool) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", script], env={
            "PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(calls), "RELOAD_FAIL": "1" if fail else "0"
        }, capture_output=True, text=True, timeout=10)

    first = run(True)
    assert first.returncode != 0
    assert dropin.exists(), first.stderr
    assert "systemctl reload sshd" in calls.read_text(), first.stderr
    assert marker.is_file(), "a failed reload must leave a retry marker"
    assert run(True).returncode != 0, "an unchanged rerun must report the repeated reload failure"
    assert calls.read_text().count("systemctl reload sshd") == 2
    assert run(False).returncode == 0
    assert not marker.exists()
