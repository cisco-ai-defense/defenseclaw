import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent / "build-sssd-ppolicy-backport.sh"


def test_build_never_removes_a_preexisting_rpmbuild_directory(tmp_path: Path) -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    body = 'mkdir -p "$WORK"\n' + source.split('mkdir -p "$WORK"\n', 1)[1].split('rpm -i --define', 1)[0]
    work = tmp_path / "work"
    old = work / "rpmbuild"
    old.mkdir(parents=True)
    marker = old / "marker"
    marker.write_text("keep", encoding="ascii")
    (work / "sssd-2.9.8-4.el9_8.1.src.rpm").write_bytes(b"fixture")
    for name, content in {
        "sudo": "exit 0",
        "rpm": "[ \"$1\" != -qp ] || echo sssd-2.9.8-4.el9_8.1",
    }.items():
        command = tmp_path / name
        command.write_text("#!/bin/sh\n" + content + "\n", encoding="ascii")
        command.chmod(0o755)
    script = (
        f"set -euo pipefail\nWORK='{work}'\nT=\"$WORK/rpmbuild\"\n"
        "SPEC=\"$T/SPECS/sssd.spec\"\nNVR=sssd-2.9.8-4.el9_8.1\n"
        "log() { :; }\nfail() { exit \"$1\"; }\n" + body
    )
    result = subprocess.run(["bash", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert marker.read_text(encoding="ascii") == "keep"
