import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).with_name("sync-local-group.sh")


def test_existing_group_is_not_rewritten(tmp_path):
    """An existing local group must not become managed just by naming it."""
    source = SCRIPT.read_text()
    source = source.replace('GROUP_NAME="replace-with-local-group"', 'GROUP_NAME="sudo"')
    source = source.replace(
        'MEMBERS=() # Example: (alice bob). This script owns the complete member list.',
        'MEMBERS=(newadmin)',
    )
    source = source.replace(
        "[[ $EUID == 0 ]] || { echo 'error: run as root' >&2; exit 1; }",
        ": # Test uses command stubs instead of root",
    )
    source = source.replace('STATE_DIR=/var/lib/defenseclaw-intune/local-groups', f'STATE_DIR={tmp_path / "state"}')
    script = tmp_path / "sync-local-group.sh"
    script.write_text(source)

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    getent = stub_dir / "getent"
    getent.write_text('#!/usr/bin/env bash\n'
                      '[[ $1 == -s ]] && shift 2\n'
                      'case "$1:$2" in\n'
                      '  passwd:newadmin) echo "newadmin:x:1001:1001::/home/newadmin:/bin/bash" ;;\n'
                      '  group:sudo) echo "sudo:x:27:oldadmin" ;;\n'
                      '  *) exit 2 ;;\n'
                      'esac\n')
    getent.chmod(0o755)
    gpasswd = stub_dir / "gpasswd"
    gpasswd.write_text('#!/usr/bin/env bash\nprintf "called" > "$CALL_LOG"\n')
    gpasswd.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    env["CALL_LOG"] = str(tmp_path / "gpasswd-called")
    result = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, check=False)

    assert result.returncode != 0
    assert "not owned by this script" in result.stderr
    assert not (tmp_path / "gpasswd-called").exists()
