import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/mdm/intune/linux/sync-local-group.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def test_primary_group_member_is_reported_and_not_removed_by_gpasswd(tmp_path: Path) -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    sync = "current=$(getent -s files group" + source.split("current=$(getent -s files group", 1)[1]
    getent = tmp_path / "getent"
    getent.write_text(
        "#!/bin/sh\ncase \"$*\" in\n"
        "  '-s files group dc-r102-team') echo 'dc-r102-team:x:2001:';;\n"
        "  '-s files passwd') echo 'alice:x:1001:2001:Alice:/home/alice:/bin/bash'; "
        "echo 'bob:x:1002:2002:Bob:/home/bob:/bin/bash';;\n"
        "esac\n", encoding="ascii",
    )
    getent.chmod(0o755)
    for name in ("gpasswd", "groupmod"):
        path = tmp_path / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >>"$CALL_LOG"\n', encoding="ascii")
        path.chmod(0o755)
    log = tmp_path / "calls"
    script = "set -euo pipefail\nGROUP_NAME=dc-r102-team\ngid=2001\nMEMBERS=(bob)\n" + sync
    result = subprocess.run(["bash", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(log)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert "alice" in result.stdout + result.stderr
    assert "primary group must be changed" in result.stdout + result.stderr
    assert "gpasswd -M bob dc-r102-team" in log.read_text()
    assert "groupmod" not in log.read_text()
