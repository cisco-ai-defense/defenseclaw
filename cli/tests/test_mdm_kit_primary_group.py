import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packaging/mdm/intune/linux/sync-local-group.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def _run_sync(tmp_path: Path, own_group: str) -> tuple[subprocess.CompletedProcess, str]:
    """Run the member sync of sync-local-group.sh with alice's primary group
    the synced group (gid 2001) and bob the only wanted member. own_group is
    what getent answers for alice's own group ("" = none, then groupadd)."""
    source = SCRIPT.read_text(encoding="utf-8")
    sync = "current=$(getent -s files group" + source.split("current=$(getent -s files group", 1)[1]
    made = tmp_path / "made-alice"
    getent = tmp_path / "getent"
    getent.write_text(
        "#!/bin/sh\ncase \"$*\" in\n"
        "  '-s files group dc-r102-team') echo 'dc-r102-team:x:2001:';;\n"
        "  '-s files passwd') echo 'alice:x:1001:2001:Alice:/home/alice:/bin/bash'; "
        "echo 'bob:x:1002:2002:Bob:/home/bob:/bin/bash';;\n"
        f"  '-s files group alice') if [ -n '{own_group}' ]; then echo '{own_group}'; "
        f"elif [ -e '{made}' ]; then echo 'alice:x:1001:'; else exit 2; fi;;\n"
        "  *) exit 2;;\n"
        "esac\n", encoding="ascii",
    )
    getent.chmod(0o755)
    for name in ("gpasswd", "groupmod", "usermod", "groupadd"):
        path = tmp_path / name
        extra = f"touch '{made}'\n" if name == "groupadd" else ""
        path.write_text(f'#!/bin/sh\necho "{name} $*" >>"$CALL_LOG"\n{extra}', encoding="ascii")
        path.chmod(0o755)
    log = tmp_path / "calls"
    log.write_text("", encoding="ascii")
    script = "set -euo pipefail\nGROUP_NAME=dc-r102-team\ngid=2001\nMEMBERS=(bob)\n" + sync
    result = subprocess.run(["bash", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(log)},
                            capture_output=True, text=True, timeout=10)
    return result, log.read_text(encoding="ascii")


@pytest.mark.parametrize("own_group", ["alice:x:1001:", ""])
def test_primary_group_member_removed_from_members_moves_to_its_own_group(tmp_path: Path, own_group: str) -> None:
    result, calls = _run_sync(tmp_path, own_group)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "gpasswd -M bob dc-r102-team" in calls
    assert "usermod -g alice -- alice" in calls
    assert ("groupadd -- alice" in calls) == (own_group == "")
    assert "moved: the primary group of alice from dc-r102-team to alice" in result.stdout
    assert "groupmod" not in calls


@pytest.mark.parametrize("own_group", ["alice:x:1001:carol", "alice:x:27:"])
def test_primary_group_member_keeps_a_shared_or_system_own_group_and_is_reported(tmp_path: Path, own_group: str) -> None:
    result, calls = _run_sync(tmp_path, own_group)
    assert result.returncode == 1
    assert "alice remains in dc-r102-team" in result.stderr
    assert "usermod" not in calls
    assert "gpasswd -M bob dc-r102-team" in calls
