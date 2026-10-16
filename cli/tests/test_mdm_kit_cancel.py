import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "packaging/mdm/linux/defenseclaw-enterprise.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


def test_cancelled_lifecycle_stops_child_and_reports_failure(tmp_path: Path) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    functions = "\n".join(function(source, name) for name in (
        "dc_json_escape", "dc_log", "dc_print_result", "dc_fail_result", "dc_stop_child", "dc_run_lifecycle"
    ))
    gateway = tmp_path / "defenseclaw-gateway"
    started = tmp_path / "started"
    done = tmp_path / "done"
    gateway.write_text(
        "#!/usr/bin/env python3\nimport os, time\n"
        f"open({str(started)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(30)\n"
        f"open({str(done)!r}, 'w').write('done')\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = (
        "DC_ACTION=ensure; DC_SCRIPT_OS=linux; DC_EXIT_FAILURE=1; DC_LOG=''; DC_CHILD=''; "
        f"DC_STAGE='{tmp_path}'\n" + functions
        + "\ntrap 'dc_stop_child; dc_fail_result 1 mdm_cancelled \"the MDM run was cancelled\"' TERM\n"
        + f"dc_run_lifecycle '{gateway}' ensure\n"
    )
    proc = subprocess.Popen(["sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        deadline = time.monotonic() + 3
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert started.exists(), "fake lifecycle did not start"
        child_pid = int(started.read_text())
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=3)
        assert proc.returncode != 0, err
        assert json.loads(out)["errors"][0]["code"] == "mdm_cancelled"
        assert not done.exists()
        assert not Path(f"/proc/{child_pid}").exists(), "lifecycle child is still running"
        assert 'trap \'dc_stop_child; dc_fail_result "$DC_EXIT_FAILURE" mdm_cancelled' in source
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
