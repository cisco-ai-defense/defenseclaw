import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        ("unwritable_tar_log", "mdm_staging_full"),
        ("zero_available", "mdm_staging_full"),
        ("mkdir_full", "mdm_staging_full"),
        ("corrupt_archive", "mdm_payload_invalid"),
    ],
)
def test_extract_payload_failure_reports_cause(
    tmp_path: Path, platform: str, failure: str, expected_code: str,
) -> None:
    wrapper = ROOT / f"packaging/mdm/{platform}/defenseclaw-enterprise.sh"
    source = wrapper.read_text(encoding="utf-8")
    helpers = "\n".join(function(source, name) for name in (
        "dc_json_escape", "dc_log", "dc_print_result", "dc_fail_result", "dc_extract_payload",
    ))
    stage = tmp_path / "stage"
    stage.mkdir()
    if failure == "unwritable_tar_log":
        (stage / "tar.err").symlink_to("/dev/full")

    tar = tmp_path / "tar"
    error = "gzip: stdin: not in gzip format" if failure == "corrupt_archive" else "No space left on device"
    extract = "exit 2" if failure == "zero_available" else f"echo '{error}' >&2; exit 2"
    tar.write_text(
        "#!/bin/sh\ncase \"$1\" in -tzf) echo defenseclaw-gateway;; "
        f"-xzf) {extract};; esac\n",
        encoding="utf-8",
    )
    tar.chmod(0o755)
    if failure in {"zero_available", "corrupt_archive"}:
        df = tmp_path / "df"
        available = "0" if failure == "zero_available" else "12345"
        df.write_text(
            "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n"
            f"printf '/dev/test 12345 1 {available} 1%% /stage\\n'\n",
            encoding="utf-8",
        )
        df.chmod(0o755)
    if failure == "mkdir_full":
        mkdir = tmp_path / "mkdir"
        mkdir.write_text("#!/bin/sh\necho 'No space left on device' >&2\nexit 1\n", encoding="utf-8")
        mkdir.chmod(0o755)

    script = (
        "set -e\nDC_ACTION=ensure; "
        f"DC_SCRIPT_OS={'linux' if platform == 'linux' else 'darwin'}; DC_EXIT_FAILURE=1; DC_LOG=''; "
        f"DC_STAGE={shlex.quote(str(stage))}; DC_STAGED_SOURCE={shlex.quote(str(tmp_path / 'payload.tar.gz'))}\n"
        + helpers + "\ndc_extract_payload\n"
    )
    result = subprocess.run(
        ["sh", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 1, result.stderr
    error_result = json.loads(result.stdout)["errors"][0]
    assert error_result["code"] == expected_code
    if failure != "corrupt_archive":
        assert str(stage) in error_result["message"] and "full" in error_result["message"]
