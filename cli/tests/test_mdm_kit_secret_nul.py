import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "packaging/mdm/linux/defenseclaw-enterprise.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


@pytest.mark.parametrize("source_kind", ["stdin", "file"])
def test_secret_with_nul_is_refused_before_lifecycle(tmp_path: Path, source_kind: str) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    names = ["dc_json_escape", "dc_log", "dc_print_result", "dc_fail_result"]
    if "dc_read_secret()" in source:
        names.append("dc_read_secret")
        call = "dc_read_secret"
    else:
        old_block = source.split('    secret_data=""\n    if [ -n "$DC_SECRET_NAME" ]; then', 1)[1].split(
            '\n    DC_CHANNEL_FLAG=', 1
        )[0]
        call = 'secret_data=""\nif [ -n "$DC_SECRET_NAME" ]; then' + old_block
    functions = "\n".join(function(source, name) for name in names)
    credential = b"part-one\x00part-two"
    secret = tmp_path / "credential"
    secret.write_bytes(credential)
    marker = tmp_path / "lifecycle-called"
    stage = tmp_path / "stage"
    stage.mkdir()
    file_arg = "''" if source_kind == "stdin" else repr(str(secret))
    script = (
        "DC_ACTION=ensure; DC_SCRIPT_OS=linux; DC_EXIT_INVALID=2; DC_LOG=''; "
        f"DC_STAGE='{stage}'; DC_MAX_SECRET_BYTES=16384; DC_SECRET_NAME=key; "
        f"DC_SECRET_STDIN={'1' if source_kind == 'stdin' else '0'}; "
        f"DC_SECRET_FILE={file_arg}\n"
        "dc_trusted_path() { return 0; }\n" + functions
        + f"\n{call}\ntouch '{marker}'\n"
    )
    result = subprocess.run(["sh", "-c", script], input=credential if source_kind == "stdin" else None,
                            env={"PATH": os.environ["PATH"]}, capture_output=True, timeout=10)
    assert result.returncode == 2, result.stderr
    error = json.loads(result.stdout)["errors"][0]
    assert error["code"] == "mdm_invalid_arguments"
    assert "NUL byte" in error["message"]
    assert not marker.exists()
    assert not (stage / "secret-input").exists()
