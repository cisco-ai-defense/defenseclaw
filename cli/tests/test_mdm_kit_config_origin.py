import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "packaging/mdm/macos/defenseclaw-enterprise.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


@pytest.mark.parametrize("origin", ["MDM inline config", "MDM standard input", "/trusted/config.yaml"])
def test_config_migration_warning_names_the_administrator_source(tmp_path: Path, origin: str) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    names = ["dc_print_result", "dc_emit_result"]
    if "dc_relabel_config_source()" in source:
        names.extend(["dc_json_escape", "dc_relabel_config_source"])
    functions = "\n".join(function(source, name) for name in names)
    stage = tmp_path / "stage"
    stage.mkdir()
    staged_config = stage / "inline-config.yaml"
    result_path = stage / "result.json"
    result_path.write_text(json.dumps({
        "warnings": [{"code": "config_version_8", "message": f"the config this run read ({staged_config}) is config_version 8"}]
    }, indent=2), encoding="utf-8")
    script = (
        f"DC_STAGE='{stage}'; DC_RESULT='{result_path}'; DC_CONFIG_STAGED='{staged_config}'; "
        f"DC_CONFIG_ORIGIN='{origin}'\n"
        "dc_log() { :; }\n" + functions + "\ndc_emit_result\n"
    )
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    message = json.loads(result.stdout)["warnings"][0]["message"]
    assert origin in message
    assert str(stage) not in message
