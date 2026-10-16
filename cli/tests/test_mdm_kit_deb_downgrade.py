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


def test_deb_downgrade_refused_before_dpkg_install(tmp_path: Path) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    functions = "\n".join(function(source, name) for name in (
        "dc_json_escape", "dc_log", "dc_print_result", "dc_fail_result", "dc_require_product_version",
        "dc_package_release_version", "dc_install_package"
    ))
    stubs = {
        "dpkg-deb": "case \"$3\" in Package) echo defenseclaw-enterprise;; Version) echo 1.0.2;; Architecture) echo amd64;; esac",
        "dpkg-query": "echo 'install ok installed 1.0.5'",
        "dpkg": "case \"$1\" in --print-architecture) echo amd64;; --compare-versions) [ \"$2\" = 1.0.2 ] && [ \"$3\" = lt ] && [ \"$4\" = 1.0.5 ]; exit $?;; -i) echo install >>\"$DC_TEST_LOG\";; esac",
    }
    for name, body in stubs.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)
    log = tmp_path / "install.log"
    script = (
        f"DC_ACTION=ensure; DC_SCRIPT_OS=linux; DC_EXIT_FAILURE=1; DC_EXIT_INVALID=2; DC_EXIT_BUSY=75; "
        f"DC_LOG=''; DC_LINUX_PACKAGE=defenseclaw-enterprise; DC_PRODUCT_VERSION=''; "
        f"DC_STAGE='{tmp_path}'; DC_STAGED_SOURCE='{tmp_path / 'old.deb'}'\n"
        + "dc_package_step() { :; }\n" + functions + "\ndc_install_package\n"
    )
    result = subprocess.run(["sh", "-c", script], env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "DC_TEST_LOG": str(log)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1, result.stderr
    assert json.loads(result.stdout)["errors"][0]["code"] == "downgrade_refused"
    assert not log.exists(), "dpkg -i ran before the downgrade refusal"
