# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The MDM wrapper refuses an RPM for another CPU before invoking rpm -U."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[2] / "packaging/mdm/linux/defenseclaw-enterprise.sh"
pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def _function(source: str, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}$", source, re.MULTILINE | re.DOTALL)
    assert match, name
    return match.group()


@pytest.mark.parametrize("package_arch,host_arch", [("aarch64", "x86_64"), ("x86_64", "aarch64")])
def test_rpm_wrong_architecture_refused_before_install(
    tmp_path: Path, package_arch: str, host_arch: str
) -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    functions = "\n".join(_function(source, name) for name in (
        "dc_json_escape", "dc_log", "dc_print_result", "dc_fail_result",
        "dc_require_product_version", "dc_package_release_version", "dc_install_package",
    ))
    rpm = tmp_path / "rpm"
    rpm.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = -qp ]; then\n"
        "  case \"$3\" in\n"
        "    '%{NAME}') echo defenseclaw-enterprise;;\n"
        "    '%{VERSION}-%{RELEASE}') echo 1.0.3-1;;\n"
        f"    '%{{ARCH}}') echo {package_arch};;\n"
        "  esac\n"
        "elif [ \"$1\" = --eval ]; then\n"
        f"  echo {host_arch}\n"
        "elif [ \"$1\" = -U ]; then\n"
        "  echo installed >\"$DC_TEST_LOG\"\n"
        "fi\n",
        encoding="utf-8",
    )
    rpm.chmod(0o755)
    log = tmp_path / "install.log"
    script = (
        "DC_ACTION=ensure; DC_SCRIPT_OS=linux; DC_EXIT_FAILURE=1; DC_EXIT_INVALID=2; DC_EXIT_BUSY=75; "
        "DC_LOG=''; DC_LINUX_PACKAGE=defenseclaw-enterprise; DC_PRODUCT_VERSION=''; "
        f"DC_STAGE='{tmp_path}'; DC_STAGED_SOURCE='{tmp_path / 'wrong.rpm'}'\n"
        + "dc_package_step() { :; }\n" + functions + "\ndc_install_package\n"
    )
    result = subprocess.run(
        ["sh", "-c", script],
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}", "DC_TEST_LOG": str(log)},
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 1, result.stderr
    error = json.loads(result.stdout)["errors"][0]
    assert error["code"] == "mdm_wrong_architecture"
    assert package_arch in error["message"] and host_arch in error["message"]
    assert not log.exists(), "rpm -U ran before the architecture refusal"
