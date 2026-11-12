# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""The hook fail-mode resolver loads on an interpreter that has no HTTP client stack.

Hook registration runs ``defenseclaw.fail_mode`` on a bare interpreter where
``requests`` is not installed. ``fail_mode`` reaches the gateway binary through
``defenseclaw.gateway_path`` (standard library only); importing
``defenseclaw.gateway`` there would pull ``requests`` in at load.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

from defenseclaw import gateway, gateway_path

_PACKAGE_PARENT = str(Path(gateway.__file__).resolve().parents[1])

_PROBE = textwrap.dedent(
    """
    import importlib.abc
    import sys

    class _Blocked(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in ("requests", "urllib3"):
                raise ModuleNotFoundError("No module named " + repr(name))
            return None

    sys.meta_path.insert(0, _Blocked())
    sys.path.insert(0, sys.argv[1])
    import defenseclaw.fail_mode as fail_mode
    import defenseclaw.gateway_path as gateway_path

    assert fail_mode.path_gateway is gateway_path.path_gateway
    assert "defenseclaw.gateway" not in sys.modules
    assert not any(m.split(".")[0] in ("requests", "urllib3") for m in sys.modules)
    print("light-ok")
    """
)


def test_fail_mode_imports_with_the_http_client_stack_absent() -> None:
    done = subprocess.run(
        [sys.executable, "-c", _PROBE, _PACKAGE_PARENT],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "light-ok"


def test_gateway_still_serves_the_same_resolver_names() -> None:
    for name in (
        "GATEWAY_BIN_NAME",
        "canonical_install_path",
        "path_gateway",
        "_launcher_sibling_gateway",
        "_is_runnable_file",
    ):
        assert getattr(gateway, name) is getattr(gateway_path, name), name
