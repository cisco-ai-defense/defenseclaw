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

"""Permission assertions shared by cross-platform security regressions."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile


def assert_owner_only_file(path: str | os.PathLike[str]) -> None:
    """Assert POSIX 0600 or the equivalent protected Windows DACL."""
    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
        return

    with tempfile.TemporaryDirectory(prefix="defenseclaw-acl-test-") as tmp:
        saved_acl = os.path.join(tmp, "acl.txt")
        subprocess.run(
            ["icacls", os.fspath(path), "/save", saved_acl],
            check=True,
            capture_output=True,
        )
        with open(saved_acl, encoding="utf-16-le") as f:
            lines = f.read().splitlines()

    # /save emits stable SDDL even when account names and status messages are
    # localized. This is exactly one protected Owner Rights full-control ACE.
    assert lines[-1] == "D:P(A;;FA;;;OW)", lines
