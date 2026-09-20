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

"""Resolve scanner executables installed with the DefenseClaw CLI."""

from __future__ import annotations

import shutil
import sysconfig


def resolve_scanner_binary(binary: str) -> str | None:
    """Return a scanner executable path, preferring this Python environment.

    Release installs put DefenseClaw and its scanner dependencies in the same
    virtual environment. Its scripts directory is not intentionally added to
    ``PATH`` on Windows, so check that managed location first (``Scripts`` on
    Windows, ``bin`` on Unix) and retain the normal ``PATH`` lookup as a
    fallback for operator-supplied installations.
    """
    command = str(binary or "").strip()
    if not command:
        return None

    scripts_dir = sysconfig.get_path("scripts")
    if scripts_dir:
        managed = shutil.which(command, path=scripts_dir)
        if managed:
            return managed

    return shutil.which(command)
