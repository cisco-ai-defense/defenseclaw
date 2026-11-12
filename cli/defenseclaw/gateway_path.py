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

"""Where the gateway binary lives: the lookups that need only the standard library.

The Python CLI entry points that run before (or without) the HTTP client stack,
such as the hook fail-mode resolver the hook registration path imports on a bare
interpreter, resolve the gateway through this module. :mod:`defenseclaw.gateway`
imports ``requests`` and ``urllib3`` at load and re-exports these names, so existing
callers keep working. Keep this module standard-library only.
"""

from __future__ import annotations

import os
import shutil
import sys

GATEWAY_BIN_NAME = "defenseclaw-gateway"

_CANONICAL_INSTALL_DIR = os.path.join(os.path.expanduser("~"), ".local", "bin")


def canonical_install_path() -> str:
    """Return the canonical install path written by the installers.

    Exposed so error messages can reference the exact same path instead of
    each hard-coding the string.
    """
    name = GATEWAY_BIN_NAME + (".exe" if os.name == "nt" else "")
    return os.path.join(_CANONICAL_INSTALL_DIR, name)


def path_gateway(*, honor_override: bool = True) -> str | None:
    """The gateway to run: ``DEFENSECLAW_GATEWAY_BIN``, else this ``defenseclaw``'s own install, else ``PATH``.

    Callers that ran ``shutil.which("defenseclaw-gateway")`` took whatever
    comes first on ``PATH``: with a DefenseClaw Setup 0.8.x install listed
    before this one (a terminal opened before the install), that was the 0.8.x
    gateway, which rejects this release's ``config.yaml`` (GAP-0099).

    ``honor_override=False`` skips ``DEFENSECLAW_GATEWAY_BIN``. The variable is not
    custody-checked, so a caller that runs the result to change state passes it,
    as Doctor's lifecycle code ignores the variable: uninstall, hook registration,
    sidecar start and restart. ``resolve_gateway_binary`` (the general CLI
    lookup), the readiness report and the trusted verifier (which checks
    custody itself) follow it.
    """
    override = os.environ.get("DEFENSECLAW_GATEWAY_BIN", "").strip() if honor_override else ""
    if override:
        return override
    return _launcher_sibling_gateway() or shutil.which(GATEWAY_BIN_NAME)


def _launcher_sibling_gateway() -> str | None:
    """The gateway of the install this ``defenseclaw`` runs from, or None.

    Two layouts: the gateway next to a ``defenseclaw`` launcher this process
    was started as, and the per-user installer's, where a native launcher in
    ``~/.local/bin`` starts the CLI from the data folder's ``.venv`` and the
    gateway stays in ``~/.local/bin`` (the process then runs as
    ``<data>/.venv/Scripts/defenseclaw``, with no gateway beside it).
    """

    launcher = sys.argv[0] if sys.argv else ""
    name = os.path.basename(launcher).lower().removesuffix(".exe")
    if name == "defenseclaw":
        candidate = os.path.join(os.path.dirname(os.path.abspath(launcher)), os.path.basename(canonical_install_path()))
        if _is_runnable_file(candidate):
            return candidate
    return _installer_venv_gateway()


def _installer_venv_gateway() -> str | None:
    """The installer's gateway when this process runs from the installer's ``.venv``.

    Only the installer's own layout counts: the interpreter's environment is
    ``<data folder>/.venv`` with the installer's ``installer`` folder beside it,
    and the installer's ``defenseclaw`` launcher sits next to the gateway. A
    project's own ``.venv`` or a source checkout still resolves the gateway
    through ``PATH``.
    """
    prefix = os.path.abspath(sys.prefix)
    if os.path.basename(prefix).lower() != ".venv" or not os.path.isdir(
        os.path.join(os.path.dirname(prefix), "installer")
    ):
        return None
    gateway_path = canonical_install_path()
    launcher = os.path.join(os.path.dirname(gateway_path), "defenseclaw" + (".exe" if os.name == "nt" else ""))
    if _is_runnable_file(gateway_path) and os.path.lexists(launcher):
        return gateway_path
    return None


def _is_runnable_file(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False
