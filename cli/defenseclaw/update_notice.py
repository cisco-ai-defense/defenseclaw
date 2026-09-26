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

"""One-line "a new release is available" notice for interactive use.

Checks the latest release at most once a day and stays silent unless both
stdout and stderr are terminals. Disabled by ``DEFENSECLAW_NO_UPDATE_CHECK=1``,
by ``CI``, or by ``update_check: false`` in config.yaml. Never raises.
"""

from __future__ import annotations

import json
import os
import sys
import time

NO_CHECK_ENV = "DEFENSECLAW_NO_UPDATE_CHECK"
_CACHE_FILE = ".update-check.json"
_CACHE_SECONDS = 24 * 60 * 60
_TIMEOUT_SECONDS = 2.0
_QUIET_COMMANDS = {"upgrade", "rollback", "migrate", "uninstall", "reset"}


def maybe_print(argv: list[str]) -> None:
    """Print the notice to stderr when a newer release exists."""

    try:
        if not _interactive(argv):
            return
        message = available_message()
        if message:
            print(f"\n  {message}", file=sys.stderr)
    except Exception:  # noqa: BLE001 - a notice must never break the command
        return


def available_message() -> str | None:
    """Return the notice text, or ``None`` when up to date or disabled."""

    from defenseclaw import __version__ as installed
    from defenseclaw.upgrade_shim import _key

    if _disabled():
        return None
    latest = _latest_cached()
    if latest and _key(latest) > _key(installed):
        return f"DefenseClaw {latest} is available (you have {installed}) — run 'defenseclaw upgrade'"
    return None


def _interactive(argv: list[str]) -> bool:
    if not (sys.stdout.isatty() and sys.stderr.isatty()):
        return False
    if not argv or argv[0] in _QUIET_COMMANDS:
        return False
    return not any(arg == "--json" or arg.startswith("--json") or arg in ("-o", "--output") for arg in argv)


def _disabled() -> bool:
    if os.environ.get(NO_CHECK_ENV, "").strip() not in ("", "0", "false") or os.environ.get("CI"):
        return True
    try:
        import yaml

        with open(os.path.join(_data_dir(), "config.yaml"), encoding="utf-8") as stream:
            raw = yaml.safe_load(stream)
    except Exception:  # noqa: BLE001 - missing or unreadable config keeps the default
        return False
    return isinstance(raw, dict) and raw.get("update_check") is False


def _latest_cached() -> str | None:
    path = os.path.join(_data_dir(), _CACHE_FILE)
    try:
        with open(path, encoding="utf-8") as stream:
            cached = json.load(stream)
        if time.time() - float(cached["checked_at"]) < _CACHE_SECONDS:
            return str(cached["latest"])
    except (OSError, ValueError, KeyError, TypeError):
        pass

    from defenseclaw.upgrade_shim import ShimError, latest_version

    try:
        latest = latest_version(timeout=_TIMEOUT_SECONDS)
    except ShimError:
        latest = ""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as stream:
            json.dump({"checked_at": time.time(), "latest": latest}, stream)
    except OSError:
        pass
    return latest or None


def _data_dir() -> str:
    return os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw")
