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

"""GAP-0037: with sandboxes off, the uninstall refusal names a check that works."""

from __future__ import annotations

import contextlib
import io

import pytest
from defenseclaw.commands import cmd_uninstall

_OFF = "`sandbox list` failed: OpenShell sandboxes are off; run `defenseclaw sandbox setup` to turn them on"
_OFF_OTHER = (
    "`sandbox list` failed: OpenShell sandboxes are off for this account, and another account runs this "
    "machine's OpenShell gateway (dck2-std1)"
)


def _one_line(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("error", [_OFF, _OFF_OTHER])
def test_sandboxes_off_refusal_names_the_teardown_dry_run_and_skip(error: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, sandbox_list_error=error)
    out = _one_line(cmd_uninstall._running_sandboxes_refusal(plan))
    assert f"the sandbox list could not be read ({error})" in out
    assert "nothing was changed" in out
    # The check it names must not be the one that just failed.
    assert "Run `defenseclaw sandbox list` to check" not in out
    assert "run `defenseclaw sandbox teardown --dry-run`" in out
    assert "run this command again with --skip-sandbox-teardown" in out
    assert "add --stop-sandboxes" in out


def test_other_unread_lists_keep_the_sandbox_list_check() -> None:
    plan = cmd_uninstall.UninstallPlan(
        sandbox_teardown=True, sandbox_list_error="`sandbox list` failed: the sandbox daemon is not running"
    )
    out = _one_line(cmd_uninstall._running_sandboxes_refusal(plan))
    assert "Run `defenseclaw sandbox list` to check" in out
    assert "--skip-sandbox-teardown" not in out


def test_stop_sandboxes_still_goes_through_with_sandboxes_off() -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, sandbox_list_error=_OFF, stop_sandboxes=True)
    assert cmd_uninstall._running_sandboxes_refusal(plan) == ""


def test_dry_run_plan_names_the_teardown_dry_run_with_sandboxes_off() -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, sandbox_list_error=_OFF)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_uninstall._render_plan(plan, dry_run=True)
    out = _one_line(buf.getvalue())
    assert "check with `defenseclaw sandbox teardown --dry-run`" in out
    assert "add --skip-sandbox-teardown when it names no sandbox, or add --stop-sandboxes" in out
