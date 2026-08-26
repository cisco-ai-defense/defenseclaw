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

"""Shared Click context types used by command modules."""

from __future__ import annotations

import click

SETUP_RESTART_HANDLED_META_KEY = "defenseclaw._setup_restart_handled"


class AppContext:
    """Shared application context passed through Click."""

    def __init__(self) -> None:
        self.cfg = None
        self.store = None
        self.logger = None
        # Set only by the root CLI when ``setup`` starts without config.yaml.
        # The setup group uses it to admit the trusted-paths bootstrap and
        # reject every other setup mutation until init has completed.
        self.preinit_setup_bootstrap = False
        # Set only when the root CLI deliberately defers setup's canonical
        # validation and runtime initialization until the setup group can see
        # its nested child command. Direct command-unit invocations retain
        # their existing already-initialized AppContext contract.
        self.setup_runtime_deferred = False


pass_ctx = click.make_pass_decorator(AppContext, ensure=True)

# Alias for command modules that import `pass_context`.
pass_context = pass_ctx


def mark_setup_restart_handled() -> None:
    """Prevent the setup group's generic result hook from restarting again."""

    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is not None:
        ctx.meta[SETUP_RESTART_HANDLED_META_KEY] = True
